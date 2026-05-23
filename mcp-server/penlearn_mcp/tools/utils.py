"""
Utility / meta tools (4 tools).
check_domain, check_ip, detect_input_type, auth_replay.
These are lightweight helpers used by the Planner and Executor layers.
"""
import asyncio
import ipaddress
import json
import re
import socket
import time
import urllib.request
import urllib.parse
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s, _run, _artifact


# ---------------------------------------------------------------------------
# detect_input_type — classify a string as IP, CIDR, domain, URL, or unknown
# ---------------------------------------------------------------------------

def _classify(value: str) -> dict:
    value = value.strip()

    # URL
    if value.startswith(("http://", "https://", "ftp://")):
        parsed = urllib.parse.urlparse(value)
        host = parsed.hostname or ""
        return {"type": "url", "value": value, "host": host}

    # Single IP (must check before CIDR — ip_network() accepts bare IPs as /32 or /128)
    try:
        addr = ipaddress.ip_address(value)
        return {
            "type": "ip",
            "value": value,
            "version": addr.version,
            "private": addr.is_private,
            "loopback": addr.is_loopback,
        }
    except ValueError:
        pass

    # CIDR (only when "/" is present to indicate an explicit network prefix)
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            is_private = net.is_private
            prefix = net.prefixlen
            return {
                "type": "cidr",
                "value": value,
                "version": net.version,
                "private": is_private,
                "prefix_len": prefix,
                "large": prefix < 16,
            }
        except ValueError:
            pass

    # Domain (simple heuristic: has a dot, no spaces, valid chars)
    domain_re = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_re.match(value):
        return {"type": "domain", "value": value}

    return {"type": "unknown", "value": value}


async def _detect_input_type(args: dict) -> list[TextContent]:
    value = (args.get("value") or "").strip()
    if not value:
        return _ok("Error: value is required.")

    result = _classify(value)
    lines = [f"Input classification: {value!r}", ""]
    lines.append(f"  Type:    {result['type']}")
    for k, v in result.items():
        if k not in ("type", "value"):
            lines.append(f"  {k}: {v}")

    if result["type"] == "cidr" and result.get("large"):
        lines.append("")
        lines.append("WARNING: CIDR prefix < /16 — this is a very large range.")
        lines.append("MASS_SCAN intent is required for scanning ranges this large.")

    return _ok("\n".join(lines))


register(Tool(
    name="detect_input_type",
    description=(
        "Classify an input value as IP, CIDR, domain, URL, or unknown. "
        "Use before any scan to determine the appropriate tool and scope check."
    ),
    inputSchema=_s(["value"], value=("string", "IP address, CIDR, domain, or URL to classify")),
), _detect_input_type)


# ---------------------------------------------------------------------------
# check_domain — scope check + basic DNS resolution for a domain
# ---------------------------------------------------------------------------

async def _check_domain(args: dict) -> list[TextContent]:
    domain = (args.get("domain") or "").strip()
    project_name = (args.get("project_name") or "").strip()

    if not domain:
        return _ok("Error: domain is required.")

    lines = [f"Domain check: {domain}", ""]

    # Scope check if project provided
    if project_name:
        ws = Path.home() / "penlearn" / "projects" / project_name / "workspace"
        scope_file = ws / "scope.json"
        if scope_file.exists():
            try:
                scope = json.loads(scope_file.read_text())
                in_scope = scope.get("in_scope", [])
                out_scope = scope.get("out_of_scope", [])
                blocked = any(domain == s or domain.endswith("." + s) for s in out_scope)
                allowed = any(domain == s or domain.endswith("." + s) for s in in_scope)
                if blocked:
                    lines.append("SCOPE: OUT OF SCOPE — do not test")
                    return _ok("\n".join(lines))
                elif allowed:
                    lines.append("SCOPE: IN SCOPE ✓")
                else:
                    lines.append("SCOPE: UNVERIFIED — not in scope list, verify before testing")
            except Exception:
                pass

    # DNS resolution
    ips: list[str] = []
    try:
        addrs = await asyncio.to_thread(socket.getaddrinfo, domain, None)
        ips = sorted(set(addr[4][0] for addr in addrs))
        lines.append(f"DNS resolved to: {', '.join(ips)}")
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    lines.append(f"  {ip} → private address")
                elif addr.is_loopback:
                    lines.append(f"  {ip} → loopback")
                else:
                    lines.append(f"  {ip} → public")
            except Exception:
                pass
    except socket.gaierror as e:
        lines.append(f"DNS resolution failed: {e}")

    # Reverse lookup
    try:
        if ips:
            hostname = (await asyncio.to_thread(socket.gethostbyaddr, ips[0]))[0]
            if hostname and hostname != domain:
                lines.append(f"Reverse DNS: {hostname}")
    except Exception:
        pass

    return _ok("\n".join(lines))


register(Tool(
    name="check_domain",
    description=(
        "Scope check and DNS resolution for a domain. "
        "Checks project scope file if project_name is provided. "
        "Returns resolved IPs and whether they are public/private."
    ),
    inputSchema=_s(
        ["domain"],
        domain=("string", "Domain name to check, e.g. target.example.com"),
        project_name=("string", "Project name for scope check (optional)"),
    ),
), _check_domain)


# ---------------------------------------------------------------------------
# check_ip — scope check + geolocation for an IP address
# ---------------------------------------------------------------------------

async def _check_ip(args: dict) -> list[TextContent]:
    ip = (args.get("ip") or "").strip()
    project_name = (args.get("project_name") or "").strip()

    if not ip:
        return _ok("Error: ip is required.")

    lines = [f"IP check: {ip}", ""]

    # Parse
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _ok(f"Error: {ip!r} is not a valid IP address.")

    lines.append(f"  Version:  IPv{addr.version}")
    lines.append(f"  Private:  {addr.is_private}")
    lines.append(f"  Loopback: {addr.is_loopback}")
    lines.append(f"  Reserved: {addr.is_reserved}")

    # Scope check
    if project_name:
        ws = Path.home() / "penlearn" / "projects" / project_name / "workspace"
        scope_file = ws / "scope.json"
        if scope_file.exists():
            try:
                scope = json.loads(scope_file.read_text())
                in_scope = scope.get("in_scope", [])
                out_scope = scope.get("out_of_scope", [])
                blocked = any(ip == s or _ip_in_network(ip, s) for s in out_scope)
                allowed = any(ip == s or _ip_in_network(ip, s) for s in in_scope)
                lines.append("")
                if blocked:
                    lines.append("SCOPE: OUT OF SCOPE — do not test")
                    return _ok("\n".join(lines))
                elif allowed:
                    lines.append("SCOPE: IN SCOPE ✓")
                else:
                    lines.append("SCOPE: UNVERIFIED — not in scope list")
            except Exception:
                pass

    # Reverse DNS
    try:
        hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
        lines.append(f"\nReverse DNS: {hostname}")
    except Exception:
        pass

    # Basic geolocation via ip-api.com (free, no key needed)
    if not addr.is_private and not addr.is_loopback:
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "penlearn-local/0.1"})
            def _geo_fetch(r=req):
                with urllib.request.urlopen(r, timeout=5) as resp:
                    return json.loads(resp.read())
            geo = await asyncio.to_thread(_geo_fetch)
            lines.append(f"\nGeo: {geo.get('city','?')}, {geo.get('regionName','?')}, {geo.get('country','?')}")
            lines.append(f"ISP: {geo.get('isp','?')}")
            lines.append(f"Org: {geo.get('org','?')}")
            lines.append(f"ASN: {geo.get('as','?')}")
        except Exception:
            pass

    return _ok("\n".join(lines))


def _ip_in_network(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


register(Tool(
    name="check_ip",
    description=(
        "Scope check, reverse DNS, and geolocation for an IP address. "
        "Checks project scope file if project_name is provided. "
        "Returns whether the IP is private/public and its geographic location."
    ),
    inputSchema=_s(
        ["ip"],
        ip=("string", "IPv4 or IPv6 address to check"),
        project_name=("string", "Project name for scope check (optional)"),
    ),
), _check_ip)


# ---------------------------------------------------------------------------
# auth_replay — replay a captured session token against an endpoint
# ---------------------------------------------------------------------------

async def _auth_replay(args: dict) -> list[TextContent]:
    endpoint = (args.get("endpoint") or "").strip()
    token = (args.get("token") or "").strip()
    token_type = (args.get("token_type") or "Bearer").strip()
    method = (args.get("method") or "GET").strip().upper()
    body = (args.get("body") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 15))

    if not endpoint:
        return _ok("Error: endpoint is required.")
    if not token:
        return _ok("Error: token is required.")

    # Build curl command for token replay
    cmd = [
        "curl", "-sL", "-m", str(timeout_s),
        "-X", method,
        "-H", f"Authorization: {token_type} {token}",
        "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) pentesting-agent/1.0",
        "-D", "-",  # include response headers
        "-w", "\n--- status=%{http_code} size=%{size_download} time=%{time_total}s ---",
    ]
    if body and method in ("POST", "PUT", "PATCH"):
        cmd += ["-H", "Content-Type: application/json", "--data-raw", body]
    cmd.append(endpoint)

    stdout, stderr, rc = await _run(cmd, timeout=timeout_s + 5)
    if rc == -1:
        return _ok(f"Token replay timed out: {stderr}")

    # Parse status code from curl -w output
    m = re.search(r"status=(\d+)", stdout)
    status_code = int(m.group(1)) if m else None

    # Split headers from body
    lines_out = stdout.splitlines()
    sep_idx = next((i for i, l in enumerate(lines_out) if l.strip() == ""), -1)
    headers_raw = lines_out[:sep_idx] if sep_idx != -1 else []
    body_raw = "\n".join(lines_out[sep_idx + 1:]) if sep_idx != -1 else stdout

    result_lines = [
        f"Token replay: {method} {endpoint}",
        f"Token type: {token_type}",
        f"Status: {status_code}",
        "",
    ]

    # Interpretation
    if status_code == 200:
        result_lines.append("RESULT: 200 OK — token ACCEPTED. Check response body for authorized data.")
        result_lines.append("  → If token was a post-logout/expired token, this is a session management finding.")
    elif status_code == 401:
        result_lines.append("RESULT: 401 Unauthorized — token REJECTED (expected for invalidated tokens).")
    elif status_code == 403:
        result_lines.append("RESULT: 403 Forbidden — token recognized but insufficient privilege.")
        result_lines.append("  → Try vertical escalation: modify role/claims in token payload.")
    elif status_code and 300 <= status_code < 400:
        location = next((h for h in headers_raw if h.lower().startswith("location:")), "")
        result_lines.append(f"RESULT: {status_code} Redirect → {location}")
    else:
        result_lines.append(f"RESULT: {status_code} — investigate manually.")

    result_lines += [
        "",
        "Response headers:",
        *[f"  {h}" for h in headers_raw[:15]],
        "",
        "Response body (first 500 chars):",
        body_raw[:500],
    ]

    result = "\n".join(result_lines)

    # Persist artifact
    if project_id:
        _artifact(int(project_id), "auth_replay", result)

    return _ok(result)


register(Tool(
    name="auth_replay",
    description=(
        "Replay a captured session token against an endpoint and interpret the response. "
        "Use to test token reuse (post-logout replay), token fixation, and horizontal/vertical "
        "privilege escalation. Returns status code with security interpretation."
    ),
    inputSchema=_s(
        ["endpoint", "token"],
        endpoint=("string", "Target endpoint URL"),
        token=("string", "Session token or API key value to replay"),
        token_type=("string", "Token scheme: Bearer, Basic, Cookie, X-Auth-Token (default: Bearer)"),
        method=("string", "HTTP method (default: GET)"),
        body=("string", "Request body for POST/PUT (JSON string, optional)"),
        project_id=("integer", "Project ID for artifact storage (optional)"),
        timeout=("integer", "Timeout in seconds (default: 15)"),
    ),
), _auth_replay)
