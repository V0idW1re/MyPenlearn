"""
OSINT tools (15 tools).
Most use external binaries or public APIs; fallbacks noted.
"""
import asyncio
import base64
import json
import re
import socket
import urllib.parse
import urllib.request
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _chk, _need, _run, _ok, _s


async def _http_get(req_or_url, *, timeout: int = 20) -> bytes:
    """Non-blocking HTTP GET wrapped in asyncio.to_thread."""
    def _do() -> bytes:
        with urllib.request.urlopen(req_or_url, timeout=timeout) as r:
            return r.read()
    return await asyncio.to_thread(_do)


async def _http_get_with_status(req_or_url, *, timeout: int = 20) -> tuple[int, dict, bytes]:
    """Non-blocking HTTP GET returning (status, headers, body)."""
    def _do() -> tuple[int, dict, bytes]:
        with urllib.request.urlopen(req_or_url, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    return await asyncio.to_thread(_do)

# ---------------------------------------------------------------------------
# theharvester_run
# ---------------------------------------------------------------------------

async def _theharvester_run(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    sources = args.get("sources", "google,bing,crtsh,dnsdumpster,hackertarget")
    limit = int(args.get("limit", 100))
    if not _chk("theHarvester"):
        return _need("theHarvester", "pip install theHarvester  or  sudo apt install theharvester")
    cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", str(limit)]
    out, err, _ = await _run(cmd, timeout=120)
    return _ok(out or err)

register(Tool(
    name="theharvester_run",
    description="Run theHarvester to gather emails, subdomains, hosts, and employee names.",
    inputSchema=_s(["domain"],
        domain=("string", "Target domain (e.g. example.com)"),
        sources=("string", "Comma-separated sources (default: google,bing,crtsh,dnsdumpster,hackertarget)"),
        limit=("integer", "Max results per source (default: 100)")),
), _theharvester_run)

# ---------------------------------------------------------------------------
# wayback_urls
# ---------------------------------------------------------------------------

async def _wayback_urls(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    limit = int(args.get("limit", 200))
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
    try:
        data = (await _http_get(url, timeout=30)).decode(errors="replace")
        lines = sorted(set(data.strip().splitlines()))
        return _ok(f"Wayback URLs for {domain} ({len(lines)} unique):\n" + "\n".join(lines[:500]))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="wayback_urls",
    description="Fetch archived URLs for a domain from the Wayback Machine CDX API.",
    inputSchema=_s(["domain"],
        domain=("string", "Target domain"),
        limit=("integer", "Max results (default: 200)")),
), _wayback_urls)

# ---------------------------------------------------------------------------
# crt_sh
# ---------------------------------------------------------------------------

async def _crt_sh(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    wildcard = args.get("wildcard", True)
    q = f"%.{domain}" if wildcard else domain
    url = f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        entries = json.loads(await _http_get(req, timeout=30))
        names = sorted({e.get("name_value", "") for e in entries if e.get("name_value")})
        return _ok(f"crt.sh results for {domain} ({len(names)} unique names):\n" + "\n".join(names[:500]))
    except Exception as e:
        return _ok(f"Error querying crt.sh: {e}")

register(Tool(
    name="crt_sh",
    description="Query crt.sh certificate transparency logs for subdomains of a domain.",
    inputSchema=_s(["domain"],
        domain=("string", "Target domain (e.g. example.com)"),
        wildcard=("boolean", "Include wildcard prefix search (default: true)")),
), _crt_sh)

# ---------------------------------------------------------------------------
# github_search
# ---------------------------------------------------------------------------

async def _github_search(args: dict) -> list[TextContent]:
    query = args.get("query", "")
    search_type = args.get("type", "code")  # code, repositories, commits
    token = args.get("token", "")
    url = f"https://api.github.com/search/{search_type}?q={urllib.parse.quote(query)}&per_page=20"
    headers_list = [("Accept", "application/vnd.github.v3+json"),
                    ("User-Agent", "penligent-local/0.1")]
    if token:
        headers_list.append(("Authorization", f"token {token}"))
    try:
        req = urllib.request.Request(url, headers=dict(headers_list))
        data = json.loads(await _http_get(req, timeout=20))
        items = data.get("items", [])
        lines = [f"GitHub {search_type} search: '{query}' ({data.get('total_count', '?')} total, showing {len(items)})"]
        for item in items:
            if search_type == "code":
                lines.append(f"  {item.get('repository', {}).get('full_name','?')}/{item.get('path','?')} - {item.get('html_url','')}")
            elif search_type == "repositories":
                lines.append(f"  {item.get('full_name','?')} stars={item.get('stargazers_count',0)} - {item.get('html_url','')}")
            else:
                lines.append(f"  {item.get('commit',{}).get('message','?')[:80]} - {item.get('html_url','')}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="github_search",
    description="Search GitHub for code, repositories, or commits matching a query (API rate-limited without token).",
    inputSchema=_s(["query"],
        query=("string", "Search query (e.g. 'target.com password' or 'org:target-corp secret')"),
        type=("string", "Search type: code (default), repositories, or commits"),
        token=("string", "Optional GitHub personal access token for higher rate limits")),
), _github_search)

# ---------------------------------------------------------------------------
# shodan_query
# ---------------------------------------------------------------------------

async def _shodan_query(args: dict) -> list[TextContent]:
    query = args.get("query", "")
    api_key = args.get("api_key", "")
    if not api_key:
        return _ok("Error: api_key is required. Get one from https://account.shodan.io")
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}&minify=false"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=20))
        matches = data.get("matches", [])
        total = data.get("total", 0)
        lines = [f"Shodan: '{query}' — {total} total results, showing {len(matches)}"]
        for m in matches:
            ip = m.get("ip_str", "?")
            port = m.get("port", "?")
            org = m.get("org", "?")
            hostnames = ", ".join(m.get("hostnames", []))
            banner = (m.get("data", "")[:80]).replace("\n", " ")
            lines.append(f"  {ip}:{port} org={org} hostnames={hostnames}")
            if banner:
                lines.append(f"    {banner}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="shodan_query",
    description="Query Shodan for internet-exposed hosts matching a dork or IP (requires Shodan API key).",
    inputSchema=_s(["query", "api_key"],
        query=("string", "Shodan search query (e.g. 'hostname:example.com port:443')"),
        api_key=("string", "Shodan API key")),
), _shodan_query)

# ---------------------------------------------------------------------------
# censys_query
# ---------------------------------------------------------------------------

async def _censys_query(args: dict) -> list[TextContent]:
    query = args.get("query", "")
    api_id = args.get("api_id", "")
    api_secret = args.get("api_secret", "")
    if not api_id or not api_secret:
        return _ok("Error: api_id and api_secret required. Register at https://search.censys.io/account/api")
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url = "https://search.censys.io/api/v2/hosts/search"
    body = json.dumps({"q": query, "per_page": 20}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json",
        "User-Agent": "penligent-local/0.1",
    })
    try:
        data = json.loads(await _http_get(req, timeout=20))
        hits = data.get("result", {}).get("hits", [])
        lines = [f"Censys: '{query}' — {len(hits)} results"]
        for h in hits:
            ip = h.get("ip", "?")
            services = [f"{s.get('port','?')}/{s.get('transport_protocol','?')} {s.get('service_name','')}" for s in h.get("services", [])]
            lines.append(f"  {ip}  services: {', '.join(services)}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="censys_query",
    description="Query Censys for hosts matching a query (requires Censys API credentials).",
    inputSchema=_s(["query", "api_id", "api_secret"],
        query=("string", "Censys search query (e.g. 'ip:1.2.3.0/24 and services.port:443')"),
        api_id=("string", "Censys API ID"),
        api_secret=("string", "Censys API secret")),
), _censys_query)

# ---------------------------------------------------------------------------
# ip_geolocation
# ---------------------------------------------------------------------------

async def _ip_geolocation(args: dict) -> list[TextContent]:
    ip = args.get("ip", "")
    url = f"https://ipinfo.io/{ip}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=10))
        lines = [f"IP: {data.get('ip', ip)}"]
        for field in ("hostname", "city", "region", "country", "org", "timezone", "loc"):
            if data.get(field):
                lines.append(f"  {field}: {data[field]}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="ip_geolocation",
    description="Look up geolocation and ASN info for an IP address using ipinfo.io.",
    inputSchema=_s(["ip"], ip=("string", "IPv4 or IPv6 address")),
), _ip_geolocation)

# ---------------------------------------------------------------------------
# asn_info
# ---------------------------------------------------------------------------

async def _asn_info(args: dict) -> list[TextContent]:
    query = args.get("query", "")  # ASN number or IP
    url = f"https://ipinfo.io/{query}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=10))
        return _ok(json.dumps(data, indent=2))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="asn_info",
    description="Look up ASN information for an ASN number (e.g. AS12345) or IP via ipinfo.io.",
    inputSchema=_s(["query"],
        query=("string", "ASN number (e.g. AS13335) or IP address")),
), _asn_info)

# ---------------------------------------------------------------------------
# cloudflare_check
# ---------------------------------------------------------------------------

async def _cloudflare_check(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    results = []
    # Check DNS A records against known Cloudflare IP ranges
    if _chk("dig"):
        out, _, _ = await _run(["dig", "+short", domain, "A"])
        results.append(f"A records:\n{out.strip()}")
        out2, _, _ = await _run(["dig", "+short", domain, "NS"])
        results.append(f"NS records:\n{out2.strip()}")
        cf_ns = any("cloudflare" in line.lower() for line in out2.splitlines())
        cf_ip_ranges = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.",
                        "141.101.", "108.162.", "190.93.", "188.114.", "197.234.", "198.41."]
        cf_a = any(any(ip.startswith(r) for r in cf_ip_ranges) for ip in out.splitlines())
        behind_cf = cf_ns or cf_a
        results.append(f"Behind Cloudflare: {behind_cf}")
        if behind_cf:
            results.append("Note: real IP may be exposed via mail MX, SPF, or historical DNS.")
    else:
        # Pure Python fallback
        try:
            ips = (await asyncio.to_thread(socket.gethostbyname_ex, domain))[2]
            results.append(f"Resolved IPs: {', '.join(ips)}")
        except Exception as e:
            results.append(f"DNS error: {e}")
    return _ok("\n\n".join(results))

register(Tool(
    name="cloudflare_check",
    description="Check if a domain is behind Cloudflare by inspecting NS records and IP ranges.",
    inputSchema=_s(["domain"], domain=("string", "Target domain")),
), _cloudflare_check)

# ---------------------------------------------------------------------------
# wayback_robots
# ---------------------------------------------------------------------------

async def _wayback_robots(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    url = f"https://web.archive.org/web/0/{domain}/robots.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = (await _http_get(req, timeout=20)).decode(errors="replace")
        return _ok(f"robots.txt for {domain} (via Wayback Machine):\n\n{data[:3000]}")
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="wayback_robots",
    description="Fetch the oldest archived robots.txt for a domain from the Wayback Machine.",
    inputSchema=_s(["domain"], domain=("string", "Target domain")),
), _wayback_robots)

# ---------------------------------------------------------------------------
# email_verify
# ---------------------------------------------------------------------------

async def _email_verify(args: dict) -> list[TextContent]:
    email = args.get("email", "")
    if "@" not in email:
        return _ok("Error: not a valid email address.")
    _, domain = email.rsplit("@", 1)
    results = [f"Email: {email}", f"Domain: {domain}"]
    # Check MX records
    if _chk("dig"):
        out, _, _ = await _run(["dig", "+short", domain, "MX"])
        results.append(f"MX records:\n{out.strip() or '(none)'}")
        out2, _, _ = await _run(["dig", "+short", domain, "TXT"])
        spf = [l for l in out2.splitlines() if "v=spf1" in l.lower()]
        results.append(f"SPF: {spf[0] if spf else '(not found)'}")
    # Regex pattern check
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    valid_fmt = bool(re.match(pattern, email))
    results.append(f"Format valid: {valid_fmt}")
    return _ok("\n".join(results))

register(Tool(
    name="email_verify",
    description="Verify an email address format and check the domain's MX/SPF records.",
    inputSchema=_s(["email"], email=("string", "Email address to verify")),
), _email_verify)

# ---------------------------------------------------------------------------
# breach_check
# ---------------------------------------------------------------------------

async def _breach_check(args: dict) -> list[TextContent]:
    email = args.get("email", "")
    # HIBP v3 API (no key needed for pwnedpasswords, but account lookup requires API key)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "penligent-local/0.1",
            "hibp-api-key": "",  # key required; will 401 without one
        })
        data = json.loads(await _http_get(req, timeout=15))
        lines = [f"Breaches for {email} ({len(data)} found):"]
        for b in data:
            lines.append(f"  {b.get('Name','?')} ({b.get('BreachDate','?')}) — {', '.join(b.get('DataClasses',[]))}")
        return _ok("\n".join(lines))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return _ok(f"No breaches found for {email}.")
        if e.code == 401:
            return _ok("HIBP API key required. Set hibp-api-key header. Get one at https://haveibeenpwned.com/API/Key")
        return _ok(f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="breach_check",
    description="Check if an email appears in Have I Been Pwned data breaches (requires HIBP API key).",
    inputSchema=_s(["email"], email=("string", "Email address to check")),
), _breach_check)

# ---------------------------------------------------------------------------
# reverse_whois
# ---------------------------------------------------------------------------

async def _reverse_whois(args: dict) -> list[TextContent]:
    query = args.get("query", "")
    # Use viewdns.info free API
    url = f"https://viewdns.info/reversewhois/?q={urllib.parse.quote(query)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=20))
        domains = data.get("response", {}).get("domains", [])
        lines = [f"Reverse WHOIS for '{query}': {len(domains)} domains"]
        for d in domains[:100]:
            lines.append(f"  {d.get('name','?')}  registered={d.get('registrar','?')}")
        return _ok("\n".join(lines))
    except Exception as e:
        # Fallback: just note the limitation
        return _ok(f"Reverse WHOIS for '{query}': try viewdns.info/reversewhois or DomainTools (error: {e})")

register(Tool(
    name="reverse_whois",
    description="Find domains registered by the same organization/person using viewdns.info reverse WHOIS.",
    inputSchema=_s(["query"],
        query=("string", "Registrant name, email, or organization to search")),
), _reverse_whois)

# ---------------------------------------------------------------------------
# pastebin_search
# ---------------------------------------------------------------------------

async def _pastebin_search(args: dict) -> list[TextContent]:
    query = args.get("query", "")
    # Use Google dork via a search engine scrape is unreliable; use psbdmp.ws API
    url = f"https://psbdmp.ws/api/search/{urllib.parse.quote(query)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=20))
        items = data if isinstance(data, list) else data.get("data", [])
        lines = [f"Pastebin search for '{query}': {len(items)} results (via psbdmp.ws)"]
        for item in items[:20]:
            pid = item.get("id", "?")
            tags = item.get("tags", "")
            lines.append(f"  https://pastebin.com/{pid}  tags={tags}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}\nTip: try Google dork:  site:pastebin.com \"{query}\"")

register(Tool(
    name="pastebin_search",
    description="Search Pastebin for pastes containing a keyword (uses psbdmp.ws API).",
    inputSchema=_s(["query"],
        query=("string", "Keyword to search for (e.g. domain name, email, company)")),
), _pastebin_search)

# ---------------------------------------------------------------------------
# whois_history
# ---------------------------------------------------------------------------

async def _whois_history(args: dict) -> list[TextContent]:
    domain = args.get("domain", "")
    if _chk("whois"):
        out, err, _ = await _run(["whois", domain], timeout=30)
        return _ok(f"WHOIS for {domain}:\n\n{(out or err)[:4000]}")
    # Pure Python via RDAP
    url = f"https://rdap.org/domain/{domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        data = json.loads(await _http_get(req, timeout=15))
        lines = [f"RDAP for {domain}:"]
        for event in data.get("events", []):
            lines.append(f"  {event.get('eventAction','?')}: {event.get('eventDate','?')}")
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            lines.append(f"  entity roles={roles} vcard_fields={len(vcard)}")
        return _ok("\n".join(lines))
    except Exception as e:
        return _ok(f"Error: {e}")

register(Tool(
    name="whois_history",
    description="Run WHOIS lookup for a domain (uses system whois or RDAP fallback).",
    inputSchema=_s(["domain"], domain=("string", "Domain name to query")),
), _whois_history)

# ---------------------------------------------------------------------------
# ghunt_osint  — Google account OSINT from email/GaiaID
# ---------------------------------------------------------------------------

async def _ghunt_osint(args: dict) -> list[TextContent]:
    email = (args.get("email") or "").strip()
    gaia_id = (args.get("gaia_id") or "").strip()

    if not email and not gaia_id:
        return _ok("Error: email or gaia_id is required.")

    if _chk("ghunt"):
        # GHunt CLI available — use it directly
        target = email or gaia_id
        cmd = ["ghunt", "email", target] if email else ["ghunt", "gaia", target]
        out, err, rc = await _run(cmd, timeout=120)
        return _ok(out or err or "GHunt returned no output.")

    # Fallback: manual Google People API probe via public endpoint
    results: list[str] = []
    results.append(f"GHunt not installed — running fallback Google OSINT probes for: {email or gaia_id}")
    results.append("")

    if email:
        # Google+ / People API public profile lookup (no auth required for basic info)
        encoded = urllib.parse.quote(email)
        probes = [
            ("Google Account existence check",
             f"https://mail.google.com/mail/gxlu?email={encoded}"),
        ]
        for label, url in probes:
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                        "Cookie": "",
                    },
                )
                status, hdrs, _ = await _http_get_with_status(req, timeout=10)
                results.append(f"[{label}]")
                results.append(f"  Status: {status}")
                set_cookie = hdrs.get("Set-Cookie", "")
                if "COMPASS" in set_cookie:
                    results.append("  → Account EXISTS (COMPASS cookie set)")
                elif status in (200, 302):
                    results.append(f"  → Possibly exists (status={status})")
                else:
                    results.append(f"  → No signal (status={status})")
            except Exception as exc:
                results.append(f"  → Error: {exc!s:.80}")
            results.append("")

        # crt.sh for email in certificate subjects
        try:
            crt_url = f"https://crt.sh/?q={urllib.parse.quote(email)}&output=json"
            req = urllib.request.Request(crt_url, headers={"User-Agent": "penligent-local/0.1"})
            certs = json.loads(await _http_get(req, timeout=15))
            if certs:
                domains = sorted(set(c.get("name_value", "") for c in certs[:50]))
                results.append(f"[Certificate Transparency] {len(certs)} certs found containing {email}:")
                for d in domains[:20]:
                    results.append(f"  {d}")
            else:
                results.append(f"[Certificate Transparency] No certs found for {email}")
        except Exception as exc:
            results.append(f"[Certificate Transparency] Error: {exc!s:.80}")
        results.append("")

    results.append("Tip: install GHunt for full profiling:")
    results.append("  pip install ghunt && ghunt login")
    results.append("GHunt can reveal: linked Google services, Maps reviews, Photos/Albums,")
    results.append("  Drive/Docs public shares, YouTube channel, Calendar events.")

    return _ok("\n".join(results))

register(Tool(
    name="ghunt_osint",
    description=(
        "Google account OSINT from an email address or Google GaiaID. "
        "Uses GHunt if installed; falls back to public API probes. "
        "Reveals linked Google services, account existence, public Maps reviews, "
        "shared Drive/Docs, Photos/Albums, YouTube channels."
    ),
    inputSchema=_s(
        [],
        email=("string", "Target Gmail / Google account email address"),
        gaia_id=("string", "Target Google GaiaID (numeric) — alternative to email"),
    ),
), _ghunt_osint)
