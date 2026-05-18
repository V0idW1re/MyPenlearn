import json
import re
import shutil
from pathlib import Path

from mcp.types import Tool

from .register_all import register
from .recon import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


def _parse_nuclei_jsonl(raw: str) -> list[dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "template_id": obj.get("template-id", ""),
            "name": obj.get("info", {}).get("name", ""),
            "severity": obj.get("info", {}).get("severity", "unknown"),
            "url": obj.get("matched-at", obj.get("host", "")),
            "description": obj.get("info", {}).get("description", ""),
            "curl_command": obj.get("curl-command", ""),
        })
    return findings


def _nuclei_summary(findings: list[dict], target: str, label: str) -> str:
    if not findings:
        return f"nuclei {label}: no findings against {target}"
    by_sev: dict[str, list] = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)
    lines = [f"nuclei {label} findings for {target} ({len(findings)} total):"]
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        if sev not in by_sev:
            continue
        lines.append(f"\n[{sev.upper()}]")
        for f in by_sev[sev]:
            lines.append(f"  {f['template_id']} — {f['name']}")
            lines.append(f"    URL: {f['url']}")
            if f["description"]:
                lines.append(f"    {f['description'][:120]}")
    return "\n".join(lines)


async def _nuclei_run(args: dict, template_path: str, tool_name: str, label: str) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("nuclei"):
        return "Error: nuclei not found in PATH. Run: sudo apt install nuclei"
    severity = (args.get("severity") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = [
        "nuclei", "-u", target, "-t", template_path,
        "-silent", "-json", "-no-interactsh", "-timeout", "10",
    ]
    if severity:
        cmd += ["-severity", severity]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, tool_name, args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nuclei_summary(_parse_nuclei_jsonl(stdout), target, label)


# ---------------------------------------------------------------------------
# templated_check  (nuclei general)
# ---------------------------------------------------------------------------

async def _templated_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("nuclei"):
        return "Error: nuclei not found in PATH. Run: sudo apt install nuclei"
    templates = (args.get("templates") or "cves,misconfiguration,exposures").strip()
    severity = (args.get("severity") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = [
        "nuclei", "-u", target, "-tags", templates,
        "-silent", "-json", "-no-interactsh", "-timeout", "10",
    ]
    if severity:
        cmd += ["-severity", severity]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "templated_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nuclei_summary(_parse_nuclei_jsonl(stdout), target, f"(tags: {templates})")


register(
    Tool(
        name="templated_check",
        description=(
            "Run nuclei template-based scanning against a target URL. "
            "Returns severity-grouped findings. "
            "Pass project_id to persist results to the database."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL, e.g. 'http://10.10.10.245'"},
                "templates": {"type": "string", "description": "Comma-separated nuclei tag filter. Default: 'cves,misconfiguration,exposures'."},
                "severity": {"type": "string", "description": "Severity filter, e.g. 'medium,high,critical'."},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Subprocess timeout in seconds (default 300)."},
            },
        },
    ),
    _templated_check,
)


# ---------------------------------------------------------------------------
# nuclei_cves  (nuclei -t cves/)
# ---------------------------------------------------------------------------

async def _nuclei_cves(args: dict) -> str:
    return await _nuclei_run(args, "cves/", "nuclei_cves", "CVEs")


register(
    Tool(
        name="nuclei_cves",
        description="Run nuclei with CVE templates (-t cves/) to detect known CVEs.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_cves,
)


# ---------------------------------------------------------------------------
# nuclei_misconfigs  (nuclei -t misconfigurations/)
# ---------------------------------------------------------------------------

async def _nuclei_misconfigs(args: dict) -> str:
    return await _nuclei_run(args, "misconfigurations/", "nuclei_misconfigs", "Misconfigurations")


register(
    Tool(
        name="nuclei_misconfigs",
        description="Run nuclei with misconfiguration templates (-t misconfigurations/).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_misconfigs,
)


# ---------------------------------------------------------------------------
# nuclei_exposures  (nuclei -t exposures/)
# ---------------------------------------------------------------------------

async def _nuclei_exposures(args: dict) -> str:
    return await _nuclei_run(args, "exposures/", "nuclei_exposures", "Exposures")


register(
    Tool(
        name="nuclei_exposures",
        description="Run nuclei with exposure templates (-t exposures/) to find sensitive data/files.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_exposures,
)


# ---------------------------------------------------------------------------
# nuclei_default_logins  (nuclei -t default-logins/)
# ---------------------------------------------------------------------------

async def _nuclei_default_logins(args: dict) -> str:
    return await _nuclei_run(args, "default-logins/", "nuclei_default_logins", "Default Logins")


register(
    Tool(
        name="nuclei_default_logins",
        description="Run nuclei with default-logins templates to detect default credentials.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_default_logins,
)


# ---------------------------------------------------------------------------
# nuclei_fuzz  (nuclei -t fuzzing/)
# ---------------------------------------------------------------------------

async def _nuclei_fuzz(args: dict) -> str:
    return await _nuclei_run(args, "fuzzing/", "nuclei_fuzz", "Fuzzing")


register(
    Tool(
        name="nuclei_fuzz",
        description="Run nuclei fuzzing templates (-t fuzzing/) for input-based vulnerabilities.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_fuzz,
)


# ---------------------------------------------------------------------------
# nuclei_network  (nuclei -t network/)
# ---------------------------------------------------------------------------

async def _nuclei_network(args: dict) -> str:
    return await _nuclei_run(args, "network/", "nuclei_network", "Network")


register(
    Tool(
        name="nuclei_network",
        description="Run nuclei network templates (-t network/) for TCP/UDP service vulnerabilities.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target host or URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_network,
)


# ---------------------------------------------------------------------------
# sqli_detect  (sqlmap)
# ---------------------------------------------------------------------------

_SQLMAP_BLOCKED_FLAGS = {"--os-shell", "--os-pwn", "--os-cmd", "--os-bof",
                         "--priv-esc", "--msf-path", "--tmp-path",
                         "--dump-all", "--passwords", "--search",
                         "--exclude-sysdbs"}
_SHELL_METACHARACTERS = {";", "&&", "||", "|", "`", "$(", ">", "<", "\n"}


def _safe_arg(value: str) -> bool:
    """Return False if value contains shell metacharacters or blocked flags."""
    for meta in _SHELL_METACHARACTERS:
        if meta in value:
            return False
    return True


async def _sqli_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("sqlmap"):
        return "Error: sqlmap not found in PATH."
    if not _safe_arg(target):
        return "Error: target contains disallowed shell metacharacters."
    data = (args.get("data") or "").strip()
    param = (args.get("param") or "").strip()
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = [
        "sqlmap", "-u", target, "--batch",
        "--level", "2", "--risk", "1",
        "--output-dir", str(Path.home() / ".local" / "share" / "penligent-local" / "sqlmap"),
    ]
    if data:
        if not _safe_arg(data):
            return "Error: data field contains disallowed characters."
        cmd += ["--data", data]
    if param:
        if param.startswith("-"):
            return f"Error: param value looks like a flag: {param!r}"
        cmd += ["-p", param]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "sqli_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    verdict_lines = [
        ln for ln in stdout.splitlines()
        if any(k in ln for k in ["injectable", "not injectable", "Parameter:", "[WARNING]", "[CRITICAL]", "sqlmap identified"])
    ]
    summary = "\n".join(verdict_lines) if verdict_lines else stdout[-2000:]
    return f"sqlmap result for {target}:\n{summary}"


register(
    Tool(
        name="sqli_detect",
        description=(
            "Run sqlmap against a target URL to detect SQL injection. "
            "Uses --batch (no prompts), level=2, risk=1 (safe). "
            "Pass data= for POST targets, param= to focus on one parameter."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameter, e.g. 'http://host/page?id=1'"},
                "data": {"type": "string", "description": "POST body string, e.g. 'user=foo&pass=bar'"},
                "param": {"type": "string", "description": "Specific parameter name to test (optional)"},
                "cookies": {"type": "string", "description": "Cookie header value for authenticated scans"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 180)"},
            },
        },
    ),
    _sqli_detect,
)


# ---------------------------------------------------------------------------
# xss_probe  (dalfox)
# ---------------------------------------------------------------------------

async def _xss_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("dalfox"):
        return (
            "dalfox is not installed. Install it with:\n"
            "  wget https://github.com/hahwul/dalfox/releases/latest/download/dalfox_linux_amd64.tar.gz\n"
            "  tar xf dalfox_linux_amd64.tar.gz && sudo mv dalfox /usr/local/bin/\n"
            "Skipping xss_probe."
        )
    cookies = (args.get("cookies") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["dalfox", "url", target, "--silence", "--format", "json"]
    if cookies:
        cmd += ["--cookie", cookies]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "xss_probe", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    try:
        data = json.loads(stdout) if stdout.strip() else []
        if isinstance(data, dict):
            data = [data]
        if not data:
            return f"dalfox: no XSS found on {target}"
        lines = [f"dalfox XSS findings for {target} ({len(data)} total):"]
        for item in data:
            lines.append(f"  param={item.get('param','?')} type={item.get('type','?')}")
            lines.append(f"    payload: {item.get('poc','')[:120]}")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return f"dalfox output:\n{stdout[:2000]}"


register(
    Tool(
        name="xss_probe",
        description=(
            "Run dalfox against a target URL to detect reflected/DOM XSS. "
            "Returns structured findings. Requires dalfox in PATH."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL with parameters, e.g. 'http://host/page?q=test'"},
                "cookies": {"type": "string", "description": "Cookie header for authenticated scans"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
        },
    ),
    _xss_probe,
)


# ---------------------------------------------------------------------------
# testssl_scan  (testssl.sh)
# ---------------------------------------------------------------------------

async def _testssl_scan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (host or host:port)."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    testssl = shutil.which("testssl") or shutil.which("testssl.sh")
    if not testssl:
        return "Error: testssl.sh not found in PATH. Install: apt install testssl.sh"
    cmd = [testssl, "--color", "0", "--quiet", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "testssl_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"testssl returned no output for {target}."


register(
    Tool(
        name="testssl_scan",
        description="Comprehensive SSL/TLS testing using testssl.sh: protocols, ciphers, vulnerabilities (BEAST, POODLE, Heartbleed, etc.).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Host or host:port, e.g. 'example.com:443'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _testssl_scan,
)


# ---------------------------------------------------------------------------
# searchsploit  (searchsploit query)
# ---------------------------------------------------------------------------

async def _searchsploit(args: dict) -> str:
    query = (args.get("query") or "").strip()
    if not query:
        return "Error: query is required."
    if not shutil.which("searchsploit"):
        return "Error: searchsploit not found in PATH. Install: apt install exploitdb"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["searchsploit", "--colour", query]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "searchsploit", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No exploits found for: {query}"


register(
    Tool(
        name="searchsploit",
        description="Search the Exploit-DB local database using searchsploit.",
        inputSchema={
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "description": "Search term, e.g. 'Apache 2.4.41' or 'vsftpd 2.3.4'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _searchsploit,
)


# ---------------------------------------------------------------------------
# metasploit_search  (msfconsole -q -x "search ...")
# ---------------------------------------------------------------------------

async def _metasploit_search(args: dict) -> str:
    query = (args.get("query") or "").strip()
    if not query:
        return "Error: query is required."
    if not shutil.which("msfconsole"):
        return "Error: msfconsole not found in PATH. Install: apt install metasploit-framework"
    search_type = (args.get("type") or "exploit").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    search_cmd = f"search type:{search_type} {query}; exit"
    cmd = ["msfconsole", "-q", "-x", search_cmd]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "metasploit_search", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    # Filter to module lines only
    lines = [ln for ln in stdout.splitlines() if "exploit/" in ln or "auxiliary/" in ln or "post/" in ln or "payload/" in ln]
    if lines:
        return f"Metasploit modules matching '{query}' (type={search_type}):\n" + "\n".join(lines[:50])
    return f"msfconsole search result:\n{stdout[-2000:]}"


register(
    Tool(
        name="metasploit_search",
        description="Search Metasploit Framework modules using msfconsole -x search.",
        inputSchema={
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "description": "Search term, e.g. 'ms17-010' or 'vsftpd'"},
                "type": {"type": "string", "description": "Module type: exploit, auxiliary, post, payload (default: exploit)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _metasploit_search,
)


# ---------------------------------------------------------------------------
# vulners_cve  (curl vulners.com API)
# ---------------------------------------------------------------------------

async def _vulners_cve(args: dict) -> str:
    cve_id = (args.get("cve_id") or "").strip()
    if not cve_id:
        return "Error: cve_id is required (e.g. 'CVE-2021-44228')."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 15))
    cmd = [
        "curl", "-sL",
        f"https://vulners.com/api/v3/search/id/?id={cve_id}&fields=cvss,description,title,references",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "vulners_cve", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if not stdout.strip():
        return f"No data returned from vulners.com for {cve_id}."
    try:
        data = json.loads(stdout)
        result = data.get("data", {}).get("documents", {})
        if not result:
            return f"No vulnerability data for {cve_id} on vulners.com."
        entry = next(iter(result.values()))
        lines = [
            f"CVE: {cve_id}",
            f"Title: {entry.get('title', 'N/A')}",
            f"CVSS: {entry.get('cvss', {}).get('score', 'N/A')}",
            f"Description: {str(entry.get('description', ''))[:300]}",
        ]
        refs = entry.get("references", [])
        if refs:
            lines.append(f"References: {', '.join(refs[:3])}")
        return "\n".join(lines)
    except (json.JSONDecodeError, KeyError):
        return f"vulners.com response:\n{stdout[:2000]}"


register(
    Tool(
        name="vulners_cve",
        description="Look up CVE details (CVSS score, description, references) from vulners.com API.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID, e.g. 'CVE-2021-44228'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 15)"},
            },
        },
    ),
    _vulners_cve,
)


# ---------------------------------------------------------------------------
# nuclei_tech  (nuclei -t technologies/)
# ---------------------------------------------------------------------------

async def _nuclei_tech(args: dict) -> str:
    return await _nuclei_run(args, "technologies/", "nuclei_tech", "Technologies")


register(
    Tool(
        name="nuclei_tech",
        description="Run nuclei technology detection templates (-t technologies/) to fingerprint the stack.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "severity": {"type": "string", "description": "Severity filter"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _nuclei_tech,
)


# ---------------------------------------------------------------------------
# wpscan_vulns  (wpscan --api-token if available)
# ---------------------------------------------------------------------------

async def _wpscan_vulns(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("wpscan"):
        return "Error: wpscan not found in PATH. Install: gem install wpscan"
    api_token = (args.get("api_token") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = [
        "wpscan", "--url", target, "--no-banner",
        "-e", "ap,at,u,vp,vt",  # plugins, themes, users, vulnerable plugins/themes
        "--format", "json",
    ]
    if api_token:
        cmd += ["--api-token", api_token]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "wpscan_vulns", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    try:
        data = json.loads(stdout) if stdout.strip().startswith("{") else None
        if not data:
            return stdout or stderr or "No wpscan output."
        vulns = []
        for plugin_name, plugin_data in (data.get("plugins") or {}).items():
            for vuln in (plugin_data.get("vulnerabilities") or []):
                vulns.append(f"  [PLUGIN:{plugin_name}] {vuln.get('title','?')} CVSS:{vuln.get('cvss',{}).get('score','?')}")
        for theme_name, theme_data in (data.get("themes") or {}).items():
            for vuln in (theme_data.get("vulnerabilities") or []):
                vulns.append(f"  [THEME:{theme_name}] {vuln.get('title','?')}")
        if vulns:
            return f"wpscan vulnerabilities for {target} ({len(vulns)}):\n" + "\n".join(vulns)
        wp_ver = (data.get("version") or {}).get("number", "?")
        users = list((data.get("users") or {}).keys())
        return (
            f"WPScan complete for {target}. WordPress version: {wp_ver}\n"
            f"Users found: {users if users else 'none'}\n"
            f"No vulnerabilities found (may require --api-token for vuln data)."
        )
    except json.JSONDecodeError:
        return stdout or stderr or "wpscan returned no output."


register(
    Tool(
        name="wpscan_vulns",
        description="WordPress vulnerability scan using wpscan with optional API token for CVE data.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "WordPress site URL"},
                "api_token": {"type": "string", "description": "WPScan API token for vulnerability database access"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _wpscan_vulns,
)


# ---------------------------------------------------------------------------
# brute_force_test — active brute-force lockout verification via hydra
# ---------------------------------------------------------------------------

# Small built-in wordlist — intentionally short to detect lockout, not crack passwords
_LOCKOUT_WORDLIST = [
    "password", "123456", "admin", "root", "password1",
    "letmein", "qwerty", "abc123",
]


async def _brute_force_test(args: dict) -> str:
    target = (args.get("target") or "").strip()
    service = (args.get("service") or "http-post-form").strip().lower()
    username = (args.get("username") or "admin").strip()
    form_path = (args.get("form_path") or "/login").strip()
    form_body = (args.get("form_body") or "username=^USER^&password=^PASS^").strip()
    fail_string = (args.get("fail_string") or "incorrect").strip()
    max_attempts = min(int(args.get("max_attempts", 8)), 12)  # hard cap at 12
    project_id = args.get("project_id")

    if not target:
        return "Error: target is required."
    if not _chk("hydra"):
        return (
            "[TOOL_MISSING] hydra not found in PATH.\n"
            "Install: sudo apt install hydra\n\n"
            "Manual lockout test: send 6+ incorrect login attempts and check if the account "
            "gets locked, rate-limited (429), or a delay is introduced."
        )

    # Write temp wordlist
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        wl_path = f.name
        f.write("\n".join(_LOCKOUT_WORDLIST[:max_attempts]) + "\n")

    try:
        if service == "http-post-form":
            form_spec = f"{form_path}:{form_body}:F={fail_string}"
            cmd = [
                "hydra", "-l", username, "-P", wl_path,
                target, "http-post-form", form_spec,
                "-t", "1",   # 1 thread — gentle, ordered
                "-V",        # verbose — show each attempt
                "-f",        # stop on first success
            ]
        elif service == "ssh":
            cmd = ["hydra", "-l", username, "-P", wl_path, "ssh://" + target,
                   "-t", "1", "-V", "-f"]
        else:
            cmd = ["hydra", "-l", username, "-P", wl_path, service + "://" + target,
                   "-t", "1", "-V", "-f"]

        stdout, stderr, rc = await _run_subprocess(cmd, timeout=60)
        await _persist(project_id, "brute_force_test", args, stdout, stderr, rc)
    finally:
        try:
            os.unlink(wl_path)
        except Exception:
            pass

    # Interpret results
    all_output = stdout + stderr
    lines = [
        f"Brute-force lockout test: {target} ({service})",
        f"Username tested: {username}, wordlist: {max_attempts} attempts",
        "",
    ]

    success_found = "login:" in stdout.lower() and "password:" in stdout.lower()
    rate_limited = any(k in all_output for k in ["429", "Too Many", "rate limit", "blocked"])
    locked_out = any(k in all_output for k in ["locked", "disabled", "suspended", "too many"])
    captcha_hint = any(k in all_output for k in ["captcha", "robot", "human"])

    if success_found:
        lines.append("FINDING: Credential found! No lockout triggered — brute-force protection ABSENT.")
        lines.append("  Severity: HIGH — ttp_category=brute, owasp_asvs_id=V2.2")
    elif locked_out:
        lines.append("INFO: Account lockout detected — brute-force protection PRESENT.")
    elif rate_limited:
        lines.append("INFO: Rate limiting detected — brute-force protection PRESENT (rate-limit).")
    elif captcha_hint:
        lines.append("INFO: CAPTCHA hint detected — brute-force protection PRESENT (CAPTCHA).")
    else:
        lines.append("WARNING: No lockout or rate-limiting detected after all attempts.")
        lines.append("  Consider this a SUSPECTED brute-force vulnerability; verify manually.")
        lines.append("  Severity: MEDIUM — ttp_category=brute, owasp_asvs_id=V2.2")

    lines += ["", "Raw output (first 40 lines):"]
    lines += stdout.splitlines()[:40]
    return "\n".join(lines)


def _chk(name: str) -> bool:
    return shutil.which(name) is not None


register(
    Tool(
        name="brute_force_test",
        description=(
            "Run a small brute-force lockout verification test using hydra. "
            "Uses a ≤12-attempt wordlist to detect whether the target enforces "
            "lockout, rate-limiting, or CAPTCHA. NOT intended for credential cracking. "
            "Requires SCAN_ACTIVE approval on non-HTB projects."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target host or IP (no protocol for non-HTTP)"},
                "service": {"type": "string", "description": "Service type: http-post-form (default), ssh, ftp, rdp, smb"},
                "username": {"type": "string", "description": "Username to test (default: admin)"},
                "form_path": {"type": "string", "description": "Login form path for HTTP (default: /login)"},
                "form_body": {"type": "string", "description": "Form body template (default: username=^USER^&password=^PASS^)"},
                "fail_string": {"type": "string", "description": "String in response indicating failure (default: incorrect)"},
                "max_attempts": {"type": "integer", "description": "Max attempts (max 12, default 8)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _brute_force_test,
)


# ---------------------------------------------------------------------------
# parsing_diff — sanitizer-vs-browser divergence XSS detection
# ---------------------------------------------------------------------------

# Edge-case markup payloads that known sanitizers and browsers parse differently
_PARSING_DIFF_PAYLOADS = [
    # Null byte injection
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # UTF-7 encoding (IE legacy)
    "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
    # Malformed attribute quotes
    "<img src=x onerror=alert(1) ",
    # SVG-based bypass
    "<svg><script>alert(1)</script></svg>",
    # HTML comment injection
    "<!--<img src=x onerror=alert(1)>-->",
    # Data URI
    '<a href="data:text/html,<script>alert(1)</script>">click</a>',
    # Polyglot
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    # CSS expression (legacy IE)
    "<div style=\"width:expression(alert(1))\">",
    # Template literal breakout
    "`${alert(1)}`",
    # Unicode normalization bypass
    "＜script＞alert(1)＜/script＞",
]

_HTML_SANITIZERS = ["bleach", "html_sanitizer", "DOMPurify"]


async def _parsing_diff(args: dict) -> str:
    target = (args.get("target") or "").strip()
    param = (args.get("param") or "q").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))

    if not target:
        return "Error: target is required."

    results: list[str] = [
        f"Parsing-differential XSS fuzz: {target}",
        f"Parameter: {param}",
        f"Payloads: {len(_PARSING_DIFF_PAYLOADS)}",
        "",
    ]

    hits: list[str] = []
    for payload in _PARSING_DIFF_PAYLOADS:
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe="")
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}{param}={encoded}"
        cmd = [
            "curl", "-sL", "-m", str(timeout_s),
            "--user-agent", "Mozilla/5.0 (X11; Linux x86_64) penligent-parsing-diff/1.0",
            url,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s + 5)
        if rc == -1:
            continue

        # Check if payload appears reflected and unescaped in response
        # Markers that suggest the payload got through unmodified
        raw_payload_reflected = payload.replace("\x00", "") in stdout
        script_tag_reflected = "<script>" in stdout.lower() and "alert" in stdout.lower()
        svg_reflected = "<svg>" in stdout.lower() and "onload" in stdout.lower()
        event_handler_reflected = re.search(r'on\w+\s*=\s*alert', stdout, re.I) is not None

        if any([raw_payload_reflected, script_tag_reflected, svg_reflected, event_handler_reflected]):
            hits.append(f"  DIVERGENCE: {payload[:60]!r}")
            hits.append(f"    URL: {url[:120]}")
            hits.append(f"    Signal: script_tag={script_tag_reflected}, svg={svg_reflected}, event={event_handler_reflected}")

    if hits:
        results.append(f"POSSIBLE SANITIZER-BROWSER DIVERGENCE: {len(hits)//3} payload(s) reflected unescaped")
        results.extend(hits)
        results.append("")
        results.append("These payloads bypassed server-side output — confirm with browser execution.")
        results.append("If confirmed: ttp_category=xss, owasp_asvs_id=V5.3.3, severity=high")
    else:
        results.append("No obvious sanitizer-browser divergences detected.")
        results.append("Note: true divergence requires a browser DOM comparison — this is a heuristic check only.")

    result = "\n".join(results)
    await _persist(project_id, "parsing_diff", args, result, "", 0)
    return result


register(
    Tool(
        name="parsing_diff",
        description=(
            "Parsing-differential XSS fuzz test. Sends edge-case markup payloads that known "
            "sanitizers and browsers interpret differently (null bytes, UTF-7, malformed attributes, "
            "SVG polyglots, unicode normalization). Detects cases where a sanitizer passes input "
            "that a browser would execute. Run after xss_probe for deeper coverage."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "param": {"type": "string", "description": "Parameter to inject into (default: q)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout per request in seconds (default: 30)"},
            },
        },
    ),
    _parsing_diff,
)


# ---------------------------------------------------------------------------
# dom_taint — runtime DOM taint analysis via headless browser
# ---------------------------------------------------------------------------

# Dangerous DOM sinks that can lead to script execution
_DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval", "Function(", "setTimeout(", "setInterval(",
    "location.href", "location.assign", "location.replace",
    "src", "href",
]

_DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.referrer", "document.URL", "document.baseURI",
    "window.name", "postMessage",
]


async def _dom_taint(args: dict) -> str:
    target = (args.get("target") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))

    if not target:
        return "Error: target is required."

    results: list[str] = [
        f"DOM taint analysis: {target}",
        "",
    ]

    # Check for headless Chrome / Chromium
    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")

    if chromium:
        # Use chromium to fetch the page source with JS execution
        cmd = [
            chromium,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--dump-dom",
            "--timeout=15000",
            target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s + 5)
        dom_content = stdout
    else:
        # Fallback: fetch raw HTML and do static analysis
        cmd = [
            "curl", "-sL", "-m", str(timeout_s),
            "--user-agent", "Mozilla/5.0 (X11; Linux x86_64)",
            target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=timeout_s + 5)
        dom_content = stdout
        results.append("Note: Chromium not found — running static DOM sink analysis on raw HTML.")
        results.append("For true runtime taint tracking, install: sudo apt install chromium")
        results.append("")

    # Static heuristic: look for sink+source patterns in inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', dom_content, re.DOTALL | re.IGNORECASE)
    script_combined = "\n".join(inline_scripts)

    sink_hits: list[str] = []
    source_hits: list[str] = []

    for sink in _DOM_SINKS:
        if sink in script_combined:
            sink_hits.append(sink)

    for source in _DOM_SOURCES:
        if source in script_combined:
            source_hits.append(source)

    # Check for hash-based routing patterns (common DOM XSS vector)
    hash_routing = "location.hash" in dom_content or "window.location.hash" in dom_content
    hash_to_html = bool(re.search(r'location\.hash.*innerHTML|innerHTML.*location\.hash', dom_content, re.DOTALL))

    results.append(f"DOM sinks found in inline scripts: {sink_hits or ['none']}")
    results.append(f"DOM sources found in inline scripts: {source_hits or ['none']}")
    results.append(f"Hash-based routing: {hash_routing}")
    results.append(f"Hash-to-innerHTML pattern: {hash_to_html}")
    results.append("")

    if hash_to_html:
        results.append("HIGH RISK: location.hash value flows directly into innerHTML — classic DOM XSS.")
        results.append("  Test: append #<img src=x onerror=alert(1)> to the URL and open in a browser.")
        results.append("  ttp_category=xss, owasp_asvs_id=V5.3.3, severity=high")
    elif sink_hits and source_hits:
        results.append(f"MEDIUM RISK: Both sources ({source_hits}) and sinks ({sink_hits}) present in inline scripts.")
        results.append("  Manually trace data flow from source to sink to confirm exploitability.")
    elif sink_hits:
        results.append(f"LOW RISK: Dangerous sinks present ({sink_hits}) but no obvious sources found.")
        results.append("  Inspect network requests and event handlers for untrusted input paths.")
    else:
        results.append("No obvious DOM source-to-sink taint paths detected statically.")
        results.append("Note: server-rendered content and external JS files are not checked here.")

    result = "\n".join(results)
    await _persist(project_id, "dom_taint", args, result, "", 0)
    return result


register(
    Tool(
        name="dom_taint",
        description=(
            "Runtime DOM taint analysis: fetch page source and scan for dangerous source-to-sink "
            "data flow patterns (location.hash → innerHTML, postMessage → eval, etc.). "
            "Uses Chromium headless if available for JS-rendered DOM; falls back to static HTML analysis. "
            "Run after xss_probe to catch DOM-based XSS that reflection scanners miss."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default: 30)"},
            },
        },
    ),
    _dom_taint,
)
