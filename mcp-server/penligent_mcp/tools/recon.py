import asyncio
import json
import re
import shutil
import socket

from mcp.types import Tool

from .register_all import register
from ._helpers import _run_subprocess, _save_artifact, _record_execution

# Nmap open-port line: "80/tcp  open  http  Apache httpd 2.4.41"
_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open\|filtered|closed\|filtered|open|filtered|closed)\s+(\S+)(?:[ \t]+(.*))?$",
    re.MULTILINE,
)


def _parse_nmap(output: str) -> list[dict]:
    ports = []
    for m in _PORT_RE.finditer(output):
        ports.append({
            "port": int(m.group(1)),
            "proto": m.group(2),
            "state": m.group(3),
            "service": m.group(4),
            "version": (m.group(5) or "").strip(),
        })
    return ports


def _nmap_summary(stdout: str, target: str, label: str) -> str:
    open_ports = [p for p in _parse_nmap(stdout) if p["state"] == "open"]
    if not open_ports:
        snippet = stdout[:2000] if stdout else "(no output)"
        return f"No open ports detected by {label} on {target}.\n\n{snippet}"
    lines = [f"Open ports on {target} ({label}):"]
    for p in open_ports:
        ver = f" ({p['version']})" if p["version"] else ""
        lines.append(f"  {p['port']}/{p['proto']}  {p['service']}{ver}")
    lines.append("\n--- full nmap output ---")
    lines.append(stdout)
    return "\n".join(lines)


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


# ---------------------------------------------------------------------------
# port_enum
# ---------------------------------------------------------------------------

async def _port_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    ports = (args.get("ports") or "").strip()
    extra_flags = (args.get("flags") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["nmap", "-sV", "--open"]
    if ports:
        cmd += ["-p", ports]
    if extra_flags:
        cmd += extra_flags.split()
    cmd.append(target)
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "port_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nmap_summary(stdout, target, "port_enum")


register(
    Tool(
        name="port_enum",
        description=(
            "Run nmap against a target to enumerate open ports and service versions. "
            "Returns a structured summary followed by full nmap output. "
            "Pass project_id to persist the result to the database."
        ),
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to scan"},
                "ports": {"type": "string", "description": "Port spec: '80,443', '1-1000', or '1-65535'. Default: top 1000."},
                "flags": {"type": "string", "description": "Extra nmap flags, e.g. '-A' or '--script vuln'. Space-separated."},
                "project_id": {"type": "integer", "description": "Local project ID — persists result to DB if provided."},
                "timeout": {"type": "integer", "description": "Subprocess timeout in seconds (default 120)."},
            },
        },
    ),
    _port_enum,
)


# ---------------------------------------------------------------------------
# port_scan  (nmap -sV -p 1-1000)
# ---------------------------------------------------------------------------

async def _port_scan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = ["nmap", "-sV", "-p", "1-1000", "--open", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "port_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nmap_summary(stdout, target, "port_scan (1-1000)")


register(
    Tool(
        name="port_scan",
        description="nmap -sV -p 1-1000 service version scan on first 1000 ports.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _port_scan,
)


# ---------------------------------------------------------------------------
# port_scan_full  (nmap -sV -p-)
# ---------------------------------------------------------------------------

async def _port_scan_full(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 600))
    cmd = ["nmap", "-sV", "-p-", "--open", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "port_scan_full", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nmap_summary(stdout, target, "port_scan_full (1-65535)")


register(
    Tool(
        name="port_scan_full",
        description="nmap -sV -p- full 65535-port scan. Slow — increase timeout.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 600)"},
            },
        },
    ),
    _port_scan_full,
)


# ---------------------------------------------------------------------------
# port_scan_udp  (nmap -sU top 100)
# ---------------------------------------------------------------------------

async def _port_scan_udp(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["nmap", "-sU", "--top-ports", "100", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "port_scan_udp", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nmap_summary(stdout, target, "port_scan_udp (top 100 UDP)")


register(
    Tool(
        name="port_scan_udp",
        description="nmap -sU UDP scan of top 100 ports. Requires root/sudo.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _port_scan_udp,
)


# ---------------------------------------------------------------------------
# service_detect  (nmap -sV --version-intensity 9)
# ---------------------------------------------------------------------------

async def _service_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    ports = (args.get("ports") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = ["nmap", "-sV", "--version-intensity", "9"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "service_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return _nmap_summary(stdout, target, "service_detect")


register(
    Tool(
        name="service_detect",
        description="nmap -sV --version-intensity 9 aggressive service/version detection.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "ports": {"type": "string", "description": "Port spec, e.g. '22,80,443'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _service_detect,
)


# ---------------------------------------------------------------------------
# os_detect  (nmap -O)
# ---------------------------------------------------------------------------

async def _os_detect(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = ["nmap", "-O", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "os_detect", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    os_lines = [ln for ln in stdout.splitlines() if "OS" in ln or "os" in ln.lower()]
    summary = "\n".join(os_lines) if os_lines else stdout[:1000]
    return f"OS detection for {target}:\n{summary}\n\n--- full output ---\n{stdout}"


register(
    Tool(
        name="os_detect",
        description="nmap -O OS fingerprinting. Requires root/sudo.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _os_detect,
)


# ---------------------------------------------------------------------------
# ping_sweep  (nmap -sn CIDR)
# ---------------------------------------------------------------------------

async def _ping_sweep(args: dict) -> str:
    cidr = (args.get("cidr") or "").strip()
    if not cidr:
        return "Error: cidr is required (e.g. '192.168.1.0/24')."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["nmap", "-sn", cidr]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ping_sweep", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    hosts = re.findall(r"Nmap scan report for (.+)", stdout)
    if not hosts:
        return f"No live hosts found in {cidr}.\n{stdout[:500]}"
    return f"Live hosts in {cidr} ({len(hosts)}):\n" + "\n".join(hosts) + f"\n\n{stdout}"


register(
    Tool(
        name="ping_sweep",
        description="nmap -sn ping sweep to discover live hosts in a CIDR range.",
        inputSchema={
            "type": "object",
            "required": ["cidr"],
            "properties": {
                "cidr": {"type": "string", "description": "CIDR range, e.g. '192.168.1.0/24'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _ping_sweep,
)


# ---------------------------------------------------------------------------
# dns_resolve
# ---------------------------------------------------------------------------

async def _dns_resolve(args: dict) -> str:
    hostname = (args.get("hostname") or "").strip()
    if not hostname:
        return "Error: hostname is required."
    try:
        results = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
        addrs = sorted({r[4][0] for r in results})
        return f"{hostname} resolves to: {', '.join(addrs)}"
    except socket.gaierror as e:
        return f"DNS resolution failed for {hostname}: {e}"


register(
    Tool(
        name="dns_resolve",
        description="Resolve a hostname to its IP address(es) using the system resolver.",
        inputSchema={
            "type": "object",
            "required": ["hostname"],
            "properties": {
                "hostname": {"type": "string", "description": "Hostname to resolve"},
            },
        },
    ),
    _dns_resolve,
)


# ---------------------------------------------------------------------------
# dns_brute  (gobuster dns or dnsrecon -D wordlist)
# ---------------------------------------------------------------------------

async def _dns_brute(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    if shutil.which("gobuster"):
        cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-q", "--no-error"]
    elif shutil.which("dnsrecon"):
        cmd = ["dnsrecon", "-d", domain, "-D", wordlist, "-t", "brt"]
    else:
        return "Error: neither gobuster nor dnsrecon found in PATH."
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dns_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "No results."


register(
    Tool(
        name="dns_brute",
        description="DNS brute-force using gobuster dns or dnsrecon -D with a wordlist.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "wordlist": {"type": "string", "description": "Path to wordlist (default: seclists subdomains-top1million-5000)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _dns_brute,
)


# ---------------------------------------------------------------------------
# dns_zone_transfer  (dig AXFR)
# ---------------------------------------------------------------------------

async def _dns_zone_transfer(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    nameserver = (args.get("nameserver") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["dig", "AXFR", domain]
    if nameserver:
        cmd += [f"@{nameserver}"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dns_zone_transfer", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if "Transfer failed" in stdout or "REFUSED" in stdout:
        return f"Zone transfer refused/failed for {domain}.\n{stdout[:500]}"
    return f"Zone transfer result for {domain}:\n{stdout}"


register(
    Tool(
        name="dns_zone_transfer",
        description="Attempt DNS zone transfer (AXFR) for a domain using dig.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "nameserver": {"type": "string", "description": "Nameserver IP to query (optional)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _dns_zone_transfer,
)


# ---------------------------------------------------------------------------
# dns_enum  (dnsenum or dnsrecon comprehensive)
# ---------------------------------------------------------------------------

async def _dns_enum(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    if shutil.which("dnsenum"):
        cmd = ["dnsenum", "--noreverse", domain]
    elif shutil.which("dnsrecon"):
        cmd = ["dnsrecon", "-d", domain, "-t", "std,axfr,brt"]
    else:
        return "Error: neither dnsenum nor dnsrecon found in PATH."
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dns_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "No results."


register(
    Tool(
        name="dns_enum",
        description="Comprehensive DNS enumeration using dnsenum or dnsrecon.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _dns_enum,
)


# ---------------------------------------------------------------------------
# subdomain_enum  (subfinder)
# ---------------------------------------------------------------------------

async def _subdomain_enum(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["subfinder", "-d", domain, "-silent"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "subdomain_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]
    if not subdomains:
        return f"No subdomains found for {domain}."
    return f"Found {len(subdomains)} subdomains for {domain}:\n" + "\n".join(subdomains)


register(
    Tool(
        name="subdomain_enum",
        description="Enumerate subdomains for a domain using subfinder. Pass project_id to persist results.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain, e.g. 'example.com'"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)"},
            },
        },
    ),
    _subdomain_enum,
)


# ---------------------------------------------------------------------------
# subdomain_brute  (ffuf with DNS wordlist)
# ---------------------------------------------------------------------------

async def _subdomain_brute(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    if not shutil.which("ffuf"):
        return "Error: ffuf not found in PATH. Install: apt install ffuf"
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = [
        "ffuf", "-u", f"http://FUZZ.{domain}", "-w", wordlist,
        "-v", "-mc", "200,204,301,302,307,401,403", "-s",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "subdomain_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No subdomains found via brute-force for {domain}."


register(
    Tool(
        name="subdomain_brute",
        description="Brute-force subdomains using ffuf with a DNS wordlist.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: seclists subdomains-top1million-5000)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _subdomain_brute,
)


# ---------------------------------------------------------------------------
# vhost_fuzz  (ffuf vhost fuzzing)
# ---------------------------------------------------------------------------

async def _vhost_fuzz(args: dict) -> str:
    target = (args.get("target") or "").strip()
    domain = (args.get("domain") or "").strip()
    if not target or not domain:
        return "Error: target (URL) and domain are required."
    if not shutil.which("ffuf"):
        return "Error: ffuf not found in PATH."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = [
        "ffuf", "-u", target, "-H", f"Host: FUZZ.{domain}",
        "-w", wordlist, "-v", "-mc", "200,204,301,302,307,401,403",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "vhost_fuzz", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "No virtual hosts discovered."


register(
    Tool(
        name="vhost_fuzz",
        description="Virtual host fuzzing using ffuf Host header injection.",
        inputSchema={
            "type": "object",
            "required": ["target", "domain"],
            "properties": {
                "target": {"type": "string", "description": "Base URL, e.g. 'http://10.10.10.1'"},
                "domain": {"type": "string", "description": "Base domain for Host header, e.g. 'example.com'"},
                "wordlist": {"type": "string", "description": "Wordlist path"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _vhost_fuzz,
)


# ---------------------------------------------------------------------------
# dir_brute  (feroxbuster or gobuster dir)
# ---------------------------------------------------------------------------

async def _dir_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    if shutil.which("feroxbuster"):
        cmd = ["feroxbuster", "-u", target, "-w", wordlist, "--silent", "-q"]
    elif shutil.which("gobuster"):
        cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "--no-error"]
    else:
        return "Error: neither feroxbuster nor gobuster found in PATH."
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "dir_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No directories found on {target}."


register(
    Tool(
        name="dir_brute",
        description="Directory brute-force using feroxbuster or gobuster dir.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL, e.g. 'http://10.10.10.1'"},
                "wordlist": {"type": "string", "description": "Wordlist path"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _dir_brute,
)


# ---------------------------------------------------------------------------
# file_brute  (gobuster with extensions)
# ---------------------------------------------------------------------------

async def _file_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("gobuster"):
        return "Error: gobuster not found in PATH."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt").strip()
    extensions = (args.get("extensions") or "php,html,txt,bak,conf,log,xml,json").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = [
        "gobuster", "dir", "-u", target, "-w", wordlist,
        "-x", extensions, "-q", "--no-error",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "file_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No files found on {target}."


register(
    Tool(
        name="file_brute",
        description="File brute-force with extensions using gobuster dir -x.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Wordlist path"},
                "extensions": {"type": "string", "description": "Comma-separated extensions (default: php,html,txt,bak,conf,log,xml,json)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _file_brute,
)


# ---------------------------------------------------------------------------
# param_fuzz  (ffuf param fuzzing on a URL)
# ---------------------------------------------------------------------------

async def _param_fuzz(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (should contain FUZZ placeholder or use wordlist)."
    if not shutil.which("ffuf"):
        return "Error: ffuf not found in PATH."
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt").strip()
    method = (args.get("method") or "GET").upper()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    url = target if "FUZZ" in target else f"{target}?FUZZ=1"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-v", "-mc", "200,204,301,302,307,401,403"]
    if method == "POST":
        cmd += ["-X", "POST", "-d", "FUZZ=1"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "param_fuzz", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "No parameters discovered."


register(
    Tool(
        name="param_fuzz",
        description="Fuzz GET/POST parameters using ffuf with a parameter names wordlist.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target URL (FUZZ placeholder or base URL)"},
                "wordlist": {"type": "string", "description": "Parameter names wordlist"},
                "method": {"type": "string", "description": "HTTP method: GET or POST (default: GET)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _param_fuzz,
)


# ---------------------------------------------------------------------------
# cert_transparency  (curl crt.sh API)
# ---------------------------------------------------------------------------

async def _cert_transparency(args: dict) -> str:
    domain = (args.get("domain") or "").strip()
    if not domain:
        return "Error: domain is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = [
        "curl", "-s", "-H", "Accept: application/json",
        f"https://crt.sh/?q=%25.{domain}&output=json",
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "cert_transparency", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if not stdout.strip():
        return f"No certificate transparency records found for {domain}."
    try:
        records = json.loads(stdout)
        names = sorted({r.get("name_value", "") for r in records if r.get("name_value")})
        return f"CT log entries for {domain} ({len(names)} unique names):\n" + "\n".join(names)
    except json.JSONDecodeError:
        return f"crt.sh response:\n{stdout[:2000]}"


register(
    Tool(
        name="cert_transparency",
        description="Query crt.sh certificate transparency logs for subdomains/certificates.",
        inputSchema={
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _cert_transparency,
)


# ---------------------------------------------------------------------------
# whois_lookup
# ---------------------------------------------------------------------------

async def _whois_lookup(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["whois", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "whois_lookup", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "No whois data returned."


register(
    Tool(
        name="whois_lookup",
        description="Run whois lookup on a domain or IP address.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Domain or IP address"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _whois_lookup,
)


# ---------------------------------------------------------------------------
# reverse_dns  (dig -x PTR)
# ---------------------------------------------------------------------------

async def _reverse_dns(args: dict) -> str:
    ip = (args.get("ip") or "").strip()
    if not ip:
        return "Error: ip is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 15))
    cmd = ["dig", "-x", ip, "+short"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "reverse_dns", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    result = stdout.strip()
    if not result:
        return f"No PTR record found for {ip}."
    return f"Reverse DNS for {ip}: {result}"


register(
    Tool(
        name="reverse_dns",
        description="Reverse DNS PTR lookup for an IP address using dig -x.",
        inputSchema={
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 15)"},
            },
        },
    ),
    _reverse_dns,
)


# ---------------------------------------------------------------------------
# traceroute
# ---------------------------------------------------------------------------

async def _traceroute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["traceroute", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "traceroute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No traceroute output for {target}."


register(
    Tool(
        name="traceroute",
        description="Run traceroute to map the network path to a target.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _traceroute,
)
