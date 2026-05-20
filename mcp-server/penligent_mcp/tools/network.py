import asyncio
import os
import re
import shutil
import tempfile
from pathlib import Path

from mcp.types import Tool

from .register_all import register
from ._helpers import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


# ---------------------------------------------------------------------------
# smb_enum  (enum4linux-ng or enum4linux)
# ---------------------------------------------------------------------------

async def _smb_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    if shutil.which("enum4linux-ng"):
        cmd = ["enum4linux-ng", "-A", target]
    elif shutil.which("enum4linux"):
        cmd = ["enum4linux", "-a", target]
    else:
        return "Error: neither enum4linux-ng nor enum4linux found in PATH. Install: apt install enum4linux"
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smb_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No SMB enumeration results for {target}."


register(
    Tool(
        name="smb_enum",
        description="Full SMB enumeration using enum4linux-ng (or enum4linux fallback): users, shares, policies.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _smb_enum,
)


# ---------------------------------------------------------------------------
# smb_shares  (smbclient -L)
# ---------------------------------------------------------------------------

async def _smb_shares(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("smbclient"):
        return "Error: smbclient not found in PATH. Install: apt install smbclient"
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["smbclient", "-L", f"//{target}", "-N"]
    if username:
        cmd += ["-U", f"{username}%{password}" if password else username]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smb_shares", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No SMB shares listed for {target}."


register(
    Tool(
        name="smb_shares",
        description="List SMB shares using smbclient -L (null session by default).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "Username (optional, null session if omitted)"},
                "password": {"type": "string", "description": "Password (optional)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _smb_shares,
)


# ---------------------------------------------------------------------------
# smb_null_session  (try null auth via smbclient)
# ---------------------------------------------------------------------------

async def _smb_null_session(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("smbclient"):
        return "Error: smbclient not found in PATH."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["smbclient", "-L", f"//{target}", "-N", "-U", ""]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smb_null_session", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if "Sharename" in stdout or "DISK" in stdout or "IPC" in stdout:
        return f"[VULN] Null session allowed on {target}!\n{stdout}"
    return f"Null session result for {target}:\n{stdout or stderr}"


register(
    Tool(
        name="smb_null_session",
        description="Test for SMB null session (anonymous authentication) via smbclient.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _smb_null_session,
)


# ---------------------------------------------------------------------------
# smb_brute  (hydra smb)
# ---------------------------------------------------------------------------

async def _smb_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("hydra"):
        return "Error: hydra not found in PATH. Install: apt install hydra"
    userlist = (args.get("userlist") or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt").strip()
    passlist = (args.get("passlist") or "/usr/share/wordlists/rockyou.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["hydra", "-L", userlist, "-P", passlist, target, "smb", "-t", "4"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smb_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    valid = [ln for ln in stdout.splitlines() if "login:" in ln.lower()]
    if valid:
        return "SMB credentials found:\n" + "\n".join(valid)
    return f"SMB brute-force complete. No credentials found.\n{stdout[-500:]}"


register(
    Tool(
        name="smb_brute",
        description="Brute-force SMB authentication using hydra.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "userlist": {"type": "string", "description": "Username wordlist path"},
                "passlist": {"type": "string", "description": "Password wordlist path"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _smb_brute,
)


# ---------------------------------------------------------------------------
# ldap_anonymous  (ldapsearch -x anonymous bind)
# ---------------------------------------------------------------------------

async def _ldap_anonymous(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("ldapsearch"):
        return "Error: ldapsearch not found in PATH. Install: apt install ldap-utils"
    base_dn = (args.get("base_dn") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base_dn or "", "-s", "base"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ldap_anonymous", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if "result: 0 Success" in stdout or "namingContexts" in stdout:
        return f"[OK] LDAP anonymous bind succeeded on {target}!\n{stdout[:2000]}"
    return f"LDAP anonymous bind result for {target}:\n{stdout or stderr}"


register(
    Tool(
        name="ldap_anonymous",
        description="Test LDAP anonymous bind and retrieve base DSE information.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "base_dn": {"type": "string", "description": "Base DN (auto-detected if empty)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _ldap_anonymous,
)


# ---------------------------------------------------------------------------
# ldap_users  (ldapsearch to get users)
# ---------------------------------------------------------------------------

async def _ldap_users(args: dict) -> str:
    target = (args.get("target") or "").strip()
    base_dn = (args.get("base_dn") or "").strip()
    if not target or not base_dn:
        return "Error: target and base_dn are required."
    if not shutil.which("ldapsearch"):
        return "Error: ldapsearch not found in PATH."
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{target}", "-b", base_dn,
        "(objectClass=person)", "sAMAccountName", "cn", "mail",
    ]
    if username:
        cmd += ["-D", username, "-w", password]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ldap_users", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    users = re.findall(r"sAMAccountName:\s*(.+)", stdout)
    if users:
        return f"LDAP users on {target} ({len(users)}):\n" + "\n".join(users) + f"\n\n{stdout[:3000]}"
    return f"LDAP user enumeration result:\n{stdout or stderr}"


register(
    Tool(
        name="ldap_users",
        description="Enumerate user accounts from LDAP via ldapsearch (objectClass=person).",
        inputSchema={
            "type": "object",
            "required": ["target", "base_dn"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "base_dn": {"type": "string", "description": "Base DN, e.g. 'dc=example,dc=com'"},
                "username": {"type": "string", "description": "Bind DN username (optional)"},
                "password": {"type": "string", "description": "Bind password (optional)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _ldap_users,
)


# ---------------------------------------------------------------------------
# ldap_dump  (ldapdomaindump)
# ---------------------------------------------------------------------------

async def _ldap_dump(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("ldapdomaindump"):
        return "Error: ldapdomaindump not found in PATH. Install: pip install ldapdomaindump"
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    if not username:
        return "Error: username is required for ldapdomaindump."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    out_dir = tempfile.mkdtemp(prefix="ldapdump_")
    cmd = [
        "ldapdomaindump", f"ldap://{target}",
        "-u", username, "-p", password,
        "-o", out_dir,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ldap_dump", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    files = list(Path(out_dir).glob("*.json")) if exit_code == 0 else []
    return f"ldapdomaindump complete. Output: {out_dir}\nFiles: {[f.name for f in files]}\n{stdout or stderr}"


register(
    Tool(
        name="ldap_dump",
        description="Dump Active Directory LDAP data using ldapdomaindump (users, groups, computers, policies).",
        inputSchema={
            "type": "object",
            "required": ["target", "username", "password"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname (DC)"},
                "username": {"type": "string", "description": "Username (DOMAIN\\user or user@domain)"},
                "password": {"type": "string", "description": "Password"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _ldap_dump,
)


# ---------------------------------------------------------------------------
# rpc_enum  (rpcclient -U "" null session)
# ---------------------------------------------------------------------------

async def _rpc_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("rpcclient"):
        return "Error: rpcclient not found in PATH. Install: apt install samba-common"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    # Run multiple rpcclient commands via echo pipe
    commands = "srvinfo\nenumdomains\nquerydominfo\n"
    proc = await asyncio.create_subprocess_exec(
        "rpcclient", "-U", "", "-N", target,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=commands.encode()), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"rpcclient timed out after {timeout_s}s"
    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    await _persist(project_id, "rpc_enum", args, stdout, stderr, proc.returncode)
    return stdout or stderr or f"No RPC data returned from {target}."


register(
    Tool(
        name="rpc_enum",
        description="RPC enumeration via rpcclient null session: srvinfo, enumdomains, querydominfo.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _rpc_enum,
)


# ---------------------------------------------------------------------------
# rpc_users  (rpcclient enumdomusers)
# ---------------------------------------------------------------------------

async def _rpc_users(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("rpcclient"):
        return "Error: rpcclient not found in PATH."
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    auth = f"{username}%{password}" if username else ""
    proc = await asyncio.create_subprocess_exec(
        "rpcclient", "-U", auth, *(["-N"] if not username else []), target,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=b"enumdomusers\n"), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"rpcclient timed out after {timeout_s}s"
    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    await _persist(project_id, "rpc_users", args, stdout, stderr, proc.returncode)
    users = re.findall(r"user:\[([^\]]+)\]", stdout)
    if users:
        return f"Domain users on {target} ({len(users)}):\n" + "\n".join(users)
    return f"rpcclient enumdomusers result:\n{stdout or stderr}"


register(
    Tool(
        name="rpc_users",
        description="Enumerate domain users via rpcclient enumdomusers (null session or authenticated).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "Username (optional, null session if empty)"},
                "password": {"type": "string", "description": "Password (optional)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _rpc_users,
)


# ---------------------------------------------------------------------------
# snmp_walk  (snmpwalk public community)
# ---------------------------------------------------------------------------

async def _snmp_walk(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("snmpwalk"):
        return "Error: snmpwalk not found in PATH. Install: apt install snmp"
    community = (args.get("community") or "public").strip()
    oid = (args.get("oid") or "1.3.6.1.2.1").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["snmpwalk", "-v2c", "-c", community, target, oid]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "snmp_walk", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No SNMP data from {target} (community={community})."


register(
    Tool(
        name="snmp_walk",
        description="SNMP walk using snmpwalk with a community string (default: public).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "community": {"type": "string", "description": "SNMP community string (default: public)"},
                "oid": {"type": "string", "description": "OID to walk (default: 1.3.6.1.2.1 mib-2)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _snmp_walk,
)


# ---------------------------------------------------------------------------
# snmp_brute  (onesixtyone community brute)
# ---------------------------------------------------------------------------

async def _snmp_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("onesixtyone"):
        return "Error: onesixtyone not found in PATH. Install: apt install onesixtyone"
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Discovery/SNMP/snmp.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["onesixtyone", "-c", wordlist, target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "snmp_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No valid SNMP community strings found for {target}."


register(
    Tool(
        name="snmp_brute",
        description="Brute-force SNMP community strings using onesixtyone.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "wordlist": {"type": "string", "description": "Community strings wordlist"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _snmp_brute,
)


# ---------------------------------------------------------------------------
# nfs_enum  (showmount -e)
# ---------------------------------------------------------------------------

async def _nfs_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("showmount"):
        return "Error: showmount not found in PATH. Install: apt install nfs-common"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["showmount", "-e", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "nfs_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if "Export list" in stdout:
        return f"[NFS shares found]\n{stdout}"
    return f"NFS enumeration for {target}:\n{stdout or stderr}"


register(
    Tool(
        name="nfs_enum",
        description="Enumerate NFS exports using showmount -e.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _nfs_enum,
)


# ---------------------------------------------------------------------------
# ftp_anon  (check anonymous FTP login)
# ---------------------------------------------------------------------------

async def _ftp_anon(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    cmd = ["curl", "-sL", "--connect-timeout", "10", f"ftp://{target}/", "--user", "anonymous:anonymous"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ftp_anon", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if exit_code == 0 or "230" in (stdout + stderr):
        return f"[VULN] Anonymous FTP login allowed on {target}!\nDirectory listing:\n{stdout}"
    return f"Anonymous FTP test for {target}: rc={exit_code}\n{stderr[:500]}"


register(
    Tool(
        name="ftp_anon",
        description="Test for anonymous FTP login using curl ftp:// with anonymous:anonymous credentials.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _ftp_anon,
)


# ---------------------------------------------------------------------------
# ftp_brute  (hydra ftp)
# ---------------------------------------------------------------------------

async def _ftp_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("hydra"):
        return "Error: hydra not found in PATH."
    userlist = (args.get("userlist") or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt").strip()
    passlist = (args.get("passlist") or "/usr/share/wordlists/rockyou.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["hydra", "-L", userlist, "-P", passlist, target, "ftp", "-t", "4"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ftp_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    valid = [ln for ln in stdout.splitlines() if "login:" in ln.lower()]
    if valid:
        return "FTP credentials found:\n" + "\n".join(valid)
    return f"FTP brute-force complete. No credentials found.\n{stdout[-500:]}"


register(
    Tool(
        name="ftp_brute",
        description="Brute-force FTP authentication using hydra.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "userlist": {"type": "string", "description": "Username wordlist path"},
                "passlist": {"type": "string", "description": "Password wordlist path"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _ftp_brute,
)


# ---------------------------------------------------------------------------
# ssh_audit  (ssh-audit)
# ---------------------------------------------------------------------------

async def _ssh_audit(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 22))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    if shutil.which("ssh-audit"):
        cmd = ["ssh-audit", "-p", str(port), target]
    elif shutil.which("ssh_audit"):
        cmd = ["ssh_audit", "-p", str(port), target]
    else:
        return "Error: ssh-audit not found. Install: pip install ssh-audit"
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ssh_audit", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No ssh-audit output for {target}:{port}."


register(
    Tool(
        name="ssh_audit",
        description="SSH configuration audit using ssh-audit: algorithms, host keys, vulnerabilities.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "SSH port (default: 22)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _ssh_audit,
)


# ---------------------------------------------------------------------------
# ssh_brute  (hydra ssh)
# ---------------------------------------------------------------------------

async def _ssh_brute(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("hydra"):
        return "Error: hydra not found in PATH."
    userlist = (args.get("userlist") or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt").strip()
    passlist = (args.get("passlist") or "/usr/share/wordlists/rockyou.txt").strip()
    port = int(args.get("port", 22))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))
    cmd = ["hydra", "-L", userlist, "-P", passlist, "-s", str(port), target, "ssh", "-t", "4"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "ssh_brute", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    valid = [ln for ln in stdout.splitlines() if "login:" in ln.lower()]
    if valid:
        return "SSH credentials found:\n" + "\n".join(valid)
    return f"SSH brute-force complete. No credentials found.\n{stdout[-500:]}"


register(
    Tool(
        name="ssh_brute",
        description="Brute-force SSH authentication using hydra.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "userlist": {"type": "string", "description": "Username wordlist path"},
                "passlist": {"type": "string", "description": "Password wordlist path"},
                "port": {"type": "integer", "description": "SSH port (default: 22)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
        },
    ),
    _ssh_brute,
)


# ---------------------------------------------------------------------------
# rdp_check  (nmap --script rdp-enum-encryption)
# ---------------------------------------------------------------------------

async def _rdp_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 3389))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = [
        "nmap", "-p", str(port),
        "--script", "rdp-enum-encryption,rdp-vuln-ms12-020",
        "-sV", target,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "rdp_check", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No RDP data for {target}:{port}."


register(
    Tool(
        name="rdp_check",
        description="RDP enumeration and vulnerability check via nmap scripts (rdp-enum-encryption, rdp-vuln-ms12-020).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "RDP port (default: 3389)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _rdp_check,
)


# ---------------------------------------------------------------------------
# smtp_enum  (smtp-user-enum VRFY/EXPN)
# ---------------------------------------------------------------------------

async def _smtp_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    if not shutil.which("smtp-user-enum"):
        return "Error: smtp-user-enum not found. Install: apt install smtp-user-enum"
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt").strip()
    method = (args.get("method") or "VRFY").upper()
    port = int(args.get("port", 25))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))
    cmd = ["smtp-user-enum", "-M", method, "-U", wordlist, "-t", target, "-p", str(port)]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smtp_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No SMTP users found on {target}."


register(
    Tool(
        name="smtp_enum",
        description="Enumerate SMTP users using smtp-user-enum with VRFY/EXPN/RCPT methods.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "wordlist": {"type": "string", "description": "Username wordlist path"},
                "method": {"type": "string", "description": "SMTP method: VRFY, EXPN, or RCPT (default: VRFY)"},
                "port": {"type": "integer", "description": "SMTP port (default: 25)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 120)"},
            },
        },
    ),
    _smtp_enum,
)


# ---------------------------------------------------------------------------
# smtp_open_relay  (check open relay via nmap script)
# ---------------------------------------------------------------------------

async def _smtp_open_relay(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 25))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = [
        "nmap", "-p", str(port),
        "--script", "smtp-open-relay",
        target,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smtp_open_relay", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    if "Server is an open relay" in stdout:
        return f"[VULN] SMTP open relay detected on {target}:{port}!\n{stdout}"
    return f"SMTP open relay check for {target}:{port}:\n{stdout or stderr}"


register(
    Tool(
        name="smtp_open_relay",
        description="Check for SMTP open relay using nmap smtp-open-relay script.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "SMTP port (default: 25)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _smtp_open_relay,
)


# ---------------------------------------------------------------------------
# mysql_probe  (nmap mysql scripts)
# ---------------------------------------------------------------------------

async def _mysql_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 3306))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = [
        "nmap", "-p", str(port), "-sV",
        "--script", "mysql-info,mysql-empty-password,mysql-databases,mysql-users",
        target,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "mysql_probe", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No MySQL data for {target}:{port}."


register(
    Tool(
        name="mysql_probe",
        description="MySQL enumeration using nmap scripts: info, empty-password, databases, users.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "MySQL port (default: 3306)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _mysql_probe,
)


# ---------------------------------------------------------------------------
# mssql_probe  (nmap mssql scripts)
# ---------------------------------------------------------------------------

async def _mssql_probe(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 1433))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = [
        "nmap", "-p", str(port), "-sV",
        "--script", "ms-sql-info,ms-sql-empty-password,ms-sql-config",
        target,
    ]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "mssql_probe", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No MSSQL data for {target}:{port}."


register(
    Tool(
        name="mssql_probe",
        description="MSSQL enumeration using nmap scripts: ms-sql-info, empty-password, config.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "MSSQL port (default: 1433)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _mssql_probe,
)


# ---------------------------------------------------------------------------
# redis_check  (redis-cli -h INFO)
# ---------------------------------------------------------------------------

async def _redis_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 6379))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    if shutil.which("redis-cli"):
        cmd = ["redis-cli", "-h", target, "-p", str(port), "INFO"]
        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
        await _persist(project_id, "redis_check", args, stdout, stderr, exit_code)
        if exit_code == -1:
            return stderr
        if "redis_version" in stdout:
            version_m = re.search(r"redis_version:(.+)", stdout)
            return f"[ACCESSIBLE] Redis on {target}:{port} is open (no auth)!\nVersion: {version_m.group(1).strip() if version_m else '?'}\n{stdout[:1000]}"
        return f"Redis check for {target}:{port}:\n{stdout or stderr}"
    # Fallback: nmap
    cmd = ["nmap", "-p", str(port), "--script", "redis-info", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "redis_check", args, stdout, stderr, exit_code)
    return stdout or stderr or f"No Redis data for {target}:{port}."


register(
    Tool(
        name="redis_check",
        description="Check Redis accessibility and gather INFO using redis-cli (or nmap fallback).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "Redis port (default: 6379)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _redis_check,
)


# ---------------------------------------------------------------------------
# mongodb_check  (mongosh or mongo --eval listDatabases)
# ---------------------------------------------------------------------------

async def _mongodb_check(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required."
    port = int(args.get("port", 27017))
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 30))
    client = shutil.which("mongosh") or shutil.which("mongo")
    if client:
        cmd = [
            client, f"mongodb://{target}:{port}/",
            "--quiet", "--eval",
            "JSON.stringify(db.adminCommand({listDatabases: 1}))",
        ]
        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
        await _persist(project_id, "mongodb_check", args, stdout, stderr, exit_code)
        if exit_code == -1:
            return stderr
        if "databases" in stdout or "totalSize" in stdout:
            return f"[ACCESSIBLE] MongoDB on {target}:{port} is open (no auth)!\n{stdout[:2000]}"
        return f"MongoDB check for {target}:{port}:\n{stdout or stderr}"
    # Fallback: nmap
    cmd = ["nmap", "-p", str(port), "--script", "mongodb-info,mongodb-databases", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "mongodb_check", args, stdout, stderr, exit_code)
    return stdout or stderr or f"No MongoDB data for {target}:{port}."


register(
    Tool(
        name="mongodb_check",
        description="Check MongoDB accessibility and list databases (unauthenticated access test).",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "MongoDB port (default: 27017)"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 30)"},
            },
        },
    ),
    _mongodb_check,
)


# ---------------------------------------------------------------------------
# kerberos_enum  (kerbrute userenum)
# ---------------------------------------------------------------------------

async def _kerberos_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    domain = (args.get("domain") or "").strip()
    if not target or not domain:
        return "Error: target (DC IP) and domain are required."
    if not shutil.which("kerbrute"):
        return "Error: kerbrute not found in PATH. Download from https://github.com/ropnop/kerbrute"
    wordlist = (args.get("wordlist") or "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 180))
    cmd = ["kerbrute", "userenum", "--dc", target, "-d", domain, wordlist]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "kerberos_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    valid = [ln for ln in stdout.splitlines() if "VALID" in ln.upper()]
    if valid:
        return f"Valid Kerberos users on {domain}:\n" + "\n".join(valid)
    return f"Kerbrute result for {domain}:\n{stdout or stderr}"


register(
    Tool(
        name="kerberos_enum",
        description="Enumerate valid Kerberos users using kerbrute userenum against an AD domain.",
        inputSchema={
            "type": "object",
            "required": ["target", "domain"],
            "properties": {
                "target": {"type": "string", "description": "Domain Controller IP"},
                "domain": {"type": "string", "description": "Active Directory domain, e.g. 'corp.local'"},
                "wordlist": {"type": "string", "description": "Username wordlist path"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 180)"},
            },
        },
    ),
    _kerberos_enum,
)


# ---------------------------------------------------------------------------
# netbios_scan  (nbtscan)
# ---------------------------------------------------------------------------

async def _netbios_scan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    if not target:
        return "Error: target is required (IP or CIDR)."
    if not shutil.which("nbtscan"):
        return "Error: nbtscan not found in PATH. Install: apt install nbtscan"
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))
    cmd = ["nbtscan", "-r", target]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "netbios_scan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No NetBIOS hosts found in {target}."


register(
    Tool(
        name="netbios_scan",
        description="Scan for NetBIOS names and workgroup info using nbtscan.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "IP address or CIDR range"},
                "project_id": {"type": "integer"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default 60)"},
            },
        },
    ),
    _netbios_scan,
)


# ---------------------------------------------------------------------------
# rustscan  (ultra-fast port scanner)
# ---------------------------------------------------------------------------

async def _rustscan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    ports = (args.get("ports") or "").strip()
    ulimit = int(args.get("ulimit", 5000))
    batch_size = int(args.get("batch_size", 4500))
    run_scripts = bool(args.get("run_scripts", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not target:
        return "Error: target is required."
    if not shutil.which("rustscan"):
        return "Error: rustscan not found in PATH. Install from https://github.com/RustScan/RustScan"

    cmd = ["rustscan", "-a", target, "--ulimit", str(ulimit), "-b", str(batch_size)]
    if ports:
        cmd += ["-p", ports]
    if extra:
        cmd += extra.split()
    if run_scripts:
        cmd += ["--", "-sC", "-sV"]

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "rustscan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Rustscan completed for {target} with no open ports."


register(
    Tool(
        name="rustscan",
        description="Ultra-fast port scanning with Rustscan. Scans all 65535 ports in seconds, then passes results to Nmap for service detection. Much faster than Nmap alone for initial discovery.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                "ports": {"type": "string", "description": "Port range (e.g. '1-1000', '80,443,8080'). Default: all ports."},
                "ulimit": {"type": "integer", "description": "File descriptor limit (default: 5000, increase for speed)"},
                "batch_size": {"type": "integer", "description": "Concurrent socket batch size (default: 4500)"},
                "run_scripts": {"type": "boolean", "description": "Pass results to Nmap -sC -sV for service enumeration (default: false)"},
                "additional_args": {"type": "string", "description": "Extra rustscan flags"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _rustscan,
)


# ---------------------------------------------------------------------------
# masscan  (high-speed mass port scanner)
# ---------------------------------------------------------------------------

async def _masscan(args: dict) -> str:
    target = (args.get("target") or "").strip()
    ports = (args.get("ports") or "1-65535").strip()
    rate = int(args.get("rate", 1000))
    interface = (args.get("interface") or "").strip()
    banners = bool(args.get("banners", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 300))

    if not target:
        return "Error: target is required."
    if not shutil.which("masscan"):
        return "Error: masscan not found in PATH. Install: apt install masscan"

    cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}"]
    if interface:
        cmd += ["-e", interface]
    if banners:
        cmd.append("--banners")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "masscan", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Masscan found no open ports on {target}."


register(
    Tool(
        name="masscan",
        description="High-speed mass port scanning with Masscan. Can scan the entire Internet in minutes. Best for wide-net scanning of large IP ranges. Requires root/sudo.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP, CIDR range, or IP list file"},
                "ports": {"type": "string", "description": "Ports to scan (default: 1-65535)"},
                "rate": {"type": "integer", "description": "Packets per second (default: 1000, max: ~10M on good hardware)"},
                "interface": {"type": "string", "description": "Network interface to use"},
                "banners": {"type": "boolean", "description": "Grab banners from open ports (default: false)"},
                "additional_args": {"type": "string", "description": "Extra masscan flags"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 300)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _masscan,
)


# ---------------------------------------------------------------------------
# autorecon  (automated comprehensive reconnaissance)
# ---------------------------------------------------------------------------

async def _autorecon(args: dict) -> str:
    target = (args.get("target") or "").strip()
    output_dir = (args.get("output_dir") or "/tmp/autorecon").strip()
    heartbeat = int(args.get("heartbeat", 60))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 600))

    if not target:
        return "Error: target is required."
    if not shutil.which("autorecon"):
        return "Error: autorecon not found in PATH. Install: pip install autorecon"

    cmd = ["autorecon", target, "-o", output_dir, "--heartbeat", str(heartbeat)]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "autorecon", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return (stdout or stderr or f"AutoRecon completed for {target}.") + f"\nResults saved to: {output_dir}"


register(
    Tool(
        name="autorecon",
        description="Automated comprehensive multi-threaded reconnaissance with AutoRecon. Runs nmap, service enumeration, and targeted scans automatically based on discovered services.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "output_dir": {"type": "string", "description": "Output directory (default: /tmp/autorecon)"},
                "heartbeat": {"type": "integer", "description": "Progress heartbeat interval in seconds (default: 60)"},
                "additional_args": {"type": "string", "description": "Extra autorecon flags (e.g. '--single-target', '--no-port-dirs')"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 600)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _autorecon,
)


# ---------------------------------------------------------------------------
# smbmap_enum  (SMB share enumeration and access testing)
# ---------------------------------------------------------------------------

async def _smbmap_enum(args: dict) -> str:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    domain = (args.get("domain") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))

    if not target:
        return "Error: target is required."
    if not shutil.which("smbmap"):
        return "Error: smbmap not found in PATH. Install: apt install smbmap"

    cmd = ["smbmap", "-H", target]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if domain:
        cmd += ["-d", domain]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "smbmap_enum", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"SMBMap found no accessible shares on {target}."


register(
    Tool(
        name="smbmap_enum",
        description="SMB share enumeration with SMBMap. Lists available shares, their permissions (READ/WRITE), and can recursively list directory contents. Supports null session and credential-based access.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "SMB username (empty for null session)"},
                "password": {"type": "string", "description": "SMB password"},
                "domain": {"type": "string", "description": "Windows domain"},
                "additional_args": {"type": "string", "description": "Extra smbmap flags (e.g. '-R' for recursive, '--download path' to download)"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 60)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _smbmap_enum,
)


# ---------------------------------------------------------------------------
# netexec_run  (network authentication testing / post-exploitation)
# ---------------------------------------------------------------------------

async def _netexec_run(args: dict) -> str:
    target = (args.get("target") or "").strip()
    protocol = (args.get("protocol") or "smb").strip()
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    hash_val = (args.get("hash") or "").strip()
    module = (args.get("module") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not target:
        return "Error: target is required."

    nxc_bin = shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")
    if not nxc_bin:
        return "Error: nxc/netexec not found in PATH. Install: pip install netexec"

    cmd = [nxc_bin, protocol, target]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if hash_val:
        cmd += ["-H", hash_val]
    if module:
        cmd += ["-M", module]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "netexec_run", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"NetExec {protocol} completed for {target}."


register(
    Tool(
        name="netexec_run",
        description="Network authentication testing and post-exploitation with NetExec (formerly CrackMapExec). Test credentials across SMB/WinRM/MSSQL/RDP/SSH, dump SAM, run commands, and spray passwords.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, CIDR, or file with targets"},
                "protocol": {"type": "string", "description": "Protocol: smb, winrm, mssql, rdp, ssh, ldap (default: smb)"},
                "username": {"type": "string", "description": "Username or file with usernames"},
                "password": {"type": "string", "description": "Password or file with passwords"},
                "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (format: LM:NT or just NT)"},
                "module": {"type": "string", "description": "NetExec module to run (e.g. 'lsassy', 'mimikatz', 'spider_plus')"},
                "additional_args": {"type": "string", "description": "Extra netexec flags (e.g. '--shares', '-x cmd', '--sam')"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _netexec_run,
)


# ---------------------------------------------------------------------------
# responder_capture  (LLMNR/NBT-NS/mDNS poisoning and credential capture)
# ---------------------------------------------------------------------------

async def _responder_capture(args: dict) -> str:
    interface = (args.get("interface") or "eth0").strip()
    analyze = bool(args.get("analyze", False))
    wpad = bool(args.get("wpad", True))
    duration = int(args.get("duration", 60))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not shutil.which("responder"):
        return "Error: responder not found in PATH. Install: apt install responder"

    cmd = ["timeout", str(duration), "responder", "-I", interface]
    if analyze:
        cmd.append("-A")
    if wpad:
        cmd.append("-w")
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=duration + 15)
    await _persist(project_id, "responder_capture", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Responder ran for {duration}s on {interface} with no captures."


register(
    Tool(
        name="responder_capture",
        description="LLMNR/NBT-NS/mDNS poisoning and NetNTLM hash capture with Responder. Passively captures credentials from misconfigured Windows hosts. Use analyze mode (-A) for passive-only operation.",
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to listen on (default: eth0)"},
                "analyze": {"type": "boolean", "description": "Analyze mode only — no poisoning, just capture (default: false)"},
                "wpad": {"type": "boolean", "description": "Enable WPAD rogue proxy (default: true)"},
                "duration": {"type": "integer", "description": "Listen duration in seconds (default: 60)"},
                "additional_args": {"type": "string", "description": "Extra responder flags (e.g. '-f' for fingerprint)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _responder_capture,
)


# ---------------------------------------------------------------------------
# arp_scan_discover  (layer 2 host discovery)
# ---------------------------------------------------------------------------

async def _arp_scan_discover(args: dict) -> str:
    target = (args.get("target") or "").strip()
    interface = (args.get("interface") or "").strip()
    local_network = bool(args.get("local_network", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 60))

    if not target and not local_network:
        return "Error: target or local_network=true is required."
    if not shutil.which("arp-scan"):
        return "Error: arp-scan not found in PATH. Install: apt install arp-scan"

    cmd = ["arp-scan"]
    if interface:
        cmd += ["-I", interface]
    if local_network:
        cmd.append("-l")
    elif target:
        cmd.append(target)
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "arp_scan_discover", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "arp-scan found no hosts."


register(
    Tool(
        name="arp_scan_discover",
        description="Layer 2 host discovery with arp-scan. Finds all live hosts on the local network segment using ARP requests. More reliable than ICMP ping on internal networks.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target CIDR range or IP (e.g. 192.168.1.0/24)"},
                "local_network": {"type": "boolean", "description": "Scan entire local network (auto-detects range, default: false)"},
                "interface": {"type": "string", "description": "Network interface (e.g. eth0, tun0)"},
                "additional_args": {"type": "string", "description": "Extra arp-scan flags"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 60)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _arp_scan_discover,
)


# ---------------------------------------------------------------------------
# enum4linux_ng  (enhanced Windows/Samba enumeration)
# ---------------------------------------------------------------------------

async def _enum4linux_ng(args: dict) -> str:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    oY = bool(args.get("yaml_output", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 120))

    if not target:
        return "Error: target is required."

    bin_path = shutil.which("enum4linux-ng") or shutil.which("enum4linux-ng.py")
    if not bin_path:
        return "Error: enum4linux-ng not found in PATH. Install: pip install enum4linux-ng"

    cmd = [bin_path, target, "-A"]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if oY:
        cmd += ["-oY", "/tmp/enum4linux-ng-output.yaml"]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=timeout_s)
    await _persist(project_id, "enum4linux_ng", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"enum4linux-ng completed for {target} with no results."


register(
    Tool(
        name="enum4linux_ng",
        description="Enhanced Windows/Samba enumeration with enum4linux-ng (modern rewrite). Enumerates users, groups, shares, password policy, OS info, and RID cycling. Better output formatting than the original.",
        inputSchema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "username": {"type": "string", "description": "Username for authenticated enumeration"},
                "password": {"type": "string", "description": "Password for authenticated enumeration"},
                "yaml_output": {"type": "boolean", "description": "Save YAML output to /tmp/enum4linux-ng-output.yaml (default: false)"},
                "additional_args": {"type": "string", "description": "Extra enum4linux-ng flags"},
                "timeout": {"type": "integer", "description": "Timeout seconds (default: 120)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _enum4linux_ng,
)
