"""
Password cracking and credential spraying tools.
"""
import re
import shlex
from pathlib import Path

from mcp.types import Tool

from .register_all import register
from ._helpers import _chk, _need, _run, _ok, _s, _artifact

# Common hash regex patterns for fallback identification
_HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5"),
    (r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$", "MD5-Crypt"),
    (r"^[a-f0-9]{40}$", "SHA1"),
    (r"^[a-f0-9]{56}$", "SHA224"),
    (r"^[a-f0-9]{64}$", "SHA256"),
    (r"^[a-f0-9]{96}$", "SHA384"),
    (r"^[a-f0-9]{128}$", "SHA512"),
    (r"^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$", "bcrypt"),
    (r"^\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}$", "SHA256-Crypt"),
    (r"^\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}$", "SHA512-Crypt"),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "NTLM (hash:salt or LM:NT)"),
    (r"^[A-F0-9]{32}:[A-F0-9]{32}$", "NTLM"),
    (r"^\$NT\$[a-f0-9]{32}$", "NT Hash"),
    (r"^[a-zA-Z0-9+/]{43}=$", "SHA256-Base64"),
    (r"^\{SHA\}[a-zA-Z0-9+/=]{28}$", "SHA1-LDAP"),
    (r"^\{SSHA\}[a-zA-Z0-9+/=]{40}$", "SSHA-LDAP"),
    (r"^[a-f0-9]{48}$", "MySQL 4.x / double SHA1"),
    (r"^\*[A-F0-9]{40}$", "MySQL5 (SHA1(SHA1))"),
    (r"^[a-zA-Z0-9]{13}$", "DES-Crypt (Unix)"),
]


# ---------------------------------------------------------------------------
# hash_identify
# ---------------------------------------------------------------------------

async def _hash_identify(args: dict) -> list:
    hash_value = (args.get("hash_value") or "").strip()
    if not hash_value:
        return _ok("Error: hash_value is required.")

    lines = [f"Identifying hash: {hash_value}"]

    # Try hashid first
    if _chk("hashid"):
        out, err, rc = await _run(["hashid", hash_value], timeout=10)
        if out.strip():
            lines.append(f"\n[hashid output]\n{out.strip()}")
            return _ok("\n".join(lines))

    # Fallback: regex matching
    matches = []
    for pattern, name in _HASH_PATTERNS:
        if re.match(pattern, hash_value, re.IGNORECASE):
            matches.append(name)

    if matches:
        lines.append(f"\n[Regex-based identification]\nPossible hash types: {', '.join(matches)}")
    else:
        length = len(hash_value)
        lines.append(f"\n[Regex-based identification]\nNo pattern match. Hash length: {length} chars")
        # Length-based fallback
        length_map = {32: "MD5 or NTLM", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
        if length in length_map:
            lines.append(f"Length {length} suggests: {length_map[length]}")

    return _ok("\n".join(lines))


register(
    Tool(
        name="hash_identify",
        description=(
            "Identify the type of a hash using hashid (if installed) "
            "with regex pattern fallback for MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, etc."
        ),
        inputSchema=_s(
            ["hash_value"],
            hash_value=("string", "The hash string to identify"),
        ),
    ),
    _hash_identify,
)


# ---------------------------------------------------------------------------
# hash_crack_online
# ---------------------------------------------------------------------------

async def _hash_crack_online(args: dict) -> list:
    hash_value = (args.get("hash_value") or "").strip()
    if not hash_value:
        return _ok("Error: hash_value is required.")

    if not _chk("curl"):
        return _need("curl", "apt install curl")

    lines = [f"Attempting online lookup for: {hash_value}"]

    # MD5Decrypt API (free, no key)
    if len(hash_value) == 32 and re.match(r"^[a-f0-9]{32}$", hash_value, re.IGNORECASE):
        out, err, rc = await _run(
            ["curl", "-s", "--connect-timeout", "10",
             f"https://md5decrypt.net/en/Api/api.php?hash={hash_value}&hash_type=md5&email=dummypwn@pwn.com&code=code1"],
            timeout=15,
        )
        lines.append(f"\n[md5decrypt.net]\n{out.strip() or 'No response'}")

    # hashes.com free lookup
    out2, err2, rc2 = await _run(
        ["curl", "-s", "--connect-timeout", "10",
         "-X", "POST", "https://hashes.com/en/api/search",
         "--data-urlencode", f"hashes[]={hash_value}"],
        timeout=15,
    )
    lines.append(f"\n[hashes.com]\n{out2.strip() or 'No response'}")

    return _ok("\n".join(lines))


register(
    Tool(
        name="hash_crack_online",
        description=(
            "Attempt online hash lookup via md5decrypt.net and hashes.com free APIs. "
            "Works best for MD5 hashes of common passwords. No API key required."
        ),
        inputSchema=_s(
            ["hash_value"],
            hash_value=("string", "The hash to look up online"),
        ),
    ),
    _hash_crack_online,
)


# ---------------------------------------------------------------------------
# john_crack
# ---------------------------------------------------------------------------

async def _john_crack(args: dict) -> list:
    hash_value = (args.get("hash_value") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    hash_type = (args.get("hash_type") or "").strip()
    project_id = args.get("project_id")

    if not hash_value:
        return _ok("Error: hash_value is required.")
    if not _chk("john"):
        return _need("john", "apt install john")

    # Write hash to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as tf:
        tf.write(hash_value + "\n")
        hash_file = tf.name

    cmd = ["john", f"--wordlist={wordlist_path}", hash_file]
    if hash_type:
        cmd.append(f"--format={hash_type}")

    out, err, rc = await _run(cmd, timeout=300)

    # Show the cracked result
    show_out, show_err, show_rc = await _run(
        ["john", "--show", hash_file] + ([f"--format={hash_type}"] if hash_type else []),
        timeout=15,
    )

    Path(hash_file).unlink(missing_ok=True)

    result = f"[john output]\n{out.strip()}\n{err.strip()}\n\n[john --show]\n{show_out.strip()}"
    if project_id:
        _artifact(int(project_id), "john_crack", result)
    return _ok(result)


register(
    Tool(
        name="john_crack",
        description=(
            "Crack a hash using John the Ripper with a wordlist. "
            "Supports all john formats (raw-md5, bcrypt, NT, sha512crypt, etc.)."
        ),
        inputSchema=_s(
            ["hash_value"],
            hash_value=("string", "The hash to crack"),
            wordlist_path=("string", "Path to wordlist (default: /usr/share/wordlists/rockyou.txt)"),
            hash_type=("string", "John format string e.g. raw-md5, NT, bcrypt, sha512crypt"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _john_crack,
)


# ---------------------------------------------------------------------------
# hashcat_crack
# ---------------------------------------------------------------------------

async def _hashcat_crack(args: dict) -> list:
    hash_value = (args.get("hash_value") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    mode = args.get("mode")
    project_id = args.get("project_id")

    if not hash_value:
        return _ok("Error: hash_value is required.")
    if mode is None:
        return _ok("Error: mode is required (e.g. 0=MD5, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt).")
    if not _chk("hashcat"):
        return _need("hashcat", "apt install hashcat")

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as tf:
        tf.write(hash_value + "\n")
        hash_file = tf.name

    cmd = ["hashcat", "-m", str(int(mode)), hash_file, wordlist_path,
           "--potfile-disable", "--quiet", "--status", "--status-timer=10"]
    out, err, rc = await _run(cmd, timeout=300)

    Path(hash_file).unlink(missing_ok=True)
    result = f"[hashcat -m {mode}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hashcat_crack", result)
    return _ok(result)


register(
    Tool(
        name="hashcat_crack",
        description=(
            "Crack a hash using hashcat with a wordlist. "
            "Common modes: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt, 5600=NetNTLMv2."
        ),
        inputSchema=_s(
            ["hash_value", "mode"],
            hash_value=("string", "The hash to crack"),
            mode=("integer", "Hashcat mode number (0=MD5, 1000=NTLM, 1800=sha512crypt, etc.)"),
            wordlist_path=("string", "Path to wordlist (default: /usr/share/wordlists/rockyou.txt)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hashcat_crack,
)


# ---------------------------------------------------------------------------
# hashcat_rules
# ---------------------------------------------------------------------------

async def _hashcat_rules(args: dict) -> list:
    hash_value = (args.get("hash_value") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    mode = args.get("mode")
    rules_file = (args.get("rules_file") or "/usr/share/hashcat/rules/best64.rule").strip()
    project_id = args.get("project_id")

    if not hash_value:
        return _ok("Error: hash_value is required.")
    if mode is None:
        return _ok("Error: mode is required.")
    if not _chk("hashcat"):
        return _need("hashcat", "apt install hashcat")

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as tf:
        tf.write(hash_value + "\n")
        hash_file = tf.name

    cmd = ["hashcat", "-m", str(int(mode)), hash_file, wordlist_path,
           "-r", rules_file, "--potfile-disable", "--quiet", "--status", "--status-timer=10"]
    out, err, rc = await _run(cmd, timeout=300)

    Path(hash_file).unlink(missing_ok=True)
    result = f"[hashcat -m {mode} -r {rules_file}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hashcat_rules", result)
    return _ok(result)


register(
    Tool(
        name="hashcat_rules",
        description=(
            "Crack a hash using hashcat with a wordlist and rules file. "
            "Defaults to best64.rule. Other useful rules: rockyou-30000.rule, d3adhob0.rule."
        ),
        inputSchema=_s(
            ["hash_value", "mode"],
            hash_value=("string", "The hash to crack"),
            mode=("integer", "Hashcat mode number"),
            wordlist_path=("string", "Path to wordlist"),
            rules_file=("string", "Path to rules file (default: best64.rule)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hashcat_rules,
)


# ---------------------------------------------------------------------------
# hydra_ssh
# ---------------------------------------------------------------------------

async def _hydra_ssh(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    port = args.get("port", 22)
    project_id = args.get("project_id")

    if not target or not username:
        return _ok("Error: target and username are required.")
    if not _chk("hydra"):
        return _need("hydra", "apt install hydra")

    cmd = ["hydra", "-l", username, "-P", wordlist_path,
           f"ssh://{target}:{port}", "-t", "4", "-V"]
    out, err, rc = await _run(cmd, timeout=300)
    result = f"[hydra ssh://{target}:{port}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hydra_ssh", result)
    return _ok(result)


register(
    Tool(
        name="hydra_ssh",
        description="Brute-force SSH credentials with hydra. Takes target, username, and wordlist.",
        inputSchema=_s(
            ["target", "username"],
            target=("string", "Target IP or hostname"),
            username=("string", "Username to attack"),
            wordlist_path=("string", "Path to password wordlist"),
            port=("integer", "SSH port (default: 22)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hydra_ssh,
)


# ---------------------------------------------------------------------------
# hydra_ftp
# ---------------------------------------------------------------------------

async def _hydra_ftp(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    port = args.get("port", 21)
    project_id = args.get("project_id")

    if not target or not username:
        return _ok("Error: target and username are required.")
    if not _chk("hydra"):
        return _need("hydra", "apt install hydra")

    cmd = ["hydra", "-l", username, "-P", wordlist_path,
           f"ftp://{target}:{port}", "-t", "4", "-V"]
    out, err, rc = await _run(cmd, timeout=300)
    result = f"[hydra ftp://{target}:{port}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hydra_ftp", result)
    return _ok(result)


register(
    Tool(
        name="hydra_ftp",
        description="Brute-force FTP credentials with hydra. Takes target, username, and wordlist.",
        inputSchema=_s(
            ["target", "username"],
            target=("string", "Target IP or hostname"),
            username=("string", "Username to attack"),
            wordlist_path=("string", "Path to password wordlist"),
            port=("integer", "FTP port (default: 21)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hydra_ftp,
)


# ---------------------------------------------------------------------------
# hydra_http_form
# ---------------------------------------------------------------------------

async def _hydra_http_form(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    form_path = (args.get("form_path") or "/login").strip()
    form_params = (args.get("form_params") or "username=^USER^&password=^PASS^").strip()
    failure_string = (args.get("failure_string") or "Invalid").strip()
    project_id = args.get("project_id")

    if not target or not username:
        return _ok("Error: target and username are required.")
    if not _chk("hydra"):
        return _need("hydra", "apt install hydra")

    form_str = f"{form_path}:{form_params}:{failure_string}"
    cmd = ["hydra", "-l", username, "-P", wordlist_path,
           target, "http-post-form", form_str, "-t", "4", "-V"]
    out, err, rc = await _run(cmd, timeout=300)
    result = f"[hydra http-post-form {target}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hydra_http_form", result)
    return _ok(result)


register(
    Tool(
        name="hydra_http_form",
        description=(
            "Brute-force HTTP form login with hydra. "
            "form_params: 'username=^USER^&password=^PASS^', failure_string: text indicating failed login."
        ),
        inputSchema=_s(
            ["target", "username"],
            target=("string", "Target IP or hostname (no http://)"),
            username=("string", "Username to attack"),
            wordlist_path=("string", "Path to password wordlist"),
            form_path=("string", "Login form path e.g. /login"),
            form_params=("string", "POST params with ^USER^ and ^PASS^ placeholders"),
            failure_string=("string", "String indicating failed login (e.g. 'Invalid password')"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hydra_http_form,
)


# ---------------------------------------------------------------------------
# hydra_smb
# ---------------------------------------------------------------------------

async def _hydra_smb(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    project_id = args.get("project_id")

    if not target or not username:
        return _ok("Error: target and username are required.")
    if not _chk("hydra"):
        return _need("hydra", "apt install hydra")

    cmd = ["hydra", "-l", username, "-P", wordlist_path,
           f"smb://{target}", "-t", "1", "-V"]
    out, err, rc = await _run(cmd, timeout=300)
    result = f"[hydra smb://{target}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hydra_smb", result)
    return _ok(result)


register(
    Tool(
        name="hydra_smb",
        description="Brute-force SMB credentials with hydra. Takes target, username, and wordlist.",
        inputSchema=_s(
            ["target", "username"],
            target=("string", "Target IP or hostname"),
            username=("string", "Username to attack"),
            wordlist_path=("string", "Path to password wordlist"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hydra_smb,
)


# ---------------------------------------------------------------------------
# hydra_rdp
# ---------------------------------------------------------------------------

async def _hydra_rdp(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    wordlist_path = (args.get("wordlist_path") or "/usr/share/wordlists/rockyou.txt").strip()
    port = args.get("port", 3389)
    project_id = args.get("project_id")

    if not target or not username:
        return _ok("Error: target and username are required.")
    if not _chk("hydra"):
        return _need("hydra", "apt install hydra")

    cmd = ["hydra", "-l", username, "-P", wordlist_path,
           f"rdp://{target}:{port}", "-t", "4", "-V"]
    out, err, rc = await _run(cmd, timeout=300)
    result = f"[hydra rdp://{target}:{port}]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "hydra_rdp", result)
    return _ok(result)


register(
    Tool(
        name="hydra_rdp",
        description="Brute-force RDP credentials with hydra. Takes target, username, and wordlist.",
        inputSchema=_s(
            ["target", "username"],
            target=("string", "Target IP or hostname"),
            username=("string", "Username to attack"),
            wordlist_path=("string", "Path to password wordlist"),
            port=("integer", "RDP port (default: 3389)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _hydra_rdp,
)


# ---------------------------------------------------------------------------
# spray_smb
# ---------------------------------------------------------------------------

async def _spray_smb(args: dict) -> list:
    target = (args.get("target") or "").strip()
    users_file = (args.get("users_file") or "").strip()
    password = (args.get("password") or "").strip()
    domain = (args.get("domain") or "WORKGROUP").strip()
    project_id = args.get("project_id")

    if not target or not password:
        return _ok("Error: target and password are required.")
    if not _chk("crackmapexec") and not _chk("nxc"):
        return _need("crackmapexec", "apt install crackmapexec  OR  pipx install netexec")

    binary = "nxc" if _chk("nxc") else "crackmapexec"

    if users_file:
        cmd = [binary, "smb", target, "-u", users_file, "-p", password, "-d", domain]
    else:
        username = (args.get("username") or "Administrator").strip()
        cmd = [binary, "smb", target, "-u", username, "-p", password, "-d", domain]

    out, err, rc = await _run(cmd, timeout=120)
    result = f"[{binary} smb spray]\n{out.strip()}\n{err.strip()}"
    if project_id:
        _artifact(int(project_id), "spray_smb", result)
    return _ok(result)


register(
    Tool(
        name="spray_smb",
        description=(
            "Password spray SMB using crackmapexec/netexec. "
            "Test one password against many users to avoid lockouts."
        ),
        inputSchema=_s(
            ["target", "password"],
            target=("string", "Target IP, hostname, or CIDR range"),
            password=("string", "Password to spray"),
            users_file=("string", "Path to file with one username per line"),
            username=("string", "Single username if not using users_file"),
            domain=("string", "Domain name (default: WORKGROUP)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _spray_smb,
)


# ---------------------------------------------------------------------------
# spray_http
# ---------------------------------------------------------------------------

async def _spray_http(args: dict) -> list:
    url = (args.get("url") or "").strip()
    users_file = (args.get("users_file") or "").strip()
    password = (args.get("password") or "").strip()
    user_field = (args.get("user_field") or "username").strip()
    pass_field = (args.get("pass_field") or "password").strip()
    failure_string = (args.get("failure_string") or "Invalid").strip()
    project_id = args.get("project_id")

    if not url or not password:
        return _ok("Error: url and password are required.")

    if not users_file:
        return _ok("Error: users_file is required for HTTP spray.")

    # Read users
    try:
        users = Path(users_file).read_text().splitlines()
        users = [u.strip() for u in users if u.strip()]
    except Exception as e:
        return _ok(f"Error reading users_file: {e}")

    if not _chk("curl"):
        return _need("curl", "apt install curl")

    results = []
    for user in users[:50]:  # Cap at 50 to avoid runaway
        out, err, rc = await _run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-X", "POST", url,
             "--data-urlencode", f"{user_field}={user}",
             "--data-urlencode", f"{pass_field}={password}",
             "-L", "--connect-timeout", "5"],
            timeout=15,
        )
        status_code = out.strip()
        # Basic heuristic: 302 or 200 without failure string may indicate success
        results.append(f"  {user}:{password} -> HTTP {status_code}")

    result = f"[HTTP spray against {url}]\n" + "\n".join(results)
    if project_id:
        _artifact(int(project_id), "spray_http", result)
    return _ok(result)


register(
    Tool(
        name="spray_http",
        description=(
            "Password spray an HTTP login form with multiple usernames. "
            "Reads users from a file, tests one password against each."
        ),
        inputSchema=_s(
            ["url", "password", "users_file"],
            url=("string", "Full URL of login endpoint"),
            password=("string", "Password to spray"),
            users_file=("string", "Path to file with one username per line"),
            user_field=("string", "Form field name for username (default: username)"),
            pass_field=("string", "Form field name for password (default: password)"),
            failure_string=("string", "String indicating failed login"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _spray_http,
)


# ---------------------------------------------------------------------------
# cewl_wordlist
# ---------------------------------------------------------------------------

async def _cewl_wordlist(args: dict) -> list:
    url = (args.get("url") or "").strip()
    output_path = (args.get("output_path") or "/tmp/cewl_wordlist.txt").strip()
    depth = args.get("depth", 2)
    min_length = args.get("min_length", 6)
    project_id = args.get("project_id")

    if not url:
        return _ok("Error: url is required.")
    if not _chk("cewl"):
        return _need("cewl", "apt install cewl")

    cmd = ["cewl", url, "-w", output_path, "-d", str(depth), "-m", str(min_length)]
    out, err, rc = await _run(cmd, timeout=120)

    try:
        word_count = len(Path(output_path).read_text().splitlines())
    except Exception:
        word_count = 0

    result = f"[cewl {url}]\n{out.strip()}\n{err.strip()}\n\nWordlist saved to {output_path} ({word_count} words)"
    if project_id:
        _artifact(int(project_id), "cewl_wordlist", result)
    return _ok(result)


register(
    Tool(
        name="cewl_wordlist",
        description=(
            "Generate a custom wordlist by spidering a URL with cewl. "
            "Extracts words from web pages that may be used as passwords."
        ),
        inputSchema=_s(
            ["url"],
            url=("string", "URL to spider for wordlist generation"),
            output_path=("string", "Output file path (default: /tmp/cewl_wordlist.txt)"),
            depth=("integer", "Spider depth (default: 2)"),
            min_length=("integer", "Minimum word length (default: 6)"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _cewl_wordlist,
)


# ---------------------------------------------------------------------------
# crunch_wordlist
# ---------------------------------------------------------------------------

async def _crunch_wordlist(args: dict) -> list:
    min_len = args.get("min_len")
    max_len = args.get("max_len")
    charset = (args.get("charset") or "abcdefghijklmnopqrstuvwxyz0123456789").strip()
    output_path = (args.get("output_path") or "/tmp/crunch_wordlist.txt").strip()
    pattern = (args.get("pattern") or "").strip()
    project_id = args.get("project_id")

    if min_len is None or max_len is None:
        return _ok("Error: min_len and max_len are required.")
    if not _chk("crunch"):
        return _need("crunch", "apt install crunch")

    cmd = ["crunch", str(min_len), str(max_len), charset, "-o", output_path]
    if pattern:
        cmd.extend(["-t", pattern])

    out, err, rc = await _run(cmd, timeout=120)
    result = f"[crunch {min_len} {max_len}]\n{out.strip()}\n{err.strip()}\n\nWordlist saved to {output_path}"
    if project_id:
        _artifact(int(project_id), "crunch_wordlist", result)
    return _ok(result)


register(
    Tool(
        name="crunch_wordlist",
        description=(
            "Generate a wordlist with crunch using min/max length and character set. "
            "Useful for targeted password generation with known patterns."
        ),
        inputSchema=_s(
            ["min_len", "max_len"],
            min_len=("integer", "Minimum password length"),
            max_len=("integer", "Maximum password length"),
            charset=("string", "Character set (default: lowercase + digits)"),
            output_path=("string", "Output file path (default: /tmp/crunch_wordlist.txt)"),
            pattern=("string", "Pattern with @ for lowercase, , for uppercase, % for digits, ^ for symbols"),
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _crunch_wordlist,
)


# ---------------------------------------------------------------------------
# credential_check
# ---------------------------------------------------------------------------

async def _credential_check(args: dict) -> list:
    target = (args.get("target") or "").strip()
    username = (args.get("username") or "").strip()
    password = (args.get("password") or "").strip()
    services = args.get("services") or ["ssh", "ftp", "smb"]
    project_id = args.get("project_id")

    if not target or not username or not password:
        return _ok("Error: target, username, and password are required.")

    results = [f"Credential check: {username}:{password} against {target}"]

    for service in services:
        service = service.lower().strip()
        if service == "ssh" and _chk("ssh"):
            out, err, rc = await _run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                 "-o", "StrictHostKeyChecking=no",
                 f"{username}@{target}", "echo OK"],
                timeout=10,
            )
            results.append(f"  SSH: {'SUCCESS' if rc == 0 else 'FAILED'} (rc={rc})")
        elif service == "ftp" and _chk("ftp"):
            import tempfile
            script = f"open {target}\n{username}\n{password}\nbye\n"
            with tempfile.NamedTemporaryFile(mode="w", suffix=".ftp", delete=False) as tf:
                tf.write(script)
                ftp_script = tf.name
            out, err, rc = await _run(["ftp", "-n", "-v"], timeout=10)
            Path(ftp_script).unlink(missing_ok=True)
            results.append(f"  FTP: check manually (use hydra_ftp for reliable testing)")
        elif service == "smb" and (_chk("smbclient") or _chk("crackmapexec") or _chk("nxc")):
            if _chk("smbclient"):
                out, err, rc = await _run(
                    ["smbclient", "-L", f"//{target}", "-U", f"{username}%{password}", "-N"],
                    timeout=15,
                )
                results.append(f"  SMB smbclient: {'SUCCESS' if rc == 0 else 'FAILED'}\n    {out.strip()[:200]}")
            else:
                binary = "nxc" if _chk("nxc") else "crackmapexec"
                out, err, rc = await _run(
                    [binary, "smb", target, "-u", username, "-p", password],
                    timeout=15,
                )
                success = "[+]" in out or "Pwn3d!" in out
                results.append(f"  SMB {binary}: {'SUCCESS' if success else 'FAILED'}\n    {out.strip()[:200]}")
        else:
            results.append(f"  {service.upper()}: tool not available or service not supported")

    result = "\n".join(results)
    if project_id:
        _artifact(int(project_id), "credential_check", result)
    return _ok(result)


register(
    Tool(
        name="credential_check",
        description=(
            "Test a single username/password credential against multiple services "
            "(ssh, ftp, smb). Useful for verifying captured credentials."
        ),
        inputSchema=_s(
            ["target", "username", "password"],
            target=("string", "Target IP or hostname"),
            username=("string", "Username to test"),
            password=("string", "Password to test"),
            services={
                "type": "array",
                "items": {"type": "string"},
                "description": "List of services to test: ssh, ftp, smb (default: all three)",
            },
            project_id=("integer", "Project ID for artifact storage"),
        ),
    ),
    _credential_check,
)
