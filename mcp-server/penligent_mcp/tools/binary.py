"""
Binary analysis, reverse engineering, and forensics tools.
Includes: gdb, radare2, binwalk, ropgadget, checksec, xxd, strings, objdump,
ghidra (headless), pwntools, volatility, volatility3, foremost, steghide,
exiftool, hashpump.
"""
import os
import shutil
import tempfile

from mcp.types import Tool

from .register_all import register
from ._helpers import _run_subprocess, _save_artifact, _record_execution


async def _persist(project_id, tool_name: str, args: dict, stdout: str, stderr: str, exit_code: int):
    if project_id:
        out_p, err_p, sha = await _save_artifact(int(project_id), tool_name, stdout, stderr)
        await _record_execution(int(project_id), tool_name, args, out_p, err_p, exit_code, sha)


# ---------------------------------------------------------------------------
# checksec  (binary security feature check)
# ---------------------------------------------------------------------------

async def _checksec(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary path is required."
    if not shutil.which("checksec"):
        return "Error: checksec not found in PATH. Install: apt install checksec"

    cmd = ["checksec", f"--file={binary}"]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=30)
    await _persist(project_id, "checksec", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"checksec completed for {binary}."


register(
    Tool(
        name="checksec",
        description="Check binary security features: RELRO, stack canary, NX, PIE, RPATH, Fortify. Essential first step in binary exploitation analysis.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary file"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _checksec,
)


# ---------------------------------------------------------------------------
# xxd_hexdump  (hex dump of a file)
# ---------------------------------------------------------------------------

async def _xxd_hexdump(args: dict) -> str:
    file_path = (args.get("file_path") or "").strip()
    offset = str(args.get("offset", 0))
    length = str(args.get("length", "")).strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not file_path:
        return "Error: file_path is required."

    cmd = ["xxd", "-s", offset]
    if length:
        cmd += ["-l", length]
    if extra:
        cmd += extra.split()
    cmd.append(file_path)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=30)
    await _persist(project_id, "xxd_hexdump", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No output from xxd for {file_path}."


register(
    Tool(
        name="xxd_hexdump",
        description="Hex dump a file with xxd. View raw bytes, patch files, or convert binary to hex for analysis.",
        inputSchema={
            "type": "object",
            "required": ["file_path"],
            "properties": {
                "file_path": {"type": "string", "description": "Path to file"},
                "offset": {"type": "integer", "description": "Start offset in bytes (default: 0)"},
                "length": {"type": "integer", "description": "Number of bytes to dump (default: all)"},
                "additional_args": {"type": "string", "description": "Extra xxd flags (e.g. '-r' to reverse/patch)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _xxd_hexdump,
)


# ---------------------------------------------------------------------------
# objdump_analyze  (disassemble / dump sections of binary)
# ---------------------------------------------------------------------------

async def _objdump_analyze(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    disassemble = bool(args.get("disassemble", True))
    section = (args.get("section") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary is required."

    cmd = ["objdump"]
    if disassemble:
        cmd.append("-d")
    else:
        cmd.append("-x")
    if section:
        cmd += ["-j", section]
    if extra:
        cmd += extra.split()
    cmd.append(binary)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
    await _persist(project_id, "objdump_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout[:8000] + ("\n... (truncated)" if len(stdout) > 8000 else "") if stdout else stderr


register(
    Tool(
        name="objdump_analyze",
        description="Disassemble a binary or dump section headers with objdump. Use for static analysis of ELF/PE files without a full RE environment.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary file"},
                "disassemble": {"type": "boolean", "description": "Disassemble code sections (default: true). Set false to dump headers only."},
                "section": {"type": "string", "description": "Specific section to dump (e.g. '.text', '.data')"},
                "additional_args": {"type": "string", "description": "Extra objdump flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _objdump_analyze,
)


# ---------------------------------------------------------------------------
# binwalk_analyze  (firmware / file embedded content analysis)
# ---------------------------------------------------------------------------

async def _binwalk_analyze(args: dict) -> str:
    file_path = (args.get("file_path") or "").strip()
    extract = bool(args.get("extract", False))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not file_path:
        return "Error: file_path is required."
    if not shutil.which("binwalk"):
        return "Error: binwalk not found in PATH. Install: apt install binwalk"

    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    if extra:
        cmd += extra.split()
    cmd.append(file_path)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
    await _persist(project_id, "binwalk_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Binwalk found no embedded content in {file_path}."


register(
    Tool(
        name="binwalk_analyze",
        description="Analyze firmware or files for embedded content with Binwalk. Detects and optionally extracts embedded file systems, kernels, and other artifacts.",
        inputSchema={
            "type": "object",
            "required": ["file_path"],
            "properties": {
                "file_path": {"type": "string", "description": "Path to firmware or binary file"},
                "extract": {"type": "boolean", "description": "Extract detected files (default: false)"},
                "additional_args": {"type": "string", "description": "Extra binwalk flags (e.g. '-M' for recursive, '-A' for architecture scan)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _binwalk_analyze,
)


# ---------------------------------------------------------------------------
# ropgadget_search  (ROP chain building)
# ---------------------------------------------------------------------------

async def _ropgadget_search(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    only = (args.get("only") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary is required."
    if not shutil.which("ROPgadget"):
        return "Error: ROPgadget not found in PATH. Install: pip install ROPgadget"

    cmd = ["ROPgadget", "--binary", binary]
    if only:
        cmd += ["--only", only]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
    await _persist(project_id, "ropgadget_search", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    lines = stdout.splitlines()
    summary = "\n".join(lines[-20:]) if len(lines) > 20 else stdout
    return f"Total gadgets: ~{len(lines)}\n\nSample/tail output:\n{summary}" if stdout else stderr


register(
    Tool(
        name="ropgadget_search",
        description="Find ROP gadgets in a binary with ROPgadget. Used for building Return-Oriented Programming chains to bypass NX/DEP protections.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary file"},
                "only": {"type": "string", "description": "Filter gadget types (e.g. 'pop|ret', 'mov|jmp')"},
                "additional_args": {"type": "string", "description": "Extra ROPgadget flags (e.g. '--rop', '--jop', '--chain')"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _ropgadget_search,
)


# ---------------------------------------------------------------------------
# gdb_analyze  (GDB batch mode analysis)
# ---------------------------------------------------------------------------

async def _gdb_analyze(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    commands = (args.get("commands") or "").strip()
    script_file = (args.get("script_file") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary is required."
    if not commands and not script_file:
        return "Error: commands or script_file is required for batch GDB analysis."
    if not shutil.which("gdb"):
        return "Error: gdb not found in PATH. Install: apt install gdb"

    tmp_path = None
    try:
        if commands and not script_file:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(commands)
                tmp_path = f.name
            script_file = tmp_path

        cmd = ["gdb", "-batch", "-x", script_file, binary]
        if extra:
            cmd += extra.split()

        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=60)
        await _persist(project_id, "gdb_analyze", args, stdout, stderr, exit_code)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if exit_code == -1:
        return stderr
    return stdout or stderr or "GDB produced no output."


register(
    Tool(
        name="gdb_analyze",
        description="Batch GDB analysis of a binary. Run GDB commands non-interactively: disassemble functions, inspect memory, check protections. Pair with PEDA/GEF if installed.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary to analyze"},
                "commands": {"type": "string", "description": "GDB commands to run (newline-separated, e.g. 'info functions\\ndisas main')"},
                "script_file": {"type": "string", "description": "Path to existing GDB script file"},
                "additional_args": {"type": "string", "description": "Extra GDB flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _gdb_analyze,
)


# ---------------------------------------------------------------------------
# radare2_analyze  (r2 static/dynamic analysis)
# ---------------------------------------------------------------------------

async def _radare2_analyze(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    commands = (args.get("commands") or "aaa;pdf @main").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary is required."
    if not shutil.which("r2"):
        return "Error: r2 (radare2) not found in PATH. Install: apt install radare2"

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".r2", delete=False) as f:
            f.write(commands)
            tmp_path = f.name

        cmd = ["r2", "-q", "-i", tmp_path]
        if extra:
            cmd += extra.split()
        cmd.append(binary)

        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
        await _persist(project_id, "radare2_analyze", args, stdout, stderr, exit_code)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if exit_code == -1:
        return stderr
    return stdout or stderr or "Radare2 produced no output."


register(
    Tool(
        name="radare2_analyze",
        description="Binary analysis with Radare2 (r2). Run r2 commands in quiet mode for disassembly, function analysis, string extraction, and vulnerability hunting.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary to analyze"},
                "commands": {"type": "string", "description": "r2 commands (semicolon-separated, default: 'aaa;pdf @main')"},
                "additional_args": {"type": "string", "description": "Extra r2 flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _radare2_analyze,
)


# ---------------------------------------------------------------------------
# ghidra_analyze  (headless Ghidra analysis)
# ---------------------------------------------------------------------------

async def _ghidra_analyze(args: dict) -> str:
    binary = (args.get("binary") or "").strip()
    project_name = (args.get("project_name") or "penligent_re").strip()
    script_file = (args.get("script_file") or "").strip()
    analysis_timeout = int(args.get("analysis_timeout", 300))
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not binary:
        return "Error: binary is required."
    if not shutil.which("analyzeHeadless"):
        return "Error: analyzeHeadless (Ghidra headless) not found in PATH. Ensure Ghidra is installed and analyzeHeadless is on PATH."

    project_dir = f"/tmp/ghidra_projects/{project_name}"
    os.makedirs(project_dir, exist_ok=True)

    cmd = [
        "analyzeHeadless", project_dir, project_name,
        "-import", binary,
        "-deleteProject",
    ]
    if script_file:
        cmd += ["-postScript", script_file]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=analysis_timeout + 30)
    await _persist(project_id, "ghidra_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Ghidra headless analysis completed for {binary}."


register(
    Tool(
        name="ghidra_analyze",
        description="Headless Ghidra binary analysis. Imports and auto-analyzes a binary for decompilation, function identification, and cross-references. Use script_file for custom post-analysis scripts.",
        inputSchema={
            "type": "object",
            "required": ["binary"],
            "properties": {
                "binary": {"type": "string", "description": "Path to binary to analyze"},
                "project_name": {"type": "string", "description": "Ghidra project name (default: penligent_re)"},
                "script_file": {"type": "string", "description": "Post-analysis Ghidra script (Java or Python)"},
                "analysis_timeout": {"type": "integer", "description": "Analysis timeout seconds (default: 300)"},
                "additional_args": {"type": "string", "description": "Extra analyzeHeadless flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _ghidra_analyze,
)


# ---------------------------------------------------------------------------
# pwntools_run  (exploit development with pwntools)
# ---------------------------------------------------------------------------

async def _pwntools_run(args: dict) -> str:
    script_content = (args.get("script_content") or "").strip()
    target_binary = (args.get("target_binary") or "").strip()
    target_host = (args.get("target_host") or "").strip()
    target_port = int(args.get("target_port", 0))
    project_id = args.get("project_id")

    if not script_content:
        return "Error: script_content is required (Python pwntools exploit script)."
    if not shutil.which("python3"):
        return "Error: python3 not found."

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script_content)
            tmp_path = f.name

        cmd = ["python3", tmp_path]
        stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=120)
        await _persist(project_id, "pwntools_run", args, stdout, stderr, exit_code)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if exit_code == -1:
        return stderr
    return stdout or stderr or "pwntools script completed with no output."


register(
    Tool(
        name="pwntools_run",
        description="Run a pwntools exploit script. Provide a complete Python exploit using the pwntools library (pwn import). Supports local process and remote socket targets.",
        inputSchema={
            "type": "object",
            "required": ["script_content"],
            "properties": {
                "script_content": {"type": "string", "description": "Complete Python exploit script using pwntools"},
                "target_binary": {"type": "string", "description": "Path to target binary (for local exploitation)"},
                "target_host": {"type": "string", "description": "Remote host for network exploitation"},
                "target_port": {"type": "integer", "description": "Remote port for network exploitation"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _pwntools_run,
)


# ---------------------------------------------------------------------------
# volatility3_analyze  (memory forensics with Volatility 3)
# ---------------------------------------------------------------------------

async def _volatility3_analyze(args: dict) -> str:
    memory_file = (args.get("memory_file") or "").strip()
    plugin = (args.get("plugin") or "").strip()
    output_file = (args.get("output_file") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not memory_file:
        return "Error: memory_file is required."
    if not plugin:
        return "Error: plugin is required (e.g. 'windows.pslist', 'linux.bash', 'windows.dlllist')."

    vol_bin = shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility3")
    if not vol_bin:
        return "Error: Volatility 3 not found (tried: vol, vol.py, volatility3). Install: pip install volatility3"

    cmd = [vol_bin, "-f", memory_file, plugin]
    if output_file:
        cmd += ["-o", output_file]
    if extra:
        cmd += extra.split()

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "volatility3_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Volatility3 {plugin} completed with no output."


register(
    Tool(
        name="volatility3_analyze",
        description="Memory forensics with Volatility 3. Analyze RAM dumps for running processes, network connections, registry hives, bash history, and malware artifacts.",
        inputSchema={
            "type": "object",
            "required": ["memory_file", "plugin"],
            "properties": {
                "memory_file": {"type": "string", "description": "Path to memory dump file (.raw, .mem, .dmp)"},
                "plugin": {"type": "string", "description": "Volatility3 plugin (e.g. 'windows.pslist', 'windows.netscan', 'linux.bash', 'windows.dlllist')"},
                "output_file": {"type": "string", "description": "Save output to file"},
                "additional_args": {"type": "string", "description": "Extra plugin arguments"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _volatility3_analyze,
)


# ---------------------------------------------------------------------------
# foremost_carve  (file carving)
# ---------------------------------------------------------------------------

async def _foremost_carve(args: dict) -> str:
    input_file = (args.get("input_file") or "").strip()
    output_dir = (args.get("output_dir") or "/tmp/foremost_output").strip()
    file_types = (args.get("file_types") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not input_file:
        return "Error: input_file is required."
    if not shutil.which("foremost"):
        return "Error: foremost not found in PATH. Install: apt install foremost"

    os.makedirs(output_dir, exist_ok=True)

    cmd = ["foremost", "-o", output_dir]
    if file_types:
        cmd += ["-t", file_types]
    if extra:
        cmd += extra.split()
    cmd.append(input_file)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=300)
    await _persist(project_id, "foremost_carve", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return (stdout or stderr or f"Foremost carving completed.") + f"\nOutput directory: {output_dir}"


register(
    Tool(
        name="foremost_carve",
        description="File carving with Foremost. Recovers files from disk images, memory dumps, and captures based on file headers/footers. Useful in CTF forensics and incident response.",
        inputSchema={
            "type": "object",
            "required": ["input_file"],
            "properties": {
                "input_file": {"type": "string", "description": "Path to input file (disk image, memory dump, etc.)"},
                "output_dir": {"type": "string", "description": "Output directory for carved files (default: /tmp/foremost_output)"},
                "file_types": {"type": "string", "description": "File types to carve: jpg,png,gif,pdf,zip,exe (comma-separated, default: all)"},
                "additional_args": {"type": "string", "description": "Extra foremost flags"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _foremost_carve,
)


# ---------------------------------------------------------------------------
# steghide_analyze  (steganography analysis)
# ---------------------------------------------------------------------------

async def _steghide_analyze(args: dict) -> str:
    action = (args.get("action") or "extract").strip()
    cover_file = (args.get("cover_file") or "").strip()
    embed_file = (args.get("embed_file") or "").strip()
    passphrase = (args.get("passphrase") or "").strip()
    output_file = (args.get("output_file") or "").strip()
    project_id = args.get("project_id")

    if not cover_file:
        return "Error: cover_file is required."
    if action not in ("extract", "info", "embed"):
        return "Error: action must be 'extract', 'info', or 'embed'."
    if action == "embed" and not embed_file:
        return "Error: embed_file is required for embed action."
    if not shutil.which("steghide"):
        return "Error: steghide not found in PATH. Install: apt install steghide"

    if action == "extract":
        cmd = ["steghide", "extract", "-sf", cover_file, "-p", passphrase or ""]
        if output_file:
            cmd += ["-xf", output_file]
    elif action == "info":
        cmd = ["steghide", "info", cover_file, "-p", passphrase or ""]
    else:
        cmd = ["steghide", "embed", "-cf", cover_file, "-ef", embed_file, "-p", passphrase or ""]

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=30)
    await _persist(project_id, "steghide_analyze", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"Steghide {action} completed for {cover_file}."


register(
    Tool(
        name="steghide_analyze",
        description="Steganography analysis with Steghide. Extract hidden data from JPEG/BMP/WAV/AU cover files, get info about embedded content, or embed data. Common in CTF challenges.",
        inputSchema={
            "type": "object",
            "required": ["cover_file"],
            "properties": {
                "cover_file": {"type": "string", "description": "Path to cover file (JPEG, BMP, WAV, AU)"},
                "action": {"type": "string", "description": "Action: extract, info, or embed (default: extract)"},
                "passphrase": {"type": "string", "description": "Passphrase for extraction/embedding (empty string = no password)"},
                "output_file": {"type": "string", "description": "Output file for extracted data"},
                "embed_file": {"type": "string", "description": "File to embed (required for embed action)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _steghide_analyze,
)


# ---------------------------------------------------------------------------
# exiftool_extract  (file metadata extraction)
# ---------------------------------------------------------------------------

async def _exiftool_extract(args: dict) -> str:
    file_path = (args.get("file_path") or "").strip()
    output_format = (args.get("output_format") or "").strip()
    extra = (args.get("additional_args") or "").strip()
    project_id = args.get("project_id")

    if not file_path:
        return "Error: file_path is required."
    if not shutil.which("exiftool"):
        return "Error: exiftool not found in PATH. Install: apt install libimage-exiftool-perl"

    cmd = ["exiftool"]
    if output_format in ("json", "xml", "csv"):
        cmd.append(f"-{output_format}")
    if extra:
        cmd += extra.split()
    cmd.append(file_path)

    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=30)
    await _persist(project_id, "exiftool_extract", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or f"No metadata found in {file_path}."


register(
    Tool(
        name="exiftool_extract",
        description="Extract metadata from files with ExifTool. Supports images, PDFs, documents, audio, and video. Reveals GPS coordinates, camera info, software, author, and timestamps.",
        inputSchema={
            "type": "object",
            "required": ["file_path"],
            "properties": {
                "file_path": {"type": "string", "description": "Path to file (image, PDF, document, etc.)"},
                "output_format": {"type": "string", "description": "Output format: json, xml, csv (default: text)"},
                "additional_args": {"type": "string", "description": "Extra exiftool flags (e.g. '-gps:all' for GPS tags only)"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _exiftool_extract,
)


# ---------------------------------------------------------------------------
# hashpump_attack  (hash length extension attack)
# ---------------------------------------------------------------------------

async def _hashpump_attack(args: dict) -> str:
    signature = (args.get("signature") or "").strip()
    data = (args.get("data") or "").strip()
    key_length = str(args.get("key_length", "")).strip()
    append_data = (args.get("append_data") or "").strip()
    project_id = args.get("project_id")

    if not all([signature, data, key_length, append_data]):
        return "Error: signature, data, key_length, and append_data are all required."
    if not shutil.which("hashpump"):
        return "Error: hashpump not found in PATH. Install: apt install hashpump"

    cmd = ["hashpump", "-s", signature, "-d", data, "-k", key_length, "-a", append_data]
    stdout, stderr, exit_code = await _run_subprocess(cmd, timeout=30)
    await _persist(project_id, "hashpump_attack", args, stdout, stderr, exit_code)
    if exit_code == -1:
        return stderr
    return stdout or stderr or "Hashpump produced no output."


register(
    Tool(
        name="hashpump_attack",
        description="Hash length extension attack with HashPump. Exploits MD5/SHA1/SHA256 MACs computed as hash(secret||data) when you know the signature and data but not the key length.",
        inputSchema={
            "type": "object",
            "required": ["signature", "data", "key_length", "append_data"],
            "properties": {
                "signature": {"type": "string", "description": "Known hash/signature (hex)"},
                "data": {"type": "string", "description": "Known data that was hashed"},
                "key_length": {"type": "integer", "description": "Length of the secret key in bytes"},
                "append_data": {"type": "string", "description": "Data to append to forge a new valid signature"},
                "project_id": {"type": "integer"},
            },
        },
    ),
    _hashpump_attack,
)
