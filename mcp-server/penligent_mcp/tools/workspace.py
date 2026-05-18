"""
Workspace / file management tools.
Manages a per-project workspace under ~/penligent/projects/<name>/workspace/.
All paths are constrained to the workspace root (no path traversal).
"""
import getpass
import hashlib
import json
import os
import shutil
import time
import zipfile
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s

WORKSPACE_ROOT = Path.home() / "penligent" / "projects"


def _ws(project_name: str) -> Path:
    """Return workspace path for a project, creating it and evidence subdirs if needed."""
    p = WORKSPACE_ROOT / project_name / "workspace"
    p.mkdir(parents=True, exist_ok=True)
    for sub in ("evidence/http", "evidence/screenshots", "evidence/tokens", "report"):
        (p / sub).mkdir(parents=True, exist_ok=True)
    return p


def _safe_path(workspace: Path, relative: str) -> Path | None:
    """Resolve relative path within workspace; return None if it escapes."""
    try:
        resolved = (workspace / relative).resolve()
        resolved.relative_to(workspace.resolve())
        return resolved
    except (ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# workspace_ls
# ---------------------------------------------------------------------------

async def _workspace_ls(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    sub = args.get("path", ".")
    ws = _ws(project_name)
    target = _safe_path(ws, sub)
    if not target:
        return _ok("Error: path escapes workspace root.")
    if not target.exists():
        return _ok(f"Path does not exist: {sub}")
    if target.is_file():
        stat = target.stat()
        return _ok(f"{target.name}  {stat.st_size} bytes")
    lines = []
    for item in sorted(target.iterdir()):
        if item.is_dir():
            lines.append(f"  [DIR]  {item.name}/")
        else:
            lines.append(f"         {item.name}  ({item.stat().st_size} bytes)")
    return _ok(f"Workspace: {project_name}/{sub}\n" + ("\n".join(lines) if lines else "(empty)"))

register(Tool(
    name="workspace_ls",
    description="List files in a project's workspace directory.",
    inputSchema=_s(["project_name"],
        project_name=("string", "Project name (as shown in the sidebar)"),
        path=("string", "Relative sub-path within workspace (default: .)")),
), _workspace_ls)

# ---------------------------------------------------------------------------
# workspace_read
# ---------------------------------------------------------------------------

async def _workspace_read(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    path = args.get("path", "")
    max_bytes = int(args.get("max_bytes", 32768))
    ws = _ws(project_name)
    target = _safe_path(ws, path)
    if not target:
        return _ok("Error: path escapes workspace root.")
    if not target.exists():
        return _ok(f"File not found: {path}")
    if target.is_dir():
        return _ok(f"Error: {path} is a directory. Use workspace_ls.")
    data = target.read_bytes()[:max_bytes]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _ok(f"[binary file, {target.stat().st_size} bytes] hex: {data[:256].hex()}")
    truncated = len(data) < target.stat().st_size
    header = f"--- {project_name}/{path} ---\n"
    footer = f"\n[truncated at {max_bytes} bytes]" if truncated else ""
    return _ok(header + text + footer)

register(Tool(
    name="workspace_read",
    description="Read a file from a project's workspace.",
    inputSchema=_s(["project_name", "path"],
        project_name=("string", "Project name"),
        path=("string", "Relative path to file within workspace"),
        max_bytes=("integer", "Maximum bytes to return (default: 32768)")),
), _workspace_read)

# ---------------------------------------------------------------------------
# workspace_write
# ---------------------------------------------------------------------------

def _infer_kind(path: str) -> str:
    name = Path(path).name.lower()
    stem = Path(path).stem.lower()
    if "nda" in stem:
        return "nda"
    if stem.startswith("scope") or name == "scope.json":
        return "scope"
    if "machine_info" in stem or "machine-info" in stem:
        return "machine_info"
    if name.endswith(".pdf") or "report" in stem or "writeup" in stem:
        return "writeup"
    if stem.startswith("notes") or name == "notes.md":
        return "notes"
    return "reference"


async def _workspace_write(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    path = args.get("path", "")
    content = args.get("content", "")
    append = args.get("append", False)
    kind = args.get("kind") or _infer_kind(path)
    ws = _ws(project_name)
    target = _safe_path(ws, path)
    if not target:
        return _ok("Error: path escapes workspace root.")
    target.parent.mkdir(parents=True, exist_ok=True)
    if append and target.exists():
        existing = target.read_text(errors="replace")
        target.write_text(existing + content)
    else:
        target.write_text(content)

    sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

    # Track in workspace_files DB (best-effort — file write already succeeded)
    try:
        from ..db import get_db
        async with get_db() as db:
            row = await (await db.execute(
                "SELECT id FROM projects WHERE name=? ORDER BY created_at DESC LIMIT 1",
                (project_name,)
            )).fetchone()
            if row:
                project_id = row[0]
                await db.execute(
                    "DELETE FROM workspace_files WHERE project_id=? AND path=?",
                    (project_id, str(target)),
                )
                await db.execute(
                    "INSERT INTO workspace_files(project_id, filename, kind, path, sha256) VALUES(?,?,?,?,?)",
                    (project_id, Path(path).name, kind, str(target), sha256),
                )
                await db.commit()
    except Exception:
        pass

    if append:
        return _ok(f"Appended {len(content)} chars to {project_name}/{path} (total: {target.stat().st_size} bytes, sha256: {sha256[:16]}…)")
    return _ok(f"Written {len(content)} chars to {project_name}/{path} (sha256: {sha256[:16]}…)")

register(Tool(
    name="workspace_write",
    description="Write or append text content to a file in a project's workspace. Tracks the file in the workspace_files DB with sha256.",
    inputSchema=_s(["project_name", "path", "content"],
        project_name=("string", "Project name"),
        path=("string", "Relative file path within workspace"),
        content=("string", "Text content to write"),
        append=("boolean", "Append to existing file instead of overwriting (default: false)"),
        kind=("string", "File kind: nda|scope|machine_info|writeup|reference|notes (auto-inferred if omitted)")),
), _workspace_write)

# ---------------------------------------------------------------------------
# workspace_note
# ---------------------------------------------------------------------------

async def _workspace_note(args: dict) -> list[TextContent]:
    import time
    project_name = args.get("project_name", "")
    note = args.get("note", "")
    tag = args.get("tag", "")
    ws = _ws(project_name)
    notes_file = ws / "notes.md"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"\n## [{ts}]{(' [' + tag + ']') if tag else ''}\n{note}\n"
    existing = notes_file.read_text() if notes_file.exists() else "# Pentest Notes\n"
    notes_file.write_text(existing + entry)
    return _ok(f"Note appended to {project_name}/notes.md")

register(Tool(
    name="workspace_note",
    description="Append a timestamped note to the project's notes.md file.",
    inputSchema=_s(["project_name", "note"],
        project_name=("string", "Project name"),
        note=("string", "Note text to append"),
        tag=("string", "Optional tag for the note (e.g. 'recon', 'exploit', 'creds')")),
), _workspace_note)

# ---------------------------------------------------------------------------
# workspace_search
# ---------------------------------------------------------------------------

async def _workspace_search(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    pattern = args.get("pattern", "")
    case_sensitive = args.get("case_sensitive", False)
    ws = _ws(project_name)
    results = []
    flags = 0 if case_sensitive else 0x02  # re.IGNORECASE = 2
    import re
    for fpath in ws.rglob("*"):
        if fpath.is_file() and fpath.stat().st_size < 5_000_000:
            try:
                text = fpath.read_text(errors="replace")
                for i, line in enumerate(text.splitlines(), 1):
                    if re.search(pattern, line, flags):
                        rel = fpath.relative_to(ws)
                        results.append(f"{rel}:{i}: {line.strip()[:120]}")
                        if len(results) >= 200:
                            break
            except Exception:
                pass
        if len(results) >= 200:
            break
    if not results:
        return _ok(f"No matches for '{pattern}' in {project_name} workspace.")
    return _ok(f"Matches for '{pattern}' in {project_name} ({len(results)}):\n" + "\n".join(results))

register(Tool(
    name="workspace_search",
    description="Search for a regex pattern across all files in a project's workspace.",
    inputSchema=_s(["project_name", "pattern"],
        project_name=("string", "Project name"),
        pattern=("string", "Regex pattern to search for"),
        case_sensitive=("boolean", "Case-sensitive search (default: false)")),
), _workspace_search)

# ---------------------------------------------------------------------------
# workspace_download
# ---------------------------------------------------------------------------

async def _workspace_download(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    url = args.get("url", "")
    dest = args.get("dest", "")
    import urllib.request
    ws = _ws(project_name)
    filename = dest or url.split("/")[-1].split("?")[0] or "download"
    target = _safe_path(ws, filename)
    if not target:
        return _ok("Error: destination path escapes workspace root.")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penligent-local/0.1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        target.write_bytes(data)
        return _ok(f"Downloaded {len(data)} bytes → {project_name}/{filename}")
    except Exception as e:
        return _ok(f"Error downloading {url}: {e}")

register(Tool(
    name="workspace_download",
    description="Download a URL to the project workspace.",
    inputSchema=_s(["project_name", "url"],
        project_name=("string", "Project name"),
        url=("string", "URL to download"),
        dest=("string", "Destination filename in workspace (default: basename of URL)")),
), _workspace_download)

# ---------------------------------------------------------------------------
# scope_set
# ---------------------------------------------------------------------------

async def _scope_set(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    targets = args.get("targets", [])
    out_of_scope = args.get("out_of_scope", [])
    notes = args.get("notes", "")
    ws = _ws(project_name)
    scope = {
        "in_scope": targets if isinstance(targets, list) else [targets],
        "out_of_scope": out_of_scope if isinstance(out_of_scope, list) else [out_of_scope],
        "notes": notes,
    }
    (ws / "scope.json").write_text(json.dumps(scope, indent=2))
    return _ok(f"Scope saved for {project_name}: {len(scope['in_scope'])} in-scope, {len(scope['out_of_scope'])} out-of-scope targets.")

register(Tool(
    name="scope_set",
    description="Define the scope for a project (in-scope and out-of-scope targets).",
    inputSchema=_s(["project_name", "targets"],
        project_name=("string", "Project name"),
        targets=("array", "List of in-scope targets (IPs, CIDRs, domains)"),
        out_of_scope=("array", "List of out-of-scope targets"),
        notes=("string", "Scope notes or rules of engagement")),
), _scope_set)

# ---------------------------------------------------------------------------
# scope_check
# ---------------------------------------------------------------------------

async def _scope_check(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    target = args.get("target", "")
    ws = _ws(project_name)
    scope_file = ws / "scope.json"
    if not scope_file.exists():
        return _ok(f"No scope defined for {project_name}. Use scope_set first.")
    scope = json.loads(scope_file.read_text())
    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])
    # Simple substring/exact matching
    blocked = any(target == s or target.endswith("." + s) or s in target for s in out_of_scope)
    allowed = any(target == s or target.endswith("." + s) or s in target for s in in_scope)
    if blocked:
        return _ok(f"OUT OF SCOPE: {target} matches out-of-scope rules. DO NOT test.")
    if allowed:
        return _ok(f"IN SCOPE: {target} is authorized for testing.")
    return _ok(f"UNKNOWN: {target} does not match any scope rule. Verify manually before testing.")

register(Tool(
    name="scope_check",
    description="Check if a target IP or domain is in scope for a project.",
    inputSchema=_s(["project_name", "target"],
        project_name=("string", "Project name"),
        target=("string", "IP address or domain to check")),
), _scope_check)

# ---------------------------------------------------------------------------
# scope_list
# ---------------------------------------------------------------------------

async def _scope_list(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    ws = _ws(project_name)
    scope_file = ws / "scope.json"
    if not scope_file.exists():
        return _ok(f"No scope defined for {project_name}.")
    scope = json.loads(scope_file.read_text())
    lines = [f"Scope for {project_name}:"]
    lines.append("  In scope:")
    for t in scope.get("in_scope", []):
        lines.append(f"    + {t}")
    lines.append("  Out of scope:")
    for t in scope.get("out_of_scope", []):
        lines.append(f"    - {t}")
    if scope.get("notes"):
        lines.append(f"  Notes: {scope['notes']}")
    return _ok("\n".join(lines))

register(Tool(
    name="scope_list",
    description="Display the defined scope for a project.",
    inputSchema=_s(["project_name"],
        project_name=("string", "Project name")),
), _scope_list)

# ---------------------------------------------------------------------------
# workspace_zip
# ---------------------------------------------------------------------------

async def _workspace_zip(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    output_path = args.get("output_path", "")
    ws = _ws(project_name)
    if not output_path:
        import time
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_path = str(Path.home() / f"{project_name}_{ts}.zip")
    try:
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in ws.rglob("*"):
                if fpath.is_file():
                    zf.write(fpath, fpath.relative_to(ws.parent))
        size = Path(output_path).stat().st_size
        return _ok(f"Workspace zipped: {output_path} ({size} bytes)")
    except Exception as e:
        return _ok(f"Error creating zip: {e}")

register(Tool(
    name="workspace_zip",
    description="Zip the entire workspace for a project into a single archive for export.",
    inputSchema=_s(["project_name"],
        project_name=("string", "Project name"),
        output_path=("string", "Output zip file path (default: ~/project_timestamp.zip)")),
), _workspace_zip)

# ---------------------------------------------------------------------------
# audit_log — append a JSONL line to workspace/evidence/audit.log
# ---------------------------------------------------------------------------

async def _audit_log(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    tool_name = (args.get("tool_name") or "").strip()
    step = args.get("step", 0)
    tool_args = args.get("tool_args")
    exit_code = args.get("exit_code", 0)
    artifact_path = (args.get("artifact_path") or "").strip()
    sha256 = (args.get("sha256") or "").strip()
    cwd = (args.get("cwd") or os.getcwd()).strip()
    reviewer = (args.get("reviewer") or "").strip() or None

    if not project_name or not tool_name:
        return _ok("Error: project_name and tool_name are required.")

    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER", "unknown")

    ws = _ws(project_name)
    audit_path = ws / "evidence" / "audit.log"

    record = {
        "ts": int(time.time()),
        "project": project_name,
        "step": step,
        "tool": tool_name,
        "args": tool_args,
        "cwd": cwd,
        "user": user,
        "exit": exit_code,
        "artifact": artifact_path or None,
        "sha256": sha256 or None,
        "reviewer": reviewer,
    }
    with audit_path.open("a") as f:
        f.write(json.dumps(record) + "\n")

    return _ok(f"Audit log appended: {audit_path}\n{json.dumps(record)}")

register(Tool(
    name="audit_log",
    description=(
        "Append a JSONL audit record to workspace/evidence/audit.log. "
        "Call after every significant tool run with the artifact path and sha256 hash "
        "to build a tamper-evident evidence chain."
    ),
    inputSchema=_s(
        ["project_name", "tool_name"],
        project_name=("string", "Project name"),
        tool_name=("string", "Name of the tool that was run"),
        step=("integer", "Step number in the engagement sequence"),
        tool_args=("string", "JSON string of the arguments passed to the tool"),
        exit_code=("integer", "Exit code returned by the tool"),
        artifact_path=("string", "Path to the output artifact file"),
        sha256=("string", "SHA-256 hex digest of the artifact file"),
        cwd=("string", "Working directory when the tool ran (default: current dir)"),
        reviewer=("string", "Identity of the human reviewer who approved this step (optional)"),
    ),
), _audit_log)

# ---------------------------------------------------------------------------
# task_status — report current engagement phase, active tool, constraints
# ---------------------------------------------------------------------------

async def _task_status(args: dict) -> list[TextContent]:
    project_name = args.get("project_name", "")
    if not project_name:
        return _ok("Error: project_name is required.")

    ws = _ws(project_name)
    lines: list[str] = [f"Engagement Status: {project_name}", ""]

    # Read audit log to derive current step and last tool
    audit_path = ws / "evidence" / "audit.log"
    last_record: dict | None = None
    step_count = 0
    if audit_path.exists():
        entries = []
        for line in audit_path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        step_count = len(entries)
        if entries:
            last_record = entries[-1]

    lines.append(f"Steps logged: {step_count}")
    if last_record:
        last_ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(last_record.get("ts", 0)))
        lines.append(f"Last tool:    {last_record.get('tool', '?')}  (step {last_record.get('step', '?')})")
        lines.append(f"Last run:     {last_ts}")
        lines.append(f"Last exit:    {last_record.get('exit', '?')}")
        if last_record.get("artifact"):
            lines.append(f"Last artifact:{last_record['artifact']}")
    lines.append("")

    # Scope summary
    scope_file = ws / "scope.json"
    if scope_file.exists():
        try:
            scope = json.loads(scope_file.read_text())
            in_s = scope.get("in_scope", [])
            out_s = scope.get("out_of_scope", [])
            lines.append(f"Scope: {len(in_s)} in-scope, {len(out_s)} out-of-scope targets")
        except Exception:
            lines.append("Scope: (parse error)")
    else:
        lines.append("Scope: not set")
    lines.append("")

    # Report / findings summary
    report_dir = ws / "report"
    if (report_dir / "exec-summary.md").exists():
        lines.append("Report: exec-summary.md exists")
    if (report_dir / "fix-list.md").exists():
        lines.append("Report: fix-list.md exists")
    lines.append("")

    # Notes
    notes_file = ws / "notes.md"
    if notes_file.exists():
        note_lines = notes_file.read_text().splitlines()
        lines.append(f"Notes: {len(note_lines)} lines in notes.md")

    return _ok("\n".join(lines))

register(Tool(
    name="task_status",
    description=(
        "Report current engagement status: steps logged, last tool run, scope summary, "
        "and report file existence. Use to check progress before resuming a session."
    ),
    inputSchema=_s(["project_name"],
        project_name=("string", "Project name")),
), _task_status)
