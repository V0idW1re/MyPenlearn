"""
Shared utilities for all penligent tool modules.
"""
import asyncio
import hashlib
import json
import shutil
import time
from pathlib import Path

from mcp.types import TextContent

from ..db import get_db

ARTIFACTS_DIR = Path.home() / ".local" / "share" / "penligent-local" / "artifacts"


# ---------------------------------------------------------------------------
# Binary availability
# ---------------------------------------------------------------------------

def _chk(name: str) -> bool:
    """Return True if `name` is found on PATH."""
    return shutil.which(name) is not None


def _need(name: str, hint: str = "") -> list[TextContent]:
    """Return a TextContent error if a required binary is missing."""
    msg = f"[TOOL_MISSING] {name} not found in PATH."
    if hint:
        msg += f" Install: {hint}"
    return [TextContent(type="text", text=msg)]


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

async def _run(
    cmd: list[str],
    timeout: int | None = 120,
    cwd: str | None = None,
    env: dict | None = None,
) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        t = f"{timeout}s" if timeout is not None else "unlimited"
        return "", f"Process timed out after {t}", -1
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


# ---------------------------------------------------------------------------
# Artifact storage
# ---------------------------------------------------------------------------

def _artifact(project_id: int, tool: str, content: str) -> str:
    """Save content to artifacts dir and return the file path."""
    base = ARTIFACTS_DIR / str(project_id) / tool
    base.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    sha = hashlib.sha256(content.encode()).hexdigest()[:12]
    out_path = base / f"{ts}_{sha}.txt"
    out_path.write_text(content)
    return str(out_path)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _ok(text: str) -> list[TextContent]:
    """Wrap a string result in a TextContent list."""
    return [TextContent(type="text", text=text)]


# ---------------------------------------------------------------------------
# Schema builder
# ---------------------------------------------------------------------------

def _s(required: list[str] | None = None, **props) -> dict:
    """
    Build a JSON Schema object dict.

    Each keyword argument: name=(type_str, description_str)
    Example:
        _s(["target"], target=("string", "IP or hostname"), port=("integer", "Port number"))
    """
    properties: dict[str, dict] = {}
    for name, spec in props.items():
        if isinstance(spec, tuple) and len(spec) == 2:
            type_str, desc = spec
            properties[name] = {"type": type_str, "description": desc}
        else:
            properties[name] = spec  # allow raw dicts too
    schema: dict = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


# ---------------------------------------------------------------------------
# Scan-level helpers shared by recon.py and scanner.py
# ---------------------------------------------------------------------------

async def _run_subprocess(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Run an external process; return (stdout, stderr, returncode)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return "", f"Process timed out after {timeout}s", -1
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


async def _save_artifact(
    project_id: int, tool: str, stdout: str, stderr: str
) -> tuple[str, str, str]:
    """Save stdout/stderr to artifact files; return (out_path, err_path, sha256)."""
    base = ARTIFACTS_DIR / str(project_id) / tool
    base.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    out_path = base / f"{ts}.stdout"
    err_path = base / f"{ts}.stderr"
    out_path.write_text(stdout)
    err_path.write_text(stderr)
    sha = hashlib.sha256(stdout.encode()).hexdigest()
    return str(out_path), str(err_path), sha


async def _record_execution(
    project_id: int,
    tool_name: str,
    args: dict,
    stdout_path: str,
    stderr_path: str,
    exit_code: int,
    artifact_hash: str,
) -> int:
    """Insert an execution_results row and return its rowid."""
    now = int(time.time())
    async with get_db() as db:
        cur = await db.execute(
            """INSERT INTO execution_results
               (project_id, tool_name, args_json, stdout_path, stderr_path,
                exit_code, status, started_at, ended_at, artifact_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                project_id,
                tool_name,
                json.dumps(args),
                stdout_path,
                stderr_path,
                exit_code,
                "success" if exit_code == 0 else "error",
                now,
                now,
                artifact_hash,
            ),
        )
        await db.commit()
        return cur.lastrowid
