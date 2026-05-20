"""
execute_command — general-purpose shell execution with audit trail.
Claude must call approve_intent(SCAN_ACTIVE or RUN_EXPLOIT) BEFORE calling
this tool for any non-passive command. Passive read-only commands are exempt.
"""
import asyncio
import json
import time
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s
from ..db import get_db

WORKSPACE_ROOT = Path.home() / "penligent" / "projects"

_PASSIVE_PREFIXES = (
    "cat ", "ls ", "find ", "echo ", "head ", "tail ", "grep ", "wc ",
    "file ", "stat ", "which ", "type ", "id", "whoami", "hostname",
    "uname ", "df ", "du ", "env", "printenv", "pwd",
)


def _is_passive(cmd: str) -> bool:
    c = cmd.strip().lower()
    for p in _PASSIVE_PREFIXES:
        base = p.rstrip()
        if c == base or c.startswith(base + " ") or c.startswith(base + "\t"):
            return True
    return False


async def _execute_command(args: dict) -> list[TextContent]:
    command = args.get("command", "").strip()
    project_name = args.get("project_name", "").strip()
    project_id = args.get("project_id")
    timeout = min(int(args.get("timeout", 60)), 300)
    intent = args.get("intent", "")  # passed through from approve_intent result

    if not command:
        return _ok("Error: command is required.")

    # Determine working directory
    if project_name:
        cwd = str(WORKSPACE_ROOT / project_name / "workspace")
    else:
        cwd = "/tmp"

    started = int(time.time())
    try:
        Path(cwd).mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return _ok(f"Command timed out after {timeout}s.\n$ {command}")
        stdout = stdout_b.decode(errors="replace")[:16384]
        stderr = stderr_b.decode(errors="replace")[:4096]
        exit_code = proc.returncode
        status = "completed"
    except Exception as e:
        return _ok(f"Execution error: {e}\n$ {command}")

    ended = int(time.time())

    # Record in execution_results DB (best-effort)
    if project_id:
        try:
            async with get_db() as db:
                await db.execute(
                    """INSERT INTO execution_results
                       (project_id, tool_name, args_json, exit_code, status, started_at, ended_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (int(project_id), "execute_command",
                     json.dumps({"command": command, "intent": intent}),
                     exit_code, status, started, ended),
                )
                await db.commit()
        except Exception:
            pass

    lines = [f"$ {command}"]
    if stdout:
        lines.append(stdout.rstrip())
    if stderr:
        lines.append(f"[stderr]\n{stderr.rstrip()}")
    lines.append(f"[exit {exit_code}]")
    return _ok("\n".join(lines))


register(Tool(
    name="execute_command",
    description=(
        "Run a shell command in the project workspace. "
        "For active/destructive commands, call approve_intent first. "
        "Passive read-only commands (cat, ls, grep, find, id, whoami) are auto-approved. "
        "stdout is capped at 16 KB; stderr at 4 KB. Timeout max is 300 s."
    ),
    inputSchema=_s(
        ["command"],
        command=("string", "Shell command to execute (run in /bin/sh -c)"),
        project_name=("string", "Project name — sets the working directory to its workspace"),
        project_id=("integer", "Project DB ID for execution_results recording"),
        timeout=("integer", "Timeout in seconds (default 60, max 300)"),
        intent=("string", "Intent string returned by approve_intent (for audit trail)"),
    ),
), _execute_command)
