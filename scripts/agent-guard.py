#!/usr/bin/env python3
# Penligent agent guard — Claude Code PreToolUse hook.
#
# Reads tool_use payload from stdin and refuses commands that would
# terminate or remove infrastructure the operator depends on (Claude
# Code itself, the Penligent desktop app, the Penligent MCP server,
# the HTB MCP registration, the OpenVPN tunnel, or any config files
# the app relies on).
#
# Exit 0 → allow. Exit 2 → block (stderr is shown to the model so it
# learns the boundary). Any other exit or parse error → allow (we fail
# open so a malformed payload never strands the agent).

import json
import os
import re
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(0)

tool_name  = payload.get("tool_name", "")
tool_input = payload.get("tool_input") or {}
if tool_name != "Bash":
    sys.exit(0)

cmd = tool_input.get("command", "")
if not isinstance(cmd, str) or not cmd.strip():
    sys.exit(0)

HOME = os.path.expanduser("~")

# Path fragments that, when targeted by destructive ops, would brick the app.
# We accept both the fully-expanded path and the `~/...` shorthand because the
# regex sees the raw command string before bash expands it. Same applies to
# `$HOME/...` (rare but possible).
def _path_variants(rel):
    return [f"{HOME}/{rel}", f"~/{rel}", f"$HOME/{rel}"]

PROTECTED_PATHS = [
    "/usr/lib/penligent-local",
    *_path_variants(".local/share/penligent-local"),
    *_path_variants(".claude.json"),
    *_path_variants(".claude/"),          # everything under ~/.claude/
    *_path_variants(".claude/settings.json"),
    *_path_variants(".local/bin/claude"),
]

# Process names whose termination would kill the agent's own tool surface
# or its connectivity to the target.
PROTECTED_PROCS = [
    "claude",
    "penligent-local",
    "penligent_mcp",
    "penligent-mcp",
    "openvpn",
]

# Each rule: (regex, human reason). Matching ANY rule blocks the command.
RULES = []

# 1. kill / pkill / killall targeting infrastructure processes
proc_alt = "|".join(re.escape(p) for p in PROTECTED_PROCS)
RULES.append((
    re.compile(rf"\b(kill|pkill|killall)\b[^|;&]*\b({proc_alt})\b", re.IGNORECASE),
    "Refusing to kill an infrastructure process Penligent depends on "
    "(Claude Code, Penligent MCP, OpenVPN tunnel, or the desktop app).",
))

# 2. rm -r / rm -rf / rm -f / rm --recursive on protected paths
path_alt = "|".join(re.escape(p) for p in PROTECTED_PATHS)
RULES.append((
    re.compile(
        rf"\brm\b(?:\s+-{{1,2}}[a-zA-Z-]*)*\s+[^|;&]*({path_alt})",
        re.IGNORECASE,
    ),
    "Refusing to delete a path Penligent or Claude Code depends on.",
))

# 3. claude mcp remove of the servers we actually use
RULES.append((
    re.compile(
        r"\bclaude\b\s+mcp\s+(?:remove|rm)\b[^|;&]*\b(penligent-local|htb-mcp-ctf)\b",
        re.IGNORECASE,
    ),
    "Refusing to unregister an MCP server the agent depends on.",
))

# 4. systemctl stop/disable/mask OpenVPN
RULES.append((
    re.compile(r"\bsystemctl\b\s+(stop|disable|mask)\s+[^|;&]*openvpn", re.IGNORECASE),
    "Refusing to disable OpenVPN at the systemd layer — disconnect from the UI instead.",
))

# 5. Removing the sudoers rule (would break passwordless VPN start)
RULES.append((
    re.compile(r"\brm\b[^|;&]*/etc/sudoers\.d/penligent-openvpn", re.IGNORECASE),
    "Refusing to remove the Penligent OpenVPN sudoers rule.",
))

# 6. Removing/disabling the guard itself
RULES.append((
    re.compile(r"\b(rm|mv|chmod\s+0?00)\b[^|;&]*agent-guard\.(py|sh)", re.IGNORECASE),
    "Refusing to remove or disable the Penligent agent guard.",
))

# 7. chattr +i / chmod 000 on protected dirs — would lock the app out
RULES.append((
    re.compile(
        rf"\b(chmod\s+0?00|chattr\s+\+i)\b[^|;&]*({path_alt})",
        re.IGNORECASE,
    ),
    "Refusing to lock down a Penligent/Claude path that the app needs to write.",
))

# 8. Rewriting ~/.claude/settings.json wholesale (truncate, > redirect, tee >)
#    Targeted blocks; surgical jq/python edits via add/merge still work since
#    they don't match the redirect pattern.
_settings_targets = "|".join(
    re.escape(p) for p in (
        f"{HOME}/.claude/settings.json",
        f"{HOME}/.claude.json",
        "~/.claude/settings.json",
        "~/.claude.json",
        "$HOME/.claude/settings.json",
        "$HOME/.claude.json",
    )
)
RULES.append((
    re.compile(
        r"(>\s*|>>\s*|tee\s+(?:-[a-zA-Z-]*\s+)*)"
        rf"({_settings_targets})\b",
        re.IGNORECASE,
    ),
    "Refusing to overwrite Claude config files directly. "
    "Use `claude mcp add` or edit specific keys; do not redirect/tee over the whole file.",
))

for rx, reason in RULES:
    if rx.search(cmd):
        sys.stderr.write(
            f"penligent-guard: blocked. {reason}\n"
            f"Command: {cmd}\n"
            "If you genuinely need this, ask the operator to run it from the host shell.\n"
        )
        sys.exit(2)

sys.exit(0)
