#!/bin/bash
set -e

INSTALL_DIR="/usr/lib/penlearn-local/mcp-server"
VENV="$INSTALL_DIR/.venv"
GUARD="/usr/lib/penlearn-local/scripts/agent-guard.py"

# Make sure the PreToolUse guard script is executable. tauri bundles it
# read-only by default; without +x the hook fires but exec fails silently.
if [ -f "$GUARD" ]; then
    chmod 755 "$GUARD"
fi

# ---------------------------------------------------------------------------
# 1. Create Python venv and install the MCP server package
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "penlearn-local: python3 not found — skipping MCP server setup" >&2
    exit 0
fi

# Ensure python3-venv is present (Debian splits it from base python3)
if ! python3 -m venv --help &>/dev/null 2>&1; then
    apt-get install -y python3-venv 2>/dev/null || true
fi

if ! python3 -m venv "$VENV"; then
    echo "penlearn-local: python3 -m venv failed — skipping MCP server setup" >&2
    exit 0
fi

# Non-fatal: requires internet access the first time
if ! "$VENV/bin/pip" install --quiet --no-input "$INSTALL_DIR"; then
    echo "penlearn-local: pip install failed (no internet?). Re-run manually:" >&2
    echo "  sudo $VENV/bin/pip install $INSTALL_DIR" >&2
fi

# ---------------------------------------------------------------------------
# 2. Add sudoers rule for passwordless openvpn (so VPN connect works without a
#    GUI password prompt every time)
# ---------------------------------------------------------------------------
SUDOERS_FILE="/etc/sudoers.d/penlearn-openvpn"
if [ ! -f "$SUDOERS_FILE" ]; then
    echo "%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
fi

# ---------------------------------------------------------------------------
# 3. Register the MCP server in the installing user's Claude Code settings
# ---------------------------------------------------------------------------

# Determine the real (non-root) user who invoked the installer
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    REAL_USER="$SUDO_USER"
elif [ -n "$PKEXEC_UID" ]; then
    REAL_USER=$(getent passwd "$PKEXEC_UID" | cut -d: -f1)
else
    # Fall back to finding the first human user (uid >= 1000)
    REAL_USER=$(getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1; exit}')
fi

if [ -z "$REAL_USER" ]; then
    echo "penlearn-local: could not determine installing user — skipping Claude settings update" >&2
    exit 0
fi

USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
CLAUDE_SETTINGS="$USER_HOME/.claude/settings.json"

mkdir -p "$USER_HOME/.claude"

python3 - "$CLAUDE_SETTINGS" "$VENV/bin/python" <<'PYEOF'
import json, sys, os

settings_path = sys.argv[1]
venv_python   = sys.argv[2]

try:
    with open(settings_path) as f:
        cfg = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    cfg = {}

cfg.setdefault("mcpServers", {})
cfg["mcpServers"]["penlearn-local"] = {
    "command": venv_python,
    "args": ["-m", "penlearn_mcp"]
}

with open(settings_path, "w") as f:
    json.dump(cfg, f, indent=2)

print(f"penlearn-local: registered MCP server in {settings_path}")
PYEOF

# Fix ownership so the user can write to their own settings
chown "$REAL_USER" "$CLAUDE_SETTINGS" 2>/dev/null || true
chown "$REAL_USER" "$USER_HOME/.claude" 2>/dev/null || true
