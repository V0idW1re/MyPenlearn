#!/bin/bash
set -e

INSTALL_DIR="/usr/lib/penlearn-local/mcp-server"
SUDOERS_FILE="/etc/sudoers.d/penlearn-openvpn"

# ---------------------------------------------------------------------------
# 1. Remove the Python venv and any runtime-generated files that dpkg does
#    not track (created by post-install.sh and normal Python operation).
# ---------------------------------------------------------------------------
rm -rf "$INSTALL_DIR/.venv"
find "$INSTALL_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$INSTALL_DIR" -type d -name "*.egg-info"  -exec rm -rf {} + 2>/dev/null || true
find "$INSTALL_DIR" -name "*.pyc" -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Remove the sudoers rule installed by post-install.sh.
# ---------------------------------------------------------------------------
if [ -f "$SUDOERS_FILE" ]; then
    rm -f "$SUDOERS_FILE"
fi

# ---------------------------------------------------------------------------
# 3. Remove the MCP server entry from the installing user's Claude settings.
# ---------------------------------------------------------------------------
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    REAL_USER="$SUDO_USER"
elif [ -n "$PKEXEC_UID" ]; then
    REAL_USER=$(getent passwd "$PKEXEC_UID" | cut -d: -f1)
else
    REAL_USER=$(getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1; exit}')
fi

if [ -n "$REAL_USER" ]; then
    USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    CLAUDE_SETTINGS="$USER_HOME/.claude/settings.json"
    if [ -f "$CLAUDE_SETTINGS" ]; then
        python3 - "$CLAUDE_SETTINGS" <<'PYEOF'
import json, sys

settings_path = sys.argv[1]
try:
    with open(settings_path) as f:
        cfg = json.load(f)
    cfg.get("mcpServers", {}).pop("penlearn-local", None)
    with open(settings_path, "w") as f:
        json.dump(cfg, f, indent=2)
except Exception:
    pass
PYEOF
    fi
fi
