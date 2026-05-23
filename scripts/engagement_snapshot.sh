#!/usr/bin/env bash
# engagement_snapshot.sh — gather everything I need to audit a Penligent engagement
# into a single tarball. Run AFTER an engagement is over (or whenever you want
# me to look at the current state).
#
# Usage:
#   scripts/engagement_snapshot.sh <project_name>
#   scripts/engagement_snapshot.sh Kobold
#
# Output: /tmp/penligent-snapshot-<project>-<timestamp>.tar.gz
set -e

PROJECT="${1:-}"
if [ -z "$PROJECT" ]; then
  echo "Usage: $0 <project_name>"
  echo ""
  echo "Existing projects:"
  ls -1 ~/penligent/projects/ 2>/dev/null || echo "  (none yet)"
  exit 1
fi

WORKSPACE_DIR="$HOME/penligent/projects/$PROJECT/workspace"
if [ ! -d "$WORKSPACE_DIR" ]; then
  echo "No workspace found at $WORKSPACE_DIR"
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
SNAP_ROOT="/tmp/penligent-snapshot-$PROJECT-$TS"
mkdir -p "$SNAP_ROOT"

# 1. Full workspace (evidence/, report/, notes, audit.log, etc.)
cp -r "$WORKSPACE_DIR" "$SNAP_ROOT/workspace"

# 2. Chat transcript + agent sessions from the Tauri sqlite db
PENLIGENT_DB="$HOME/.local/share/penligent-local/penligent.db"
if [ -f "$PENLIGENT_DB" ]; then
  sqlite3 "$PENLIGENT_DB" ".dump chat_messages" > "$SNAP_ROOT/chat_messages.sql" 2>/dev/null || true
  sqlite3 "$PENLIGENT_DB" ".dump agent_sessions" > "$SNAP_ROOT/agent_sessions.sql" 2>/dev/null || true
  sqlite3 "$PENLIGENT_DB" ".dump agent_messages" > "$SNAP_ROOT/agent_messages.sql" 2>/dev/null || true
  sqlite3 "$PENLIGENT_DB" ".dump findings" > "$SNAP_ROOT/findings.sql" 2>/dev/null || true
  sqlite3 "$PENLIGENT_DB" ".dump execution_results" > "$SNAP_ROOT/execution_results.sql" 2>/dev/null || true
  # Also a human-readable findings export
  sqlite3 "$PENLIGENT_DB" \
    "SELECT id, name, severity, verify_status, attack_chain_position, ttp_category, impact FROM findings WHERE project_id IN (SELECT id FROM projects WHERE name = '$PROJECT');" \
    > "$SNAP_ROOT/findings.txt" 2>/dev/null || true
fi

# 3. Active running app log if present
[ -f /tmp/penligent-local.log ] && cp /tmp/penligent-local.log "$SNAP_ROOT/app.log"

# 4. Versions snapshot so I know exactly what build behaved this way
{
  echo "=== Penligent version ==="
  dpkg -l penligent-local 2>/dev/null | tail -1
  echo ""
  echo "=== Git commit ==="
  cd /home/kali/penligent-local 2>/dev/null && git rev-parse HEAD 2>/dev/null
  echo ""
  echo "=== Claude version ==="
  ~/.local/bin/claude --version 2>/dev/null || echo "(claude CLI not on PATH)"
  echo ""
  echo "=== MCP tool count ==="
  /usr/lib/penligent-local/mcp-server/.venv/bin/python -c "from penligent_mcp.tools.register_all import get_tool_definitions; print(len(get_tool_definitions()))" 2>/dev/null
} > "$SNAP_ROOT/versions.txt"

# 5. User notes file (you can edit this after capture)
cat > "$SNAP_ROOT/USER_NOTES.md" <<'EOF'
# Engagement notes — please fill in before sending to Claude

## Outcome
- [ ] Got a foothold
- [ ] Got user
- [ ] Got root
- [ ] Submitted flag(s)

## What worked well
(e.g. "Ctrl+K palette was great", "wiki_query gave me the right answer for X")

## What felt slow / wrong / surprising
(e.g. "Got stuck on Y for 6 turns", "Agent kept retrying a failed tool",
"Status bar token count jumped suddenly to 50k on turn 12 — why?")

## Specific turns to look at
(turn numbers or rough timestamps where something interesting happened)

## Open questions
(things you'd like me to investigate when I read this)
EOF

# 6. Tarball it
TAR="/tmp/penligent-snapshot-$PROJECT-$TS.tar.gz"
tar czf "$TAR" -C /tmp "$(basename "$SNAP_ROOT")"
rm -rf "$SNAP_ROOT"

echo ""
echo "Snapshot saved: $TAR"
echo ""
echo "Size: $(du -h "$TAR" | cut -f1)"
echo ""
echo "Now:"
echo "  1. Edit USER_NOTES.md inside the tarball (or extract, edit, re-tar)."
echo "  2. Tell Claude: 'Audit the engagement: $TAR'"
