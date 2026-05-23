# Penligent Local

A self-hosted, autonomous penetration testing agent that runs entirely on your machine. Combines a Tauri 2 desktop app, a Svelte 5 UI, and a Python MCP server to give Claude Code a full suite of offensive security tools, a persistent knowledge base, and a structured engagement workflow — without any cloud dependency beyond Anthropic.

> Built on Kali, for Kali. One `.deb`, no manual setup.

---

## Quick start

```bash
# Grab the latest .deb
wget https://github.com/V0idW1re/MyPenteligent/releases/latest/download/penligent-local_0.1.11_amd64.deb

# Install (the post-install script handles MCP venv, sudoers, claude registration)
sudo dpkg -i penligent-local_0.1.11_amd64.deb

# Launch
penligent-local
```

First launch shows a 3-step welcome wizard. After that, press <kbd>Ctrl</kbd>+<kbd>K</kbd> to open the command palette or just type your objective into the chat.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Penligent Local (Tauri 2 desktop app)                  │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Engagements  │  │     Chat     │  │   Findings    │  │
│  │  (sidebar)   │  │   (center)   │  │  (P0–P4 rail) │  │
│  │              │  │  streaming   │  │   + Attack    │  │
│  │              │  │   markdown   │  │     Path      │  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
│        ┌───────────────────────────────────────┐        │
│        │  Workspace · Settings · CmdPalette    │        │
│        └───────────────────────────────────────┘        │
│                           │                             │
│                    Tauri IPC (Rust)                     │
│                           │                             │
│              Claude Code CLI subprocess                 │
│          --output-format stream-json                    │
│          --append-system-prompt <pentest rules>         │
│          --resume <session_id>                          │
│   model · token-usage · halt-channel · session state    │
└───────────────────────────┼─────────────────────────────┘
                            │ stdio
              ┌─────────────▼──────────────┐
              │   Claude Code (claude CLI)  │
              │   Auth: handled by claude   │
              └─────────────┬──────────────┘
                            │ MCP (stdio, per turn)
              ┌─────────────▼──────────────┐
              │   Penligent MCP Server      │
              │   (Python, 289 tools)       │
              │                             │
              │  Tool categories:           │
              │  • Recon (nmap, masscan…)   │
              │  • Web (49 probes incl.     │
              │    SSRF/XSS/SQLi/XXE/etc.)  │
              │  • Network attacks          │
              │  • Exploitation helpers     │
              │  • Post-exploit toolkit     │
              │  • Findings / workspace DB  │
              │  • Wiki / second brain      │
              │  • CVSS / MITRE / OWASP     │
              │  • HITL guardrails          │
              │  • HTB API integration      │
              └──────────────┬──────────────┘
                             │ reads
              ┌──────────────▼──────────────┐
              │ Wiki second-brain           │
              │ ~/.local/share/penligent-   │
              │  local/wiki/                │
              │   pages/methodology/*.md    │
              │   pages/modules/*.md        │
              │   raw/ (HTB Academy /       │
              │         course notes)       │
              └─────────────────────────────┘
```

---

## Features

### Agent runtime

- **Streaming chat** with Claude Code, full stream-json parsing — text, tool calls, errors, and model name surface as they arrive
- **Session continuity** — Claude resumes the same session via `--resume`; the system prompt enforces no-repeat rules so completed steps are never suggested again
- **Real-time token telemetry** in the status bar: `turn N · cache N · $X · session N · $Y` parsed from `result.usage`. Cache-read tokens highlighted green
- **Live model detection** — status bar shows the actual model the agent is using (e.g. `Sonnet 4.6`), parsed from `message.model` on every assistant event. No more hardcoded labels
- **GUI walkthrough mode** — when a GUI app is required (Burp, browser, VNC, MSF GUI), the agent stops and delivers numbered, sub-stepped manual instructions with expected visual feedback

### Knowledge base (second brain)

- **Persistent pentest wiki** at `~/.local/share/penligent-local/wiki/`
- **12 methodology pages bundled in the `.deb`** — evidence-first, compliance-mappings, waf-bypass, web-engagement-startup, osint-pre-engagement, auth-session-testing, broken-access-control, cloud-attack-surface, llm-attack-surface, document-parser-exploits, detection-blind-spots, pentest-engagement
- **System prompt mandates `wiki_query()`** before every task so the agent prefers your synthesized notes over its training data
- **Per-process LRU+TTL cache** on idempotent wiki and workspace reads — same `wiki_query()` within a turn doesn't re-execute file scans

### Safety & reliability

- **HITL guardrails** — agent calls `approve_intent` for any exploit / active scan / shell-spawn / file-write / OOB callback / flag-submit / machine-reset
- **MCP-down auto-halt** — if the MCP health check flips from ok → error, the running Claude turn is halted (no point firing tool calls into a dead server) and a blocking modal surfaces the error
- **Approval modal** — Esc defers, decision errors surface inline, scope/rate-limit/stop-conditions/time-window from the agent visible up front
- **Workspace persistence** — every finding, note, and file lives in `~/penligent/projects/<name>/workspace/` with a tamper-evident sha256 audit chain
- **Evidence-first contract** — agent only marks a finding `verified` when all five fields are populated: preconditions, control_request, test_request, observable_effect, retest_after_fix

### Interface

- **Three-panel layout** — engagements sidebar, streaming chat, live findings rail
- **Attack Path visualisation** — chat-side rail shows the agent's plan as a vertical chain of steps with status icons (✓ done / → in_progress / ○ pending); Workspace tab has a time-based horizontal kill-chain
- **Priority badges** — findings ranked P0 (critical) → P4 (info), severity summary bar at top
- **Command palette** — <kbd>Ctrl</kbd>+<kbd>K</kbd> opens a fuzzy-search palette covering every shortcut and quick action
- **Keyboard shortcuts** — see [Shortcuts](#shortcuts) below
- **Message virtualization** — only the last 100 messages mount in the DOM by default; "↑ Load 50 earlier messages" expands the window with scroll position preserved
- **Markdown renderer** — zero-dependency inline renderer with LRU cache: code fences with copy buttons, headings, lists, blockquotes, bold/italic/strikethrough, inline code
- **Manual-action callout** — GUI walkthrough completions are detected and rendered as a highlighted amber callout

### Integrations

- **OpenVPN** — browse and connect to `.ovpn` profiles from Settings or the wizard; passwordless sudo rule installed automatically
- **HackTheBox auto-approval** — when `HTB_APP_TOKEN` is set, machine start/stop/reset and flag submission proceed without confirmation prompts
- **VirtualBox / VMware compatible** — software rendering enabled automatically inside the binary; no manual configuration needed

---

## Requirements

- Kali Linux (tested on 2024.x and 2026.x — VMware and VirtualBox)
- [`claude` CLI](https://claude.ai/code) installed and logged in (`~/.local/bin/claude`)
- Python 3.11+ (for the MCP server — pre-installed on Kali)
- OpenVPN (`/usr/sbin/openvpn`) — optional, for HTB lab access

---

## Installation

### Option A — Install the pre-built `.deb` (recommended)

Download `penligent-local_0.1.11_amd64.deb` from the [latest release](https://github.com/V0idW1re/MyPenteligent/releases/latest), then:

```bash
sudo dpkg -i penligent-local_0.1.11_amd64.deb
penligent-local
```

The installer automatically:

- Installs the binary to `/usr/bin/penligent-local`
- Bundles the Python MCP server to `/usr/lib/penligent-local/mcp-server/`
- Ships 12 baseline methodology wiki pages under `penligent_mcp/data/methodology/` (seeded on first wiki tool call into `~/.local/share/penligent-local/wiki/pages/methodology/`)
- Creates a Python virtual environment and `pip install -e .` the MCP server package
- Registers the MCP server entry in `~/.claude/settings.json`
- Adds a narrow sudoers rule (`NOPASSWD: /usr/sbin/openvpn`) so VPN connects without a password prompt

No manual setup is needed after `dpkg -i`.

### Option B — Build from source

```bash
# 1. Install Rust + Tauri CLI
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install tauri-cli

# 2. Install Node dependencies
cd desktop/ui && npm install && cd ../..

# 3. Build the .deb
cd desktop && cargo tauri build

# 4. Install
sudo dpkg -i target/release/bundle/deb/penligent-local_0.1.11_amd64.deb
```

#### MCP server (source builds only)

The post-install script handles this automatically for `.deb` installs. If running from source without installing the `.deb`:

```bash
cd mcp-server
python3 -m venv .venv
.venv/bin/pip install -e .
```

Then add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "penligent-local": {
      "command": "/path/to/mcp-server/.venv/bin/python",
      "args": ["-m", "penligent_mcp"]
    }
  }
}
```

---

## Shortcuts

Every shortcut is also a command in the palette — discover via <kbd>Ctrl</kbd>+<kbd>K</kbd>, no memorisation required.

| Key | Action |
|-----|--------|
| <kbd>Ctrl</kbd>+<kbd>K</kbd> | Toggle command palette (fuzzy search across all commands) |
| <kbd>Ctrl</kbd>+<kbd>1</kbd> / <kbd>2</kbd> / <kbd>3</kbd> | Chat / Workspace / Settings tab |
| <kbd>Ctrl</kbd>+<kbd>,</kbd> | Jump to Settings |
| <kbd>Ctrl</kbd>+<kbd>J</kbd> | Focus chat input |
| <kbd>?</kbd> | Show keyboard shortcuts cheat sheet |
| <kbd>Esc</kbd> | Close any modal (palette, help, approval, MCP-down) |
| <kbd>Enter</kbd> | Send chat message |
| <kbd>Shift</kbd>+<kbd>Enter</kbd> | Newline in chat input |

Palette commands also include:

- VPN: reconnect last profile / disconnect
- MCP: re-run health check
- Clear chat for the current engagement
- Re-run first-run setup wizard

---

## Second-brain wiki

Every install ships with a baseline knowledge base under `~/.local/share/penligent-local/wiki/`. The agent reads from this **before every task** via the `wiki_query()` MCP tool.

### Layout

```
~/.local/share/penligent-local/wiki/
├── index.md                  ← top-level index of every page; first thing Claude reads
├── manifest.json             ← raw-source → page tracking (sha256-keyed)
├── log.md                    ← append-only ingest log
├── pages/                    ← Claude-owned synthesised pages
│   ├── methodology/          ← 12 baseline pages bundled with the .deb
│   ├── modules/              ← module/topic pages (Web Apps, Active Directory, etc.)
│   ├── techniques/           ← attack technique pages
│   └── machines/             ← per-machine writeups
└── raw/                      ← immutable original sources (your notes, HTB Academy markdown, etc.)
```

### MCP tools

The agent has nine wiki tools registered:

- `wiki_query(keywords)` — keyword-rank search across all pages
- `wiki_read_page(path)` — read one synthesised page
- `wiki_read_raw(path)` — read an original raw source
- `wiki_write_page(path, content)` — Claude can author / update pages
- `wiki_mark_ingested(raw_path, pages_created)` — mark a raw file as processed
- `wiki_ingest_all()` — return the queue of un-ingested raw files
- `wiki_status` — summary counts of ingested / pending / stale
- `wiki_log(entry)` — append an entry to `log.md`
- `wiki_lint` — find broken page links and orphan pages

### Adding your own knowledge

Drop any markdown file into `~/.local/share/penligent-local/wiki/raw/<topic>/<name>.md`, then in the chat tell the agent: "ingest the new files in raw/". Claude reads the schema, synthesises pages, updates the manifest and log, and the content is queryable on the next task.

---

## Checking MCP server health

The MCP server is **stdio-based** — Claude Code spawns it as a subprocess per turn, so it does not listen on any port. There is no HTTP endpoint to curl.

### From the app

The status bar at the bottom of the window shows a live dot:

| Dot | Meaning |
|---|---|
| Green — `MCP · 289 tools` | Server is healthy, tool count confirmed |
| Yellow (pulsing) | Health check in progress (runs every 15 s) |
| Red — `MCP · error` | Import failed — hover the dot for the error |

**MCP-down behaviour (v0.1.8+):** if the dot flips red while an agent turn is running, the turn is halted and a blocking modal appears with the error and a `Recheck now` button. On recovery the modal auto-dismisses.

### From a terminal

```bash
# Check Claude Code sees the server
claude mcp list

# Inside an interactive Claude Code session
/mcp

# Check the Python import (same probe the status dot uses)
/usr/lib/penligent-local/mcp-server/.venv/bin/python -c "import penligent_mcp; print('ok')"

# Check the process during an active agent turn
pgrep -a -f penligent_mcp
```

The MCP process only lives for the duration of a Claude turn — pgrep returning nothing between turns is normal.

---

## Configuration

### First-run wizard

Launches automatically on first start. Three optional steps:

1. **HTB API Token** — HTB profile → Settings → API → create app token. Used for REST API calls.
2. **OpenVPN sudoers** — installs the narrow `/etc/sudoers.d/penligent-openvpn` rule.
3. **Default VPN profile** — point at your `.ovpn` file.

Skip any step; re-run anytime via <kbd>Ctrl</kbd>+<kbd>K</kbd> → "Re-run first-run setup wizard".

### HTB App Token (later)

Settings → HackTheBox → API Token → paste → Save & Register.

Stored locally at `~/.local/share/penligent-local/config.json`, passed to Claude as `HTB_APP_TOKEN`, and used to register the HTB MCP server entry.

### VPN

Settings → OpenVPN → Browse for your `.ovpn` file (or paste the path) → Connect.

The passwordless sudo rule for OpenVPN is added automatically by the `.deb` installer. If you installed from source, add it manually once:

```bash
echo "%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" | \
  sudo tee /etc/sudoers.d/penligent-openvpn && \
  sudo chmod 440 /etc/sudoers.d/penligent-openvpn
```

Enable **auto-reconnect on drop** in Settings → OpenVPN to have the app reconnect using the most recently used profile if the tunnel dies.

---

## Usage

1. Launch `penligent-local`
2. Create an engagement in the left sidebar — pick HTB Machine, CTF, Bug Bounty, or Pentest
3. Set the target IP if applicable (set during creation, or right-click → Rename)
4. (HTB) connect VPN from Settings or the status bar
5. Type your objective in the chat and press <kbd>Enter</kbd>
6. The agent enumerates, exploits, and documents findings automatically
7. When a GUI step is needed, follow the numbered walkthrough and reply when done
8. Findings appear in real-time in the right panel with P0–P4 priority
9. Attack path on the right rail tracks the agent's plan; Workspace tab has a time-scaled kill-chain
10. Say `done` or `generate report` to produce `exec-summary.md`, `fix-list.md`, and `controls.json` in `workspace/report/`

### Engagement kinds

| Kind | Auto-approve scope | Use case |
|------|---------------------|----------|
| **HTB Machine** | All offensive intents when `HTB_APP_TOKEN` is present | Lab boxes, training |
| **CTF Event** | Recon + dir-brute auto; exploit needs approval | Time-bound CTFs |
| **Bug Bounty** | All offensive intents need explicit approval | Public scope hunting |
| **Authorized Pentest** | All intents need approval + SOW reference in note | Client engagements |

---

## Troubleshooting

**MCP dot is red on launch.**
The Python venv is missing or broken. Reinstall the `.deb`, or check that the post-install script ran without errors:
```bash
sudo dpkg --configure penligent-local
ls /usr/lib/penligent-local/mcp-server/.venv/bin/python
```

**The MCP-down modal won't dismiss even after I fix the issue.**
Click `Recheck now`. If MCP is healthy the modal auto-dismisses. If not, the displayed error is the same one the periodic check sees — fix that.

**Status bar says `Claude · waiting…` forever.**
That's the placeholder shown before the first assistant response of a session. After your first message + Claude's reply, it switches to the real model name. If it never updates, check that Claude Code is logged in (`claude --version`).

**Tool calls fail with "module not found".**
The MCP venv was created against a different Python. Re-create it:
```bash
sudo /usr/lib/penligent-local/mcp-server/.venv/bin/pip install -e /usr/lib/penligent-local/mcp-server
```

**`Couldn't load findings.` red block in the findings panel.**
The DB schema is older than this build. Restart the app — `ensure_schema()` runs idempotent `ALTER TABLE` migrations on every launch.

**Wizard never appeared on first launch.**
The setup-complete flag was already set. Open the palette (<kbd>Ctrl</kbd>+<kbd>K</kbd>) → "Re-run first-run setup wizard".

**Long chat sessions feel sluggish.**
Past 100 messages, the chat windows to the latest 100. Click the dashed `↑ Load 50 earlier messages` button at the top to expand. Browser-level `Ctrl+F` only searches mounted DOM — use `workspace_search` via the agent to grep the persisted history.

**VPN reconnect doesn't work.**
Open Settings → OpenVPN. Make sure a profile is marked default (star icon). The auto-reconnect uses the most recent profile, falling back to the default.

**Status bar shows `MCP · error` but `claude mcp list` is happy.**
Hover the red dot for the exact error. Common causes: a Python syntax error in a custom MCP tool you added, a missing dependency after editing `pyproject.toml`, or the venv `python` pointing at a removed system Python.

---

## Data

| Path | Contents |
|------|----------|
| `~/.local/share/penligent-local/penligent.db` | Projects, findings, chat history, agent sessions, plans (SQLite WAL) |
| `~/.local/share/penligent-local/config.json` | HTB token, UI zoom, VPN auto-reconnect, setup_complete flag |
| `~/.local/share/penligent-local/artifacts/` | Raw tool stdout/stderr saved per execution |
| `~/.local/share/penligent-local/wiki/` | Second-brain: methodology pages, modules, raw sources, manifest |
| `~/penligent/projects/<name>/workspace/` | Per-engagement files, notes, evidence, scan output |
| `~/.claude/settings.json` | MCP server registration (Penligent + HTB) |
| `/etc/sudoers.d/penligent-openvpn` | Narrow passwordless sudo rule for OpenVPN only |

---

## Uninstall

### 1 — Remove the application

```bash
sudo dpkg -r penligent-local
```

This removes `/usr/bin/penligent-local`, `/usr/lib/penligent-local/`, and the desktop entry. The sudoers rule and user data are left behind on purpose.

### 2 — Remove the sudoers rule

```bash
sudo rm /etc/sudoers.d/penligent-openvpn
```

### 3 — Remove user data (optional)

```bash
# App database, HTB token, settings, tool output artifacts, wiki
rm -rf ~/.local/share/penligent-local/

# Per-engagement workspace files, notes, scan output, evidence
rm -rf ~/penligent/
```

### 4 — Remove the MCP server entry from Claude settings (optional)

```bash
# Open ~/.claude/settings.json and remove the "penligent-local" key under "mcpServers"
```

### 5 — Remove the Claude CLI (optional)

```bash
rm ~/.local/bin/claude
# Claude auth tokens and local config
rm -rf ~/.claude/
```

---

## Security notes

- No Anthropic API key required — Claude Code handles authentication
- No outbound connections except to Anthropic (Claude Code) and HTB (`labs.hackthebox.com`)
- All data stays on the local machine — no telemetry, no analytics
- Sudoers rule is scoped to `/usr/sbin/openvpn` only — **never** `NOPASSWD: ALL`
- HITL approve_intent guardrails surface dangerous operations to the user; the system prompt mandates them for every exploit / scan / shell / file-write / OOB / flag-submit / machine-reset
- The wiki second-brain is local-only; the agent is instructed to treat fetched tool output as data, not instructions (prompt-injection defence)
- Intended for use on a dedicated pentesting VM, not a daily-driver machine

---

## Changelog

### v0.1.11 (current)

Findings panel migration fix + README polish. `list_findings` on the Rust side queried `risk_items` columns (`impact`, `compliance_controls_json`, `remediation_json`, …) that only Python's MCP server's migration code added to the table — if the user opened the app before MCP ever connected to the DB, the SELECT failed, the silent `catch (_) {}` swallowed the error, and the panel showed "No findings yet." even when findings existed. Rust `ensure_schema()` now mirrors the same `ALTER TABLE` migrations Python runs, and the frontend surfaces any future schema-drift errors as a red block instead of an empty list. Discovered via a structured test pass with 5 seeded findings — see the screenshot trail referenced in commit `368e3c8`. The README also got a full polish pass (394 → 507 lines): new Quick Start, Shortcuts, Second-brain wiki, Troubleshooting sections, plus the Features list now reflects every v0.1.2–v0.1.10 feature instead of just the v0.1.0 set.

### v0.1.10

UI audit across all ten Svelte panels — seven concrete bugs fixed. `ApprovalModal` shows decide errors inline (was console-only); Esc defers the decision. `Sidebar` rename + delete surface errors inline (were silently swallowed); decorative "Save" item removed. `Settings` `.ovpn` path is editable (was read-only). `Findings` no longer crashes on null severity. `Workspace` notes save flushes synchronously on project switch / destroy (fast tab switches used to silently drop typing). Also: `risk_items` schema migrations mirrored on the Rust side so the Findings panel works even when the user opens the app before the MCP server has ever connected to the DB.

### v0.1.9

Real model label in the status bar. Was hardcoded `Sonnet 4.6` since v0.1.4 — now parsed from `message.model` on every Claude Code `assistant` stream-json event. Falls back to a placeholder before the first turn arrives. `fmtModel()` helper formats `claude-sonnet-4-5-20250929` into `Sonnet 4.5`; full id on hover.

### v0.1.8

MCP-down auto-halt + modal. When MCP health flips ok → error, the in-flight Claude turn is halted via a `claude_halt` Tauri command (oneshot channel + `tokio::select!` + `kill_on_drop`) and a blocking modal explains what happened. `Recheck now` button re-runs `pollMcpHealth` immediately. Auto-dismisses on recovery. The status-bar dot is unchanged — modal is additive.

### v0.1.7

`web.py` audit pass 2 — nine more bugs across eight probe functions. Critical: `graphql_probe` false-positive (`rc == 0` matched every successful curl, including 404s) fixed via real HTTP status capture. `file_upload_check` honours its `timeout` arg. `jwt_decode` no longer crashes on malformed headers. URL construction in `open_redirect_check`, `ssti_probe`, `lfi_probe`, `cmdi_probe`, `path_traversal`, `prototype_pollution` switched to the parser-aware `_build_url_with_param()`. Detection broadened in `lfi_probe` / `path_traversal` (cloud IMDS, php://filter source disclosure, Windows boot.ini). `cmdi_probe` time-based detection now compares to baseline latency. `ssti_probe` `[SAFE]` relabelled `[NO_MATCH]`.

### v0.1.6

First-run wizard polish. New Welcome step with bulleted overview. Back button on every step. Show/Hide on the HTB token field. `.ovpn` path editable (matches Settings). New Summary step with `✓` / `—` icons. Save errors render inline. `Ctrl+K` → "Re-run first-run setup wizard" command. `wzFinish()` collects errors instead of silently swallowing them.

### v0.1.5

`web.py` audit pass 1. 13 probe tools now honour their documented `timeout` arg (was hardcoded internally). `jwt_crack` is alg-aware (HS256/384/512) and fails non-HMAC tokens with a clear error pointing at alg-confusion attacks. SSRF / RFI URL construction via parser-aware helper. SSRF probe now detects cloud-metadata shapes as `[VULN]` instead of just reporting size. XXE probe gets `callback_host` arg + broader detection. Java deserialization probe actually delivers the payload and measures elapsed time vs the gadget's 5s sleep.

### v0.1.4

Token telemetry, message virtualization, command palette + shortcuts. Status bar now reads `Sonnet 4.6 · turn 1.9k · cache 1.8k · $0.0034 · session 12.4k · $0.18` with real values from Claude Code stream-json `result.usage` (was a `cost × 200000` approximation). Cache-read tokens highlighted green. Chat keeps only the last 100 messages in the DOM by default; older accessible via "↑ Load earlier" with scroll position preserved. <kbd>Ctrl</kbd>+<kbd>K</kbd> opens a fuzzy-search command palette covering tab navigation, focus chat input, VPN actions, MCP recheck. Power-user shortcuts: <kbd>Ctrl</kbd>+<kbd>1</kbd>/<kbd>2</kbd>/<kbd>3</kbd>, <kbd>Ctrl</kbd>+<kbd>,</kbd>, <kbd>Ctrl</kbd>+<kbd>J</kbd>, <kbd>?</kbd>.

### v0.1.3

Wiki bootstrap. 12 baseline methodology pages (evidence-first, compliance-mappings, waf-bypass, etc.) ship in the `.deb` under `penligent_mcp/data/methodology/` and seed into `~/.local/share/penligent-local/wiki/pages/methodology/` on first wiki tool call. Idempotent — never overwrites existing user edits. Closes the v0.1.2 carry-over where the trimmed system prompt routed to wiki pages that only existed on the maintainer's machine.

### v0.1.2

System prompt trim (-67%, ~5,900 → ~1,935 tokens per turn), chat-streaming perf (O(N²) → O(N), capped at 60 Hz; markdown LRU cache), MCP read caching (60s TTL, 64 entries per namespace for wiki/workspace reads). Bundle fixes: `cloud.py` and `binary.py` were imported by `register_all.py` but missing from the `.deb` — fresh installs of 0.1.1 silently failed to start the MCP server. Also added the new `wiki.py` and `_cache.py` modules to the bundle.

### v0.1.0

Initial release. Three-panel UI, HTB / VPN integration, MCP server with ~280 tools, SQLite-backed engagements with chat history. Various bootstrap fixes (VirtualBox software rendering, OpenVPN browse, VPN stuck-at-connecting, hardcoded `/home/kali` paths, rpc_users crash, fresh-install DB bootstrap).
