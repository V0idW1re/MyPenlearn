# Penligent Local

A self-hosted, autonomous penetration testing agent that runs entirely on your machine. Combines a Tauri 2 desktop app, a Svelte 5 UI, and a Python MCP server to give Claude Code a full suite of offensive security tools — without any cloud dependency beyond Anthropic.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Penligent Local (Tauri 2 desktop app)                  │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │ Engagements  │  │     Chat     │  │   Findings    │ │
│  │  (sidebar)   │  │   (center)   │  │  (P0–P4 rail) │ │
│  └──────────────┘  └──────────────┘  └───────────────┘ │
│                           │                             │
│                    Tauri IPC (Rust)                      │
│                           │                             │
│              Claude Code CLI subprocess                  │
│          --output-format stream-json                     │
│          --append-system-prompt <pentest rules>          │
│          --resume <session_id>                           │
└───────────────────────────┼─────────────────────────────┘
                            │ stdio
              ┌─────────────▼──────────────┐
              │   Claude Code (claude CLI)  │
              │   Auth: handled by claude   │
              └─────────────┬──────────────┘
                            │ MCP (stdio)
              ┌─────────────▼──────────────┐
              │   Penligent MCP Server      │
              │   (Python, 200+ tools)      │
              │                             │
              │  • HTB API (machines/flags) │
              │  • Nmap / masscan / ffuf    │
              │  • Exploitation helpers     │
              │  • Post-exploit toolkit     │
              │  • Findings / workspace DB  │
              │  • CVSS / MITRE / OWASP     │
              └─────────────────────────────┘
```

---

## Features

- **Three-panel UI** — Engagements list, streaming chat, live findings rail
- **Priority badges** — Findings ranked P0 (critical) → P4 (info) with colour-coded severity
- **Severity summary bar** — Instant P0·N P1·N P2·N counts at the top of the findings panel
- **Session continuity** — Claude resumes the same session with `--resume`; system prompt enforces no-repeat rules so completed steps are never suggested again
- **GUI walkthrough mode** — When a GUI app is required (Burp, browser, VNC), the agent stops and delivers numbered, sub-stepped manual instructions with expected visual feedback
- **OpenVPN integration** — Browse and connect to `.ovpn` profiles directly from Settings; passwordless sudo rule added automatically by the installer
- **HackTheBox auto-approval** — When `HTB_APP_TOKEN` is set, machine start/stop/reset and flag submission proceed without confirmation prompts
- **Workspace persistence** — Every finding, note, and file written to `~/penligent/projects/<name>/workspace/`; SQLite WAL-mode DB survives VM shutdowns
- **Markdown renderer** — Zero-dependency inline renderer: code fences with copy buttons, headings, lists, blockquotes, bold/italic/strikethrough, inline code
- **Manual-action callout** — GUI walkthrough completions are detected and rendered as a highlighted amber callout
- **VirtualBox compatible** — Software rendering enabled automatically inside the binary; no manual configuration needed

---

## Requirements

- Kali Linux (tested on 2024.x — VMware and VirtualBox)
- [`claude` CLI](https://claude.ai/code) installed and logged in (`~/.local/bin/claude`)
- Python 3.11+ (for the MCP server — pre-installed on Kali)
- OpenVPN (`/usr/sbin/openvpn`) — optional, for HTB lab access

---

## Installation

### Option A — Install the pre-built .deb (recommended)

Download `penligent-local_0.1.8_amd64.deb` from the [latest release](https://github.com/V0idW1re/MyPenteligent/releases/latest), then:

```bash
sudo dpkg -i penligent-local_0.1.8_amd64.deb
penligent-local
```

The installer automatically:

- Installs the binary to `/usr/bin/penligent-local`
- Bundles the Python MCP server to `/usr/lib/penligent-local/mcp-server/`
- Creates a Python virtual environment and installs the MCP server package
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
sudo dpkg -i target/release/bundle/deb/penligent-local_0.1.8_amd64.deb
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

## Checking MCP server health

The MCP server is **stdio-based** — Claude Code spawns it as a subprocess per turn, so it does not listen on any port. There is no HTTP endpoint to curl.

### From the app

The status bar at the bottom of the window shows a live dot:

| Dot | Meaning |
|---|---|
| Green — `MCP · 280 tools` | Server is healthy, tool count confirmed |
| Yellow (pulsing) | Health check in progress (runs every 15 s) |
| Red — `MCP · error` | Import failed — hover the dot to see the error |

### From a terminal

**Check Claude Code sees the server:**
```bash
claude mcp list
```

**Check inside an interactive Claude Code session:**
```
/mcp
```

**Check the Python import (same probe the status dot uses):**
```bash
/usr/lib/penligent-local/mcp-server/.venv/bin/python -c "import penligent_mcp; print('ok')"
```

**Check if the process is alive during an active agent turn:**
```bash
pgrep -a -f penligent_mcp
```
Prints the PID and command if running; nothing if no turn is in progress (that is normal).

---

## Configuration

### HTB App Token

Settings → HTB App Token → paste your token from HTB profile → Settings → API.

Stored locally at `~/.local/share/penligent-local/config.json`, passed to Claude as `HTB_APP_TOKEN`.

### VPN

Settings → OpenVPN → Browse for your `.ovpn` file → Connect.

The passwordless sudo rule for OpenVPN is added automatically by the `.deb` installer. If you installed from source, add it manually once:

```bash
echo "%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" | \
  sudo tee /etc/sudoers.d/penligent-openvpn && \
  sudo chmod 440 /etc/sudoers.d/penligent-openvpn
```

---

## Usage

1. Launch `penligent-local`
2. Create an engagement in the left sidebar — choose HTB Machine, CTF, Bug Bounty, or Pentest
3. Set the target IP if applicable (right-click → rename, or set during creation)
4. Type your objective in the chat and press Enter
5. The agent enumerates, exploits, and documents findings automatically
6. When a GUI step is needed, follow the numbered walkthrough and reply when done
7. Findings appear in real-time in the right panel with P0–P4 priority

---

## Data

| Path | Contents |
|---|---|
| `~/.local/share/penligent-local/penligent.db` | Projects, findings, chat history (SQLite WAL) |
| `~/.local/share/penligent-local/config.json` | HTB token, local settings |
| `~/.local/share/penligent-local/artifacts/` | Raw tool output saved per execution |
| `~/penligent/projects/<name>/workspace/` | Per-engagement files, notes, scan output |

---

## Uninstall

### 1 — Remove the application

```bash
sudo dpkg -r penligent-local
```

This removes the binary, the bundled MCP server, and the desktop entry. Configuration and data are intentionally kept (see step 3 if you want to remove those too).

### 2 — Remove the sudoers rule

```bash
sudo rm -f /etc/sudoers.d/penligent-openvpn
```

### 3 — Remove user data (optional)

```bash
# App database, HTB token, settings, tool output artifacts
rm -rf ~/.local/share/penligent-local/

# Per-engagement workspace files, notes, scan output
rm -rf ~/penligent/
```

> These directories contain your findings and chat history. Only delete them if you no longer need the data.

### 4 — Remove the MCP server entry from Claude settings (optional)

```bash
# Open ~/.claude/settings.json and remove the "penligent-local" key under "mcpServers"
```

### 5 — Remove the Claude CLI (optional)

```bash
npm uninstall -g @anthropic-ai/claude-code

# Claude auth tokens and local config
rm -rf ~/.claude/
```

---

## Changelog

### v0.1.8 (current)

**Features:**

- **MCP-down auto-halt + modal.** When the periodic MCP health check flips from `ok` to `error`, the frontend now invokes a new `claude_halt` Tauri command to stop the in-flight Claude turn (no point firing tool calls into a dead server) and surfaces a blocking modal explaining what happened. The modal shows any captured error, offers a "Recheck now" button (re-runs `pollMcpHealth` immediately instead of waiting up to 15s), and auto-dismisses when health recovers. The bottom-right status-bar dot is unchanged — this is purely additive.
- **`claude_halt` Tauri command.** Backend uses a `tokio::sync::oneshot` channel stored in `ClaudeState`; `run_turn`'s read loop is now a `tokio::select!` with the halt arm `biased;` so an idle agent gets stopped promptly. The existing `kill_on_drop(true)` does the actual SIGTERM as the `Child` handle goes out of scope. Returns `true` if a turn was actually halted, `false` if nothing was running.

### v0.1.7

**Bug fixes (web.py audit, second pass):**

Nine more bugs fixed across eight probe functions. Test suite now at 1,477 passed (390 subtests), up one from v0.1.6 thanks to a new php://filter source-disclosure detection.

- **`graphql_probe` critical false-positive fixed.** `rc == 0` matched every successful curl call (including 404 responses), so every probed endpoint reported `[EXISTS]`. Now reads the actual HTTP status code via curl `-w` and only marks `[EXISTS]` on 200/400 with a GraphQL `errors[]` body shape. `[VULN]` requires `"__schema"` or `"queryType"` in body (quoted to avoid bare-substring matches).
- **`file_upload_check` honours the documented `timeout` arg.** Was parsed and ignored — both `curl -m` and the asyncio.wait_for were hardcoded. Also captures the HTTP status code and flags 2xx responses containing `success` / `uploaded` / `filename` / URL-field signals as `[LIKELY ACCEPTED]`. Added inline note that this tool tests upload acceptance, not file executability.
- **`jwt_decode` crashed on malformed JWTs.** `header.get(...)` was called unconditionally — if base64-decode failed and returned a `"<decode error>"` string, this raised `AttributeError`. Now guarded with `isinstance` checks. RS/ES/PS algorithms get an actionable hint about `alg=none` and RS→HS key confusion attacks.
- **URL construction bugs in 5 more probes**: `open_redirect_check`, `ssti_probe`, `lfi_probe`, `cmdi_probe`, `path_traversal`, `prototype_pollution` GET-payload path. All switched to the parser-aware `_build_url_with_param()` helper. No more malformed URLs when targets already have query strings; payloads now properly URL-encoded.
- **`open_redirect_check` was silently skipping 6 of 11 default params.** Hardcoded `params[:5]` slice replaced with configurable `max_params` / `max_payloads` args.
- **`lfi_probe` / `path_traversal` detection broadened.** Both now use the shared `_imds_signal` helper (catches `/etc/passwd`, Windows boot.ini, cloud IMDS shapes) plus base64 source-disclosure for php://filter and explicit win.ini section names.
- **`lfi_probe` `[CHECK]` threshold tightened.** Was 100B absolute → 500B delta-from-baseline. Pre-fix every response over 100 bytes flooded the output with manual-review noise.
- **`cmdi_probe` time-based detection now compares to a baseline.** Pre-fix a 4+ second jitter spike on a slow endpoint triggered a false-positive blind cmdi finding even without a payload. Now measures baseline latency at start of probe and only flags `[VULN]` when delta exceeds baseline + 4s.
- **`ssti_probe` `[SAFE]` relabelled `[NO_MATCH]`.** A payload not reflecting `49` doesn't prove safety (HTML-escape, different engine, payload landed in non-rendered context, etc.). Honest label.

### v0.1.6

**First-run wizard polish:**

- **New Welcome step** with a one-line positioning sentence, a bulleted overview of the three setup steps (HTB token / OpenVPN sudoers / VPN profile) with optional/recommended badges, and a hint that the wizard can be re-run anytime from `Ctrl+K`.
- **Back button on every step.** Typing the wrong HTB token used to mean restarting the wizard.
- **Show/Hide toggle** on the HTB token field (defaults hidden).
- **OVPN path input is editable** — paste works alongside the Browse button.
- **New Summary step** before Finish, with ✓/— icons and the masked last-6 chars of the HTB token. Errors during save now render inline as a styled red block so users can see what failed, instead of the wizard closing silently.
- **`Ctrl+K` → "Re-run first-run setup wizard"** command added. Resets all wizard state and reopens the dialog.
- **Internal:** `wzFinish()` now collects errors per save operation instead of `catch (_) {}` swallowing them; the wizard stays open with the error list visible if anything failed.

### v0.1.5

**Bug fixes (web.py audit pass):**

- **13 probe tools honoured documented `timeout` arg.** `open_redirect_check`, `ssrf_probe`, `ssti_probe`, `lfi_probe`, `rfi_probe`, `xxe_probe`, `cmdi_probe`, `path_traversal`, `idor_check`, `rate_limit_check`, `graphql_probe`, `prototype_pollution`, `deserialization_check` accepted `timeout: int` but hardcoded 15s (or 10s/30s) internally. The agent could never override — slow targets and time-based probes silently failed. Now every probe uses the parsed `timeout_s`.
- **`jwt_crack` algorithm-aware.** Previously hardcoded HS256/SHA-256. Tokens using HS384, HS512, RS256, ES256 silently returned "secret not found" — false negatives every time. Now reads the JWT header `alg`, picks hashcat mode 16500/16600/16700 for HS256/384/512, and fails non-HMAC algorithms with a clear pointer to `alg=none` and RS→HS key confusion.
- **`jwt_crack` output parsing.** Hashcat result extraction now uses `--show` + `rsplit(":", 1)` instead of a regex that captured the first `:` on a line.
- **SSRF / RFI URL construction.** Old pattern `f"{target}?{param}={payload}"` produced malformed URLs (`http://x?a=1?param=…`) when the target already had a query string, and never URL-encoded the payload — so `&` in a payload polluted the outer query. New `_build_url_with_param()` helper parses, encodes, and reassembles. Adopted by SSRF + RFI probes.
- **SSRF probe positive signal.** Previously reported only "HTTP code + body_len" per payload — the agent had to guess. Now detects AWS / GCP / Azure / DigitalOcean metadata content, `/etc/passwd`, Windows boot.ini, and falls back to a body-size differential heuristic. Reports `[VULN]` when confirmed.
- **XXE probe broadened.** Dropped the useless "blind_oob" payload pointing at the target's own `127.0.0.1`. Added `callback_host` arg, `php://filter` base64 source disclosure, Windows hosts file payload, proper OOB DTD payload. Detection extended beyond `root:`/`daemon:` to base64 source bytes and XML parser-error keywords (`doctype`/`entity`/`saxparser`/`expat`/`lxml.etree`/`xerces`).
- **Java deserialization probe actually delivers the payload.** Previously generated a ysoserial payload and returned "send as POST body" without sending it; the required `target` arg was unused. Now POSTs the binary payload to the target and measures elapsed time vs the gadget's 5s sleep. Reports `[CONFIRMED]` with measured delay. Binary-safe: ysoserial stdout streams to a temp file so the 0xAC 0xED magic bytes hit the wire intact (sidesteps `_run_subprocess`'s UTF-8 decoding).

Tests: 1,476 passed, 390 subtests passed.

### v0.1.4

**Features:**

- **Command palette + keyboard shortcuts.** `Ctrl+K` opens a fuzzy-search palette covering tab navigation, chat focus, VPN reconnect/disconnect, MCP re-check, clear-chat, and the keyboard help dialog itself. Power-user shortcuts: `Ctrl+1/2/3` jumps between Chat / Workspace / Settings, `Ctrl+,` opens Settings, `Ctrl+J` focuses the chat input, `?` shows the cheat sheet, `Esc` closes any modal. Every shortcut is also exposed as a command in the palette so nothing has to be memorised.
- **Real per-turn / session token telemetry in the status bar.** Replaces an earlier `cost × 200000` approximation with actual `usage` data parsed from Claude Code's stream-json `result.usage` event. Status bar now shows `turn 1.9k · cache 1.8k · $0.0034 · session 12.4k · $0.18`. Cache-read tokens are highlighted in green — a visible cost-saving signal whenever the trimmed system prompt is server-side cached.

**Performance:**

- **Windowed message rendering.** Long sessions used to keep every message mounted; agentic turns produce multiple tool_use panels each, so the DOM grew unbounded and layout cost climbed visibly. Now only the last 100 messages are mounted by default — older ones stay in `messages[]` (persisted, hash-chained, still searchable by the agent via `workspace_search`). A dashed-border `↑ Load 50 earlier messages` button at the top of the chat expands the window on demand, with scroll position preserved.

### v0.1.3

**Features:**

- **Wiki bootstrap — methodology pages now ship in the .deb.** A fresh install used to give an empty second-brain: `wiki_query('evidence-first')`, `wiki_query('compliance-mappings')`, etc. would return nothing on day one. The bundle now includes 12 baseline methodology pages under `penligent_mcp/data/methodology/`, and the wiki tools copy any missing seed into the user's wiki on first use. Idempotent — never overwrites existing user edits.

Seeded pages: `evidence-first`, `compliance-mappings`, `waf-bypass`, `web-engagement-startup`, `osint-pre-engagement`, `auth-session-testing`, `broken-access-control`, `cloud-attack-surface`, `llm-attack-surface`, `document-parser-exploits`, `detection-blind-spots`, `pentest-engagement`.

### v0.1.2

**Performance:**

- **System prompt trimmed 67%** — from ~5,900 to ~1,935 tokens per turn. Methodology sections (compliance tables, WAF bypass, XSS layers, XXE, OSINT, auth/session, BAC, cloud, LLM, PDF, blind spots) moved out of the prompt and into wiki pages the agent loads on demand via `wiki_query()`. Saves ~3,900 tokens every turn.
- **Chat streaming** — coalesced rapid claude://chunk events into a single rAF-batched render (was O(N²) array churn over a turn, now O(N) capped at 60Hz). Added a 256-entry LRU cache for `renderMarkdown` so settled message parts and finished tool_use blocks don't re-parse on every frame. Smooth-scroll queue replaced with instant scroll inside the rAF callback.
- **MCP read caching** — in-process LRU+TTL cache for `wiki_*` and `workspace_*` idempotent reads (60s TTL / 64 entries per namespace). Mutating tools invalidate their namespace. Cache state never outlives a single turn.

**Bug fixes:**

- **`cloud.py` / `binary.py` missing from .deb bundle** — both were imported by the MCP server but absent from `tauri.conf.json` files map; a fresh install would fail to start the MCP server. Added to the bundle.
- **`wiki.py` / `_cache.py` missing from .deb bundle** — same issue for the newly added MCP modules. Added.
- **Inline `import re` calls in `wiki.py`** — flagged by `TestPythonSyntax::test_no_remaining_inline_imports`. Hoisted to module-top imports.

**Features:**

- **Wiki / Second Brain MCP tool** (`wiki.py`, 554 lines) — query/read/write/lint/ingest the local pentest knowledge base at `~/.local/share/penligent-local/wiki/`. The system prompt now mandates `wiki_query()` before every task so the agent prefers your synthesized notes over its training data.
- **11 methodology wiki pages** seeded locally (evidence-first, compliance-mappings, waf-bypass, web-engagement-startup, osint-pre-engagement, auth-session-testing, broken-access-control, cloud-attack-surface, llm-attack-surface, document-parser-exploits, detection-blind-spots) — these back the keywords the trimmed system prompt references.
- **`scripts/ingest_machines.py`** — bulk ingestion helper for machine writeups.

### v0.1.0

**Bug fixes:**

- **MCP server bundled in .deb** — previously missing from the package; the agent had no tools on a fresh install. Now fully automatic via post-install script (venv creation, pip install, `~/.claude/settings.json` registration, sudoers rule).
- **VirtualBox / VM support** — app hung on launch in VMs with no GPU. Fixed by setting `WEBKIT_DISABLE_COMPOSITING_MODE=1` and `LIBGL_ALWAYS_SOFTWARE=1` inside the binary before WebKit initialises; also reflected in the `.desktop` entry for launcher compatibility.
- **OpenVPN Browse button** — silently did nothing. Root cause: Tauri v2 requires explicit capability grants. Fixed by adding `dialog:allow-open` to `capabilities/default.json`.
- **VPN stuck at "connecting"** — OpenVPN writes its log to stderr, not stdout. Fixed by merging both streams through a single channel so "Initialization Sequence Completed" is always detected.
- **VPN tun IP never shown** — CIDR notation (`10.10.14.42/23`) failed IP parsing. Fixed by stripping the `/prefix` before validation.
- **Hardcoded `/home/kali` paths** — broke for any non-`kali` username. Fixed in: `claude_proc.rs` (Claude binary path and work-dir fallback), `App.svelte` (project workspace path), `Settings.svelte` (Browse dialog default path). All now use `dirs::home_dir()` / `homeDir()` at runtime.
- **`rpc_users` rpcclient crash** — an empty string `""` was passed as a positional argument to `rpcclient` when a username was provided, causing it to fail. Fixed with `*(["-N"] if not username else [])`.
- **`post-install.sh` non-fatal pip failure** — `set -e` caused dpkg to mark the package as broken if pip/hatchling had no internet access. Made the install step non-fatal with a clear retry instruction; also auto-installs `python3-venv` if missing.
- **Chat history wipe on bad JSON** — a single message with malformed stored content caused `JSON.parse` to throw inside `.map()`, wiping all displayed history. Fixed with per-message parsing using `flatMap`.
- **Silent project creation failure** — if the server rejected a project name (e.g., containing `/`), the modal closed with no feedback. Error message now shown in red below the name field.
- **Unhandled `homeDir()` rejection** — missing `.catch()` on the `homeDir()` promise in `App.svelte`. Added.
- **Fresh-install database bootstrap** — `projects` and `chat_messages` tables were not created by the Rust app, so the UI failed before the Python MCP server had ever run. Fixed with `ensure_schema()` in `db_commands.rs`.

---

## Security notes

- No Anthropic API key required — Claude Code handles authentication
- No outbound connections except to Anthropic (Claude Code) and HTB (`labs.hackthebox.com`)
- All data stays on the local machine
- Sudoers rule is scoped to `/usr/sbin/openvpn` only — never `NOPASSWD: ALL`
- Intended for use on a dedicated pentesting VM, not a daily-driver machine
