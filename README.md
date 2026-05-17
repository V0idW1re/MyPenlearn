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
- **OpenVPN integration** — Browse and connect to `.ovpn` profiles directly from Settings; narrow sudoers rule (`NOPASSWD: /usr/sbin/openvpn` only)
- **HackTheBox auto-approval** — When `HTB_APP_TOKEN` is set, machine start/stop/reset and flag submission proceed without confirmation prompts
- **Workspace persistence** — Every finding, note, and file written to `~/penligent/projects/<name>/workspace/`; SQLite WAL-mode DB survives VM shutdowns
- **Markdown renderer** — Zero-dependency inline renderer: code fences with copy buttons, headings, lists, blockquotes, bold/italic/strikethrough, inline code
- **Manual-action callout** — GUI walkthrough completions are detected and rendered as a highlighted amber callout

---

## Requirements

- Kali Linux (tested on 2024.x in VMware)
- [`claude` CLI](https://claude.ai/code) installed and logged in (`~/.local/bin/claude`)
- Python 3.11+ (for the MCP server)
- OpenVPN (`/usr/sbin/openvpn`) — optional, for HTB lab access

---

## Installation

### Option A — Install the pre-built .deb

```bash
sudo dpkg -i penligent-local_0.1.0_amd64.deb
penligent-local
```

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
sudo dpkg -i target/release/bundle/deb/penligent-local_0.1.0_amd64.deb
```

### MCP server (required for tools)

The MCP server is bundled in the `.deb` at `/usr/lib/penligent-local/mcp-server/`. It is started automatically by `claude` via the MCP config. If building from source:

```bash
cd mcp-server
pip install -e .
```

---

## Configuration

### HTB App Token

Settings → HTB App Token → paste your token from HTB profile → Settings → API.

Stored locally at `~/.local/share/penligent-local/config.json`, passed to Claude as `HTB_APP_TOKEN`.

### VPN (optional)

Settings → OpenVPN → Browse for your `.ovpn` file → Connect.

For passwordless VPN, add the sudoers rule once:

```bash
echo "kali ALL=(ALL) NOPASSWD: /usr/sbin/openvpn" | \
  sudo tee /etc/sudoers.d/penligent-openvpn
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
| `~/penligent/projects/<name>/workspace/` | Per-engagement files, notes, scan output |

---

## Security notes

- No Anthropic API key required — Claude Code handles authentication
- No outbound connections except to Anthropic (Claude Code) and HTB (`labs.hackthebox.com`)
- All data stays on the local machine
- Sudoers rule is scoped to `/usr/sbin/openvpn` only — never `NOPASSWD: ALL`
- Intended for use on a dedicated pentesting VM, not a daily-driver machine
