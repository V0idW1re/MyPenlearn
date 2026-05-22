---
name: web-engagement-startup
description: Five-step opening sequence for every web engagement — probe, detect, map, audit headers
tags: [methodology, web, startup, recon, csp, security-headers]
source: Penligent Local methodology
---

# Web Engagement — Startup Sequence

> At the start of every web engagement, run these five steps **in this order**. Their output drives every subsequent decision.

## The Five Steps

| Step | MCP Tool | What you get |
|------|---------|--------------|
| 1 | `http_probe` | Baseline response, headers, status code, server fingerprint |
| 2 | `tech_detect` | Framework, server, CMS, JS libraries (Wappalyzer-style signals) |
| 3 | `check_sensitive_paths` | Crawlergo 40-path heuristic — auth endpoints, admin panels, API roots |
| 4 | `csp_audit` | Content Security Policy: nonce reuse, unsafe-inline, unsafe-eval, SRI gaps |
| 5 | `security_headers` | X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy, X-Content-Type-Options |

## Notes per Step

### 1. http_probe
- Capture full headers and the first 4KB of body for fingerprinting
- Note the `Server`, `X-Powered-By`, `Set-Cookie` formats
- If 302/301 → follow the redirect chain and probe the destination too

### 2. tech_detect
- Confirms what `http_probe` suggested
- Identifies vulnerable component versions for CVE lookup
- Flag any framework with known recent CVEs (Spring4Shell, log4j, Confluence, Atlassian, etc.)

### 3. check_sensitive_paths
- Default: passes 40 high-value paths
- If the target runs a versioned API: set `use_prefixes=true` to expand the search (`/api/v1/...`, `/v2/...`)
- Interesting status codes to investigate: **200 JSON**, **401**, **403**, **500**

### 4. csp_audit
- A weak CSP doubles the impact of any XSS finding
- Flag: `'unsafe-inline'`, `'unsafe-eval'`, `*` in `script-src`, missing `frame-ancestors`
- Note nonce reuse across responses — that's a CSP bypass primitive

### 5. security_headers
- Missing `Strict-Transport-Security` → MITM downgrade primer
- Missing `X-Frame-Options` and `Content-Security-Policy frame-ancestors` → clickjacking
- Missing `Referrer-Policy` → token leak risk
- Missing `Permissions-Policy` → broad sensor/feature access in iframes

## Interesting Responses Become Investigation Targets

After steps 1–5, the agent has a map. Investigation priority order:

1. **200 JSON** responses on `check_sensitive_paths` → undocumented API endpoint, try IDOR/BOLA
2. **401** with `WWW-Authenticate: Bearer` → JWT or OAuth — see [[auth-session-testing]]
3. **403** that is NOT the WAF (no WAF headers) → broken access control — see [[broken-access-control]]
4. **500** errors → stack trace / framework hint may leak source paths
5. **302** to /login on every protected path → standard session model, proceed with auth tests

## Cross-Reference

- [[osint-pre-engagement]] — passive intel to run **before** these five steps
- [[auth-session-testing]] — what to do when 401/403 protected endpoints surface
- [[waf-bypass]] — if step 1 returns 403/429 with WAF signature, do not conclude not-vulnerable
