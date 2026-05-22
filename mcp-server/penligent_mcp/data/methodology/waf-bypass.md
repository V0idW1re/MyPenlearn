---
name: waf-bypass
description: WAF bypass encoding strategy — do not conclude not-vulnerable from a 403/429 without trying multiple variants
tags: [methodology, waf, bypass, encoding, sqli, xss, evasion]
source: Penligent Local methodology
---

# WAF Bypass — Mandatory Variant Testing

> When a payload returns **403** or **429** with a WAF signature, do NOT conclude not-vulnerable immediately. Test at least **three** encoding variants before giving up.

## The Three-Variant Rule

A response of 403 / 429 / "Request Blocked" / Cloudflare challenge / Akamai signature means **the WAF saw the payload**, not that the underlying app is patched. Only mark not-vulnerable after **≥3 distinct bypass variants** all fail.

## Encoding Variants to Try

| Variant | Example | Notes |
|---------|---------|-------|
| **URL-encode** | `%27` (`'`), `%3C` (`<`), `%3E` (`>`) | First line of bypass; cheap |
| **Double URL-encode** | `%2527` (`%27`) | Bypasses single-pass decoders |
| **SQL comment injection** | `SE/**/LECT`, `UN/*!12345*/ION` | Splits keyword across signatures |
| **MySQL versioned comment** | `/*!50000UNION*/`, `/*!UNION*/` | Bypasses keyword-list WAFs |
| **Case variation** | `SeLeCt`, `uNiOn`, `OnLoAd` | Defeats case-sensitive regex |
| **Hex encoding** | `0x27` instead of `'` | For SQLi number contexts |
| **Unicode normalization** | `%u0027` (`'`), full-width `＇` | Some WAFs decode Unicode after pattern match |
| **Origin spoof** | `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Originating-IP` | Internal-source bypass |
| **HTTP/2 → HTTP/1.1 smuggling** | desync attack | Only when WAF is in front of an origin proxy |
| **Path normalization** | `..%2f`, `..;/`, `..%c0%af`, `;param=value` | For path-based WAF rules |

## Example Decision Tree

```
Payload returns 403/429
   ↓
1. Try URL-encoded variant
   ↓ blocked
2. Try double-URL-encoded variant
   ↓ blocked
3. Try comment-injected variant (SE/**/LECT)
   ↓ blocked
4. Try case-variation variant (SeLeCt)
   ↓ blocked
5. Try X-Forwarded-For: 127.0.0.1 spoof on the original payload
   ↓ blocked → now mark as not-vulnerable, record finding with verify_status='open' and note WAF
```

## Confirmation Signals

You have bypassed the WAF when:

- The same payload that previously returned 403 now returns 200, 500, or a 302 with attack-success indicators
- An error message appears that mentions the underlying tech stack (PHP, MySQL, ASP.NET) — meaning the payload reached the app
- Timing differential changes between control and variant (esp. for time-based blind SQLi)
- An OOB callback (DNS or HTTP) fires from the target's IP after a properly-crafted SSRF / XXE variant

## WAF Fingerprint Recognition

A few signature blocks before the bypass attempt:

| WAF | Response signal |
|-----|----------------|
| Cloudflare | `Server: cloudflare`, `cf-ray:` header, "Attention Required! \| Cloudflare" body |
| AWS WAF | `x-amzn-RequestId`, "The request could not be satisfied" |
| Akamai | `Server: AkamaiGHost`, "Reference #" in body |
| Imperva | `x-iinfo` header, `incap_ses_` cookie |
| F5 BIG-IP ASM | `Server: BigIP`, `TS01a8d10f` cookie |
| ModSecurity | "Mod_Security" string, 406/501 status |

## Related

- [[xss-mutation]] — three-layer encoding for XSS specifically
- [[xxe-injection]] — payload variants for XML targets
- [[detection-blind-spots]] — automated scanners often stop at the first 403
