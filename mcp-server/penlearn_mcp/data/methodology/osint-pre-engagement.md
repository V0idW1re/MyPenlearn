---
name: osint-pre-engagement
description: Passive intelligence collection before any active scan — DNS, CT logs, code leaks, Google dorking
tags: [methodology, osint, recon, passive, dns, certificate-transparency, github-leaks, dorking]
source: Penlearn Local methodology
---

# OSINT & Pre-Engagement Recon

> Before any active scan, collect passive intelligence. Active traffic is observable; OSINT is not.

## Passive Intel Checklist

| Source | What to collect | MCP / tool |
|--------|----------------|-----------|
| DNS records | A, AAAA, MX, TXT, NS, CNAME, SOA, CAA | `dns_resolve` |
| Subdomains | Certificate Transparency, subfinder, amass | `cert_transparency`, subfinder |
| Public code leaks | GitHub/GitLab dorks for API keys, credentials, endpoints tied to the target domain | github-dorker, trufflehog |
| Search engine dorking | `site:target filetype:env`, `inurl:admin`, `inurl:backup`, `inurl:config`, `intitle:"index of"` | Google, Bing, Yandex |
| Wayback Machine | Archived endpoints no longer in the live tree | wayback, `wayback_paths` |
| Shodan / Censys / FOFA | Banner-derived host inventory, certificate-shared assets | `shodan_query` |
| Pastebin / haveibeenpwned | Historic credential leaks for the target's email domain | hibp, pastebin search |

All passive operations are **always auto-approved** — `PASSIVE_RECON`, `DNS_RESOLVE`, `WHOIS`, `CERT_TRANSPARENCY`, `WAYBACK`, `SHODAN_QUERY` never need `approve_intent`.

## DNS Records — What Each Tells You

| Record | Significance |
|--------|--------------|
| `A` / `AAAA` | Host IP — feeds port scan target list |
| `MX` | Email provider — Google Workspace? O365? On-prem Exchange? |
| `TXT` | SPF, DMARC, DKIM — also leaks service integrations (Atlassian, Zoom, Salesforce verification strings) |
| `NS` | DNS provider — Cloudflare, AWS Route53, Akamai (also a WAF signal) |
| `CNAME` | Reveals SaaS dependencies (`*.elasticbeanstalk.com`, `*.azurewebsites.net`, `*.cloudfront.net`) |
| `SOA` | Primary DNS server — sometimes still answers `AXFR` |
| `CAA` | Authorized certificate issuers — narrows phishing-cert detection |

## Certificate Transparency

CT logs (crt.sh, censys.io, certspotter) reveal **every** SAN that's ever been issued for the domain — including staging, dev, internal hostnames that resolve only inside corp networks.

```
crt.sh?q=%25.target.com&output=json
```

Filter the JSON for `name_value`, dedupe, then run `dns_resolve` against each candidate to find live hosts.

## GitHub / GitLab Dorking

Search patterns against the target's organization or email domain:

| Dork | Targets |
|------|---------|
| `"target.com" filename:.env` | leaked env files |
| `"target.com" "aws_access_key_id"` | AWS creds |
| `"target.com" "BEGIN RSA PRIVATE KEY"` | leaked keys |
| `"target.com" filename:.npmrc _auth` | npm registry tokens |
| `"target.com" filename:settings.py SECRET_KEY` | Django secrets |
| `"target.com" extension:sql` | SQL dumps with schema or data |

For confirmed leaks: capture the commit SHA + author + file path; treat as a **suspected** finding pending [[evidence-first]] verification.

## Google Dorking Cheat Sheet

```
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:bak
site:target.com inurl:admin
site:target.com inurl:backup
site:target.com inurl:config
site:target.com inurl:swagger
site:target.com inurl:openapi
site:target.com inurl:graphql
site:target.com intitle:"index of"
site:target.com "phpinfo()"
```

## Record OSINT in Workspace

Every passive discovery should land in `workspace_note(tag='osint')` **before** any active testing begins:

```python
workspace_note(
    tag='osint',
    title='Subdomain enumeration via CT',
    content='Found 47 unique subdomains in crt.sh for *.target.com. '
            'Highlights: dev-api.target.com (200 JSON), '
            'staging-admin.target.com (401 Basic), '
            'old-jenkins.target.com (200 — Jenkins 2.222.1).'
)
```

This becomes the basis of the recon section of the final report.

## Cross-Reference

- [[web-engagement-startup]] — the active steps that follow OSINT
- [[evidence-first]] — turning passive leads into confirmed findings
