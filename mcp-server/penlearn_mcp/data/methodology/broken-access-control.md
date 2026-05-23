---
name: broken-access-control
description: Three-axis test protocol for broken access control — horizontal, vertical, client-side
tags: [methodology, broken-access-control, idor, bola, escalation, rbac]
source: Penlearn Local methodology
---

# Broken Access Control

> For every user-scoped resource endpoint, test all three escalation axes. BAC is **A01** in OWASP Top 10 — the most common impactful finding.

## The Three Escalation Axes

### 1. Horizontal Escalation (IDOR / BOLA)

Substitute the resource ID with another user's:

```
GET /api/invoice?id=1     ← your invoice
GET /api/invoice?id=2     ← another tenant's invoice; SHOULD return 403
```

Test surfaces:
- Numeric / sequential IDs in path or query → try `id+1`, `id-1`, `1`, `9999`
- UUIDs in path → less guessable but check if leaked elsewhere (referer logs, mobile app bundle, etag)
- Slugs in path (`/profile/janedoe`) → try usernames discovered via OSINT or `/api/users` enumeration
- Composite paths (`/org/<oid>/project/<pid>/file/<fid>`) → swap each segment independently

### 2. Vertical Escalation (Role Confusion)

Modify role / permission fields the user shouldn't control:

```
Request body:    {"name": "Alice", "role": "user"}
Modified body:   {"name": "Alice", "role": "admin"}
Modified body:   {"name": "Alice", "role": "user", "isAdmin": true}
Modified body:   {"name": "Alice", "role": "user", "permissions": ["*"]}
```

Test surfaces:
- JSON body field injection (`role`, `isAdmin`, `tier`, `permissions`, `scope`)
- JWT payload editing — change `"role":"user"` to `"role":"admin"` and re-sign (or try `alg=none`)
- Cookie field injection — `session=<base64>; role=admin`
- HTTP method on the admin endpoint — try `PATCH` when the docs only show `POST`
- Mass assignment via PATCH endpoints meant for partial updates

### 3. Client-Side Bypass (Hidden API)

Call API endpoints hidden behind disabled UI elements:

- Disabled buttons in HTML often POST to live backend routes
- Hidden form fields may bind to server-side authorization checks that don't exist
- "Coming soon" tabs sometimes load the real endpoint via JS that simply hides the response

```
1. Inspect the page with disabled UI.
2. Search the JS bundle for the endpoint pattern (`/api/admin`, `/api/internal`).
3. Replay the request directly with curl / Burp.
4. If it returns 200 with privileged data → vertical escalation via client-side bypass.
```

## Quick Detection Patterns

| Signal | What it means |
|--------|---------------|
| Endpoint returns 200 for any integer ID, including ones outside your tenant | BOLA confirmed |
| `PATCH /api/users/me` accepts a `role` field that the UI never shows | Vertical escalation primer |
| `/api/admin/...` returns 200 with valid session even though the UI hides the link | Client-side authz only |
| JWT payload contains role info but is HS256 signed with a short secret | Try cracking the secret with hashcat (mode 16500) |
| `/api/users/<id>` works for anyone's ID but `/api/users/<id>/delete` returns 403 | Read-side BAC, write-side enforced — uneven enforcement |

## Compliance Mapping

- OWASP_TOP10: **A01:2021 Broken Access Control**
- ASVS: V4.1 (General Access Control), V4.2 (Operation Level Access Control), V4.3 (Other Access Control)
- MITRE ATT&CK: T1078 (Valid Accounts), T1530 (Data from Cloud Storage Object)
- CWE: CWE-639 (Authorization Through User-Controlled Key), CWE-862 (Missing Authorization)
- PCI_DSS: 7.1, 7.2 (Restrict access by business need)
- NIST 800-53: AC-3 (Access Enforcement), AC-6 (Least Privilege)

## Recording the Finding

Use the [[evidence-first]] template:

```json
{
  "preconditions": ["role: basic_user", "tenant_id: A"],
  "control_request": "GET /api/invoice?id=<user_A_invoice> returns 200 with own data",
  "test_request": "GET /api/invoice?id=<user_B_invoice> returns 200 with cross-tenant data",
  "observable_effect": "cross-tenant data disclosed: <user_B>'s invoice contents fully visible",
  "supporting_artifacts": ["request_a.txt", "response_a.txt", "request_b.txt", "response_b.txt"],
  "retest_after_fix": "repeat both requests after the ownership check is added to the resolver"
}
```

## Cross-Reference

- [[auth-session-testing]] — must be authenticated to test BAC
- [[evidence-first]] — five-field evidence rule
- [[compliance-mappings]] — full framework control list
