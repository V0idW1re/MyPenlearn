---
name: auth-session-testing
description: Six-step protocol for every login / auth endpoint — brute-force, fixation, reuse, MFA, password policy, OAuth/OIDC
tags: [methodology, authentication, session, brute-force, mfa, oauth, oidc, jwt]
source: Penligent Local methodology
---

# Authentication & Session Testing

> For every login / auth endpoint discovered, test in this order. Each step has a specific failure mode that maps to a CWE / ASVS control.

## The Six-Step Protocol

### 1. Brute-Force Protection
- Submit >5 failed login attempts in quick succession.
- **Expected**: lockout, exponential delay, CAPTCHA, or `429 Too Many Requests`.
- **Failure mode**: identical 401 timing and status forever → no rate limit.
- Map: CWE-307, ASVS V2.2.1, MITRE T1110.

### 2. Session Fixation
- Capture a pre-auth session token (visit `/login`, note `Set-Cookie`).
- Authenticate while keeping that token in the request.
- **Expected**: server issues a NEW session ID upon successful auth.
- **Failure mode**: same token persists → attacker can pre-set a victim's session ID.
- Map: CWE-384, ASVS V3.2.1.

### 3. Token Reuse After Logout
- Capture a valid session token (cookie or Bearer).
- Logout via the documented endpoint.
- Replay the token against a protected endpoint.
- **Expected**: 401 / 403.
- **Failure mode**: 200 with content → token not invalidated server-side.
- Map: CWE-613, ASVS V3.3.1.

### 4. MFA Bypass
- Complete the password step only — do NOT complete the second factor.
- Attempt direct navigation to post-auth pages (`/dashboard`, `/api/me`, `/account/settings`).
- **Expected**: redirect back to MFA challenge.
- **Failure mode**: post-auth page renders → MFA enforced client-side only.
- Also test: skipping the MFA POST entirely while POSTing to the next step in the flow, replaying a previously-completed MFA token across sessions, requesting `/api/me` directly with the partial-auth cookie.
- Map: CWE-287, ASVS V2.7.1, MITRE T1556.006.

### 5. Password Policy
- Attempt to set passwords: `password`, `12345678`, `qwerty`, the username, the email-local-part.
- **Expected**: rejected with explicit policy violation.
- **Failure mode**: accepted → weak policy.
- Also test minimum length (try 6, 8, 10 chars), breach-list check (try `Password1!` which is in every common breach list).
- Map: CWE-521, ASVS V2.1.1, NIST 800-63B.

### 6. OAuth / OIDC
- Inspect the authorization request: must include `state` parameter (CSRF protection).
- Inspect `redirect_uri`: confirm strict matching, not prefix matching.
- For OIDC: confirm PKCE enforcement (`code_challenge`, `code_challenge_method=S256`).
- Test scope escalation: change `scope=openid` to `scope=openid offline_access admin` mid-flow.
- Test `id_token` JWT signature: try `alg=none`, try key confusion (RS256 → HS256 with public key as HMAC secret).
- Map: CWE-345 / CWE-352, ASVS V3.5, MITRE T1550.001.

## Common Quick Wins

| Symptom | Likely vuln |
|---------|-------------|
| Login form returns different status codes for valid vs invalid username | Username enumeration (CWE-204) |
| `Remember me` cookie is a static long-lived JWT with no rotation | Persistent token theft risk |
| Password reset link contains an integer or sequential token | Token brute-force / IDOR on reset |
| JWT in `Authorization: Bearer` has `alg=HS256` and is publicly verifiable | Try key recovery via JWKS pollution or `kid` injection |
| Cookie has no `HttpOnly`, no `Secure`, no `SameSite` | XSS-to-session-takeover primer |

## Compliance Mapping

- ASVS: V2 (Authentication), V3 (Session Management)
- OWASP_TOP10: A07 (Identification & Authentication Failures)
- MITRE ATT&CK: T1110 (Brute Force), T1556 (Modify Authentication Process), T1078 (Valid Accounts)
- PCI_DSS: 8.3 (Multi-factor / strong authentication)
- NIST 800-53: IA-2, IA-5

## Cross-Reference

- [[broken-access-control]] — what to test once you're authenticated
- [[evidence-first]] — every auth bypass needs control / test / observable-effect pair
