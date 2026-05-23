---
name: jwt-forgery
description: Forging JWT tokens against apps that leave default secrets, accept the `none` algorithm, or expose key-derivation material — symmetric secret recovery and known-claim attacks
tags: [methodology, jwt, jws, auth-bypass, hs256, none-alg, token-forge]
source: Penlearn Local methodology
---

# JWT Forgery

> JSON Web Tokens are signed claims. If you control the signing secret — or trick the verifier into not checking it — you become any user the app trusts. This page covers the four most common openings.

## Anatomy refresher

A JWT is `base64url(header).base64url(payload).base64url(signature)`. The signature is HMAC (HS256/HS384/HS512), RSA (RS256), or ECDSA (ES256) over `header.payload`. Verification uses the **algorithm declared in the header** and the server's configured secret/key.

```python
import base64, json, hmac, hashlib

def b64url(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def make_jwt(payload: dict, secret: bytes, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = h + b"." + p
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return (msg + b"." + b64url(sig)).decode()
```

## Attack #1 — Default / leaked symmetric secret

The single most common JWT issue: the app uses `HS256` with a secret that the developer **forgot to override**. Grep the upstream source for any of:

- `"default-jwt-secret-change-me"`, `"changeme"`, `"secret"`, `"your-256-bit-secret"`
- Variables set in `.env.example` but absent from `.env`
- Hardcoded fallbacks in `auth/jwt.go`, `services/auth/*.py`, `lib/jwt.*`

Recovery flow:

1. Pin the app version (Server header, JS bundle, `/version`, `/api/health`).
2. Open the matching GitHub tag. Look in `internal/config`, `internal/services/auth`, `crypto/jwt.go`, or equivalent.
3. Find where `JWT_SECRET` (or its alias) is read — confirm there's a literal default that activates when the env is unset.
4. Check whether the box's systemd unit / dockerfile / `.env` actually sets it. If not, you have the secret.

Forge a token with claims matching what `/me`-style endpoints check (often `sub`, `user_id`, `role`, `app_version`, `exp`). Verify with one auth-required GET (e.g. `/api/auth/me`, `/api/admin/health`). 401 → the secret is overridden somewhere you couldn't see; 200 → root-equivalent in the app.

## Attack #2 — `alg: none` confusion

Some libraries honour `"alg": "none"` and accept tokens with no signature. Forge:

```
{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.
```

Note the **trailing dot with empty signature**. Test against `/api/auth/me` first. Mitigations have been widespread since 2015 but legacy apps and lazy custom verifiers still fall for it.

## Attack #3 — Algorithm confusion (RS256 → HS256)

If the verifier uses RS256 (asymmetric) but the library lets the header dictate the algorithm, you can sign with HS256 using the **public key as the symmetric secret**:

1. Fetch the public key (`/.well-known/jwks.json`, `/oauth/jwks`, server cert SAN).
2. Convert the JWK to PEM.
3. Set `"alg": "HS256"` in the header.
4. HMAC-sign with the PEM bytes (newlines and all — test both with and without trailing newline).

## Attack #4 — Predictable / brute-forceable secret

If the secret is a passphrase (not a 256-bit random key), `jwt-cracker`, `hashcat -m 16500`, or `john --format=hmac-sha256` against the captured token will recover it. Wordlists: rockyou, then darkweb2017-top10000.

```bash
hashcat -m 16500 captured.jwt /usr/share/wordlists/rockyou.txt
```

A weak secret is a much higher-yield target than user passwords because **one crack = every user**.

## Diagnosis when forgery returns 401

The verifier might be normalising every auth failure to a single response code. Use these probes to narrow down what failed:

- Send an obviously expired token (`exp` in the past) — if 401 reads the same as a forged token, the verifier hides which check failed.
- Send a token with `sub` for a user you know exists in the DB vs. a random UUID — different response timing can leak.
- Compare with `Authorization: Bearer not-even-a-token` — should be 400 if validation is strict, 401 if loose.
- Try every reasonable algorithm in the header: HS256, HS384, HS512, RS256, ES256, none.

If all return identical 401, the load-bearing secret is almost certainly correctly set and unguessable — pivot to credential recovery instead (config files, env vars, password reuse).

## Compliance mapping

- ttp_category: `auth_bypass`
- MITRE ATT&CK: T1550.001 (Web Session Cookie / Token), T1078 (Valid Accounts)
- OWASP_TOP10: A07 (Identification & Authentication Failures)
- CWE: CWE-347 (Improper Verification of Cryptographic Signature), CWE-798 (Use of Hard-coded Credentials)

## Cross-Reference

- [[evidence-first]] — five-field template; `test_request` should include the forged token and the resulting authed action
- [[auth-session-testing]] — broader session-handling checks
- [[arcane-cve-chain]] — case study: Arcane v1.13.0 ships a default JWT_SECRET that's only safe if the operator sets it explicitly
