---
name: cloud-attack-surface
description: Cloud / container attack surface — IAM, IMDS, k8s, secrets, CI/CD; the standard public-entry-to-exfil chain
tags: [methodology, cloud, aws, gcp, azure, iam, imds, kubernetes, docker, ci-cd, ssrf]
source: Penlearn Local methodology
---

# Cloud & Container Attack Surface

> When the target includes cloud infrastructure (AWS/GCP/Azure) or container orchestration, follow this six-axis enumeration. The blast-radius chain is consistent across providers: **public entry → IAM pivot → secrets/storage → exfil**.

## The Six Axes

### 1. Shadow Asset Discovery

Enumerate public-facing resources not in the scope document:

- **S3-like buckets**: `target-prod`, `target-staging`, `target-backup`, `target-logs` — try wordlist mutation + `aws s3 ls --no-sign-request s3://<name>`
- **CloudFront / CDN distributions**: subdomain enumeration via CT logs often reveals `d2xxxxxx.cloudfront.net` aliases
- **API Gateways**: `*.execute-api.<region>.amazonaws.com` URLs frequently leak in JS bundles
- **Public ECR images**: `aws ecr-public describe-repositories --region us-east-1`
- **Forgotten staging clusters**: dev / staging / qa subdomains pointing to live ELB / Cloud Run / App Service URLs

### 2. IAM Misconfiguration

The single most common cloud finding:

- **Overly permissive roles**: `iam:PassRole *`, `s3:*` on `Resource: "*"`, `lambda:InvokeFunction *`
- **Unused permission policies**: an inactive role with admin still poses risk
- **Cross-account trust relationships**: `sts:AssumeRole` with overly broad `Condition` blocks (no `ExternalId`, no `aws:SourceAccount`)
- **Mis-scoped IAM roles**: a Lambda role with `s3:GetObject *` when it only reads one bucket

Tools: `aws iam simulate-principal-policy`, ScoutSuite, Prowler, CloudSploit.

### 3. Metadata Service Probe (IMDS / Instance Metadata)

Test for SSRF against the cloud metadata endpoint — full creds and instance identity in plain JSON:

| Provider | Endpoint | IMDSv2 enforcement signal |
|----------|----------|--------------------------|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Requires `X-aws-ec2-metadata-token` if IMDSv2 only |
| AWS (IPv6) | `http://[fd00:ec2::254]/latest/meta-data/` | Same |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires `Metadata-Flavor: Google` header |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Requires `Metadata: true` header |

Detection: any user-controlled URL fetch (image upload via URL, PDF generator, webhook config, OAuth redirect_uri) → try the metadata IP. **IMDSv1 still enabled** is a finding by itself even before exploitation.

### 4. CI/CD Exposure

- **Orphaned GitHub Actions runners** with broad `GITHUB_TOKEN` scopes or self-hosted runners exposed to public PRs
- **Exposed `.github/workflows/*.yml`** revealing secret names and deployment topology
- **Leaked secrets in build logs**: `echo $AWS_SECRET_ACCESS_KEY` accidentally not masked
- **Public artifact registries**: GHCR / Docker Hub / npm packages built from internal-only Git history (Git history exposed in shipped artifact)
- **Branch-protection bypass**: pull-request runners run with elevated permissions on first-time contributors

### 5. Container / Kubernetes Baseline

| Service | Port | Test |
|---------|------|------|
| Docker daemon | 2375 (cleartext), 2376 (TLS) | `curl http://target:2375/version` — if it answers, it's wide open |
| Kubernetes API | 8080 (insecure), 6443 (TLS) | `curl https://target:6443/api -k` — if it returns API discovery, check auth |
| etcd | 2379, 2380 | Direct access = full cluster secret store |
| kubelet | 10250 | `curl -k https://target:10250/pods` — direct pod enum + exec |
| Docker socket mount inside container | `/var/run/docker.sock` | Detect via `mount | grep docker.sock` from any container shell |

Container escape primitives:
- `--privileged` flag → trivial host root via `--device=/dev/sda` mount
- Mounted `docker.sock` → spawn host container via docker API
- `capabilities=SYS_ADMIN` → `unshare` + `nsenter` host PID namespace
- Old kernel + outdated containerd → CVE-2024-21626 (runc leak) is common

### 6. Stale Token Signals

- **Environment variable leaks**: any process listing showing `AWS_SECRET_ACCESS_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_CLIENT_SECRET`
- **`.env` files in repository history**: even if deleted from current HEAD, `git log -p -- .env` finds them
- **Long-lived tokens not rotated**: `aws iam list-access-keys` keys older than 90 days
- **Orphaned service account keys**: GCP SA JSON files with no associated active workload

## The Standard Attack Chain

```
Public entry  →  IAM pivot  →  Lateral to secrets/storage  →  Exfil blast radius
    │              │                  │                            │
    SSRF to        AssumeRole with    Read S3, Secrets Manager,    Stage to attacker
    metadata       weak Condition;    DynamoDB tables, RDS         S3 / external
    OR open S3     escalate via        snapshots                   storage
    OR public      iam:PassRole
    GHA runner
```

## Compliance Mapping

- NIST 800-53: AC-2 (Account Management), AC-6 (Least Privilege), CM-8 (Information System Component Inventory)
- ISO 27001: A.9.2.3 (Management of Privileged Access Rights)
- PCI DSS: 7.1 (Restrict access)
- CIS Cloud Benchmarks (AWS / GCP / Azure)
- OWASP Cloud-Native Top 10

## Cross-Reference

- [[broken-access-control]] — same axes apply to cloud APIs
- [[evidence-first]] — every IAM finding needs `aws iam get-policy --policy-arn <arn>` JSON as artifact
- [[compliance-mappings]] — full framework table
