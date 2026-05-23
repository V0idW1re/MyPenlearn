---
name: compliance-mappings
description: Compliance control references for every confirmed finding — NIST, ISO, PCI, SOC, GDPR, OWASP, AI-specific
tags: [methodology, compliance, nist, iso27001, pci-dss, soc2, gdpr, owasp, owasp-genai, nist-tevv]
source: Penlearn Local methodology
---

# Compliance Mappings

> Every confirmed finding should populate `compliance_controls` with at least one mapping per applicable framework. Use this as the canonical reference.

## NIST

| Framework | Control / Section | When it applies |
|-----------|-------------------|----------------|
| **NIST 800-115** | Technical Guide to Information Security Testing — section that matches the test class (recon, vuln scan, exploit, etc.) | Every assessment |
| **NIST SSDF** | PW.6.1 (sanitize inputs), RV.1 (identify vulns), RV.2 (assess), RV.3 (manage) | Findings tied to SDLC remediation |
| **NIST 800-53** | AC (access control), AU (audit & accountability), CM (configuration management), SI (system & information integrity) | Federal / regulated environments |
| **NIST TEVV** | NIST AI 100-5 Test/Evaluation/Verification/Validation | AI/LLM target systems — pair with OWASP_GENAI |

## ISO 27001

| Control | Topic |
|---------|-------|
| A.9.4 | Access control |
| A.9.2.3 | Privileged access rights management |
| A.12.6 | Vulnerability management |

## PCI DSS

| Requirement | Topic |
|-------------|-------|
| 6.2 | Protect system components from known vulnerabilities |
| 6.3 | Vulnerability management |
| 7.1 | Restrict access to system components by business need |
| 8.3 | Strong authentication |

## SOC 2

| Trust Service Criterion | Topic |
|-------------------------|-------|
| CC6 | Logical access controls |
| CC7 | System operations |
| CC8 | Change management |

## OWASP Top 10 (2021)

| ID | Category | Common findings |
|----|----------|-----------------|
| A01 | Broken Access Control | IDOR, vertical/horizontal escalation, missing auth |
| A02 | Cryptographic Failures | weak TLS, plaintext credential storage |
| A03 | Injection | SQLi, command injection, XSS, NoSQL injection |
| A04 | Insecure Design | missing rate limit, missing MFA, race conditions |
| A05 | Security Misconfiguration | default creds, debug pages exposed, dir listing |
| A06 | Vulnerable & Outdated Components | CVE-known library versions |
| A07 | Identification & Authentication Failures | brute-force allowed, session fixation, weak password policy |
| A08 | Software & Data Integrity Failures | unsigned updates, insecure deserialization |
| A09 | Security Logging & Monitoring Failures | no audit log, no alerting |
| A10 | Server-Side Request Forgery (SSRF) | metadata service access, internal-network probe |

## GDPR

| Article | Topic |
|---------|-------|
| Article 25 | Data protection by design and by default |
| Article 32 | Security of processing |
| Article 33 | Personal data breach notification |

## OWASP Generative AI Red-Teaming (LLM Top 10)

For findings against AI assistants, chatbots, RAG systems, agentic tools:

| ID | Category |
|----|----------|
| LLM01 | Prompt Injection |
| LLM02 | Insecure Output Handling |
| LLM03 | Training Data Poisoning |
| LLM04 | Model Denial of Service |
| LLM05 | Supply Chain Vulnerabilities |
| LLM06 | Sensitive Information Disclosure |
| LLM07 | Insecure Plugin Design |
| LLM08 | Excessive Agency |
| LLM09 | Overreliance |
| LLM10 | Model Theft |

Pair LLM findings with **NIST_TEVV** (testing/evaluation/verification/validation framework for AI systems).

## How to Populate `compliance_controls`

Use a list of `framework:control` strings:

```json
"compliance_controls": [
  "OWASP_TOP10:A01",
  "NIST_800_53:AC-3",
  "ISO_27001:A.9.4",
  "PCI_DSS:7.1"
]
```

If unsure which controls apply, pick at least:
- The closest OWASP_TOP10 category, **and**
- Either the relevant NIST 800-53 family or ISO 27001 control.

For AI/LLM targets, **always** include OWASP_GENAI and NIST_TEVV mappings.

## Related

- [[evidence-first]] — the five evidence fields every confirmed finding needs
- [[detection-blind-spots]] — known gaps in automated detection
