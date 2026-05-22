---
name: evidence-first
description: Penligent's five-field evidence rule that separates suspected from confirmed findings; template and audit chain
tags: [methodology, evidence, findings, verification, audit]
source: Penligent Local methodology
---

# Evidence-First — Suspected vs Confirmed

> A finding is **CONFIRMED** only when all five evidence fields are documented. Anything less is **SUSPECTED**. One well-evidenced chain beats thirty theoretical findings.

## The Five Required Fields

| Field | What it captures |
|-------|------------------|
| `preconditions` | Role, feature flags, configuration, session state required for the test |
| `control_request` | The baseline behavior — the normal-case request and its response |
| `test_request` | The modified input or attack payload that triggers the issue |
| `observable_effect` | The concrete proof tied to the claim — what changed, what was disclosed |
| `retest_after_fix` | Exact steps another operator can follow to re-validate after remediation |

If any one of these is missing, the finding is **suspected** — never call it confirmed.

## MCP Tool Flow

```
record_finding(..., verify_status='open')       # suspected, immediate
   ↓ (after all five fields populated)
verify_finding(finding_id, decision='verified') # promotes to confirmed
```

## Evidence Field Template

```json
{
  "preconditions": [
    "role: basic_user",
    "feature_flag: beta_exports=enabled"
  ],
  "control_request": "GET /api/exports/12345 returns 403",
  "test_request": "GET /api/exports/67890 returns 200",
  "observable_effect": "cross-tenant data disclosed",
  "supporting_artifacts": [
    "request.txt",
    "response.txt",
    "screenshot.png"
  ],
  "retest_after_fix": "repeat both control and test requests after authorization patch"
}
```

## Confirmed Findings Must Also Include

| Field | Purpose |
|-------|---------|
| `attack_chain_position` | 1 = initial foothold, 2 = lateral / pivot, 3+ = deeper access / impact |
| `impact` | One sentence describing blast radius if exploited in production |
| `repro_steps` | Ordered list of exact reproduction steps |
| `remediation` | Owner team, priority, action list, expected verification trace |
| `compliance_controls` | See [[compliance-mappings]] for the full framework table |

## Audit Trail

After each significant tool run that contributes evidence:

```python
audit_log(
    tool='<name>',
    step=<n>,
    exit_code=<code>,
    artifact='<path>',
    sha256='<sha256sum of artifact>'
)
```

This appends a JSONL record to `workspace/evidence/audit.log` with schema:
```json
{"ts": <unix_ts>, "project": "<name>", "step": <n>, "tool": "<name>",
 "args": <args_json>, "exit": <code>, "artifact": "<path>", "sha256": "<hash>"}
```

Hash every artifact (`sha256sum <file>`) **before** calling `audit_log` — this makes the evidence chain tamper-evident.

## Regression After Fix

When a fix has been applied:

1. Re-run the exact `control_request` and `test_request` from the finding.
2. Call `mark_regression(finding_id=<id>, passed=<bool>, note=<observations>)`.
3. `passed=true` → finding auto-marked verified with timestamp.
4. `passed=false` → `regression_required` set, finding stays open.

Never mark a regression fixed based on code review alone — re-run the reproduction steps.

## Quality > Quantity

Favor chain quality over raw finding count. A single confirmed multi-step chain (initial-foothold → lateral → impact) with full evidence is more valuable to a client than thirty disconnected theoretical findings.
