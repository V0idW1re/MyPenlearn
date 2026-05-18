"""
Plan layer tools (4 tools).
Create and manage structured engagement plans with step-by-step sequences.
The plans/plan_steps tables in SQLite are the authoritative record.
"""
import json
import time

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s
from ..db import get_db

VALID_VERBS = {
    "passive_recon", "active_recon", "subdomain_enum", "port_scan",
    "dir_brute", "http_probe", "tech_detect", "sqli_detect", "xss_probe",
    "ssrf_probe", "lfi_probe", "auth_test", "session_test", "bac_test",
    "exploit_run", "privesc", "post_exploit", "lateral_move",
    "evidence_collect", "report_generate", "custom",
}

VALID_STEP_STATUSES = {"pending", "in_progress", "done", "skipped", "failed"}


# ---------------------------------------------------------------------------
# plan_create
# ---------------------------------------------------------------------------

async def _plan_create(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    objective = (args.get("objective") or "").strip()
    if not project_id:
        return _ok("Error: project_id is required.")
    if not objective:
        return _ok("Error: objective is required.")

    constraints = args.get("constraints")
    kpis = args.get("kpis") or [
        "time_to_first_validated_chain",
        "evidence_completeness",
        "validated_finding_rate",
        "false_positive_burden",
    ]
    compliance_targets = args.get("compliance_targets") or [
        "NIST_800_115", "OWASP_TOP10", "ISO_27001",
    ]
    steps_raw = args.get("steps") or []

    async with get_db() as db:
        proj = await (await db.execute(
            "SELECT id FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        if not proj:
            return _ok(f"Error: project_id {project_id} not found.")

        cur = await db.execute(
            """INSERT INTO plans
               (project_id, objective, constraints_json, kpis_json,
                compliance_targets_json, version, created_at)
               VALUES (?,?,?,?,?,1,?)""",
            (
                int(project_id),
                objective,
                json.dumps(constraints) if constraints else None,
                json.dumps(kpis),
                json.dumps(compliance_targets),
                int(time.time()),
            ),
        )
        plan_id = cur.lastrowid

        for idx, step in enumerate(steps_raw):
            verb = (step.get("verb") or "custom").lower()
            await db.execute(
                """INSERT INTO plan_steps
                   (plan_id, step_idx, verb, target, args_json, budget_json, status)
                   VALUES (?,?,?,?,?,?,'pending')""",
                (
                    plan_id,
                    idx,
                    verb,
                    step.get("target", ""),
                    json.dumps(step.get("args")) if step.get("args") else None,
                    json.dumps(step.get("budget")) if step.get("budget") else None,
                ),
            )

        await db.commit()

    step_summary = ""
    if steps_raw:
        step_summary = f"\nSteps ({len(steps_raw)}):\n"
        for idx, step in enumerate(steps_raw):
            step_summary += f"  {idx}. [{step.get('verb','custom')}] {step.get('target','')}\n"

    return _ok(
        f"Plan created: id={plan_id} for project_id={project_id}\n"
        f"Objective: {objective}{step_summary}"
    )


register(Tool(
    name="plan_create",
    description=(
        "Create a structured engagement plan for a project. "
        "Specify the objective, optional constraints (rate, MFA, no-destructive), "
        "KPIs, compliance targets, and an ordered step sequence. "
        "Returns the plan id."
    ),
    inputSchema=_s(
        ["project_id", "objective"],
        project_id=("integer", "Project ID"),
        objective=("string", "Plain-English engagement objective"),
        constraints=("object", "Optional constraints: {rate_limit_rps, respect_mfa, no_destructive_actions}"),
        kpis={"type": "array", "items": {"type": "string"},
              "description": "KPI names to track (default: time_to_first_validated_chain, evidence_completeness, etc.)"},
        compliance_targets={"type": "array", "items": {"type": "string"},
                            "description": "Compliance frameworks to map findings to"},
        steps={"type": "array", "items": {"type": "object"},
               "description": "Array of step objects: [{verb, target, args, budget}]"},
    ),
), _plan_create)


# ---------------------------------------------------------------------------
# plan_get
# ---------------------------------------------------------------------------

async def _plan_get(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    plan_id = args.get("plan_id")

    if not project_id and not plan_id:
        return _ok("Error: project_id or plan_id is required.")

    async with get_db() as db:
        if plan_id:
            row = await (await db.execute(
                "SELECT id, project_id, objective, constraints_json, kpis_json, "
                "compliance_targets_json, version, created_at FROM plans WHERE id=?",
                (int(plan_id),)
            )).fetchone()
        else:
            row = await (await db.execute(
                "SELECT id, project_id, objective, constraints_json, kpis_json, "
                "compliance_targets_json, version, created_at FROM plans "
                "WHERE project_id=? ORDER BY created_at DESC LIMIT 1",
                (int(project_id),)
            )).fetchone()

        if not row:
            return _ok("No plan found.")

        pid = row["id"]
        steps = await (await db.execute(
            "SELECT id, step_idx, verb, target, args_json, budget_json, "
            "status, started_at, ended_at FROM plan_steps WHERE plan_id=? ORDER BY step_idx",
            (pid,)
        )).fetchall()

    lines = [
        f"Plan id={pid} (project_id={row['project_id']}, v{row['version']})",
        f"Objective: {row['objective']}",
        "",
    ]
    if row["constraints_json"]:
        try:
            c = json.loads(row["constraints_json"])
            lines.append(f"Constraints: {c}")
        except Exception:
            pass
    if row["kpis_json"]:
        try:
            lines.append(f"KPIs: {', '.join(json.loads(row['kpis_json']))}")
        except Exception:
            pass
    if row["compliance_targets_json"]:
        try:
            lines.append(f"Compliance: {', '.join(json.loads(row['compliance_targets_json']))}")
        except Exception:
            pass
    lines.append("")

    if steps:
        lines.append("Steps:")
        for s in steps:
            status_icon = {"pending": "○", "in_progress": "→", "done": "✓",
                           "skipped": "—", "failed": "✗"}.get(s["status"], "?")
            target = s["target"] or ""
            lines.append(f"  {status_icon} [{s['step_idx']}] {s['verb']}  {target}  ({s['status']})")
    else:
        lines.append("No steps defined.")

    return _ok("\n".join(lines))


register(Tool(
    name="plan_get",
    description=(
        "Get the current plan for a project (most recent) or a specific plan by id. "
        "Shows objective, constraints, KPIs, compliance targets, and all steps with status."
    ),
    inputSchema=_s(
        [],
        project_id=("integer", "Project ID — returns the most recent plan"),
        plan_id=("integer", "Specific plan ID (optional, overrides project_id lookup)"),
    ),
), _plan_get)


# ---------------------------------------------------------------------------
# plan_update_step
# ---------------------------------------------------------------------------

async def _plan_update_step(args: dict) -> list[TextContent]:
    step_id = args.get("step_id")
    status = (args.get("status") or "").strip().lower()

    if not step_id:
        return _ok("Error: step_id is required.")
    if status not in VALID_STEP_STATUSES:
        return _ok(f"Error: status must be one of {sorted(VALID_STEP_STATUSES)}.")

    now = int(time.time())
    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id, status FROM plan_steps WHERE id=?", (int(step_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: step_id {step_id} not found.")

        if status == "in_progress":
            await db.execute(
                "UPDATE plan_steps SET status=?, started_at=? WHERE id=?",
                (status, now, int(step_id))
            )
        elif status in ("done", "skipped", "failed"):
            await db.execute(
                "UPDATE plan_steps SET status=?, ended_at=? WHERE id=?",
                (status, now, int(step_id))
            )
        else:
            await db.execute(
                "UPDATE plan_steps SET status=? WHERE id=?",
                (status, int(step_id))
            )
        await db.commit()

    return _ok(f"Step {step_id} updated to '{status}'.")


register(Tool(
    name="plan_update_step",
    description=(
        "Update the status of a plan step. "
        "Call with status='in_progress' when starting a step, "
        "'done' when complete, 'failed' if it errored, 'skipped' if bypassed."
    ),
    inputSchema=_s(
        ["step_id", "status"],
        step_id=("integer", "plan_steps.id to update"),
        status=("string", "New status: pending | in_progress | done | skipped | failed"),
    ),
), _plan_update_step)


# ---------------------------------------------------------------------------
# plan_next_step  — return next pending step to execute
# ---------------------------------------------------------------------------

async def _plan_next_step(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    plan_id = args.get("plan_id")

    if not project_id and not plan_id:
        return _ok("Error: project_id or plan_id is required.")

    async with get_db() as db:
        if not plan_id:
            row = await (await db.execute(
                "SELECT id FROM plans WHERE project_id=? ORDER BY created_at DESC LIMIT 1",
                (int(project_id),)
            )).fetchone()
            if not row:
                return _ok("No plan found for this project.")
            plan_id = row["id"]

        step = await (await db.execute(
            "SELECT id, step_idx, verb, target, args_json, budget_json FROM plan_steps "
            "WHERE plan_id=? AND status='pending' ORDER BY step_idx LIMIT 1",
            (int(plan_id),)
        )).fetchone()

    if not step:
        return _ok("All plan steps are complete — no pending steps remaining.")

    args_info = ""
    if step["args_json"]:
        try:
            args_info = f"\n  Args: {json.loads(step['args_json'])}"
        except Exception:
            pass

    return _ok(
        f"Next step: id={step['id']} idx={step['step_idx']}\n"
        f"  Verb:   {step['verb']}\n"
        f"  Target: {step['target'] or '(none)'}"
        + args_info
    )


register(Tool(
    name="plan_next_step",
    description=(
        "Return the next pending step from the current plan. "
        "Use this at the start of each execution loop to know what to do next."
    ),
    inputSchema=_s(
        [],
        project_id=("integer", "Project ID"),
        plan_id=("integer", "Specific plan ID (optional)"),
    ),
), _plan_next_step)
