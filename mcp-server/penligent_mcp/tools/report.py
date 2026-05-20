"""
Report generation tools (1 tool).
Reads all findings for a project and produces Markdown + optional PDF reports.
"""
import json
import shutil
import time
from pathlib import Path

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s, _run
from ..db import get_db

WORKSPACE_ROOT = Path.home() / "penligent" / "projects"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

PRIORITY = {
    "critical": "P0",
    "high":     "P1",
    "medium":   "P2",
    "low":      "P3",
    "info":     "P4",
}


def _ws_report(project_name: str) -> Path:
    p = WORKSPACE_ROOT / project_name / "workspace" / "report"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _severity_table(findings: list) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f["severity"] or "").lower()
        if sev in counts:
            counts[sev] += 1
    rows = ["| Severity | Count |", "|----------|-------|"]
    for sev in SEVERITY_ORDER:
        if counts[sev] > 0:
            rows.append(f"| {SEV_EMOJI[sev]} {sev.upper()} | {counts[sev]} |")
    return "\n".join(rows)


def _build_exec_summary(project: dict, findings: list, ts_str: str) -> str:
    total = len(findings)
    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    open_ = sum(1 for f in findings if f.get("verify_status") == "open")
    verified = sum(1 for f in findings if f.get("verify_status") == "verified")
    fp = sum(1 for f in findings if f.get("verify_status") == "false_positive")

    lines = [
        f"# Penligent Engagement Report",
        f"",
        f"**Target:** {project['target']}",
        f"**Project:** {project['name']}",
        f"**Kind:** {project['kind']}",
        f"**Generated:** {ts_str}",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"This engagement identified **{total}** finding(s) across the target scope.",
        f"Of these, **{crit} critical** and **{high} high** severity findings require immediate remediation.",
        f"",
        _severity_table(findings),
        f"",
        f"| Status | Count |",
        f"|--------|-------|",
        f"| Open | {open_} |",
        f"| Verified | {verified} |",
        f"| False Positive | {fp} |",
        f"",
    ]

    # Attack chain summary
    chained = [f for f in findings if f.get("attack_chain_position") is not None]
    if chained:
        chained.sort(key=lambda x: x.get("attack_chain_position") or 99)
        lines += [
            f"## Attack Chain",
            f"",
            f"A {len(chained)}-step attack chain was identified:",
            f"",
        ]
        for f in chained:
            pos = f["attack_chain_position"]
            lines.append(f"{pos}. **{f['title']}** ({f['severity'].upper()}) — {f.get('description', '')[:120]}")
        lines.append("")

    return "\n".join(lines)


def _build_finding_md(f: dict, idx: int) -> str:
    sev = (f["severity"] or "").lower()
    prio = PRIORITY.get(sev, "P?")
    emoji = SEV_EMOJI.get(sev, "⚪")
    status = f.get("verify_status") or "open"

    lines = [
        f"### {emoji} [{prio}] {f['title']}",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Severity | {sev.upper()} |",
        f"| Status | {status.upper()} |",
    ]
    if f.get("cve_id"):
        lines.append(f"| CVE | {f['cve_id']} |")
    if f.get("cvss"):
        lines.append(f"| CVSS | {f['cvss']} |")
    if f.get("ttp_category"):
        lines.append(f"| TTP | {f['ttp_category']} |")
    if f.get("mitre_attack_id"):
        lines.append(f"| MITRE ATT&CK | {f['mitre_attack_id']} |")
    if f.get("owasp_asvs_id"):
        lines.append(f"| OWASP ASVS | {f['owasp_asvs_id']} |")
    if f.get("attack_chain_position") is not None:
        lines.append(f"| Chain Position | {f['attack_chain_position']} |")
    lines.append("")

    if f.get("description"):
        lines += ["**Description**", "", f["description"], ""]

    if f.get("impact"):
        lines += ["**Impact**", "", f"_{f['impact']}_", ""]

    evidence = None
    if f.get("evidence_json"):
        try:
            evidence = json.loads(f["evidence_json"])
        except Exception:
            evidence = f["evidence_json"]
    if evidence:
        lines += ["**Evidence**", "", f"```\n{json.dumps(evidence, indent=2) if isinstance(evidence, (dict, list)) else evidence}\n```", ""]

    repro = None
    if f.get("repro_steps_json"):
        try:
            repro = json.loads(f["repro_steps_json"])
        except Exception:
            repro = f["repro_steps_json"]
    if repro:
        lines += ["**Reproduction Steps**", ""]
        if isinstance(repro, list):
            for i, step in enumerate(repro, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append(str(repro))
        lines.append("")

    remediation = None
    if f.get("remediation_json"):
        try:
            remediation = json.loads(f["remediation_json"])
        except Exception:
            remediation = f["remediation_json"]
    if remediation:
        lines += ["**Remediation**", ""]
        if isinstance(remediation, dict):
            if remediation.get("owner"):
                lines.append(f"- **Owner:** {remediation['owner']}")
            if remediation.get("priority"):
                lines.append(f"- **Priority:** {remediation['priority']}")
            if remediation.get("actions"):
                lines.append("- **Actions:**")
                for action in remediation["actions"]:
                    lines.append(f"  - {action}")
            if remediation.get("verification"):
                lines.append(f"- **Verification:** {remediation['verification']}")
        else:
            lines.append(str(remediation))
        lines.append("")

    compliance = None
    if f.get("compliance_controls_json"):
        try:
            compliance = json.loads(f["compliance_controls_json"])
        except Exception:
            pass
    if compliance and isinstance(compliance, dict):
        lines += ["**Compliance Controls**", ""]
        for fw, items in compliance.items():
            fw_clean = fw.replace("_", " ")
            items_str = ", ".join(items) if isinstance(items, list) else str(items)
            lines.append(f"- **{fw_clean}:** {items_str}")
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _build_fix_list(findings: list) -> str:
    lines = [
        "# Fix List",
        "",
        "Ordered by severity. Each item links to the full finding above.",
        "",
        "| # | Priority | Title | Status | Owner |",
        "|---|----------|-------|--------|-------|",
    ]
    # Sort: critical → high → medium → low → info, then verified before open
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    status_rank = {"verified": 0, "open": 1, "false_positive": 2}
    sorted_f = sorted(
        findings,
        key=lambda x: (
            sev_rank.get(x.get("severity", "info"), 99),
            status_rank.get(x.get("verify_status", "open"), 99),
        )
    )
    for i, f in enumerate(sorted_f, 1):
        sev = (f.get("severity") or "info").lower()
        prio = PRIORITY.get(sev, "P?")
        status = (f.get("verify_status") or "open").upper()
        remediation = {}
        if f.get("remediation_json"):
            try:
                remediation = json.loads(f["remediation_json"]) or {}
            except Exception:
                pass
        owner = remediation.get("owner", "—") if isinstance(remediation, dict) else "—"
        lines.append(f"| {i} | {prio} | {f['title']} | {status} | {owner} |")

    lines.append("")
    return "\n".join(lines)


def _build_controls_json(findings: list) -> dict:
    controls: dict = {}
    for f in findings:
        if not f.get("compliance_controls_json"):
            continue
        try:
            ctrl = json.loads(f["compliance_controls_json"])
        except Exception:
            continue
        if not isinstance(ctrl, dict):
            continue
        for fw, items in ctrl.items():
            if fw not in controls:
                controls[fw] = {}
            if not isinstance(items, list):
                items = [str(items)]
            for item in items:
                if item not in controls[fw]:
                    controls[fw][item] = []
                controls[fw][item].append({
                    "finding_id": f["id"],
                    "title": f["title"],
                    "severity": f["severity"],
                })
    return controls


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------

async def _generate_report(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    project_name = (args.get("project_name") or "").strip()
    include_pdf = bool(args.get("include_pdf", False))

    if not project_id:
        return _ok("Error: project_id is required.")
    if not project_name:
        return _ok("Error: project_name is required.")

    async with get_db() as db:
        proj_row = await (await db.execute(
            "SELECT id, target, name, kind FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        if not proj_row:
            return _ok(f"Error: project_id {project_id} not found.")
        project = dict(proj_row)

        rows = await (await db.execute(
            """SELECT id, severity, title, description, evidence_json, cve_id, cvss,
                      attack_chain_position, ttp_category, mitre_attack_id, owasp_asvs_id,
                      impact, repro_steps_json, compliance_controls_json, remediation_json,
                      verify_status, created_at
               FROM risk_items WHERE project_id=?
               ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                               WHEN 'low' THEN 3 ELSE 4 END,
                 created_at""",
            (int(project_id),)
        )).fetchall()

    findings = [dict(r) for r in rows]
    ts = int(time.time())
    ts_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

    report_dir = _ws_report(project_name)

    # Build exec-summary.md
    exec_md = _build_exec_summary(project, findings, ts_str)

    # Build full findings section
    findings_sections = []
    if findings:
        findings_sections.append("## Findings\n")
        for i, f in enumerate(findings, 1):
            findings_sections.append(_build_finding_md(f, i))
    full_md = exec_md + "\n".join(findings_sections)

    exec_path = report_dir / "exec-summary.md"
    exec_path.write_text(full_md)

    # Build fix-list.md
    fix_path = report_dir / "fix-list.md"
    fix_path.write_text(_build_fix_list(findings))

    # Build controls.json
    controls = _build_controls_json(findings)
    ctrl_path = report_dir / "controls.json"
    ctrl_path.write_text(json.dumps(controls, indent=2))

    output_files = [str(exec_path), str(fix_path), str(ctrl_path)]
    pdf_note = ""

    # Optional PDF via pandoc
    if include_pdf:
        if shutil.which("pandoc"):
            pdf_path = report_dir / "report.pdf"
            _, stderr, rc = await _run(
                ["pandoc", str(exec_path), "-o", str(pdf_path),
                 "--pdf-engine=xelatex", "-V", "geometry:margin=2cm"],
                timeout=60,
            )
            if rc == 0:
                output_files.append(str(pdf_path))
                pdf_note = f"\nPDF generated: {pdf_path}"
            else:
                pdf_note = f"\nPandoc PDF failed: {stderr[:200]}"
        else:
            pdf_note = "\nPandoc not found — skipping PDF. Install: sudo apt install pandoc texlive-xetex"

    summary = (
        f"Report generated for project '{project_name}' ({len(findings)} finding(s)).\n"
        f"  exec-summary.md → {exec_path}\n"
        f"  fix-list.md     → {fix_path}\n"
        f"  controls.json   → {ctrl_path}"
        + pdf_note
    )
    return _ok(summary)


register(
    Tool(
        name="generate_report",
        description=(
            "Generate a full engagement report for a project. "
            "Writes exec-summary.md (findings + compliance), fix-list.md (remediation table), "
            "and controls.json (framework control index) to workspace/report/. "
            "Optionally generates a PDF via pandoc."
        ),
        inputSchema=_s(
            ["project_id", "project_name"],
            project_id=("integer", "Project ID"),
            project_name=("string", "Project name (used to locate workspace directory)"),
            include_pdf=("boolean", "Generate PDF via pandoc (default false)"),
        ),
    ),
    _generate_report,
)
