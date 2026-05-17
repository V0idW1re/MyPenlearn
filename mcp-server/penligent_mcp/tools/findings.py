import json
import time

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s
from ..db import get_db

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# record_finding
# ---------------------------------------------------------------------------

async def _record_finding(args: dict) -> str:
    project_id = args.get("project_id")
    severity = (args.get("severity") or "").strip().lower()
    title = (args.get("title") or "").strip()

    if not project_id:
        return "Error: project_id is required."
    if not title:
        return "Error: title is required."
    if severity not in SEVERITY_ORDER:
        return f"Error: severity must be one of {SEVERITY_ORDER}. Got: {severity!r}"

    description = (args.get("description") or "").strip()
    evidence = args.get("evidence")          # dict or None — stored as JSON
    cve_id = (args.get("cve_id") or "").strip() or None
    cvss = args.get("cvss")
    chain_pos = args.get("attack_chain_position")
    ttp_cat = (args.get("ttp_category") or "").strip() or None
    mitre_id = (args.get("mitre_attack_id") or "").strip() or None
    owasp_id = (args.get("owasp_asvs_id") or "").strip() or None
    execution_id = args.get("execution_id")

    async with get_db() as db:
        # Verify project exists
        row = await (await db.execute(
            "SELECT id FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        if not row:
            return f"Error: project_id {project_id} not found."

        cur = await db.execute(
            """INSERT INTO risk_items
               (project_id, execution_id, severity, title, description,
                evidence_json, cve_id, cvss, attack_chain_position,
                ttp_category, mitre_attack_id, owasp_asvs_id,
                verify_status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'open',?)""",
            (
                int(project_id),
                int(execution_id) if execution_id else None,
                severity,
                title,
                description,
                json.dumps(evidence) if evidence else None,
                cve_id,
                float(cvss) if cvss is not None else None,
                int(chain_pos) if chain_pos is not None else None,
                ttp_cat,
                mitre_id,
                owasp_id,
                int(time.time()),
            ),
        )
        await db.commit()
        finding_id = cur.lastrowid

    return (
        f"Finding recorded: id={finding_id} severity={severity} title={title!r}\n"
        f"  project_id={project_id} verify_status=open"
    )


register(
    Tool(
        name="record_finding",
        description=(
            "Persist a security finding to the database. "
            "Returns the new finding id. "
            "Severity must be: critical, high, medium, low, or info."
        ),
        inputSchema={
            "type": "object",
            "required": ["project_id", "severity", "title"],
            "properties": {
                "project_id": {"type": "integer"},
                "severity": {
                    "type": "string",
                    "enum": list(SEVERITY_ORDER),
                },
                "title": {"type": "string", "description": "Short finding title"},
                "description": {"type": "string", "description": "Full description"},
                "evidence": {
                    "type": "object",
                    "description": (
                        "Structured evidence: "
                        "{http_trace, screenshot, command, output, ...}"
                    ),
                },
                "cve_id": {"type": "string", "description": "CVE identifier if applicable"},
                "cvss": {"type": "number", "description": "CVSS score (0.0–10.0)"},
                "attack_chain_position": {
                    "type": "integer",
                    "description": "Position in the attack chain (1 = first step)",
                },
                "ttp_category": {
                    "type": "string",
                    "description": "TTP category slug, e.g. 'sqli', 'xss', 'rce'",
                },
                "mitre_attack_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID, e.g. 'T1190'",
                },
                "owasp_asvs_id": {
                    "type": "string",
                    "description": "OWASP ASVS control ID, e.g. 'V5.3.4'",
                },
                "execution_id": {
                    "type": "integer",
                    "description": "execution_results.id that produced this finding",
                },
            },
        },
    ),
    _record_finding,
)


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

async def _list_findings(args: dict) -> str:
    project_id = args.get("project_id")
    if not project_id:
        return "Error: project_id is required."

    severity_filter = (args.get("severity") or "").strip().lower()
    status_filter = (args.get("verify_status") or "").strip().lower()

    query = "SELECT * FROM risk_items WHERE project_id=?"
    params: list = [int(project_id)]

    if severity_filter and severity_filter in SEVERITY_ORDER:
        query += " AND severity=?"
        params.append(severity_filter)

    if status_filter in ("open", "verified", "false_positive"):
        query += " AND verify_status=?"
        params.append(status_filter)

    query += " ORDER BY CASE severity "
    query += " ".join(
        f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITY_ORDER)
    )
    query += " END, created_at DESC"

    async with get_db() as db:
        rows = await (await db.execute(query, params)).fetchall()

    if not rows:
        return f"No findings for project {project_id}."

    lines = [f"Findings for project {project_id} ({len(rows)} total):"]
    for r in rows:
        cve = f" [{r['cve_id']}]" if r["cve_id"] else ""
        cvss = f" CVSS={r['cvss']}" if r["cvss"] is not None else ""
        chain = f" chain={r['attack_chain_position']}" if r["attack_chain_position"] else ""
        lines.append(
            f"  id={r['id']} [{r['severity'].upper()}]{cve}{cvss}{chain} "
            f"status={r['verify_status']}  {r['title']}"
        )
        if r["description"]:
            lines.append(f"    {r['description'][:120]}")

    return "\n".join(lines)


register(
    Tool(
        name="list_findings",
        description=(
            "List all security findings for a project, ordered by severity. "
            "Optionally filter by severity or verify_status."
        ),
        inputSchema={
            "type": "object",
            "required": ["project_id"],
            "properties": {
                "project_id": {"type": "integer"},
                "severity": {
                    "type": "string",
                    "enum": list(SEVERITY_ORDER),
                    "description": "Filter by severity",
                },
                "verify_status": {
                    "type": "string",
                    "enum": ["open", "verified", "false_positive"],
                    "description": "Filter by verification status",
                },
            },
        },
    ),
    _list_findings,
)


# ---------------------------------------------------------------------------
# verify_finding
# ---------------------------------------------------------------------------

async def _verify_finding(args: dict) -> str:
    finding_id = args.get("finding_id")
    decision = (args.get("decision") or "").strip().lower()
    context = (args.get("context") or "").strip()

    if not finding_id:
        return "Error: finding_id is required."
    if decision not in ("verified", "false_positive"):
        return "Error: decision must be 'verified' or 'false_positive'."

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id, title, severity FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return f"Error: finding id={finding_id} not found."

        await db.execute(
            "UPDATE risk_items SET verify_status=?, verify_context=? WHERE id=?",
            (decision, context or None, int(finding_id)),
        )
        await db.commit()

    return (
        f"Finding id={finding_id} ({row['severity'].upper()}: {row['title']!r}) "
        f"marked as {decision}."
        + (f"\n  Context: {context}" if context else "")
    )


register(
    Tool(
        name="verify_finding",
        description=(
            "Update a finding's verification status to 'verified' or 'false_positive'. "
            "Optionally record a context note explaining the decision."
        ),
        inputSchema={
            "type": "object",
            "required": ["finding_id", "decision"],
            "properties": {
                "finding_id": {"type": "integer"},
                "decision": {
                    "type": "string",
                    "enum": ["verified", "false_positive"],
                },
                "context": {
                    "type": "string",
                    "description": "Note explaining verification decision",
                },
            },
        },
    ),
    _verify_finding,
)


# ---------------------------------------------------------------------------
# update_finding
# ---------------------------------------------------------------------------

async def _update_finding(args: dict) -> list[TextContent]:
    finding_id = args.get("finding_id")
    if not finding_id:
        return _ok("Error: finding_id is required.")
    updates = {}
    for field in ("title", "description", "severity", "cve_id", "cvss",
                  "mitre_attack_id", "owasp_asvs_id", "ttp_category"):
        if field in args and args[field] is not None:
            updates[field] = args[field]
    if not updates:
        return _ok("Error: no fields to update.")
    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding id={finding_id} not found.")
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [int(finding_id)]
        await db.execute(f"UPDATE risk_items SET {set_clause} WHERE id=?", values)
        await db.commit()
    return _ok(f"Finding id={finding_id} updated: {', '.join(f'{k}={v}' for k,v in updates.items())}")

register(Tool(
    name="update_finding",
    description="Update fields of an existing finding (title, description, severity, CVE, CVSS, MITRE ID, etc.).",
    inputSchema=_s(["finding_id"],
        finding_id=("integer", "Finding ID to update"),
        title=("string", "New title"),
        description=("string", "New description"),
        severity=("string", "New severity: critical/high/medium/low/info"),
        cve_id=("string", "CVE identifier"),
        cvss=("number", "CVSS score 0.0–10.0"),
        mitre_attack_id=("string", "MITRE ATT&CK technique ID"),
        owasp_asvs_id=("string", "OWASP ASVS control ID"),
        ttp_category=("string", "TTP category slug")),
), _update_finding)


# ---------------------------------------------------------------------------
# delete_finding
# ---------------------------------------------------------------------------

async def _delete_finding(args: dict) -> list[TextContent]:
    finding_id = args.get("finding_id")
    if not finding_id:
        return _ok("Error: finding_id is required.")
    async with get_db() as db:
        row = await (await db.execute(
            "SELECT title, severity FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding id={finding_id} not found.")
        await db.execute("DELETE FROM risk_items WHERE id=?", (int(finding_id),))
        await db.commit()
    return _ok(f"Finding id={finding_id} ({row['severity'].upper()}: {row['title']!r}) deleted.")

register(Tool(
    name="delete_finding",
    description="Permanently delete a finding from the database.",
    inputSchema=_s(["finding_id"],
        finding_id=("integer", "Finding ID to delete")),
), _delete_finding)


# ---------------------------------------------------------------------------
# export_findings_json
# ---------------------------------------------------------------------------

async def _export_findings_json(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    if not project_id:
        return _ok("Error: project_id is required.")
    async with get_db() as db:
        rows = await (await db.execute(
            "SELECT * FROM risk_items WHERE project_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, created_at DESC",
            (int(project_id),)
        )).fetchall()
    findings = [dict(r) for r in rows]
    return _ok(json.dumps(findings, indent=2))

register(Tool(
    name="export_findings_json",
    description="Export all findings for a project as a JSON array.",
    inputSchema=_s(["project_id"],
        project_id=("integer", "Project ID")),
), _export_findings_json)


# ---------------------------------------------------------------------------
# export_findings_markdown
# ---------------------------------------------------------------------------

async def _export_findings_markdown(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    if not project_id:
        return _ok("Error: project_id is required.")
    async with get_db() as db:
        proj = await (await db.execute(
            "SELECT name FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        rows = await (await db.execute(
            "SELECT * FROM risk_items WHERE project_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, created_at DESC",
            (int(project_id),)
        )).fetchall()
    proj_name = proj["name"] if proj else f"project-{project_id}"
    lines = [f"# Security Findings — {proj_name}\n",
             f"**Total:** {len(rows)} findings\n",
             "---\n"]
    sev_counts = {}
    for r in rows:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1
    for sev in SEVERITY_ORDER:
        if sev in sev_counts:
            lines.append(f"- **{sev.upper()}:** {sev_counts[sev]}")
    lines.append("\n---\n")
    for r in rows:
        sev = r["severity"].upper()
        lines.append(f"## [{sev}] {r['title']}")
        if r["cve_id"]:
            lines.append(f"**CVE:** {r['cve_id']}")
        if r["cvss"]:
            lines.append(f"**CVSS:** {r['cvss']}")
        if r["mitre_attack_id"]:
            lines.append(f"**MITRE ATT&CK:** {r['mitre_attack_id']}")
        lines.append(f"**Status:** {r['verify_status']}")
        if r["description"]:
            lines.append(f"\n{r['description']}")
        lines.append("\n---\n")
    return _ok("\n".join(lines))

register(Tool(
    name="export_findings_markdown",
    description="Export all findings for a project as a formatted Markdown report.",
    inputSchema=_s(["project_id"],
        project_id=("integer", "Project ID")),
), _export_findings_markdown)


# ---------------------------------------------------------------------------
# calculate_cvss_score
# ---------------------------------------------------------------------------

async def _calculate_cvss_score(args: dict) -> list[TextContent]:
    # CVSS v3.1 base score approximation
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC = {"L": 0.77, "H": 0.44}
    PR = {"N": 0.85, "L": 0.62, "H": 0.27}
    UI = {"N": 0.85, "R": 0.62}
    S_vals = {"U": False, "C": True}
    CI_vals = {"N": 0.0, "L": 0.22, "H": 0.56}

    av = args.get("attack_vector", "N")
    ac = args.get("attack_complexity", "L")
    pr = args.get("privileges_required", "N")
    ui = args.get("user_interaction", "N")
    scope = args.get("scope", "U")
    conf = args.get("confidentiality", "N")
    integ = args.get("integrity", "N")
    avail = args.get("availability", "N")

    try:
        scope_changed = S_vals.get(scope, False)
        if scope_changed and pr == "L":
            pr_val = 0.50
        elif scope_changed and pr == "H":
            pr_val = 0.50
        else:
            pr_val = PR.get(pr, 0.85)

        iss = 1 - (1 - CI_vals.get(conf, 0)) * (1 - CI_vals.get(integ, 0)) * (1 - CI_vals.get(avail, 0))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * AV.get(av, 0.85) * AC.get(ac, 0.77) * pr_val * UI.get(ui, 0.85)

        if impact <= 0:
            base_score = 0.0
        elif scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        import math
        base_score = math.ceil(base_score * 10) / 10

        if base_score == 0:
            rating = "None"
        elif base_score < 4.0:
            rating = "Low"
        elif base_score < 7.0:
            rating = "Medium"
        elif base_score < 9.0:
            rating = "High"
        else:
            rating = "Critical"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{conf}/I:{integ}/A:{avail}"
        return _ok(f"CVSS v3.1 Base Score: {base_score} ({rating})\nVector: {vector}")
    except Exception as e:
        return _ok(f"Error calculating CVSS: {e}")

register(Tool(
    name="calculate_cvss_score",
    description="Calculate a CVSS v3.1 base score from metric values.",
    inputSchema=_s([],
        attack_vector=("string", "AV: N=Network, A=Adjacent, L=Local, P=Physical (default N)"),
        attack_complexity=("string", "AC: L=Low, H=High (default L)"),
        privileges_required=("string", "PR: N=None, L=Low, H=High (default N)"),
        user_interaction=("string", "UI: N=None, R=Required (default N)"),
        scope=("string", "S: U=Unchanged, C=Changed (default U)"),
        confidentiality=("string", "C: N=None, L=Low, H=High (default N)"),
        integrity=("string", "I: N=None, L=Low, H=High (default N)"),
        availability=("string", "A: N=None, L=Low, H=High (default N)")),
), _calculate_cvss_score)


# ---------------------------------------------------------------------------
# map_mitre_attack
# ---------------------------------------------------------------------------

_MITRE_MAP = {
    "sqli": ("T1190", "Exploit Public-Facing Application"),
    "xss": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "rce": ("T1059", "Command and Scripting Interpreter"),
    "ssrf": ("T1090", "Proxy"),
    "lfi": ("T1083", "File and Directory Discovery"),
    "xxe": ("T1190", "Exploit Public-Facing Application"),
    "ssti": ("T1059", "Command and Scripting Interpreter"),
    "idor": ("T1078", "Valid Accounts"),
    "privesc": ("T1068", "Exploitation for Privilege Escalation"),
    "cred_dump": ("T1003", "OS Credential Dumping"),
    "brute": ("T1110", "Brute Force"),
    "spray": ("T1110.003", "Brute Force: Password Spraying"),
    "phishing": ("T1566", "Phishing"),
    "lateral": ("T1021", "Remote Services"),
    "persistence": ("T1543", "Create or Modify System Process"),
    "exfil": ("T1041", "Exfiltration Over C2 Channel"),
    "recon": ("T1595", "Active Scanning"),
    "osint": ("T1589", "Gather Victim Identity Information"),
}

async def _map_mitre_attack(args: dict) -> list[TextContent]:
    ttp = (args.get("ttp_category") or "").strip().lower()
    if ttp in _MITRE_MAP:
        tid, name = _MITRE_MAP[ttp]
        return _ok(f"MITRE ATT&CK mapping for '{ttp}':\n  ID: {tid}\n  Technique: {name}\n  URL: https://attack.mitre.org/techniques/{tid.replace('.','/')}/")
    lines = [f"No exact mapping for '{ttp}'. Known TTP categories:"]
    for k, (tid, name) in _MITRE_MAP.items():
        lines.append(f"  {k:15s} → {tid} ({name})")
    return _ok("\n".join(lines))

register(Tool(
    name="map_mitre_attack",
    description="Map a TTP category (e.g. sqli, xss, privesc) to its MITRE ATT&CK technique ID.",
    inputSchema=_s(["ttp_category"],
        ttp_category=("string", "TTP slug: sqli, xss, rce, ssrf, lfi, xxe, ssti, idor, privesc, cred_dump, brute, spray, phishing, lateral, persistence, exfil, recon, osint")),
), _map_mitre_attack)


# ---------------------------------------------------------------------------
# risk_summary
# ---------------------------------------------------------------------------

async def _risk_summary(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    if not project_id:
        return _ok("Error: project_id is required.")
    async with get_db() as db:
        proj = await (await db.execute(
            "SELECT name FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        rows = await (await db.execute(
            "SELECT severity, verify_status, count(*) as cnt FROM risk_items "
            "WHERE project_id=? GROUP BY severity, verify_status",
            (int(project_id),)
        )).fetchall()
    proj_name = proj["name"] if proj else f"project-{project_id}"
    counts: dict = {s: {"open": 0, "verified": 0, "false_positive": 0} for s in SEVERITY_ORDER}
    for r in rows:
        sev = r["severity"]
        status = r["verify_status"]
        if sev in counts and status in counts[sev]:
            counts[sev][status] = r["cnt"]
    lines = [f"Risk Summary — {proj_name}", ""]
    total_open = sum(counts[s]["open"] + counts[s]["verified"] for s in SEVERITY_ORDER)
    lines.append(f"Total confirmed findings: {total_open}")
    lines.append("")
    for sev in SEVERITY_ORDER:
        c = counts[sev]
        total = c["open"] + c["verified"] + c["false_positive"]
        if total:
            lines.append(f"  {sev.upper():10s} open={c['open']} verified={c['verified']} fp={c['false_positive']}")
    return _ok("\n".join(lines))

register(Tool(
    name="risk_summary",
    description="Show a counts-by-severity summary of all findings for a project.",
    inputSchema=_s(["project_id"],
        project_id=("integer", "Project ID")),
), _risk_summary)
