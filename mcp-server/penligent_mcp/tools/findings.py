import json
import math
import time

from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s
from ..db import get_db

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# record_finding
# ---------------------------------------------------------------------------

async def _record_finding(args: dict) -> list:
    project_id = args.get("project_id")
    severity = (args.get("severity") or "").strip().lower()
    title = (args.get("title") or "").strip()

    if not project_id:
        return _ok("Error: project_id is required.")
    if not title:
        return _ok("Error: title is required.")
    if severity not in SEVERITY_ORDER:
        return _ok(f"Error: severity must be one of {SEVERITY_ORDER}. Got: {severity!r}")

    description = (args.get("description") or "").strip()
    evidence = args.get("evidence")
    cve_id = (args.get("cve_id") or "").strip() or None
    cvss = args.get("cvss")
    chain_pos = args.get("attack_chain_position")
    ttp_cat = (args.get("ttp_category") or "").strip() or None
    mitre_id = (args.get("mitre_attack_id") or "").strip() or None
    owasp_id = (args.get("owasp_asvs_id") or "").strip() or None
    execution_id = args.get("execution_id")
    impact = (args.get("impact") or "").strip() or None
    blast_radius = (args.get("blast_radius") or "").strip() or None
    confirmed_exploitable = 1 if args.get("confirmed_exploitable") else 0
    repro_steps = args.get("repro_steps")
    compliance = args.get("compliance_controls")
    remediation = args.get("remediation")

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: project_id {project_id} not found.")

        cur = await db.execute(
            """INSERT INTO risk_items
               (project_id, execution_id, severity, title, description,
                evidence_json, cve_id, cvss, attack_chain_position,
                ttp_category, mitre_attack_id, owasp_asvs_id,
                impact, blast_radius, confirmed_exploitable,
                repro_steps_json, compliance_controls_json, remediation_json,
                verify_status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?)""",
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
                impact,
                blast_radius,
                confirmed_exploitable,
                json.dumps(repro_steps) if repro_steps else None,
                json.dumps(compliance) if compliance else None,
                json.dumps(remediation) if remediation else None,
                int(time.time()),
            ),
        )
        await db.commit()
        finding_id = cur.lastrowid

    chain_str = f" chain={chain_pos}" if chain_pos is not None else ""
    return _ok(
        f"Finding recorded: id={finding_id} severity={severity}{chain_str} title={title!r}\n"
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
                "impact": {
                    "type": "string",
                    "description": "One sentence: what an attacker gains if exploited",
                },
                "blast_radius": {
                    "type": "string",
                    "description": "What an attacker would get in production — scope of damage",
                },
                "confirmed_exploitable": {
                    "type": "boolean",
                    "description": "True only when all 5 evidence conditions are met",
                },
                "repro_steps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered list of exact steps to reproduce the finding",
                },
                "compliance_controls": {
                    "type": "object",
                    "description": (
                        "Compliance framework mappings, e.g. "
                        "{\"NIST_800_115\": [\"Testing Authentication Mechanisms\"], "
                        "\"ISO_27001\": [\"A.9.4 Access Control\"], "
                        "\"PCI_DSS\": [\"8.3 Strong Cryptography\"]}"
                    ),
                },
                "remediation": {
                    "type": "object",
                    "description": (
                        "Remediation spec: "
                        "{\"owner\": \"team\", \"priority\": \"P1\", "
                        "\"actions\": [\"...\"], \"verification\": \"...\"}"
                    ),
                },
            },
        },
    ),
    _record_finding,
)


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

async def _list_findings(args: dict) -> list:
    project_id = args.get("project_id")
    if not project_id:
        return _ok("Error: project_id is required.")

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
        return _ok(f"No findings for project {project_id}.")

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

    return _ok("\n".join(lines))


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

async def _verify_finding(args: dict) -> list:
    finding_id = args.get("finding_id")
    decision = (args.get("decision") or "").strip().lower()
    context = (args.get("context") or "").strip()

    if not finding_id:
        return _ok("Error: finding_id is required.")
    if decision not in ("verified", "false_positive"):
        return _ok("Error: decision must be 'verified' or 'false_positive'.")

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id, title, severity FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding id={finding_id} not found.")

        await db.execute(
            "UPDATE risk_items SET verify_status=?, verify_context=? WHERE id=?",
            (decision, context or None, int(finding_id)),
        )
        await db.commit()

    return _ok(
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
        chain = f" · Chain #{r['attack_chain_position']}" if r["attack_chain_position"] else ""
        lines.append(f"## [{sev}]{chain} {r['title']}")
        meta = []
        if r["cve_id"]:
            meta.append(f"**CVE:** {r['cve_id']}")
        if r["cvss"]:
            meta.append(f"**CVSS:** {r['cvss']}")
        if r["mitre_attack_id"]:
            meta.append(f"**MITRE:** {r['mitre_attack_id']}")
        if r["owasp_asvs_id"]:
            meta.append(f"**ASVS:** {r['owasp_asvs_id']}")
        meta.append(f"**Status:** {r['verify_status']}")
        if meta:
            lines.append("  ".join(meta))
        if r["description"]:
            lines.append(f"\n{r['description']}")
        if r["impact"]:
            lines.append(f"\n**Impact:** {r['impact']}")
        repro = r["repro_steps_json"]
        if repro:
            try:
                steps = json.loads(repro)
                lines.append("\n**Reproduction Steps:**")
                for i, s in enumerate(steps, 1):
                    lines.append(f"{i}. {s}")
            except Exception:
                pass
        controls = r["compliance_controls_json"]
        if controls:
            try:
                ctrl = json.loads(controls)
                lines.append("\n**Compliance Controls:**")
                for fw, items in ctrl.items():
                    lines.append(f"- {fw}: {', '.join(items) if isinstance(items, list) else items}")
            except Exception:
                pass
        remediation = r["remediation_json"]
        if remediation:
            try:
                rem = json.loads(remediation)
                lines.append("\n**Remediation:**")
                if rem.get("owner"):
                    lines.append(f"- Owner: {rem['owner']}")
                if rem.get("priority"):
                    lines.append(f"- Priority: {rem['priority']}")
                for action in rem.get("actions", []):
                    lines.append(f"- {action}")
                if rem.get("verification"):
                    lines.append(f"- Verification: {rem['verification']}")
            except Exception:
                pass
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

    av = (args.get("attack_vector") or "N").strip().upper()
    ac = (args.get("attack_complexity") or "L").strip().upper()
    pr = (args.get("privileges_required") or "N").strip().upper()
    ui = (args.get("user_interaction") or "N").strip().upper()
    scope = (args.get("scope") or "U").strip().upper()
    conf = (args.get("confidentiality") or "N").strip().upper()
    integ = (args.get("integrity") or "N").strip().upper()
    avail = (args.get("availability") or "N").strip().upper()

    invalid = []
    if av not in AV: invalid.append(f"attack_vector={av!r} (valid: N/A/L/P)")
    if ac not in AC: invalid.append(f"attack_complexity={ac!r} (valid: L/H)")
    if pr not in PR: invalid.append(f"privileges_required={pr!r} (valid: N/L/H)")
    if ui not in UI: invalid.append(f"user_interaction={ui!r} (valid: N/R)")
    if scope not in S_vals: invalid.append(f"scope={scope!r} (valid: U/C)")
    if conf not in CI_vals: invalid.append(f"confidentiality={conf!r} (valid: N/L/H)")
    if integ not in CI_vals: invalid.append(f"integrity={integ!r} (valid: N/L/H)")
    if avail not in CI_vals: invalid.append(f"availability={avail!r} (valid: N/L/H)")
    if invalid:
        return _ok("Error: invalid CVSS metric(s):\n" + "\n".join(f"  {e}" for e in invalid))

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
    "broken_access_control": ("T1078", "Valid Accounts"),
    "auth_bypass": ("T1078", "Valid Accounts"),
    "session_fixation": ("T1185", "Browser Session Hijacking"),
    "csrf": ("T1185", "Browser Session Hijacking"),
    "waf_bypass": ("T1027", "Obfuscated Files or Information"),
    "open_redirect": ("T1090", "Proxy"),
    "path_traversal": ("T1083", "File and Directory Discovery"),
    "file_upload": ("T1505.003", "Server Software Component: Web Shell"),
    "xml_injection": ("T1190", "Exploit Public-Facing Application"),
    "xpath_injection": ("T1190", "Exploit Public-Facing Application"),
    "info_disclosure": ("T1040", "Network Sniffing"),
    "misconfig": ("T1190", "Exploit Public-Facing Application"),
    "deserialization": ("T1059", "Command and Scripting Interpreter"),
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
    description="Map a TTP category to its MITRE ATT&CK technique ID.",
    inputSchema=_s(["ttp_category"],
        ttp_category=("string", "TTP slug: sqli, xss, rce, ssrf, lfi, xxe, ssti, idor, broken_access_control, auth_bypass, session_fixation, csrf, waf_bypass, open_redirect, path_traversal, file_upload, xml_injection, xpath_injection, info_disclosure, misconfig, deserialization, privesc, cred_dump, brute, spray, phishing, lateral, persistence, exfil, recon, osint")),
), _map_mitre_attack)


# ---------------------------------------------------------------------------
# map_owasp_asvs
# ---------------------------------------------------------------------------

_ASVS_MAP = {
    "auth_bypass":           ("V2.1",  "V2 Authentication — Passwords"),
    "brute":                 ("V2.2",  "V2 Authentication — General Authenticator Requirements"),
    "session_fixation":      ("V3.3",  "V3 Session Management — Session Termination"),
    "csrf":                  ("V4.2.3","V4 Access Control — Anti-CSRF Controls"),
    "broken_access_control": ("V4.1",  "V4 Access Control — General"),
    "idor":                  ("V4.2",  "V4 Access Control — Object Level Access Control"),
    "sqli":                  ("V5.3.4","V5 Validation — SQL and Database Queries"),
    "xss":                   ("V5.3.3","V5 Validation — Contextual Output Encoding"),
    "rce":                   ("V5.2",  "V5 Validation — Sanitization and Sandboxing"),
    "lfi":                   ("V12.1", "V12 Files and Resources — File Upload"),
    "path_traversal":        ("V12.3", "V12 Files and Resources — File Execution"),
    "file_upload":           ("V12.2", "V12 Files and Resources — File Integrity"),
    "ssrf":                  ("V10.3", "V10 Malicious Code — Application Integrity"),
    "xxe":                   ("V14.3", "V14 Configuration — Dependency Security"),
    "ssti":                  ("V5.2",  "V5 Validation — Sanitization and Sandboxing"),
    "open_redirect":         ("V5.1.5","V5 Validation — Input Validation Requirements"),
    "info_disclosure":       ("V8.3",  "V8 Data Protection — Private Data"),
    "misconfig":             ("V14.1", "V14 Configuration — Build and Deploy"),
    "deserialization":       ("V1.5",  "V1 Architecture — Input and Output Architecture"),
    "privesc":               ("V4.1",  "V4 Access Control — General"),
    "xml_injection":         ("V5.5.1","V5 Validation — XML and XPath Injection Prevention"),
    "xpath_injection":       ("V5.5.2","V5 Validation — XML and XPath Injection Prevention"),
    "waf_bypass":            ("V5.3",  "V5 Validation — Output Encoding and Injection Prevention"),
    "cred_dump":             ("V2.6",  "V2 Authentication — Credential Storage"),
    "recon":                 ("V14.2", "V14 Configuration — Dependency Security"),
}

async def _map_owasp_asvs(args: dict) -> list[TextContent]:
    ttp = (args.get("ttp_category") or "").strip().lower()
    if ttp in _ASVS_MAP:
        ctrl_id, name = _ASVS_MAP[ttp]
        return _ok(
            f"OWASP ASVS mapping for '{ttp}':\n"
            f"  Control ID: {ctrl_id}\n"
            f"  Section: {name}\n"
            f"  URL: https://owasp.org/www-project-application-security-verification-standard/"
        )
    lines = [f"No exact ASVS mapping for '{ttp}'. Known categories:"]
    for k, (ctrl_id, name) in _ASVS_MAP.items():
        lines.append(f"  {k:25s} → {ctrl_id} ({name})")
    return _ok("\n".join(lines))

register(Tool(
    name="map_owasp_asvs",
    description="Map a TTP category to its OWASP Application Security Verification Standard (ASVS) control ID.",
    inputSchema=_s(["ttp_category"],
        ttp_category=("string", "TTP slug: auth_bypass, brute, session_fixation, csrf, broken_access_control, idor, sqli, xss, rce, lfi, path_traversal, file_upload, ssrf, xxe, xml_injection, xpath_injection, ssti, open_redirect, info_disclosure, misconfig, deserialization, privesc, waf_bypass, cred_dump, recon")),
), _map_owasp_asvs)


# ---------------------------------------------------------------------------
# mark_regression — record post-fix regression test result
# ---------------------------------------------------------------------------

async def _mark_regression(args: dict) -> list[TextContent]:
    finding_id = args.get("finding_id")
    passed = args.get("passed")  # True = fix worked, False = still vulnerable
    note = (args.get("note") or "").strip()

    if not finding_id:
        return _ok("Error: finding_id is required.")
    if passed is None:
        return _ok("Error: passed (boolean) is required.")

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding_id {finding_id} not found.")

        if passed:
            await db.execute(
                """UPDATE risk_items
                   SET regression_required=0, regression_verified_at=?, regression_note=?,
                       verify_status='verified'
                   WHERE id=?""",
                (int(time.time()), note or "Regression test passed — fix confirmed.", int(finding_id)),
            )
            msg = f"Finding {finding_id}: regression PASSED — marked verified."
        else:
            await db.execute(
                """UPDATE risk_items
                   SET regression_required=1, regression_note=?, verify_status='open'
                   WHERE id=?""",
                (note or "Regression test FAILED — vulnerability persists after fix.", int(finding_id)),
            )
            msg = f"Finding {finding_id}: regression FAILED — still vulnerable."

        await db.commit()
    return _ok(msg)

register(Tool(
    name="mark_regression",
    description=(
        "Record the result of a post-fix regression test. "
        "If passed=true, sets verify_status='verified' and records regression_verified_at. "
        "If passed=false, sets regression_required=1 and records the note. "
        "Call after re-running the exact reproduction steps from the original finding."
    ),
    inputSchema=_s(
        ["finding_id", "passed"],
        finding_id=("integer", "risk_items.id to update"),
        passed=("boolean", "True if the fix resolved the vulnerability, False if it persists"),
        note=("string", "Notes from the regression run"),
    ),
), _mark_regression)


# ---------------------------------------------------------------------------
# map_owasp_top10
# ---------------------------------------------------------------------------

_TOP10_MAP = {
    "broken_access_control": ("A01:2021", "Broken Access Control"),
    "idor":                  ("A01:2021", "Broken Access Control"),
    "privesc":               ("A01:2021", "Broken Access Control"),
    "auth_bypass":           ("A07:2021", "Identification and Authentication Failures"),
    "brute":                 ("A07:2021", "Identification and Authentication Failures"),
    "session_fixation":      ("A07:2021", "Identification and Authentication Failures"),
    "cred_dump":             ("A02:2021", "Cryptographic Failures"),
    "sqli":                  ("A03:2021", "Injection"),
    "xss":                   ("A03:2021", "Injection"),
    "cmdi":                  ("A03:2021", "Injection"),
    "ssti":                  ("A03:2021", "Injection"),
    "xml_injection":         ("A03:2021", "Injection"),
    "xpath_injection":       ("A03:2021", "Injection"),
    "xxe":                   ("A03:2021", "Injection"),
    "misconfig":             ("A05:2021", "Security Misconfiguration"),
    "info_disclosure":       ("A05:2021", "Security Misconfiguration"),
    "csrf":                  ("A01:2021", "Broken Access Control"),
    "deserialization":       ("A08:2021", "Software and Data Integrity Failures"),
    "file_upload":           ("A04:2021", "Insecure Design"),
    "path_traversal":        ("A01:2021", "Broken Access Control"),
    "lfi":                   ("A01:2021", "Broken Access Control"),
    "ssrf":                  ("A10:2021", "Server-Side Request Forgery"),
    "open_redirect":         ("A01:2021", "Broken Access Control"),
    "recon":                 ("A05:2021", "Security Misconfiguration"),
    "osint":                 ("A05:2021", "Security Misconfiguration"),
    "waf_bypass":            ("A05:2021", "Security Misconfiguration"),
    "ai_prompt_injection":   ("A03:2021", "Injection"),
    "lateral":               ("A01:2021", "Broken Access Control"),
    "persistence":           ("A08:2021", "Software and Data Integrity Failures"),
    "exfil":                 ("A09:2021", "Security Logging and Monitoring Failures"),
}

async def _map_owasp_top10(args: dict) -> list[TextContent]:
    ttp = (args.get("ttp_category") or "").strip().lower()
    if ttp in _TOP10_MAP:
        code, name = _TOP10_MAP[ttp]
        return _ok(
            f"OWASP Top 10 mapping for '{ttp}':\n"
            f"  Code: {code}\n"
            f"  Category: {name}\n"
            f"  URL: https://owasp.org/Top10/"
        )
    lines = [f"No exact Top 10 mapping for '{ttp}'. Full mapping:"]
    seen: set = set()
    for k, (code, name) in _TOP10_MAP.items():
        if code not in seen:
            lines.append(f"  {code} — {name}")
            seen.add(code)
    return _ok("\n".join(lines))

register(Tool(
    name="map_owasp_top10",
    description="Map a TTP category to its OWASP Top 10 (2021) category code and name.",
    inputSchema=_s(["ttp_category"],
        ttp_category=("string", "TTP slug: sqli, xss, ssrf, idor, auth_bypass, misconfig, deserialization, ai_prompt_injection, etc.")),
), _map_owasp_top10)


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


# ---------------------------------------------------------------------------
# record_fix — document the fix applied to a finding
# ---------------------------------------------------------------------------

async def _record_fix(args: dict) -> list[TextContent]:
    finding_id = args.get("finding_id")
    patch_summary = (args.get("patch_summary") or "").strip()
    if not finding_id:
        return _ok("Error: finding_id is required.")
    if not patch_summary:
        return _ok("Error: patch_summary is required.")

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding_id {finding_id} not found.")
        cur = await db.execute(
            """INSERT INTO fix_records
               (finding_id, patch_summary, tests_added, deployment_notes, fix_owner, created_at)
               VALUES (?,?,?,?,?,?)""",
            (
                int(finding_id),
                patch_summary,
                (args.get("tests_added") or "").strip() or None,
                (args.get("deployment_notes") or "").strip() or None,
                (args.get("fix_owner") or "").strip() or None,
                int(time.time()),
            ),
        )
        await db.commit()
        fix_id = cur.lastrowid
    return _ok(f"Fix record created: id={fix_id} for finding_id={finding_id}")


register(Tool(
    name="record_fix",
    description=(
        "Document the fix applied to a finding. "
        "Call after a patch ships, before running record_verification. "
        "Creates a fix_records entry linked to the finding."
    ),
    inputSchema=_s(
        ["finding_id", "patch_summary"],
        finding_id=("integer", "risk_items.id this fix addresses"),
        patch_summary=("string", "Description of the patch — what was changed and where"),
        tests_added=("string", "Regression tests added to prevent recurrence"),
        deployment_notes=("string", "Deployment context — env, version, PR reference"),
        fix_owner=("string", "Team or person responsible for the fix"),
    ),
), _record_fix)


# ---------------------------------------------------------------------------
# record_verification — document black-box re-test confirming fix closure
# ---------------------------------------------------------------------------

async def _record_verification(args: dict) -> list[TextContent]:
    finding_id = args.get("finding_id")
    retest_summary = (args.get("retest_summary") or "").strip()
    if not finding_id:
        return _ok("Error: finding_id is required.")
    if not retest_summary:
        return _ok("Error: retest_summary is required.")

    fix_record_id = args.get("fix_record_id")
    evidence_of_closure = (args.get("evidence_of_closure") or "").strip() or None
    verified_by = (args.get("verified_by") or "").strip() or None

    async with get_db() as db:
        row = await (await db.execute(
            "SELECT id FROM risk_items WHERE id=?", (int(finding_id),)
        )).fetchone()
        if not row:
            return _ok(f"Error: finding_id {finding_id} not found.")
        cur = await db.execute(
            """INSERT INTO verification_records
               (finding_id, fix_record_id, retest_summary, evidence_of_closure,
                verified_by, verified_at)
               VALUES (?,?,?,?,?,?)""",
            (
                int(finding_id),
                int(fix_record_id) if fix_record_id else None,
                retest_summary,
                evidence_of_closure,
                verified_by,
                int(time.time()),
            ),
        )
        # Auto-update the finding status
        await db.execute(
            "UPDATE risk_items SET verify_status='verified', regression_required=0, "
            "regression_verified_at=? WHERE id=?",
            (int(time.time()), int(finding_id)),
        )
        await db.commit()
        ver_id = cur.lastrowid
    return _ok(
        f"Verification record created: id={ver_id} for finding_id={finding_id}\n"
        f"Finding marked verified."
    )


register(Tool(
    name="record_verification",
    description=(
        "Document the black-box re-test confirming a finding is closed. "
        "Call after record_fix, re-running the exact reproduction steps. "
        "Marks the finding as verified and creates a verification_records entry."
    ),
    inputSchema=_s(
        ["finding_id", "retest_summary"],
        finding_id=("integer", "risk_items.id being verified"),
        fix_record_id=("integer", "fix_records.id (optional, links fix to verification)"),
        retest_summary=("string", "Summary of the re-test: what was tested, what was observed"),
        evidence_of_closure=("string", "Path to evidence artifact or description of proof"),
        verified_by=("string", "Researcher identity performing the re-test"),
    ),
), _record_verification)

# ---------------------------------------------------------------------------
# ttp_lookup — look up a TTP category in the library
# ---------------------------------------------------------------------------

async def _ttp_lookup(args: dict) -> list[TextContent]:
    category = (args.get("category") or "").strip().lower()
    if not category:
        return _ok("Error: category is required.")
    try:
        async with get_db() as db:
            row = await (await db.execute(
                "SELECT category, name, detection_method, verification_payload, "
                "false_positive_patterns, waf_bypass, mitre_id, asvs_id "
                "FROM ttp_library WHERE category=?",
                (category,)
            )).fetchone()
            if not row:
                # Fall back to substring match
                row = await (await db.execute(
                    "SELECT category, name, detection_method, verification_payload, "
                    "false_positive_patterns, waf_bypass, mitre_id, asvs_id "
                    "FROM ttp_library WHERE category LIKE ?",
                    (f"%{category}%",)
                )).fetchone()
    except Exception as e:
        return _ok(f"DB error: {e}")

    if not row:
        return _ok(f"No TTP entry found for '{category}'.")

    record = dict(row)
    lines = [f"TTP: {record['name']} ({record['category']})"]
    if record.get("mitre_id"):
        lines.append(f"MITRE ATT&CK: {record['mitre_id']}")
    if record.get("asvs_id"):
        lines.append(f"OWASP ASVS:   {record['asvs_id']}")
    for k in ("detection_method", "verification_payload", "false_positive_patterns", "waf_bypass"):
        if record.get(k):
            lines.append(f"\n{k.replace('_', ' ').title()}:\n{record[k]}")
    return _ok("\n".join(lines))

register(Tool(
    name="ttp_lookup",
    description=(
        "Look up a TTP (technique/tactic/procedure) category in the library. "
        "Returns MITRE ATT&CK ID, OWASP ASVS ID, detection method, verification payload, "
        "false-positive patterns, and WAF bypass hints. "
        "Categories: sqli, xss, rce, lfi, ssrf, idor, xxe, ssti, csrf, auth_bypass, "
        "path_traversal, cmd_injection, deserialization, open_redirect, file_upload, "
        "information_disclosure, misconfig."
    ),
    inputSchema=_s(["category"],
        category=("string", "TTP category slug (e.g. 'sqli', 'xss', 'ssrf')")),
), _ttp_lookup)
