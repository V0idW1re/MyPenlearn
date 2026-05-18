"""
HITL guardrails tools (2 tools).
approve_intent: deny-by-default policy engine for sensitive operation classes.
check_sensitive_paths: Crawlergo-style 40-path heuristic for API surface discovery.
"""
import json
import os
import time

import httpx
from mcp.types import Tool, TextContent

from .register_all import register
from ._helpers import _ok, _s, _run
from ..db import get_db

# ---------------------------------------------------------------------------
# Intent policy tables
# ---------------------------------------------------------------------------

# Auto-denied for all project kinds — require explicit approval every time
DENY_ALWAYS = frozenset([
    "EGRESS_CALL",         # outbound network to non-target IPs
    "WRITE_CREDS",         # write credentials to disk outside workspace
    "MODIFY_SUDOERS",      # sudoers modification
    "INSTALL_ROOTKIT",     # persistence at boot
    "MASS_SCAN",           # /8 or larger CIDR scans
])

# Require approval unless project kind is htb_machine / htb_ctf with valid HTB token
HTB_AUTO_APPROVE = frozenset([
    "RUN_EXPLOIT",
    "SCAN_ACTIVE",
    "SPAWN_SHELL",
    "SUBMIT_FLAG",
    "RESET_MACHINE",
])

# Require approval for bug_bounty and authorized_pentest
PENTEST_GATE = frozenset([
    "SCAN_ACTIVE",
    "RUN_EXPLOIT",
    "WRITE_FILE",
    "SPAWN_SHELL",
])

# Always auto-approved (read-only / passive)
AUTO_APPROVE = frozenset([
    "READ_FILE",
    "WORKSPACE_WRITE",
    "RECORD_FINDING",
    "PASSIVE_RECON",
    "DNS_RESOLVE",
    "WHOIS",
    "CERT_TRANSPARENCY",
    "WAYBACK",
    "SHODAN_QUERY",
])


def _has_htb_token() -> bool:
    return bool(os.environ.get("HTB_APP_TOKEN", "").strip())


async def _approve_intent(args: dict) -> list[TextContent]:
    project_id = args.get("project_id")
    intent = (args.get("intent") or "").strip().upper()
    scope_json = args.get("scope")
    rate_limit = args.get("rate_limit")
    stop_conditions = args.get("stop_conditions")
    time_window = args.get("time_window")
    justification = (args.get("justification") or "").strip()

    if not project_id:
        return _ok("Error: project_id is required.")
    if not intent:
        return _ok("Error: intent is required.")

    # Hard deny — no override possible
    if intent in DENY_ALWAYS:
        return _ok(
            f"DENIED: Intent '{intent}' is in the unconditional deny list. "
            "This operation is not permitted under any circumstances in Penligent Local."
        )

    # Auto-approve passive / safe operations
    if intent in AUTO_APPROVE:
        return _ok(f"APPROVED: '{intent}' is auto-approved (passive/safe operation).")

    async with get_db() as db:
        proj_row = await (await db.execute(
            "SELECT id, kind FROM projects WHERE id=?", (int(project_id),)
        )).fetchone()
        if not proj_row:
            return _ok(f"Error: project_id {project_id} not found.")
        project_kind = proj_row["kind"]

        # HTB auto-approve path
        if project_kind in ("htb_machine", "htb_ctf") and intent in HTB_AUTO_APPROVE:
            if _has_htb_token():
                decision = "approved"
                note = f"Auto-approved: HTB project with valid token. Intent={intent}."
                await db.execute(
                    """INSERT INTO approvals
                       (project_id, intent, scope_json, rate_limit, stop_conditions_json,
                        time_window, requested_at, decided_at, decision, decision_note)
                       VALUES (?,?,?,?,?,?,?,?,'approved',?)""",
                    (
                        int(project_id), intent,
                        json.dumps(scope_json) if scope_json else None,
                        int(rate_limit) if rate_limit else None,
                        json.dumps(stop_conditions) if stop_conditions else None,
                        int(time_window) if time_window else None,
                        int(time.time()), int(time.time()), note,
                    ),
                )
                await db.commit()
                return _ok(f"APPROVED: {note}")
            else:
                return _ok(
                    f"DENIED: Intent '{intent}' on HTB project requires HTB_APP_TOKEN. "
                    "Set your HTB App Token in Penligent Local settings."
                )

        # Pentest / bug-bounty gate — record as pending, surface to user
        if intent in PENTEST_GATE or intent in HTB_AUTO_APPROVE:
            await db.execute(
                """INSERT INTO approvals
                   (project_id, intent, scope_json, rate_limit, stop_conditions_json,
                    time_window, requested_at, decision, decision_note)
                   VALUES (?,?,?,?,?,?,?,'pending',?)""",
                (
                    int(project_id), intent,
                    json.dumps(scope_json) if scope_json else None,
                    int(rate_limit) if rate_limit else None,
                    json.dumps(stop_conditions) if stop_conditions else None,
                    int(time_window) if time_window else None,
                    int(time.time()),
                    f"Awaiting operator approval. Justification: {justification}",
                ),
            )
            await db.commit()
            scope_summary = json.dumps(scope_json) if scope_json else "not specified"
            return _ok(
                f"PENDING: Intent '{intent}' requires operator approval for project kind '{project_kind}'.\n"
                f"Scope: {scope_summary}\n"
                f"Justification: {justification or '(none provided)'}\n\n"
                "The approval request has been recorded. Do not proceed until the operator "
                "explicitly grants approval in the Penligent Local UI or replies 'approved'."
            )

        # Unknown intent — deny by default
        return _ok(
            f"DENIED: Intent '{intent}' is not in any approved category for project kind '{project_kind}'. "
            "Penligent Local operates on a deny-by-default policy. "
            "If this operation is needed, request approval from the operator."
        )


register(
    Tool(
        name="approve_intent",
        description=(
            "HITL policy engine. Call this before any sensitive operation to check if it is "
            "approved for the current project. Returns APPROVED, PENDING, or DENIED with rationale. "
            "HTB projects with a valid token auto-approve RUN_EXPLOIT, SCAN_ACTIVE, SPAWN_SHELL, "
            "SUBMIT_FLAG, RESET_MACHINE. All other projects gate these intents. "
            "EGRESS_CALL, WRITE_CREDS, MODIFY_SUDOERS, INSTALL_ROOTKIT, MASS_SCAN are always denied."
        ),
        inputSchema=_s(
            ["project_id", "intent"],
            project_id=("integer", "Project ID"),
            intent=(
                "string",
                "Operation class: RUN_EXPLOIT | SCAN_ACTIVE | WRITE_FILE | EGRESS_CALL | "
                "SPAWN_SHELL | SUBMIT_FLAG | RESET_MACHINE | PASSIVE_RECON | RECORD_FINDING | "
                "WORKSPACE_WRITE | READ_FILE | DNS_RESOLVE | WHOIS | CERT_TRANSPARENCY | "
                "WAYBACK | SHODAN_QUERY | MASS_SCAN | WRITE_CREDS | MODIFY_SUDOERS | "
                "INSTALL_ROOTKIT"
            ),
            scope_json=("string", "JSON describing the target scope for this operation"),
            rate_limit=("integer", "Max requests/minute for this approval"),
            stop_conditions=("string", "JSON list of conditions that auto-revoke approval"),
            time_window=("integer", "Approval validity in seconds"),
            justification=("string", "Reason for the request — shown to operator"),
        ),
    ),
    _approve_intent,
)


# ---------------------------------------------------------------------------
# check_sensitive_paths — Crawlergo 40-path heuristic
# ---------------------------------------------------------------------------

# Verbatim 40-path list from the Penligent Local handoff specification
SENSITIVE_PATHS = [
    "/data/",
    "/json/",
    "/rest/",
    "/query",
    "/search",
    "/filter",
    "/export",
    "/import",
    "/upload/",
    "/download/",
    "/file/",
    "/document/",
    "/auth/",
    "/authenticate/",
    "/login/",
    "/signin/",
    "/logout/",
    "/signout/",
    "/register/",
    "/signup/",
    "/user/",
    "/users/",
    "/profile/",
    "/account/",
    "/session/",
    "/token/",
    "/oauth/",
    "/sso/",
    "/admin/",
    "/administrator/",
    "/manage/",
    "/manager/",
    "/config/",
    "/configuration/",
    "/setting/",
    "/settings/",
    "/backup/",
    "/restore/",
    "/debug/",
    "/test/",
    "api",
]

# Additional common API versioning prefixes to try each path under
API_PREFIXES = ["", "/api", "/api/v1", "/api/v2", "/v1", "/v2"]

# Status codes we consider "interesting" (not 404/410/501)
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500}


async def _check_sensitive_paths(args: dict) -> list[TextContent]:
    base_url = (args.get("base_url") or "").strip().rstrip("/")
    project_id = args.get("project_id")
    timeout_s = int(args.get("timeout", 10))
    use_prefixes = bool(args.get("use_prefixes", False))

    if not base_url:
        return _ok("Error: base_url is required.")

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) pentesting-agent/1.0",
        "Accept": "application/json, text/html, */*",
    }

    paths_to_check = []
    if use_prefixes:
        for prefix in API_PREFIXES:
            for path in SENSITIVE_PATHS:
                full = f"{base_url}{prefix}{path}"
                if full not in paths_to_check:
                    paths_to_check.append(full)
    else:
        paths_to_check = [f"{base_url}{path}" for path in SENSITIVE_PATHS]

    hits: list[dict] = []
    errors: list[str] = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        timeout=timeout_s,
    ) as client:
        for url in paths_to_check:
            try:
                resp = await client.get(url, headers=headers)
                code = resp.status_code
                if code in INTERESTING_CODES:
                    content_type = resp.headers.get("content-type", "")
                    server = resp.headers.get("server", "")
                    length = len(resp.content)
                    hits.append({
                        "url": url,
                        "status": code,
                        "content_type": content_type,
                        "server": server,
                        "length": length,
                        "note": _classify(code, content_type),
                    })
            except httpx.TimeoutException:
                errors.append(f"  TIMEOUT: {url}")
            except Exception as exc:
                errors.append(f"  ERROR: {url} — {exc!s:.80}")

    # Format results
    lines = [
        f"Sensitive path scan: {base_url}",
        f"Checked {len(paths_to_check)} paths — {len(hits)} interesting response(s)",
        "",
    ]

    if hits:
        lines.append("## Interesting Paths")
        lines.append("")
        # Group by note category
        for h in sorted(hits, key=lambda x: x["status"]):
            lines.append(
                f"  [{h['status']}] {h['url']}"
                f"  ({h['length']} bytes)"
                f"{' → ' + h['note'] if h['note'] else ''}"
            )
        lines.append("")

        # Auth/admin endpoints deserve special mention
        auth_hits = [h for h in hits if any(
            p in h["url"] for p in ["/auth", "/login", "/signin", "/admin", "/oauth", "/sso", "/token"]
        )]
        if auth_hits:
            lines.append("## Authentication Surface")
            lines.append("")
            for h in auth_hits:
                lines.append(f"  [{h['status']}] {h['url']}")
            lines.append("")
            lines.append(
                "Recommendation: Test each auth endpoint for brute-force protection, "
                "session fixation, token reuse, and MFA bypass."
            )
            lines.append("")

        data_hits = [h for h in hits if any(
            p in h["url"] for p in ["/data/", "/json/", "/rest/", "/api", "/export", "/download/"]
        )]
        if data_hits:
            lines.append("## Data / API Surface")
            lines.append("")
            for h in data_hits:
                lines.append(f"  [{h['status']}] {h['url']}")
            lines.append("")
            lines.append(
                "Recommendation: Test each data endpoint for IDOR, broken access control, "
                "SQLi, and mass assignment."
            )
            lines.append("")

    if errors:
        lines.append("## Errors / Timeouts")
        lines.extend(errors)
        lines.append("")

    if not hits:
        lines.append("No sensitive paths returned interesting responses.")

    result = "\n".join(lines)

    # Persist artifact
    if project_id:
        from ._helpers import _artifact
        _artifact(int(project_id), "check_sensitive_paths", result)

    return _ok(result)


def _classify(status: int, content_type: str) -> str:
    if status in (401, 403):
        return "auth-gated — test for bypass"
    if status == 200 and "json" in content_type:
        return "JSON endpoint — inspect for IDOR/BAC"
    if status == 200:
        return "accessible"
    if status in (301, 302, 307, 308):
        return "redirect — follow manually"
    if status == 500:
        return "server error — may indicate injection surface"
    if status == 405:
        return "method not allowed — try POST/PUT"
    if status == 400:
        return "bad request — probe further"
    return ""


register(
    Tool(
        name="check_sensitive_paths",
        description=(
            "Crawlergo-style 40-path heuristic scan. Probes a base URL for sensitive paths "
            "(auth endpoints, admin panels, API roots, data exports, config pages) and returns "
            "interesting responses grouped by category. Use this early in every web engagement "
            "before deeper directory brute-force."
        ),
        inputSchema=_s(
            ["base_url"],
            base_url=("string", "Base URL to probe, e.g. http://10.10.10.1"),
            project_id=("integer", "Project ID for artifact storage (optional)"),
            timeout=("integer", "Per-request timeout in seconds (default 10)"),
            use_prefixes=(
                "boolean",
                "Also try /api, /api/v1, /api/v2, /v1, /v2 prefixes (default false)"
            ),
        ),
    ),
    _check_sensitive_paths,
)
