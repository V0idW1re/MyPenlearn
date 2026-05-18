import aiosqlite
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

DB_DIR = Path.home() / ".local" / "share" / "penligent-local"
DB_PATH = DB_DIR / "penligent.db"

SCHEMA_VERSION = 1

CREATE_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        name TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('htb_machine','htb_ctf','bug_bounty','authorized_pentest')),
        htb_machine_id INTEGER,
        htb_container_id TEXT,
        scope_json TEXT,
        status TEXT DEFAULT 'active',
        created_at INTEGER DEFAULT (strftime('%s','now')),
        updated_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        objective TEXT NOT NULL,
        constraints_json TEXT,
        kpis_json TEXT,
        compliance_targets_json TEXT,
        version INTEGER DEFAULT 1,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS plan_steps (
        id INTEGER PRIMARY KEY,
        plan_id INTEGER NOT NULL REFERENCES plans(id),
        step_idx INTEGER NOT NULL,
        verb TEXT NOT NULL,
        target TEXT,
        args_json TEXT,
        budget_json TEXT,
        status TEXT DEFAULT 'pending',
        started_at INTEGER,
        ended_at INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_results (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        plan_step_id INTEGER REFERENCES plan_steps(id),
        tool_name TEXT NOT NULL,
        tool_version TEXT,
        args_json TEXT,
        stdout_path TEXT,
        stderr_path TEXT,
        exit_code INTEGER,
        status TEXT,
        started_at INTEGER,
        ended_at INTEGER,
        claude_tool_use_id TEXT,
        artifact_hash TEXT,
        wordlist_sha256 TEXT,
        mitre_attack_id TEXT,
        owasp_asvs_id TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_items (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        execution_id INTEGER REFERENCES execution_results(id),
        severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
        title TEXT NOT NULL,
        description TEXT,
        evidence_json TEXT,
        cve_id TEXT,
        cvss REAL,
        attack_chain_position INTEGER,
        ttp_category TEXT,
        mitre_attack_id TEXT,
        owasp_asvs_id TEXT,
        impact TEXT,
        repro_steps_json TEXT,
        compliance_controls_json TEXT,
        remediation_json TEXT,
        verify_status TEXT DEFAULT 'open' CHECK(verify_status IN ('open','verified','false_positive')),
        verify_context TEXT,
        false_positive_score REAL,
        false_positive_rationale TEXT,
        blast_radius TEXT,
        confirmed_exploitable INTEGER DEFAULT 0,
        regression_required INTEGER DEFAULT 0,
        regression_verified_at INTEGER,
        regression_note TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_artifacts (
        id INTEGER PRIMARY KEY,
        risk_item_id INTEGER NOT NULL REFERENCES risk_items(id),
        kind TEXT NOT NULL,
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        har_path TEXT,
        pcap_path TEXT,
        dom_diff_path TEXT,
        console_log_path TEXT,
        reviewer TEXT,
        captured_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS fix_records (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES risk_items(id),
        patch_summary TEXT,
        tests_added TEXT,
        deployment_notes TEXT,
        fix_owner TEXT,
        created_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS verification_records (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES risk_items(id),
        fix_record_id INTEGER REFERENCES fix_records(id),
        retest_summary TEXT NOT NULL,
        evidence_of_closure TEXT,
        verified_by TEXT,
        verified_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workspace_files (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        filename TEXT NOT NULL,
        kind TEXT CHECK(kind IN ('nda','scope','machine_info','writeup','reference','notes')),
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        added_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        intent TEXT NOT NULL,
        scope_json TEXT,
        rate_limit INTEGER,
        stop_conditions_json TEXT,
        time_window INTEGER,
        requested_at INTEGER DEFAULT (strftime('%s','now')),
        decided_at INTEGER,
        decision TEXT CHECK(decision IN ('approved','denied','pending')),
        decision_note TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_sessions (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        claude_session_id TEXT,
        started_at INTEGER DEFAULT (strftime('%s','now')),
        ended_at INTEGER,
        tokens_in INTEGER DEFAULT 0,
        tokens_out INTEGER DEFAULT 0,
        cost_estimate REAL DEFAULT 0,
        vpn_state TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_messages (
        id INTEGER PRIMARY KEY,
        session_id INTEGER NOT NULL REFERENCES agent_sessions(id),
        turn_idx INTEGER NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('user','assistant','tool')),
        content_json TEXT NOT NULL,
        tokens INTEGER,
        created_at INTEGER DEFAULT (strftime('%s','now')),
        hash_prev TEXT,
        hash_self TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS vpn_profiles (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        ovpn_path TEXT NOT NULL,
        kind TEXT CHECK(kind IN ('starting_point','machines','fortresses','pro_labs','seasonal','release_arena','custom_authorized')),
        region TEXT,
        last_connected_at INTEGER,
        is_default INTEGER DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS htb_credentials (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        mcp_token_hash TEXT,
        app_token_hash TEXT,
        added_at INTEGER DEFAULT (strftime('%s','now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ttp_library (
        category TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        detection_method TEXT,
        verification_payload TEXT,
        false_positive_patterns TEXT,
        waf_bypass TEXT,
        mitre_id TEXT,
        asvs_id TEXT
    )
    """,
]

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_risk_items_project ON risk_items(project_id)",
    "CREATE INDEX IF NOT EXISTS idx_execution_results_project ON execution_results(project_id)",
    "CREATE INDEX IF NOT EXISTS idx_agent_messages_session ON agent_messages(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_plan_steps_plan ON plan_steps(plan_id)",
    "CREATE INDEX IF NOT EXISTS idx_workspace_files_project ON workspace_files(project_id)",
]


async def init_db() -> None:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=FULL")
        await db.execute("PRAGMA foreign_keys=ON")

        for stmt in CREATE_STATEMENTS:
            await db.execute(stmt)
        for idx in INDEXES:
            await db.execute(idx)

        row = await (await db.execute("SELECT version FROM schema_version")).fetchone()
        if row is None:
            await db.execute(
                "INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
            )

        # Migrate existing risk_items tables that predate these columns
        for col, typedef in [
            ("impact",                   "TEXT"),
            ("repro_steps_json",         "TEXT"),
            ("compliance_controls_json", "TEXT"),
            ("remediation_json",         "TEXT"),
            ("false_positive_rationale", "TEXT"),
            ("blast_radius",             "TEXT"),
            ("confirmed_exploitable",    "INTEGER DEFAULT 0"),
            ("regression_required",      "INTEGER DEFAULT 0"),
            ("regression_verified_at",   "INTEGER"),
            ("regression_note",          "TEXT"),
        ]:
            try:
                await db.execute(f"ALTER TABLE risk_items ADD COLUMN {col} {typedef}")
            except Exception:
                pass  # column already exists

        # Migrate evidence_artifacts
        for col, typedef in [
            ("har_path",        "TEXT"),
            ("pcap_path",       "TEXT"),
            ("dom_diff_path",   "TEXT"),
            ("console_log_path","TEXT"),
            ("reviewer",        "TEXT"),
        ]:
            try:
                await db.execute(f"ALTER TABLE evidence_artifacts ADD COLUMN {col} {typedef}")
            except Exception:
                pass

        # Migrate execution_results
        for col, typedef in [
            ("tool_version",    "TEXT"),
            ("wordlist_sha256", "TEXT"),
            ("mitre_attack_id", "TEXT"),
            ("owasp_asvs_id",   "TEXT"),
        ]:
            try:
                await db.execute(f"ALTER TABLE execution_results ADD COLUMN {col} {typedef}")
            except Exception:
                pass

        await _seed_ttp_library(db)
        await db.commit()


_TTP_SEED = [
    ("sqli",                 "SQL Injection",                "T1190", "V5.3.4"),
    ("xss",                  "Cross-Site Scripting",         "T1059.007", "V5.3.3"),
    ("rce",                  "Remote Code Execution",        "T1190", "V5.3.8"),
    ("lfi",                  "Local File Inclusion",         "T1083", "V12.3.1"),
    ("ssrf",                 "Server-Side Request Forgery",  "T1090", "V10.3.2"),
    ("idor",                 "Insecure Direct Object Ref",   "T1078", "V4.1.1"),
    ("xxe",                  "XML External Entity",          "T1190", "V5.5.1"),
    ("ssti",                 "Server-Side Template Injection","T1059", "V5.3.9"),
    ("csrf",                 "Cross-Site Request Forgery",   "T1566", "V4.2.2"),
    ("auth_bypass",          "Authentication Bypass",        "T1110", "V2.1.1"),
    ("path_traversal",       "Path Traversal",               "T1083", "V12.3.1"),
    ("cmd_injection",        "Command Injection",            "T1059", "V5.3.8"),
    ("deserialization",      "Insecure Deserialization",     "T1190", "V1.14.6"),
    ("open_redirect",        "Open Redirect",                "T1598", "V5.1.5"),
    ("file_upload",          "Unrestricted File Upload",     "T1105", "V12.1.1"),
    ("information_disclosure","Information Disclosure",      "T1213", "V7.4.1"),
    ("misconfig",            "Security Misconfiguration",    "T1190", "V14.1.1"),
]

async def _seed_ttp_library(db) -> None:
    row = await (await db.execute("SELECT COUNT(*) FROM ttp_library")).fetchone()
    if row and row[0] > 0:
        return
    for category, name, mitre_id, asvs_id in _TTP_SEED:
        try:
            await db.execute(
                "INSERT OR IGNORE INTO ttp_library(category, name, mitre_id, asvs_id) VALUES(?,?,?,?)",
                (category, name, mitre_id, asvs_id),
            )
        except Exception:
            pass


@asynccontextmanager
async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("PRAGMA journal_mode=WAL")
        db.row_factory = aiosqlite.Row
        yield db


if __name__ == "__main__":
    asyncio.run(init_db())
    print(f"DB initialized at {DB_PATH}")
