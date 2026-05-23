use serde::{Deserialize, Serialize};
use serde_json;
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use sha2::{Sha256, Digest};

static SCHEMA_DONE: AtomicBool = AtomicBool::new(false);

// ── Struct definitions ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub project_id: i64,
    pub title: String,
    pub severity: String,
    pub description: Option<String>,
    pub status: String,             // mapped from verify_status
    pub found_at: i64,              // mapped from created_at (unix epoch)
    pub chain_position: Option<i64>,
    pub cve_id: Option<String>,
    pub mitre_id: Option<String>,
    pub owasp_asvs_id: Option<String>,
    pub ttp_category: Option<String>,
    pub impact: Option<String>,
    pub compliance_controls: Option<String>, // raw JSON string
    pub remediation: Option<String>,         // raw JSON string
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: i64,
    pub project_id: i64,
    pub role: String,
    pub content: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub target: String,
    pub kind: String,
    pub status: String,
    pub created_at: i64,
}

// ── DB helpers ───────────────────────────────────────────────────────────────

fn db_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".local/share/penligent-local/penligent.db")
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".local/share/penligent-local/config.json")
}

pub fn open_db() -> Result<Connection, String> {
    open()
}

fn open() -> Result<Connection, String> {
    let path = db_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("mkdir failed: {e}"))?;
    }
    let conn = Connection::open(&path).map_err(|e| format!("DB open failed: {e}"))?;
    conn.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA journal_mode=WAL;")
        .map_err(|e| format!("PRAGMA failed: {e}"))?;
    if !SCHEMA_DONE.load(Ordering::Relaxed) {
        ensure_schema(&conn)?;
        SCHEMA_DONE.store(true, Ordering::Relaxed);
    }
    Ok(conn)
}

// Creates the tables that Rust reads/writes so the app works before the
// Python MCP server has ever run.  Matches the Python schema exactly so
// subsequent CREATE TABLE IF NOT EXISTS calls from Python are no-ops.
fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS projects (
            id               INTEGER PRIMARY KEY,
            target           TEXT    NOT NULL DEFAULT '',
            name             TEXT    NOT NULL,
            kind             TEXT    NOT NULL,
            htb_machine_id   INTEGER,
            htb_container_id TEXT,
            scope_json       TEXT,
            status           TEXT    DEFAULT 'active',
            created_at       INTEGER DEFAULT (strftime('%s','now')),
            updated_at       INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS chat_messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL,
            role        TEXT    NOT NULL,
            content     TEXT    NOT NULL,
            created_at  INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS workspace_files (
            id         INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            filename   TEXT    NOT NULL,
            kind       TEXT,
            path       TEXT    NOT NULL,
            sha256     TEXT    NOT NULL,
            added_at   INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS agent_sessions (
            id                INTEGER PRIMARY KEY,
            project_id        INTEGER NOT NULL,
            claude_session_id TEXT,
            started_at        INTEGER DEFAULT (strftime('%s','now')),
            ended_at          INTEGER,
            vpn_state         TEXT,
            tokens_in         INTEGER DEFAULT 0,
            tokens_out        INTEGER DEFAULT 0,
            cost_estimate     REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS vpn_profiles (
            id                INTEGER PRIMARY KEY,
            name              TEXT    NOT NULL,
            ovpn_path         TEXT    NOT NULL,
            kind              TEXT,
            region            TEXT,
            last_connected_at INTEGER,
            is_default        INTEGER DEFAULT 0
        );",
    )
    .map_err(|e| e.to_string())?;

    // Migrate agent_sessions for older DBs that predate cost/token columns
    for (col, typedef) in &[
        ("vpn_state",     "TEXT"),
        ("tokens_in",     "INTEGER DEFAULT 0"),
        ("tokens_out",    "INTEGER DEFAULT 0"),
        ("cost_estimate", "REAL DEFAULT 0"),
    ] {
        let _ = conn.execute_batch(&format!(
            "ALTER TABLE agent_sessions ADD COLUMN {col} {typedef}"
        ));
    }

    // Mirror the Python MCP server's risk_items migrations so the Findings
    // panel works even when the user opens the app before the MCP server
    // ever runs. Each statement is idempotent (silently fails if the column
    // already exists, or if risk_items itself doesn't yet exist).
    // See mcp-server/penligent_mcp/db.py — keep these two lists in sync.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='risk_items'",
            [],
            |r| r.get::<_, i32>(0),
        )
        .unwrap_or(0) > 0;
    if table_exists {
        for (col, typedef) in &[
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
        ] {
            let _ = conn.execute_batch(&format!(
                "ALTER TABLE risk_items ADD COLUMN {col} {typedef}"
            ));
        }
    }
    Ok(())
}

// ── Config ───────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn save_config_value(key: String, value: String) -> Result<(), String> {
    let path = config_path();
    let mut cfg: serde_json::Value = if path.exists() {
        serde_json::from_str(
            &std::fs::read_to_string(&path).map_err(|e| e.to_string())?
        ).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    cfg[key] = serde_json::Value::String(value);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_config_value(key: String) -> Result<Option<String>, String> {
    let path = config_path();
    if !path.exists() {
        return Ok(None);
    }
    let cfg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| e.to_string())?
    )
    .unwrap_or_else(|_| serde_json::json!({}));
    Ok(cfg[key].as_str().map(String::from))
}

// ── Projects ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_projects() -> Result<Vec<Project>, String> {
    let conn = open()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, COALESCE(target,''), kind, status, created_at \
             FROM projects ORDER BY created_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                target: row.get(2)?,
                kind: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

#[tauri::command]
pub fn create_project(name: String, target: String, kind: String, scope_json: Option<String>) -> Result<Project, String> {
    let valid_kinds = ["htb_machine", "htb_ctf", "bug_bounty", "authorized_pentest"];
    if !valid_kinds.contains(&kind.as_str()) {
        return Err(format!("Invalid kind: {kind}"));
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name cannot be empty".into());
    }
    if name.contains('/') || name.contains("..") {
        return Err("Name cannot contain '/' or '..'".into());
    }

    let workspace = dirs::home_dir()
        .unwrap_or_default()
        .join("penligent/projects")
        .join(&name)
        .join("workspace");
    std::fs::create_dir_all(&workspace)
        .map_err(|e| format!("Failed to create workspace: {e}"))?;

    let scope = scope_json.filter(|s| !s.trim().is_empty());
    let conn = open()?;
    conn.execute(
        "INSERT INTO projects (target, name, kind, scope_json) VALUES (?1, ?2, ?3, ?4)",
        params![target, name, kind, scope],
    )
    .map_err(|e| e.to_string())?;

    let id = conn.last_insert_rowid();
    Ok(Project {
        id,
        name,
        target,
        kind,
        status: "active".into(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    })
}

#[tauri::command]
pub fn rename_project(id: i64, name: String) -> Result<Project, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name cannot be empty".into());
    }
    let conn = open()?;
    conn.execute(
        "UPDATE projects SET name = ?1, updated_at = strftime('%s','now') WHERE id = ?2",
        params![name, id],
    )
    .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, COALESCE(target,''), kind, status, created_at \
             FROM projects WHERE id = ?1",
        )
        .map_err(|e| e.to_string())?;
    stmt.query_row(params![id], |row| {
        Ok(Project {
            id:         row.get(0)?,
            name:       row.get(1)?,
            target:     row.get(2)?,
            kind:       row.get(3)?,
            status:     row.get(4)?,
            created_at: row.get(5)?,
        })
    })
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_project(id: i64) -> Result<(), String> {
    let mut conn = open()?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM chat_messages WHERE project_id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    let _ = tx.execute("DELETE FROM approvals WHERE project_id = ?1", params![id]);
    let _ = tx.execute("DELETE FROM agent_sessions WHERE project_id = ?1", params![id]);
    let _ = tx.execute("DELETE FROM workspace_files WHERE project_id = ?1", params![id]);
    let _ = tx.execute("DELETE FROM execution_results WHERE project_id = ?1", params![id]);
    let _ = tx.execute(
        "DELETE FROM plan_steps WHERE plan_id IN (SELECT id FROM plans WHERE project_id = ?1)",
        params![id],
    );
    let _ = tx.execute("DELETE FROM plans WHERE project_id = ?1", params![id]);
    let _ = tx.execute("DELETE FROM risk_items WHERE project_id = ?1", params![id]);
    tx.execute("DELETE FROM projects WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

// ── Chat messages ─────────────────────────────────────────────────────────────

#[tauri::command]
pub fn save_message(project_id: i64, role: String, content: String) -> Result<i64, String> {
    let conn = open()?;
    conn.execute(
        "INSERT INTO chat_messages (project_id, role, content) VALUES (?1, ?2, ?3)",
        params![project_id, role, content],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

#[tauri::command]
pub fn load_messages(project_id: i64) -> Result<Vec<ChatMessage>, String> {
    let conn = open()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, project_id, role, content, created_at \
             FROM chat_messages WHERE project_id = ?1 ORDER BY created_at, id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(ChatMessage {
                id:         row.get(0)?,
                project_id: row.get(1)?,
                role:       row.get(2)?,
                content:    row.get(3)?,
                created_at: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ── Findings ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_findings(project_id: i64) -> Result<Vec<Finding>, String> {
    let conn = open()?;

    // risk_items is created by the Python MCP server; return empty until it exists.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='risk_items'",
            [],
            |r| r.get::<_, i32>(0),
        )
        .unwrap_or(0) > 0;
    if !table_exists {
        return Ok(vec![]);
    }

    let mut stmt = conn
        .prepare(
            "SELECT id, project_id, title, severity, description,
                    verify_status, created_at,
                    attack_chain_position, cve_id, mitre_attack_id,
                    owasp_asvs_id, ttp_category,
                    impact, compliance_controls_json, remediation_json
             FROM risk_items WHERE project_id = ?1
             ORDER BY CASE severity
               WHEN 'critical' THEN 0 WHEN 'high' THEN 1
               WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
             created_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(Finding {
                id:                  row.get(0)?,
                project_id:          row.get(1)?,
                title:               row.get(2)?,
                severity:            row.get(3)?,
                description:         row.get(4)?,
                status:              row.get(5)?,
                found_at:            row.get(6)?,
                chain_position:      row.get(7)?,
                cve_id:              row.get(8)?,
                mitre_id:            row.get(9)?,
                owasp_asvs_id:       row.get(10)?,
                ttp_category:        row.get(11)?,
                impact:              row.get(12)?,
                compliance_controls: row.get(13)?,
                remediation:         row.get(14)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

#[tauri::command]
pub fn clear_messages(project_id: i64) -> Result<(), String> {
    let conn = open()?;
    conn.execute(
        "DELETE FROM chat_messages WHERE project_id = ?1",
        params![project_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ── Approvals ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Approval {
    pub id: i64,
    pub project_id: i64,
    pub intent: String,
    pub scope_json: Option<String>,
    pub rate_limit: Option<i64>,
    pub stop_conditions_json: Option<String>,
    pub time_window: Option<i64>,
    pub decision_note: Option<String>,
    pub requested_at: i64,
    pub project_kind: String,
}

#[tauri::command]
pub fn list_pending_approvals(project_id: i64) -> Result<Vec<Approval>, String> {
    let conn = open()?;

    // Table may not exist yet if Python MCP server has never run.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='approvals'",
            [],
            |r| r.get::<_, i32>(0),
        )
        .unwrap_or(0) > 0;
    if !table_exists {
        return Ok(vec![]);
    }

    let mut stmt = conn
        .prepare(
            "SELECT a.id, a.project_id, a.intent, a.scope_json, a.rate_limit, \
             a.stop_conditions_json, a.time_window, a.decision_note, a.requested_at, \
             COALESCE(p.kind, '') \
             FROM approvals a \
             LEFT JOIN projects p ON p.id = a.project_id \
             WHERE a.project_id = ?1 AND a.decision = 'pending' \
             ORDER BY a.requested_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(Approval {
                id:                   row.get(0)?,
                project_id:           row.get(1)?,
                intent:               row.get(2)?,
                scope_json:           row.get(3)?,
                rate_limit:           row.get(4)?,
                stop_conditions_json: row.get(5)?,
                time_window:          row.get(6)?,
                decision_note:        row.get(7)?,
                requested_at:         row.get(8)?,
                project_kind:         row.get(9)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

#[tauri::command]
pub fn decide_approval(approval_id: i64, decision: String, note: String) -> Result<(), String> {
    if decision != "approved" && decision != "denied" {
        return Err(format!("Invalid decision: {decision}. Must be 'approved' or 'denied'."));
    }
    let conn = open()?;
    // authorized_pentest approvals require a SOW reference note
    if decision == "approved" {
        let kind: Option<String> = conn.query_row(
            "SELECT p.kind FROM approvals a JOIN projects p ON p.id=a.project_id WHERE a.id=?1",
            params![approval_id],
            |r| r.get(0),
        ).ok();
        if kind.as_deref() == Some("authorized_pentest") && note.trim().is_empty() {
            return Err("Authorized pentest approvals require a SOW reference in the note field.".into());
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "UPDATE approvals SET decision = ?1, decided_at = ?2, decision_note = ?3 WHERE id = ?4",
        params![decision, now, note, approval_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ── Workspace files ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceFile {
    pub id: i64,
    pub project_id: i64,
    pub filename: String,
    pub kind: Option<String>,
    pub path: String,
    pub sha256: String,
    pub added_at: i64,
}

#[tauri::command]
pub fn list_workspace_files(project_id: i64) -> Result<Vec<WorkspaceFile>, String> {
    let conn = open()?;
    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='workspace_files'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !table_exists { return Ok(vec![]); }

    let mut stmt = conn.prepare(
        "SELECT id, project_id, filename, kind, path, sha256, added_at \
         FROM workspace_files WHERE project_id=?1 ORDER BY added_at DESC",
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map(params![project_id], |row| {
        Ok(WorkspaceFile {
            id:         row.get(0)?,
            project_id: row.get(1)?,
            filename:   row.get(2)?,
            kind:       row.get(3)?,
            path:       row.get(4)?,
            sha256:     row.get(5)?,
            added_at:   row.get(6)?,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

// ── Agent sessions ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: i64,
    pub project_id: i64,
    pub claude_session_id: Option<String>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub vpn_state: Option<String>,
}

#[tauri::command]
pub fn create_agent_session(project_id: i64) -> Result<i64, String> {
    let conn = open()?;
    conn.execute(
        "INSERT INTO agent_sessions(project_id) VALUES(?1)",
        params![project_id],
    ).map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

#[tauri::command]
pub fn list_resumable_sessions(project_id: i64) -> Result<Vec<AgentSession>, String> {
    let conn = open()?;
    let mut stmt = conn.prepare(
        "SELECT id, project_id, claude_session_id, started_at, ended_at, vpn_state \
         FROM agent_sessions \
         WHERE project_id=?1 AND ended_at IS NULL AND claude_session_id IS NOT NULL \
           AND started_at > strftime('%s','now') - 604800 \
         ORDER BY started_at DESC LIMIT 3",
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map(params![project_id], |row| {
        Ok(AgentSession {
            id:                row.get(0)?,
            project_id:        row.get(1)?,
            claude_session_id: row.get(2)?,
            started_at:        row.get(3)?,
            ended_at:          row.get(4)?,
            vpn_state:         row.get(5)?,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

// Internal helpers called from claude_proc.rs (not Tauri commands).
pub fn write_session_claude_id(db_session_id: i64, claude_session_id: &str) {
    if let Ok(conn) = open() {
        let _ = conn.execute(
            "UPDATE agent_sessions SET claude_session_id=?1 WHERE id=?2",
            params![claude_session_id, db_session_id],
        );
    }
}

pub fn end_agent_session_db(db_session_id: i64) {
    if let Ok(conn) = open() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let _ = conn.execute(
            "UPDATE agent_sessions SET ended_at=?1 WHERE id=?2",
            params![now, db_session_id],
        );
    }
}

// ── VPN profiles ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnProfile {
    pub id: i64,
    pub name: String,
    pub ovpn_path: String,
    pub kind: Option<String>,
    pub region: Option<String>,
    pub last_connected_at: Option<i64>,
    pub is_default: bool,
}

#[tauri::command]
pub fn save_vpn_profile(name: String, ovpn_path: String, kind: String, region: Option<String>) -> Result<VpnProfile, String> {
    let name = name.trim().to_string();
    let ovpn_path = ovpn_path.trim().to_string();
    if name.is_empty() || ovpn_path.is_empty() {
        return Err("name and ovpn_path are required".into());
    }
    let kind_opt = if kind.is_empty() { None } else { Some(kind) };
    let region_opt = region.filter(|s| !s.trim().is_empty());
    let conn = open()?;
    conn.execute(
        "INSERT INTO vpn_profiles(name, ovpn_path, kind, region) VALUES(?1,?2,?3,?4)",
        params![name, ovpn_path, kind_opt, region_opt],
    ).map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    Ok(VpnProfile { id, name, ovpn_path, kind: kind_opt, region: region_opt, last_connected_at: None, is_default: false })
}

#[tauri::command]
pub fn list_vpn_profiles() -> Result<Vec<VpnProfile>, String> {
    let conn = open()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, ovpn_path, kind, region, last_connected_at, is_default \
         FROM vpn_profiles ORDER BY is_default DESC, COALESCE(last_connected_at, 0) DESC",
    ).map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(VpnProfile {
            id:                row.get(0)?,
            name:              row.get(1)?,
            ovpn_path:         row.get(2)?,
            kind:              row.get(3)?,
            region:            row.get(4)?,
            last_connected_at: row.get(5)?,
            is_default:        row.get::<_, i32>(6)? != 0,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

#[tauri::command]
pub fn delete_vpn_profile(id: i64) -> Result<(), String> {
    let conn = open()?;
    conn.execute("DELETE FROM vpn_profiles WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn set_default_vpn_profile(id: i64) -> Result<(), String> {
    let mut conn = open()?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("UPDATE vpn_profiles SET is_default=0", [])
        .map_err(|e| e.to_string())?;
    tx.execute("UPDATE vpn_profiles SET is_default=1 WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn vpn_profile_touch(ovpn_path: &str) {
    if let Ok(conn) = open() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let _ = conn.execute(
            "UPDATE vpn_profiles SET last_connected_at=?1 WHERE ovpn_path=?2",
            params![now, ovpn_path],
        );
    }
}

// ── update_project_target ─────────────────────────────────────────────────────

#[tauri::command]
pub fn update_project_target(id: i64, target: String) -> Result<(), String> {
    let conn = open()?;
    conn.execute(
        "UPDATE projects SET target=?1, updated_at=strftime('%s','now') WHERE id=?2",
        params![target, id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Session cost / token tracking ────────────────────────────────────────────

#[tauri::command]
pub fn update_session_cost(db_session_id: i64, cost_usd: f64) -> Result<(), String> {
    let conn = open()?;
    conn.execute(
        "UPDATE agent_sessions SET cost_estimate=?1 WHERE id=?2",
        params![cost_usd, db_session_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

// Internal helper called from claude_proc.rs
pub fn update_session_cost_internal(db_session_id: i64, cost_usd: f64) {
    if let Ok(conn) = open() {
        let _ = conn.execute(
            "UPDATE agent_sessions SET cost_estimate=?1 WHERE id=?2",
            params![cost_usd, db_session_id],
        );
    }
}

// ── Session VPN state ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn update_session_vpn_state(db_session_id: i64, vpn_profile: String) -> Result<(), String> {
    let conn = open()?;
    let val = if vpn_profile.is_empty() { None } else { Some(vpn_profile) };
    conn.execute(
        "UPDATE agent_sessions SET vpn_state=?1 WHERE id=?2",
        params![val, db_session_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Workspace file upload (copy from disk + sha256 + DB row) ─────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AddFileResult {
    pub id: i64,
    pub project_id: i64,
    pub filename: String,
    pub kind: Option<String>,
    pub path: String,
    pub sha256: String,
    pub added_at: i64,
}

#[tauri::command]
pub fn add_workspace_file(
    project_id: i64,
    project_name: String,
    src_path: String,
    kind: String,
) -> Result<AddFileResult, String> {
    let src = std::path::Path::new(&src_path);
    if !src.exists() {
        return Err(format!("Source file not found: {src_path}"));
    }

    let filename = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let dest_dir = dirs::home_dir()
        .unwrap_or_default()
        .join("penligent/projects")
        .join(&project_name)
        .join("workspace");
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("mkdir failed: {e}"))?;
    let dest = dest_dir.join(&filename);
    std::fs::copy(src, &dest).map_err(|e| format!("copy failed: {e}"))?;

    // Compute sha256 via system sha256sum
    let sha256 = {
        let out = std::process::Command::new("sha256sum")
            .arg(&dest)
            .output()
            .map_err(|e| format!("sha256sum failed: {e}"))?;
        if !out.status.success() {
            return Err(format!("sha256sum exited {}", out.status));
        }
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string()
    };

    let kind_opt = if kind.is_empty() { None } else { Some(kind) };
    let path_str = dest.to_string_lossy().to_string();

    let conn = open()?;
    let _ = conn.execute(
        "DELETE FROM workspace_files WHERE project_id=?1 AND path=?2",
        params![project_id, path_str],
    );
    conn.execute(
        "INSERT INTO workspace_files(project_id, filename, kind, path, sha256) VALUES(?1,?2,?3,?4,?5)",
        params![project_id, filename, kind_opt, path_str, sha256],
    ).map_err(|e| e.to_string())?;

    let id = conn.last_insert_rowid();
    let added_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Ok(AddFileResult { id, project_id, filename, kind: kind_opt, path: path_str, sha256, added_at })
}

// ── Project notes (read/write ~/penligent/projects/<name>/workspace/notes.md) ─

#[tauri::command]
pub fn read_project_notes(project_name: String) -> Result<String, String> {
    let path = dirs::home_dir()
        .unwrap_or_default()
        .join("penligent/projects")
        .join(&project_name)
        .join("workspace/notes.md");
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_project_notes(project_name: String, content: String) -> Result<(), String> {
    let dir = dirs::home_dir()
        .unwrap_or_default()
        .join("penligent/projects")
        .join(&project_name)
        .join("workspace");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("notes.md"), content).map_err(|e| e.to_string())
}

// ── Plans ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PlanView {
    pub id: i64,
    pub project_id: i64,
    pub objective: String,
    pub constraints_json: Option<String>,
    pub version: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: i64,
    pub plan_id: i64,
    pub step_idx: i64,
    pub verb: String,
    pub target: Option<String>,
    pub status: String,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
}

#[tauri::command]
pub fn get_current_plan(project_id: i64) -> Result<Option<PlanView>, String> {
    let conn = open()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plans'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !exists { return Ok(None); }

    let row = conn.query_row(
        "SELECT id, project_id, objective, constraints_json, version, created_at \
         FROM plans WHERE project_id=?1 ORDER BY created_at DESC LIMIT 1",
        params![project_id],
        |r| Ok(PlanView {
            id: r.get(0)?,
            project_id: r.get(1)?,
            objective: r.get(2)?,
            constraints_json: r.get(3)?,
            version: r.get(4)?,
            created_at: r.get(5)?,
        }),
    );
    match row {
        Ok(p) => Ok(Some(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn get_plan_steps(plan_id: i64) -> Result<Vec<PlanStep>, String> {
    let conn = open()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plan_steps'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !exists { return Ok(vec![]); }

    let mut stmt = conn.prepare(
        "SELECT id, plan_id, step_idx, verb, target, status, started_at, ended_at \
         FROM plan_steps WHERE plan_id=?1 ORDER BY step_idx",
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map(params![plan_id], |r| {
        Ok(PlanStep {
            id: r.get(0)?,
            plan_id: r.get(1)?,
            step_idx: r.get(2)?,
            verb: r.get(3)?,
            target: r.get(4)?,
            status: r.get(5)?,
            started_at: r.get(6)?,
            ended_at: r.get(7)?,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

// ── Execution results ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResult {
    pub id: i64,
    pub project_id: i64,
    pub tool_name: String,
    pub args_json: Option<String>,
    pub exit_code: Option<i64>,
    pub status: Option<String>,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub artifact_hash: Option<String>,
    pub mitre_attack_id: Option<String>,
}

#[tauri::command]
pub fn list_execution_results(project_id: i64) -> Result<Vec<ExecResult>, String> {
    let conn = open()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='execution_results'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !exists { return Ok(vec![]); }

    let mut stmt = conn.prepare(
        "SELECT id, project_id, tool_name, args_json, exit_code, status, \
         started_at, ended_at, artifact_hash, mitre_attack_id \
         FROM execution_results WHERE project_id=?1 \
         ORDER BY COALESCE(started_at, id) DESC LIMIT 50",
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map(params![project_id], |r| {
        Ok(ExecResult {
            id: r.get(0)?,
            project_id: r.get(1)?,
            tool_name: r.get(2)?,
            args_json: r.get(3)?,
            exit_code: r.get(4)?,
            status: r.get(5)?,
            started_at: r.get(6)?,
            ended_at: r.get(7)?,
            artifact_hash: r.get(8)?,
            mitre_attack_id: r.get(9)?,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

// ── Evidence artifacts ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub id: i64,
    pub risk_item_id: i64,
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub captured_at: i64,
}

#[tauri::command]
pub fn list_evidence_artifacts(risk_item_id: i64) -> Result<Vec<EvidenceArtifact>, String> {
    let conn = open()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='evidence_artifacts'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !exists { return Ok(vec![]); }

    let mut stmt = conn.prepare(
        "SELECT id, risk_item_id, kind, path, sha256, captured_at \
         FROM evidence_artifacts WHERE risk_item_id=?1 ORDER BY captured_at DESC",
    ).map_err(|e| e.to_string())?;

    let rows = stmt.query_map(params![risk_item_id], |r| {
        Ok(EvidenceArtifact {
            id: r.get(0)?,
            risk_item_id: r.get(1)?,
            kind: r.get(2)?,
            path: r.get(3)?,
            sha256: r.get(4)?,
            captured_at: r.get(5)?,
        })
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();
    Ok(rows)
}

// ── Agent messages hash chain ─────────────────────────────────────────────────

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

#[tauri::command]
pub fn persist_agent_message(
    session_id: i64,
    turn_idx: i64,
    role: String,
    content_json: String,
    tokens: Option<i64>,
) -> Result<(), String> {
    let conn = open()?;
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agent_messages (
            id           INTEGER PRIMARY KEY,
            session_id   INTEGER NOT NULL,
            turn_idx     INTEGER NOT NULL,
            role         TEXT    NOT NULL,
            content_json TEXT    NOT NULL,
            tokens       INTEGER,
            created_at   INTEGER DEFAULT (strftime('%s','now')),
            hash_prev    TEXT,
            hash_self    TEXT    NOT NULL
        )"
    );

    let prev_hash: Option<String> = conn.query_row(
        "SELECT hash_self FROM agent_messages WHERE session_id=?1 ORDER BY turn_idx DESC LIMIT 1",
        params![session_id],
        |r| r.get(0),
    ).ok();

    let chain_input = format!(
        "{}|{}",
        &content_json,
        prev_hash.as_deref().unwrap_or("genesis")
    );
    let hash_self = sha256_hex(&chain_input);
    let hash_prev = prev_hash.as_deref().unwrap_or("genesis").to_string();

    conn.execute(
        "INSERT INTO agent_messages(session_id, turn_idx, role, content_json, tokens, hash_prev, hash_self)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![session_id, turn_idx, role, content_json, tokens, hash_prev, hash_self],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn persist_agent_message_internal(
    session_id: i64,
    turn_idx: i64,
    role: &str,
    content_json: &str,
    tokens: Option<i64>,
) {
    if let Ok(conn) = open() {
        let _ = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_messages (
                id           INTEGER PRIMARY KEY,
                session_id   INTEGER NOT NULL,
                turn_idx     INTEGER NOT NULL,
                role         TEXT    NOT NULL,
                content_json TEXT    NOT NULL,
                tokens       INTEGER,
                created_at   INTEGER DEFAULT (strftime('%s','now')),
                hash_prev    TEXT,
                hash_self    TEXT    NOT NULL
            )"
        );
        let prev_hash: Option<String> = conn.query_row(
            "SELECT hash_self FROM agent_messages WHERE session_id=?1 ORDER BY turn_idx DESC LIMIT 1",
            params![session_id],
            |r| r.get(0),
        ).ok();
        let chain_input = format!(
            "{}|{}",
            content_json,
            prev_hash.as_deref().unwrap_or("genesis")
        );
        let hash_self = sha256_hex(&chain_input);
        let hash_prev = prev_hash.unwrap_or_else(|| "genesis".to_string());
        let _ = conn.execute(
            "INSERT INTO agent_messages(session_id, turn_idx, role, content_json, tokens, hash_prev, hash_self)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![session_id, turn_idx, role, content_json, tokens, hash_prev, hash_self],
        );
    }
}

#[tauri::command]
pub fn verify_message_chain(session_id: i64) -> Result<bool, String> {
    let conn = open()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='agent_messages'",
        [], |r| r.get::<_, i32>(0),
    ).unwrap_or(0) > 0;
    if !exists { return Ok(true); }

    let mut stmt = conn.prepare(
        "SELECT content_json, hash_prev, hash_self FROM agent_messages \
         WHERE session_id=?1 ORDER BY turn_idx",
    ).map_err(|e| e.to_string())?;

    let mut prev = "genesis".to_string();
    let rows: Vec<(String, String, String)> = stmt
        .query_map(params![session_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    for (content_json, hash_prev_stored, hash_self_stored) in &rows {
        if hash_prev_stored != &prev {
            return Ok(false);
        }
        let chain_input = format!("{}|{}", content_json, hash_prev_stored);
        let expected = sha256_hex(&chain_input);
        if &expected != hash_self_stored {
            return Ok(false);
        }
        prev = hash_self_stored.clone();
    }
    Ok(true)
}

// ── Sudoers rule installer ────────────────────────────────────────────────────

#[tauri::command]
pub fn install_sudoers_rule() -> Result<(), String> {
    let user = std::env::var("USER").unwrap_or_else(|_| "kali".to_string());
    let rule = format!("{user} ALL=(root) NOPASSWD: /usr/sbin/openvpn\n");
    let tmp = "/tmp/penligent-sudoers";
    std::fs::write(tmp, &rule).map_err(|e| e.to_string())?;
    let out = std::process::Command::new("sudo")
        .args(["install", "-m", "440", "-o", "root", "-g", "root", tmp, "/etc/sudoers.d/penligent-openvpn"])
        .output()
        .map_err(|e| format!("sudo install failed: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

// ── Read workspace file contents for inline preview ──────────────────────────

#[tauri::command]
pub fn read_workspace_file(path: String) -> Result<String, String> {
    let p = std::path::Path::new(&path);
    if !p.exists() {
        return Err(format!("File not found: {path}"));
    }
    // Limit preview to 32 KiB
    let data = std::fs::read(p).map_err(|e| e.to_string())?;
    let preview = &data[..data.len().min(32768)];
    match std::str::from_utf8(preview) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Ok(format!("[binary file — {} bytes]", data.len())),
    }
}

// ── Register HTB MCP server via `claude mcp add` ──────────────────────────────

#[tauri::command]
pub fn register_htb_mcp_server(token: String) -> Result<String, String> {
    if token.trim().is_empty() {
        return Err("Token cannot be empty".into());
    }
    let claude = dirs::home_dir()
        .unwrap_or_default()
        .join(".local/bin/claude");
    if !claude.exists() {
        return Err("Claude Code is not installed. Install it from Settings, then retry.".into());
    }
    let output = std::process::Command::new(&claude)
        .args([
            "mcp", "add",
            "--transport", "http",
            "--scope", "user",
            "htb-mcp-ctf",
            "https://mcp.hackthebox.ai/v1/ctf/mcp/",
            "--header", &format!("Authorization: Bearer {}", token.trim()),
        ])
        .output()
        .map_err(|e| format!("Failed to run claude mcp add: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() || stdout.contains("htb-mcp-ctf") || stderr.contains("htb-mcp-ctf") {
        Ok("HTB MCP server registered successfully.".into())
    } else {
        Err(format!("claude mcp add failed: {stdout}{stderr}"))
    }
}

// ── Register the Penligent MCP server in ~/.claude/settings.json ──────────────
// Idempotent: merges the entry without clobbering other keys. Called on every
// app launch so a settings.json that was overwritten by the Claude installer
// (which happens on a fresh `curl claude.ai/install.sh | bash`) gets healed
// without the user having to know what went wrong.

fn locate_mcp_python() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib/penligent-local/mcp-server/.venv/bin/python"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("../../../mcp-server/.venv/bin/python"));
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

fn locate_agent_guard() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib/penligent-local/scripts/agent-guard.py"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            // dev: target/debug/penligent-local → ../../../scripts/agent-guard.py
            candidates.push(parent.join("../../../scripts/agent-guard.py"));
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

#[tauri::command]
pub fn register_local_mcp_server() -> Result<String, String> {
    let python = locate_mcp_python()
        .ok_or_else(|| "Penligent MCP venv not found".to_string())?;
    let python_str = python.to_string_lossy().to_string();

    let home = dirs::home_dir().ok_or("HOME not set")?;
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    std::fs::create_dir_all(&claude_dir).map_err(|e| e.to_string())?;

    let mut cfg: serde_json::Value = match std::fs::read_to_string(&settings_path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };
    if !cfg.is_object() {
        cfg = serde_json::json!({});
    }

    let obj = cfg.as_object_mut().unwrap();
    let mcp = obj.entry("mcpServers".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !mcp.is_object() {
        *mcp = serde_json::json!({});
    }
    let mcp_obj = mcp.as_object_mut().unwrap();

    let desired_mcp = serde_json::json!({
        "command": python_str,
        "args": ["-m", "penligent_mcp"],
    });

    let mut changed = false;
    if mcp_obj.get("penligent-local") != Some(&desired_mcp) {
        mcp_obj.insert("penligent-local".to_string(), desired_mcp);
        changed = true;
    }

    // Also install the PreToolUse guard so the agent can't kill claude / rm
    // ~/.claude / unregister MCP servers / disable the VPN. The guard is a
    // small Python script bundled in the .deb (or repo for dev builds);
    // settings.json points at its absolute path.
    if let Some(guard) = locate_agent_guard() {
        let guard_str = guard.canonicalize().unwrap_or(guard).to_string_lossy().to_string();
        let desired_hook = serde_json::json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": guard_str } ],
        });

        let hooks = cfg.as_object_mut().unwrap()
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !hooks.is_object() { *hooks = serde_json::json!({}); }
        let hooks_obj = hooks.as_object_mut().unwrap();

        let pre_tool_use = hooks_obj
            .entry("PreToolUse".to_string())
            .or_insert_with(|| serde_json::json!([]));
        if !pre_tool_use.is_array() { *pre_tool_use = serde_json::json!([]); }
        let arr = pre_tool_use.as_array_mut().unwrap();

        // Find an existing penligent guard entry (by matching the script
        // basename). If it already matches `desired_hook` exactly, leave it.
        // Otherwise rebuild it so a moved script path or stale config heals.
        let mut existing_idx: Option<usize> = None;
        for (i, h) in arr.iter().enumerate() {
            let cmd = h.pointer("/hooks/0/command").and_then(|v| v.as_str()).unwrap_or("");
            if cmd.contains("agent-guard.py") {
                existing_idx = Some(i);
                break;
            }
        }
        match existing_idx {
            Some(i) if arr[i] == desired_hook => {}
            Some(i) => { arr[i] = desired_hook; changed = true; }
            None    => { arr.push(desired_hook); changed = true; }
        }
    }

    if changed {
        let pretty = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
        std::fs::write(&settings_path, pretty).map_err(|e| e.to_string())?;
        Ok(format!("Registered penligent-local MCP server + guard at {}", settings_path.display()))
    } else {
        Ok("penligent-local MCP entry and guard already present.".into())
    }
}

// ── Install Claude Code via the official installer ────────────────────────────
// Runs `curl -fsSL https://claude.ai/install.sh | bash` and then re-registers
// the local MCP server (the installer clobbers ~/.claude/settings.json).

#[tauri::command]
pub fn install_claude_code() -> Result<String, String> {
    let output = std::process::Command::new("bash")
        .args(["-lc", "curl -fsSL https://claude.ai/install.sh | bash"])
        .output()
        .map_err(|e| format!("Failed to run installer: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!("Claude install failed:\n{stdout}\n{stderr}").trim().to_string());
    }

    let claude = dirs::home_dir().unwrap_or_default().join(".local/bin/claude");
    if !claude.exists() {
        return Err(format!(
            "Installer reported success but {} is missing.\n{}",
            claude.display(), stdout
        ));
    }

    // Heal settings.json (the installer rewrites it).
    let _ = register_local_mcp_server();
    Ok(format!("Claude Code installed at {}", claude.display()))
}

#[tauri::command]
pub fn count_mcp_tools() -> Result<u32, String> {
    // Check exe-relative dev path first so dev builds read the live source tree,
    // then fall back to the installed system path.
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("../../../mcp-server/penligent_mcp/tools"));
        }
    }
    dirs.push(std::path::PathBuf::from("/usr/lib/penligent-local/mcp-server/penligent_mcp/tools"));
    for dir in &dirs {
        if !dir.exists() { continue; }
        let mut count = 0u32;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("py") { continue; }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines() {
                        if line.starts_with("register(") { count += 1; }
                    }
                }
            }
        }
        if count > 0 { return Ok(count); }
    }
    Ok(0)
}

#[tauri::command]
pub fn get_claude_version() -> Result<String, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let claude_local = format!("{home}/.local/bin/claude");
    let output = std::process::Command::new(&claude_local)
        .arg("--version")
        .output()
        .or_else(|_| std::process::Command::new("claude").arg("--version").output())
        .map_err(|e| e.to_string())?;
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(s)
}

#[derive(Debug, Serialize)]
pub struct McpHealthStatus {
    pub ok: bool,
    pub tool_count: u32,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HtbMcpStatus {
    /// "ok" — entry present in claude config
    /// "missing" — token saved but no registration found
    /// "no_token" — user hasn't configured HTB at all; status bar should hide
    pub state: String,
    pub error: Option<String>,
}

fn htb_mcp_entry_present() -> bool {
    let path = match dirs::home_dir() {
        Some(h) => h.join(".claude.json"),
        None => return false,
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let cfg: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // `claude mcp add --scope user` writes top-level mcpServers; older versions
    // landed it under projects.<cwd>.mcpServers. Accept either so a user who
    // ran `add` from any cwd still passes the check.
    if cfg.get("mcpServers")
        .and_then(|m| m.get("htb-mcp-ctf"))
        .is_some() {
        return true;
    }
    if let Some(projects) = cfg.get("projects").and_then(|p| p.as_object()) {
        for (_, v) in projects {
            if v.get("mcpServers")
                .and_then(|m| m.get("htb-mcp-ctf"))
                .is_some() {
                return true;
            }
        }
    }
    false
}

fn load_config_str(key: &str) -> String {
    let path = config_path();
    if !path.exists() { return String::new(); }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let cfg: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({}));
    cfg[key].as_str().map(String::from).unwrap_or_default()
}

#[derive(Debug, Serialize)]
pub struct DiagItem {
    pub id: String,
    pub name: String,
    pub ok: bool,
    pub hint: String,
    /// id of a repair command the UI can invoke; empty when there's no
    /// programmatic fix (e.g. data dir missing — user has bigger problems).
    pub fix: String,
}

#[tauri::command]
pub fn run_diagnostics() -> Vec<DiagItem> {
    let mut out: Vec<DiagItem> = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // 1. Claude Code binary
    let claude = home.join(".local/bin/claude");
    let claude_ok = claude.exists();
    out.push(DiagItem {
        id: "claude_installed".into(),
        name: "Claude Code installed".into(),
        ok: claude_ok,
        hint: if claude_ok { format!("{}", claude.display()) }
              else { "~/.local/bin/claude is missing — install it.".into() },
        fix: if claude_ok { "".into() } else { "install_claude".into() },
    });

    // 2. Penligent MCP registered in ~/.claude/settings.json
    let settings_path = home.join(".claude/settings.json");
    let mcp_registered = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("mcpServers").and_then(|m| m.get("penligent-local")).cloned())
        .is_some();
    out.push(DiagItem {
        id: "penligent_mcp_registered".into(),
        name: "Penligent MCP registered".into(),
        ok: mcp_registered,
        hint: if mcp_registered { "Entry present in ~/.claude/settings.json".into() }
              else { "mcpServers.penligent-local missing — agent has no Penligent tools.".into() },
        fix: if mcp_registered { "".into() } else { "register_local_mcp".into() },
    });

    // 3. Penligent MCP venv imports
    let python = locate_mcp_python();
    let venv_ok = python.as_ref().map(|p| {
        std::process::Command::new(p)
            .args(["-c", "import penligent_mcp"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }).unwrap_or(false);
    out.push(DiagItem {
        id: "penligent_mcp_imports".into(),
        name: "Penligent MCP imports".into(),
        ok: venv_ok,
        hint: match (&python, venv_ok) {
            (Some(p), true)  => format!("{}", p.display()),
            (Some(p), false) => format!("`import penligent_mcp` failed under {}", p.display()),
            (None, _)        => "venv not found — reinstall the .deb or run scripts/post-install.sh.".into(),
        },
        fix: "".into(),  // no in-app pip-install fix — needs system context
    });

    // 4. HTB MCP — only relevant if user has a token
    let token = load_config_str("htb_app_token");
    if !token.trim().is_empty() {
        let htb_ok = htb_mcp_entry_present();
        out.push(DiagItem {
            id: "htb_mcp_registered".into(),
            name: "HTB MCP registered".into(),
            ok: htb_ok,
            hint: if htb_ok { "htb-mcp-ctf entry present in claude config.".into() }
                  else { "Token saved but htb-mcp-ctf not registered — agent has no HTB tools.".into() },
            fix: if htb_ok { "".into() } else { "register_htb_mcp".into() },
        });
    }

    // 5. Agent guard installed AND wired into Claude hooks. Both pieces
    //    must hold: the script must exist on disk AND settings.json must
    //    point at a path containing "agent-guard.py" in PreToolUse[Bash].
    let guard_path = locate_agent_guard();
    let guard_executable = guard_path.as_ref().map(|p| {
        // is_file + readable as executable; cheap approximation via metadata.
        std::fs::metadata(p)
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false)
    }).unwrap_or(false);
    let hook_wired = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("hooks").and_then(|h| h.get("PreToolUse")).cloned())
        .and_then(|arr| arr.as_array().cloned())
        .map(|arr| arr.iter().any(|h| {
            h.pointer("/hooks/0/command")
                .and_then(|v| v.as_str())
                .map(|c| c.contains("agent-guard.py"))
                .unwrap_or(false)
        }))
        .unwrap_or(false);
    let guard_ok = guard_path.is_some() && guard_executable && hook_wired;
    out.push(DiagItem {
        id: "agent_guard".into(),
        name: "Agent guard installed".into(),
        ok: guard_ok,
        hint: match (&guard_path, guard_executable, hook_wired) {
            (None, _, _)          => "agent-guard.py not bundled — reinstall the .deb.".into(),
            (Some(p), false, _)   => format!("{} not executable (chmod +x).", p.display()),
            (Some(p), true, false) => format!("Guard at {} but not wired into ~/.claude/settings.json — agent can still kill claude/openvpn.", p.display()),
            (Some(p), true, true)  => format!("Active · blocks destructive Bash via {}", p.display()),
        },
        fix: if guard_ok { "".into() } else { "register_local_mcp".into() },
    });

    // 6. OpenVPN sudoers
    let sudoers = std::path::Path::new("/etc/sudoers.d/penligent-openvpn").exists();
    out.push(DiagItem {
        id: "sudoers_rule".into(),
        name: "OpenVPN sudoers rule".into(),
        ok: sudoers,
        hint: if sudoers { "/etc/sudoers.d/penligent-openvpn present.".into() }
              else { "VPN connect will prompt for password each time.".into() },
        fix: if sudoers { "".into() } else { "install_sudoers".into() },
    });

    // 7. Data dir writable
    let data_dir = home.join(".local/share/penligent-local");
    let data_ok = data_dir.is_dir() && std::fs::metadata(&data_dir)
        .map(|m| !m.permissions().readonly()).unwrap_or(false);
    out.push(DiagItem {
        id: "data_dir".into(),
        name: "Data dir writable".into(),
        ok: data_ok,
        hint: format!("{}", data_dir.display()),
        fix: "".into(),
    });

    out
}

#[tauri::command]
pub fn htb_mcp_health_check() -> HtbMcpStatus {
    let token = load_config_str("htb_app_token");
    if token.trim().is_empty() {
        return HtbMcpStatus { state: "no_token".into(), error: None };
    }
    if htb_mcp_entry_present() {
        HtbMcpStatus { state: "ok".into(), error: None }
    } else {
        HtbMcpStatus {
            state: "missing".into(),
            error: Some("htb-mcp-ctf not registered with Claude Code. Re-save your HTB token in Settings.".into()),
        }
    }
}

#[tauri::command]
pub fn mcp_health_check() -> McpHealthStatus {
    // Prefer installed path; fall back to dev-build path relative to the exe.
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib/penligent-local/mcp-server/.venv/bin/python"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("../../../mcp-server/.venv/bin/python"));
        }
    }

    let python = match candidates.into_iter().find(|p| p.exists()) {
        Some(p) => p,
        None => return McpHealthStatus {
            ok: false,
            tool_count: 0,
            error: Some("venv not found".into()),
        },
    };

    let out = std::process::Command::new(&python)
        .args(["-c", "import penligent_mcp; print('ok')"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match out {
        Ok(o) if o.status.success() => {
            let tool_count = count_mcp_tools().unwrap_or(0);
            McpHealthStatus { ok: true, tool_count, error: None }
        }
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
            McpHealthStatus { ok: false, tool_count: 0, error: Some(msg) }
        }
        Err(e) => McpHealthStatus {
            ok: false,
            tool_count: 0,
            error: Some(e.to_string()),
        },
    }
}
