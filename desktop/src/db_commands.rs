use serde::{Deserialize, Serialize};
use serde_json;
use rusqlite::{Connection, params};
use std::path::PathBuf;

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

fn open() -> Result<Connection, String> {
    let path = db_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("mkdir failed: {e}"))?;
    }
    let conn = Connection::open(&path).map_err(|e| format!("DB open failed: {e}"))?;
    conn.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA journal_mode=WAL;")
        .map_err(|e| format!("PRAGMA failed: {e}"))?;
    ensure_schema(&conn)?;
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
    // risk_items may not exist yet if the Python MCP server has never run
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
    pub time_window: Option<i64>,
    pub decision_note: Option<String>,
    pub requested_at: i64,
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
            "SELECT id, project_id, intent, scope_json, rate_limit, \
             time_window, decision_note, requested_at \
             FROM approvals \
             WHERE project_id = ?1 AND decision = 'pending' \
             ORDER BY requested_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![project_id], |row| {
            Ok(Approval {
                id:           row.get(0)?,
                project_id:   row.get(1)?,
                intent:       row.get(2)?,
                scope_json:   row.get(3)?,
                rate_limit:   row.get(4)?,
                time_window:  row.get(5)?,
                decision_note: row.get(6)?,
                requested_at: row.get(7)?,
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
    pub last_connected_at: Option<i64>,
    pub is_default: bool,
}

#[tauri::command]
pub fn save_vpn_profile(name: String, ovpn_path: String, kind: String) -> Result<VpnProfile, String> {
    let name = name.trim().to_string();
    let ovpn_path = ovpn_path.trim().to_string();
    if name.is_empty() || ovpn_path.is_empty() {
        return Err("name and ovpn_path are required".into());
    }
    let kind_opt = if kind.is_empty() { None } else { Some(kind) };
    let conn = open()?;
    conn.execute(
        "INSERT INTO vpn_profiles(name, ovpn_path, kind) VALUES(?1,?2,?3)",
        params![name, ovpn_path, kind_opt],
    ).map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    Ok(VpnProfile { id, name, ovpn_path, kind: kind_opt, last_connected_at: None, is_default: false })
}

#[tauri::command]
pub fn list_vpn_profiles() -> Result<Vec<VpnProfile>, String> {
    let conn = open()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, ovpn_path, kind, last_connected_at, is_default \
         FROM vpn_profiles ORDER BY is_default DESC, COALESCE(last_connected_at, 0) DESC",
    ).map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(VpnProfile {
            id:                row.get(0)?,
            name:              row.get(1)?,
            ovpn_path:         row.get(2)?,
            kind:              row.get(3)?,
            last_connected_at: row.get(4)?,
            is_default:        row.get::<_, i32>(5)? != 0,
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

// ── Register HTB MCP server via `claude mcp add` ──────────────────────────────

#[tauri::command]
pub fn register_htb_mcp_server(token: String) -> Result<String, String> {
    if token.trim().is_empty() {
        return Err("Token cannot be empty".into());
    }
    let claude = dirs::home_dir()
        .unwrap_or_default()
        .join(".local/bin/claude");
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
        Ok(format!("claude mcp add output: {stdout}{stderr}"))
    }
}
