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
    pub status: String,    // mapped from verify_status
    pub found_at: i64,     // mapped from created_at (unix epoch integer)
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
        );",
    )
    .map_err(|e| e.to_string())
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
pub fn create_project(name: String, target: String, kind: String) -> Result<Project, String> {
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

    let conn = open()?;
    conn.execute(
        "INSERT INTO projects (target, name, kind) VALUES (?1, ?2, ?3)",
        params![target, name, kind],
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
                    verify_status, created_at
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
                id:          row.get(0)?,
                project_id:  row.get(1)?,
                title:       row.get(2)?,
                severity:    row.get(3)?,
                description: row.get(4)?,
                status:      row.get(5)?,
                found_at:    row.get(6)?,
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
