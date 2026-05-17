use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use dirs;

const CLAUDE_BIN: &str = "/home/kali/.local/bin/claude";

const SYSTEM_PROMPT: &str = "\
You are Penligent, an autonomous penetration testing agent running on Kali Linux inside Penligent Local.\n\
\n\
## Workspace\n\
All file output goes to ~/penligent/projects/<project_name>/workspace/. \
Save every significant discovery — credential, hash, open port, service version, vulnerability, flag — \
using the MCP tools: add_finding, workspace_note, or workspace_write.\n\
\n\
## GUI Application Walkthroughs\n\
When a task requires a graphical application that cannot be driven from the terminal \
(web browser navigation, Burp Suite GUI, OWASP ZAP, Metasploit Framework GUI, Maltego, \
a VNC/RDP session, a target login page, a web form, any GUI-only tool), \
you MUST stop automating and instead deliver a complete step-by-step manual walkthrough. Format it as:\n\
\n\
1. Numbered steps — no step skipped, no step assumed.\n\
2. Each step states: exact menu path / button / field / keyboard shortcut to use, \
exact value / URL / payload / credential to enter, and what the user should see on screen (expected visual feedback).\n\
3. Sub-actions within a step are listed as sub-points (e.g. 2a, 2b, 2c).\n\
4. Write as if the user has never opened this application before.\n\
5. Close every walkthrough with the exact sentence: \
\"Let me know when you have completed these steps and I will continue.\"\n\
\n\
Never skip this procedure for any GUI interaction. The user is physically at the machine and will follow your instructions precisely.\n\
\n\
## HackTheBox\n\
When HTB_APP_TOKEN is present, proceed with machine start, stop, reset, and flag submission without asking for confirmation.\n\
\n\
## Methodology\n\
Enumerate fully before exploiting. Run port scans, version detection, and directory brute-force in parallel where possible. \
Document every discovered piece of information in the workspace throughout the engagement.";

fn load_htb_token() -> Option<String> {
    let path = dirs::home_dir()?
        .join(".local/share/penligent-local/config.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v["htb_app_token"].as_str().map(String::from)
}

// ---------------------------------------------------------------------------
// Types emitted to the frontend
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ChatChunk {
    pub kind: String,     // "text" | "tool_use" | "tool_result" | "system" | "error"
    pub text: Option<String>,
    pub tool_name: Option<String>,
    pub tool_input: Option<serde_json::Value>,
    pub session_id: Option<String>,
    pub cost_usd: Option<f64>,
}

// ---------------------------------------------------------------------------
// Claude Code JSON stream types (subset we care about)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct StreamEvent {
    #[serde(rename = "type")]
    kind: String,
    subtype: Option<String>,
    message: Option<MessageWrapper>,
    session_id: Option<String>,
    total_cost_usd: Option<f64>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct MessageWrapper {
    content: Option<Vec<ContentBlock>>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    name: Option<String>,
    input: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Session state  (shared across Tauri commands)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ClaudeState {
    pub session_id: Option<String>,
    pub project_id: Option<i64>,
    pub work_dir: Option<PathBuf>,
}

pub type SharedClaudeState = Arc<Mutex<ClaudeState>>;

// ---------------------------------------------------------------------------
// Core: run one Claude Code turn and stream events to the window
// ---------------------------------------------------------------------------

pub async fn run_turn(
    app: AppHandle,
    state: SharedClaudeState,
    message: String,
) -> Result<(), String> {
    let (session_id, work_dir) = {
        let s = state.lock().unwrap();
        (s.session_id.clone(), s.work_dir.clone())
    };

    let work_dir = work_dir.unwrap_or_else(|| PathBuf::from("/home/kali"));

    let mut cmd = Command::new(CLAUDE_BIN);
    cmd.arg("--output-format").arg("stream-json")
        .arg("--dangerously-skip-permissions")
        .arg("--append-system-prompt").arg(SYSTEM_PROMPT)
        .arg("-p").arg(&message)
        .current_dir(&work_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    if let Some(token) = load_htb_token() {
        cmd.env("HTB_APP_TOKEN", token);
    }

    if let Some(ref sid) = session_id {
        cmd.arg("--resume").arg(sid);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn claude: {e}"))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Drain stderr in background (Claude Code logs go there)
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(_)) = lines.next_line().await {}
    });

    let mut lines = BufReader::new(stdout).lines();
    let mut new_session_id: Option<String> = None;

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let event: StreamEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => {
                // Raw text line — forward as-is (fallback for non-JSON output)
                let chunk = ChatChunk {
                    kind: "text".into(),
                    text: Some(line),
                    tool_name: None,
                    tool_input: None,
                    session_id: None,
                    cost_usd: None,
                };
                let _ = app.emit("claude://chunk", chunk);
                continue;
            }
        };

        if let Some(ref sid) = event.session_id {
            new_session_id = Some(sid.clone());
        }

        match event.kind.as_str() {
            "assistant" => {
                if let Some(msg) = event.message {
                    for block in msg.content.unwrap_or_default() {
                        let chunk = match block.kind.as_str() {
                            "text" => ChatChunk {
                                kind: "text".into(),
                                text: block.text,
                                tool_name: None,
                                tool_input: None,
                                session_id: event.session_id.clone(),
                                cost_usd: None,
                            },
                            "tool_use" => ChatChunk {
                                kind: "tool_use".into(),
                                text: None,
                                tool_name: block.name,
                                tool_input: block.input,
                                session_id: event.session_id.clone(),
                                cost_usd: None,
                            },
                            _ => continue,
                        };
                        let _ = app.emit("claude://chunk", chunk);
                    }
                }
            }
            "result" => {
                let cost = event.total_cost_usd;
                let chunk = ChatChunk {
                    kind: "result".into(),
                    text: event.subtype,
                    tool_name: None,
                    tool_input: None,
                    session_id: event.session_id.clone(),
                    cost_usd: cost,
                };
                let _ = app.emit("claude://chunk", chunk);
            }
            "system" => {
                if event.subtype.as_deref() == Some("init") {
                    // Session initialised — nothing to forward
                }
            }
            _ => {
                if let Some(err) = event.error {
                    let chunk = ChatChunk {
                        kind: "error".into(),
                        text: Some(err.to_string()),
                        tool_name: None,
                        tool_input: None,
                        session_id: None,
                        cost_usd: None,
                    };
                    let _ = app.emit("claude://chunk", chunk);
                }
            }
        }
    }

    // Wait for the process to exit
    let _ = child.wait().await;

    // Persist the new session ID so the next turn can resume
    if let Some(ref sid) = new_session_id {
        let mut s = state.lock().unwrap();
        s.session_id = Some(sid.clone());
    }

    // Signal frontend that the turn is complete
    let _ = app.emit("claude://done", serde_json::json!({
        "session_id": new_session_id
    }));

    Ok(())
}

// ---------------------------------------------------------------------------
// Tauri commands (called from the frontend)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn claude_send(
    message: String,
    app: AppHandle,
    state: tauri::State<'_, SharedClaudeState>,
) -> Result<(), String> {
    let state_clone = Arc::clone(&state);
    run_turn(app, state_clone, message).await
}

#[tauri::command]
pub fn claude_set_context(
    project_id: i64,
    work_dir: String,
    state: tauri::State<'_, SharedClaudeState>,
) {
    let mut s = state.lock().unwrap();
    s.project_id = Some(project_id);
    s.work_dir = Some(PathBuf::from(work_dir));
    s.session_id = None; // fresh session for new project
}

#[tauri::command]
pub fn claude_get_session(
    state: tauri::State<'_, SharedClaudeState>,
) -> Option<String> {
    state.lock().unwrap().session_id.clone()
}

#[tauri::command]
pub fn claude_clear_session(
    state: tauri::State<'_, SharedClaudeState>,
) {
    state.lock().unwrap().session_id = None;
}
