use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

// ---------------------------------------------------------------------------
// VPN state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct VpnState {
    pub status: VpnStatus,
    pub tun_ip: Option<String>,
    pub profile_name: Option<String>,
    pub error: Option<String>,
}

impl Default for VpnState {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            tun_ip: None,
            profile_name: None,
            error: None,
        }
    }
}

#[derive(Default)]
pub struct VpnManager {
    pub state: VpnState,
    child: Option<Child>,
    ovpn_path: Option<String>,
}

pub type SharedVpnManager = Arc<Mutex<VpnManager>>;

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

pub async fn connect(
    app: AppHandle,
    manager: SharedVpnManager,
    ovpn_path: String,
    profile_name: String,
) -> Result<(), String> {
    // Enforce single-connection invariant
    {
        let mut m = manager.lock().unwrap();
        if m.state.status == VpnStatus::Connected || m.state.status == VpnStatus::Connecting {
            return Err("A VPN connection is already active. Disconnect first.".into());
        }
        m.state = VpnState {
            status: VpnStatus::Connecting,
            profile_name: Some(profile_name.clone()),
            ..Default::default()
        };
        m.ovpn_path = Some(ovpn_path.clone());
        emit_state(&app, &m.state);
    }

    // Try passwordless sudo first (our sudoers rule), fall back to pkexec
    let use_sudo = tokio::process::Command::new("sudo")
        .args(["-n", "/usr/sbin/openvpn", "--version"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let (prog, args): (&str, Vec<&str>) = if use_sudo {
        ("sudo", vec!["/usr/sbin/openvpn", "--config", &ovpn_path])
    } else {
        ("pkexec", vec!["/usr/sbin/openvpn", "--config", &ovpn_path])
    };

    let child = Command::new(prog)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn openvpn: {e}"))?;

    // Transfer child ownership into the manager
    {
        let mut m = manager.lock().unwrap();
        m.child = Some(child);
    }

    // Watch both stdout and stderr for "Initialization Sequence Completed" and tun IP.
    // OpenVPN may write to either stream depending on platform and privilege level.
    let manager_clone = Arc::clone(&manager);
    let app_clone = app.clone();

    tokio::spawn(async move {
        let (stdout, stderr) = {
            let mut m = manager_clone.lock().unwrap();
            let stdout = m.child.as_mut().and_then(|c| c.stdout.take());
            let stderr = m.child.as_mut().and_then(|c| c.stderr.take());
            (stdout, stderr)
        };

        let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        if let Some(stdout) = stdout {
            let tx = line_tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await { let _ = tx.send(line); }
            });
        }
        if let Some(stderr) = stderr {
            let tx = line_tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await { let _ = tx.send(line); }
            });
        }
        drop(line_tx); // closes rx once both sub-tasks finish

        // Parse tun IP from lines like:
        //   "ip addr add 10.10.14.42/23 dev tun0"
        //   "/sbin/ip addr add dev tun0 local 10.10.14.42 peer 10.10.14.43"
        while let Some(line) = line_rx.recv().await {
            let tun_ip = parse_tun_ip(&line);

            if line.contains("Initialization Sequence Completed") {
                let mut m = manager_clone.lock().unwrap();
                m.state.status = VpnStatus::Connected;
                if let Some(ip) = tun_ip { m.state.tun_ip = Some(ip); }
                emit_state(&app_clone, &m.state);
            } else if let Some(ip) = tun_ip {
                let mut m = manager_clone.lock().unwrap();
                m.state.tun_ip = Some(ip);
            } else if line.contains("ERROR") || line.contains("error") {
                let mut m = manager_clone.lock().unwrap();
                if m.state.status != VpnStatus::Connected {
                    m.state.status = VpnStatus::Error;
                    m.state.error = Some(line.clone());
                    emit_state(&app_clone, &m.state);
                }
            }
        }

        // Both streams closed — process has exited; reap it
        let child = { let mut m = manager_clone.lock().unwrap(); m.child.take() };
        if let Some(mut c) = child { let _ = c.wait().await; }

        let mut m = manager_clone.lock().unwrap();
        if m.state.status != VpnStatus::Disconnected {
            let dropped_profile = m.state.profile_name.clone();
            m.state.status = VpnStatus::Disconnected;
            m.state.tun_ip = None;
            emit_state(&app_clone, &m.state);
            // Emit drop event so the frontend can offer reconnect
            if let Some(name) = dropped_profile {
                let _ = app_clone.emit("vpn://dropped", name);
            }
        }
    });

    Ok(())
}

fn parse_tun_ip(line: &str) -> Option<String> {
    for part in line.split_whitespace() {
        // Strip CIDR suffix (e.g., "10.10.14.42/23" → "10.10.14.42")
        let candidate = part.split('/').next().unwrap_or("");
        let candidate = candidate.trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if looks_like_tun_ip(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn looks_like_tun_ip(s: &str) -> bool {
    // Must be a valid-ish IPv4 in the HTB tun range (10.x.x.x) or any RFC1918
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
        && (s.starts_with("10.") || s.starts_with("192.168.") || s.starts_with("172."))
}

fn emit_state(app: &AppHandle, state: &VpnState) {
    let _ = app.emit("vpn://state", state.clone());
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

pub async fn disconnect(manager: SharedVpnManager, app: AppHandle) -> Result<(), String> {
    let child = {
        let mut m = manager.lock().unwrap();
        m.ovpn_path = None;
        m.child.take()
    };

    if let Some(mut child) = child {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    let mut m = manager.lock().unwrap();
    m.state = VpnState::default();
    emit_state(&app, &m.state);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vpn_connect(
    ovpn_path: String,
    profile_name: String,
    app: AppHandle,
    state: tauri::State<'_, SharedVpnManager>,
) -> Result<(), String> {
    connect(app, Arc::clone(&state), ovpn_path, profile_name).await
}

#[tauri::command]
pub async fn vpn_disconnect(
    app: AppHandle,
    state: tauri::State<'_, SharedVpnManager>,
) -> Result<(), String> {
    disconnect(Arc::clone(&state), app).await
}

#[tauri::command]
pub fn vpn_status(
    state: tauri::State<'_, SharedVpnManager>,
) -> VpnState {
    state.lock().unwrap().state.clone()
}

#[tauri::command]
pub async fn vpn_reconnect(
    app: AppHandle,
    state: tauri::State<'_, SharedVpnManager>,
) -> Result<(), String> {
    let (ovpn_path, profile_name) = {
        let m = state.lock().unwrap();
        (m.ovpn_path.clone(), m.state.profile_name.clone())
    };
    let ovpn = ovpn_path.ok_or_else(|| "No profile cached for reconnect. Connect manually first.".to_string())?;
    let name = profile_name.unwrap_or_else(|| "VPN".to_string());
    connect(app, Arc::clone(&state), ovpn, name).await
}
