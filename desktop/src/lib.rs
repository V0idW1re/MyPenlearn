pub mod claude_proc;
pub mod vpn;
pub mod db_commands;

use claude_proc::SharedClaudeState;
use vpn::SharedVpnManager;

use std::sync::Mutex;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(SharedClaudeState::new(Mutex::new(
            claude_proc::ClaudeState::default(),
        )))
        .manage(SharedVpnManager::new(Mutex::new(
            vpn::VpnManager::default(),
        )))
        .invoke_handler(tauri::generate_handler![
            claude_proc::claude_send,
            claude_proc::claude_set_context,
            claude_proc::claude_get_session,
            claude_proc::claude_clear_session,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_status,
            db_commands::list_projects,
            db_commands::create_project,
            db_commands::rename_project,
            db_commands::delete_project,
            db_commands::save_message,
            db_commands::load_messages,
            db_commands::list_findings,
            db_commands::clear_messages,
            db_commands::save_config_value,
            db_commands::load_config_value,
        ])
        .run(tauri::generate_context!())
        .expect("error while running penligent-local");
}
