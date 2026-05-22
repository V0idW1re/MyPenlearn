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
            claude_proc::claude_halt,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_status,
            vpn::vpn_reconnect,
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
            db_commands::list_pending_approvals,
            db_commands::decide_approval,
            db_commands::list_workspace_files,
            db_commands::create_agent_session,
            db_commands::list_resumable_sessions,
            db_commands::save_vpn_profile,
            db_commands::list_vpn_profiles,
            db_commands::delete_vpn_profile,
            db_commands::set_default_vpn_profile,
            db_commands::update_project_target,
            db_commands::update_session_cost,
            db_commands::update_session_vpn_state,
            db_commands::add_workspace_file,
            db_commands::read_project_notes,
            db_commands::write_project_notes,
            db_commands::register_htb_mcp_server,
            vpn::vpn_set_auto_reconnect,
            db_commands::get_current_plan,
            db_commands::get_plan_steps,
            db_commands::list_execution_results,
            db_commands::list_evidence_artifacts,
            db_commands::persist_agent_message,
            db_commands::verify_message_chain,
            db_commands::install_sudoers_rule,
            db_commands::read_workspace_file,
            db_commands::count_mcp_tools,
            db_commands::get_claude_version,
            db_commands::mcp_health_check,
        ])
        .run(tauri::generate_context!())
        .expect("error while running penligent-local");
}
