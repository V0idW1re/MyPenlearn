<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { homeDir } from "@tauri-apps/api/path";
  import { open } from "@tauri-apps/plugin-dialog";
  import Sidebar from "./lib/Sidebar.svelte";
  import Chat from "./routes/Chat.svelte";
  import Findings from "./lib/Findings.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import Settings from "./lib/Settings.svelte";
  import ApprovalModal from "./lib/ApprovalModal.svelte";
  import Workspace from "./lib/Workspace.svelte";

  let activeProject = $state(null);
  let vpnState   = $state({ status: "disconnected", tun_ip: null, profile_name: null });
  let vpnDropped = $state(null);
  let resumableSession = $state(null);   // { id, claude_session_id, started_at, workDir, vpn_state }
  let sessionId  = $state(null);
  let activeTab  = $state("chat");
  let currentTool = $state(null);
  let tokenCount = $state(0);
  let pendingApproval = $state(null);
  let approvalPollTimer = null;
  let activeDbSessionId = $state(null);

  // First-run wizard state
  let wizardOpen  = $state(false);
  let wizardStep  = $state(1);
  let wzHtbToken  = $state("");
  let wzOvpnPath  = $state("");
  let wzSudoersDone = $state(false);
  let wzSudoersErr  = $state("");
  let wzBusy = $state(false);

  async function pollApprovals() {
    if (!activeProject) return;
    try {
      const pending = await invoke("list_pending_approvals", { projectId: activeProject.id });
      pendingApproval = pending.length > 0 ? pending[0] : null;
    } catch (_) {
      pendingApproval = null;
    }
  }

  function handleApprovalDecide() {
    pendingApproval = null;
    // Poll again shortly in case more are queued
    setTimeout(pollApprovals, 500);
  }

  onMount(async () => {
    await listen("vpn://state", (e) => {
      vpnState = e.payload;
      // Record connected VPN profile into active agent_sessions row
      if (e.payload?.status === "connected" && e.payload?.profile_name && activeDbSessionId) {
        invoke("update_session_vpn_state", {
          dbSessionId: activeDbSessionId,
          vpnProfile: e.payload.profile_name,
        }).catch(() => {});
      }
    });
    await listen("vpn://dropped", (e) => { vpnDropped = e.payload; });

    await listen("claude://done", (e) => {
      if (e.payload?.project_id && activeProject?.id !== e.payload.project_id) return;
      if (e.payload?.session_id) sessionId = e.payload.session_id;
      currentTool = null;
      pollApprovals();
    });

    await listen("claude://chunk", (e) => {
      const c = e.payload;
      if (c.kind === "tool_use") currentTool = c.tool_name;
      if (c.cost_usd != null) tokenCount += Math.round(c.cost_usd * 200000);
      // Surface approvals quickly when the agent calls approve_intent
      if (c.tool_name === "approve_intent") setTimeout(pollApprovals, 800);
    });

    try { vpnState = await invoke("vpn_status"); } catch (_) {}

    try {
      const z = await invoke("load_config_value", { key: "ui_zoom" });
      if (z) document.documentElement.style.zoom = parseFloat(z);
    } catch (_) {}

    try {
      const done = await invoke("load_config_value", { key: "setup_complete" });
      if (!done) wizardOpen = true;
    } catch (_) {
      wizardOpen = true;
    }

    // Poll for approvals every 5 seconds when a project is active
    approvalPollTimer = setInterval(() => { if (activeProject) pollApprovals(); }, 5000);

    return () => { if (approvalPollTimer) clearInterval(approvalPollTimer); };
  });

  async function applyContext(project, workDir, resumeId, dbSessionId) {
    activeDbSessionId = dbSessionId ?? null;
    invoke("claude_set_context", {
      projectId: project.id,
      workDir,
      resumeClaudeSessionId: resumeId ?? null,
      dbSessionId: dbSessionId ?? null,
    }).catch(console.error);
  }

  async function handleProjectSelect(project) {
    activeProject = project;
    sessionId = null;
    currentTool = null;
    tokenCount = 0;
    pendingApproval = null;
    resumableSession = null;
    activeDbSessionId = null;
    if (!project) return;
    setTimeout(pollApprovals, 300);
    const selectedId = project.id;
    const home = await homeDir();
    const workDir = `${home}/penligent/projects/${project.name}/workspace`;
    try {
      const sessions = await invoke("list_resumable_sessions", { projectId: selectedId });
      // Guard: user may have switched to a different project while this awaited
      if (activeProject?.id !== selectedId) return;
      if (sessions.length > 0) {
        resumableSession = { ...sessions[0], workDir };
      } else {
        const dbSid = await invoke("create_agent_session", { projectId: selectedId }).catch(() => null);
        if (activeProject?.id !== selectedId) return;
        applyContext(project, workDir, null, dbSid);
      }
    } catch (_) {
      if (activeProject?.id !== selectedId) return;
      applyContext(project, workDir, null, null);
    }
  }

  async function handleResumeDecision(doResume) {
    if (!activeProject || !resumableSession) return;
    const s = resumableSession;
    resumableSession = null;
    if (doResume) {
      applyContext(activeProject, s.workDir, s.claude_session_id, s.id);
    } else {
      const dbSid = await invoke("create_agent_session", { projectId: activeProject.id }).catch(() => null);
      applyContext(activeProject, s.workDir, null, dbSid);
    }
  }

  async function wzInstallSudoers() {
    wzBusy = true;
    wzSudoersErr = "";
    try {
      await invoke("install_sudoers_rule");
      wzSudoersDone = true;
    } catch (e) {
      wzSudoersErr = String(e);
    } finally {
      wzBusy = false;
    }
  }

  async function wzBrowseOvpn() {
    const home = await homeDir();
    const path = await open({
      title: "Select default .ovpn file",
      filters: [{ name: "OpenVPN Config", extensions: ["ovpn"] }],
      defaultPath: `${home}/Downloads`,
    });
    if (path) wzOvpnPath = path;
  }

  async function wzFinish() {
    wzBusy = true;
    try {
      if (wzHtbToken.trim()) {
        await invoke("save_config_value", { key: "htb_app_token", value: wzHtbToken.trim() });
        await invoke("save_config_value", { key: "htb_mcp_token", value: wzHtbToken.trim() });
        await invoke("register_htb_mcp_server", { token: wzHtbToken.trim() }).catch(() => {});
      }
      if (wzOvpnPath) {
        const name = wzOvpnPath.split("/").pop().replace(".ovpn", "");
        await invoke("save_vpn_profile", { name, ovpnPath: wzOvpnPath, kind: "" }).catch(() => {});
      }
      await invoke("save_config_value", { key: "setup_complete", value: "1" });
    } catch (_) {}
    wizardOpen = false;
    wzBusy = false;
  }
</script>

<div class="pl-app">
  <div class="pl-titlebar">
    <div class="pl-traffic">
      <span style="background:#ff5f57"></span>
      <span style="background:#febc2e"></span>
      <span style="background:#28c840"></span>
    </div>
    <div class="pl-tabs">
      <button class="pl-tab" class:active={activeTab === "chat"}
        onclick={() => activeTab = "chat"}>Chat</button>
      <button class="pl-tab" class:active={activeTab === "workspace"}
        onclick={() => activeTab = "workspace"}>Workspace</button>
      <button class="pl-tab" class:active={activeTab === "settings"}
        onclick={() => activeTab = "settings"}>Settings</button>
    </div>
    <div class="pl-app-name">
      {#if activeProject}
        <span class="pl-crumb">Penligent</span>
        <span class="pl-crumb-sep">/</span>
        <span class="pl-engagement">{activeProject.name}</span>
      {:else}
        Penligent Local
      {/if}
    </div>
  </div>

  <div class="pl-main" style="display:{activeTab === 'chat' ? 'flex' : 'none'}">
    <div class="pl-sidebar">
      <Sidebar {activeProject} onSelect={handleProjectSelect} />
    </div>
    <Chat project={activeProject} {sessionId} />
    <Findings project={activeProject} />
  </div>

  <div class="pl-main" style="display:{activeTab === 'workspace' ? 'flex' : 'none'}">
    <Workspace project={activeProject} onSwitchToChat={() => activeTab = "chat"} />
  </div>

  <div class="pl-main" style="display:{activeTab === 'settings' ? 'flex' : 'none'}">
    <Settings {vpnState} />
  </div>

  <StatusBar {vpnState} {currentTool} {tokenCount} />

  {#if pendingApproval}
    <ApprovalModal approval={pendingApproval} onDecide={handleApprovalDecide} />
  {/if}

  {#if resumableSession}
    <div class="pl-resume-banner">
      <span>Session from {new Date(resumableSession.started_at * 1000).toLocaleString()} found</span>
      {#if resumableSession.vpn_state && vpnState?.status !== 'connected'}
        <span class="pl-resume-vpn">· VPN was: <strong>{resumableSession.vpn_state}</strong></span>
        <button class="pl-resume-vpn-btn" onclick={() => {
          invoke("vpn_reconnect").catch(console.error);
        }}>Reconnect VPN</button>
      {/if}
      <span>—</span>
      <button class="pl-resume-btn" onclick={() => handleResumeDecision(true)}>Resume</button>
      <button class="pl-resume-btn pl-resume-fresh" onclick={() => handleResumeDecision(false)}>Start Fresh</button>
    </div>
  {/if}

  {#if vpnDropped}
    <div class="pl-vpn-drop">
      <span class="pl-vpn-drop-icon">&#9888;</span>
      VPN dropped: <strong>{vpnDropped}</strong>
      <button class="pl-vpn-reconnect" onclick={() => {
        invoke("vpn_reconnect").catch(console.error);
        vpnDropped = null;
      }}>Reconnect</button>
      <button class="pl-vpn-dismiss" onclick={() => vpnDropped = null}>&#x2715;</button>
    </div>
  {/if}

  {#if wizardOpen}
    <div class="pl-wizard-backdrop">
      <div class="pl-wizard">
        <div class="pl-wiz-header">
          <span class="pl-wiz-title">Welcome to Penligent Local</span>
          <div class="pl-wiz-steps">
            {#each [1,2,3] as s}
              <span class="pl-wiz-dot" class:active={s === wizardStep} class:done={s < wizardStep}></span>
            {/each}
          </div>
        </div>

        <div class="pl-wiz-body">
          {#if wizardStep === 1}
            <p class="pl-wiz-label">HTB API Token</p>
            <p class="pl-wiz-hint">HTB profile → Settings → API → create app token. Used for REST API calls and MCP server authentication.</p>
            <input class="pl-wiz-input" type="password" placeholder="eyJ0eXAi…" bind:value={wzHtbToken} />
          {:else if wizardStep === 2}
            <p class="pl-wiz-label">OpenVPN privilege</p>
            <p class="pl-wiz-hint">Installs a narrow sudoers rule so the agent can start/stop OpenVPN without a password prompt. Only <code>/usr/sbin/openvpn</code> is permitted.</p>
            {#if wzSudoersDone}
              <span class="pl-wiz-ok">&#10003; Installed</span>
            {:else}
              <button class="pl-wiz-action-btn" onclick={wzInstallSudoers} disabled={wzBusy}>
                {wzBusy ? "Installing…" : "Install sudoers rule"}
              </button>
              {#if wzSudoersErr}<span class="pl-wiz-err">{wzSudoersErr}</span>{/if}
            {/if}
          {:else if wizardStep === 3}
            <p class="pl-wiz-label">Default VPN profile</p>
            <p class="pl-wiz-hint">Select your HTB .ovpn file. You can add more profiles in Settings later.</p>
            <div class="pl-wiz-row">
              <input class="pl-wiz-input" value={wzOvpnPath} placeholder="~/Downloads/lab.ovpn" readonly />
              <button class="pl-wiz-browse" onclick={wzBrowseOvpn}>Browse</button>
            </div>
          {/if}
        </div>

        <div class="pl-wiz-actions">
          {#if wizardStep < 3}
            <button class="pl-wiz-skip" onclick={() => wizardStep++} disabled={wzBusy}>Skip</button>
            <button class="pl-wiz-next" onclick={() => wizardStep++} disabled={wzBusy}>Next →</button>
          {:else}
            <button class="pl-wiz-skip" onclick={wzFinish} disabled={wzBusy}>Skip</button>
            <button class="pl-wiz-next" onclick={wzFinish} disabled={wzBusy}>
              {wzBusy ? "Saving…" : "Finish"}
            </button>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(*, *::before, *::after) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) { background: #0d1117; }

  :global(*::-webkit-scrollbar)       { width: 5px; height: 5px; }
  :global(*::-webkit-scrollbar-track) { background: transparent; }
  :global(*::-webkit-scrollbar-thumb) { background: #30363d; border-radius: 3px; }
  :global(*::-webkit-scrollbar-thumb:hover) { background: #484f58; }

  .pl-app {
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }

  .pl-titlebar {
    height: 38px;
    background: #010409;
    border-bottom: 1px solid #30363d;
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 10px;
    flex-shrink: 0;
  }

  .pl-traffic { display: flex; gap: 6px; }
  .pl-traffic :global(span) {
    width: 11px; height: 11px; border-radius: 50%; display: block;
  }

  .pl-tabs { display: flex; gap: 2px; margin-left: 14px; }

  .pl-tab {
    padding: 6px 12px;
    border-radius: 5px;
    cursor: pointer;
    color: #8b949e;
    font-size: 12px;
    font-weight: 500;
    user-select: none;
    background: none;
    border: none;
    font-family: inherit;
  }
  .pl-tab:hover:not(.active) { background: #1c2128; }
  .pl-tab.active { background: #21262d; color: #e6edf3; }

  .pl-app-name {
    margin-left: auto;
    font-size: 12px;
    color: #6e7681;
    font-weight: 500;
    letter-spacing: 0.02em;
    display: flex;
    align-items: center;
    gap: 0;
  }
  .pl-crumb      { color: #484f58; }
  .pl-crumb-sep  { color: #30363d; margin: 0 5px; }
  .pl-engagement { color: #e6edf3; font-weight: 600; letter-spacing: 0.01em; }

  .pl-main {
    flex: 1;
    display: flex;
    min-height: 0;
    overflow: hidden;
  }

  .pl-resume-banner {
    position: fixed;
    bottom: 32px;
    left: 50%;
    transform: translateX(-50%);
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 12px;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    z-index: 498;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  }
  .pl-resume-btn {
    background: #238636;
    border: none;
    border-radius: 4px;
    color: #fff;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-resume-btn:hover { background: #2ea043; }
  .pl-resume-fresh { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; }
  .pl-resume-fresh:hover { background: #30363d; }
  .pl-resume-vpn { font-size: 11px; color: #8b949e; }
  .pl-resume-vpn-btn {
    background: #1a2a1a;
    border: 1px solid #3fb950;
    border-radius: 4px;
    color: #3fb950;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-resume-vpn-btn:hover { background: #3fb950; color: #0d1117; }

  .pl-vpn-drop {
    position: fixed;
    bottom: 32px;
    left: 50%;
    transform: translateX(-50%);
    background: #2d1a00;
    border: 1px solid #d29922;
    border-radius: 6px;
    color: #e6edf3;
    font-size: 12px;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    z-index: 500;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  }
  .pl-vpn-drop-icon { color: #d29922; font-size: 14px; }
  .pl-vpn-reconnect {
    background: #d29922;
    border: none;
    border-radius: 4px;
    color: #0d1117;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-vpn-reconnect:hover { background: #e3a42e; }
  .pl-vpn-dismiss {
    background: none;
    border: none;
    color: #8b949e;
    cursor: pointer;
    font-size: 13px;
    padding: 0 2px;
    line-height: 1;
    font-family: inherit;
  }
  .pl-vpn-dismiss:hover { color: #c9d1d9; }

  .pl-sidebar {
    width: 220px;
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow-y: auto;
  }

  .pl-wizard-backdrop {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.78);
    display: flex; align-items: center; justify-content: center;
    z-index: 2000;
  }
  .pl-wizard {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    width: 420px;
    max-width: 92vw;
    box-shadow: 0 20px 60px rgba(0,0,0,0.6);
    overflow: hidden;
  }
  .pl-wiz-header {
    padding: 18px 20px 14px;
    border-bottom: 1px solid #21262d;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .pl-wiz-title { font-size: 14px; font-weight: 600; color: #e6edf3; }
  .pl-wiz-steps { display: flex; gap: 6px; }
  .pl-wiz-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: #30363d;
    transition: background 0.15s;
  }
  .pl-wiz-dot.active { background: #58a6ff; }
  .pl-wiz-dot.done { background: #3fb950; }

  .pl-wiz-body {
    padding: 20px 20px 16px;
    min-height: 130px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .pl-wiz-label { font-size: 13px; color: #e6edf3; font-weight: 600; margin: 0; }
  .pl-wiz-hint { font-size: 12px; color: #6e7681; line-height: 1.5; margin: 0; }
  .pl-wiz-hint code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #9fef00; font-size: 11px;
    background: rgba(159,239,0,0.06);
    padding: 1px 4px; border-radius: 3px;
  }
  .pl-wiz-input {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 12px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    padding: 8px 10px;
    outline: none;
    width: 100%;
    transition: border-color 0.12s;
  }
  .pl-wiz-input:focus { border-color: #58a6ff; }
  .pl-wiz-input[readonly] { color: #8b949e; cursor: default; }
  .pl-wiz-row { display: flex; gap: 6px; align-items: center; }
  .pl-wiz-row .pl-wiz-input { flex: 1; width: auto; }
  .pl-wiz-browse {
    background: #21262d; border: 1px solid #30363d;
    color: #c9d1d9; padding: 7px 12px;
    border-radius: 5px; cursor: pointer;
    font-size: 12px; font-family: inherit; white-space: nowrap;
  }
  .pl-wiz-browse:hover { background: #30363d; }
  .pl-wiz-action-btn {
    background: #238636; border: none;
    color: #fff; padding: 8px 16px;
    border-radius: 6px; cursor: pointer;
    font-size: 12px; font-family: inherit; font-weight: 600;
    align-self: flex-start;
  }
  .pl-wiz-action-btn:not(:disabled):hover { background: #2ea043; }
  .pl-wiz-action-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .pl-wiz-ok { color: #3fb950; font-size: 13px; font-weight: 600; }
  .pl-wiz-err { color: #f85149; font-size: 11px; }

  .pl-wiz-actions {
    padding: 12px 20px 16px;
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 8px;
    border-top: 1px solid #21262d;
  }
  .pl-wiz-skip {
    background: none; border: none;
    color: #6e7681; cursor: pointer;
    font-size: 12px; font-family: inherit;
    padding: 6px 10px; border-radius: 4px;
  }
  .pl-wiz-skip:hover:not(:disabled) { color: #c9d1d9; background: #21262d; }
  .pl-wiz-skip:disabled { opacity: 0.4; cursor: not-allowed; }
  .pl-wiz-next {
    background: #1f6feb; border: none;
    color: #fff; padding: 7px 18px;
    border-radius: 6px; cursor: pointer;
    font-size: 12px; font-weight: 600; font-family: inherit;
  }
  .pl-wiz-next:hover:not(:disabled) { background: #388bfd; }
  .pl-wiz-next:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
