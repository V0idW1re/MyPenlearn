<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import Sidebar from "./lib/Sidebar.svelte";
  import Chat from "./routes/Chat.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import Settings from "./lib/Settings.svelte";

  let activeProject = $state(null);
  let vpnState   = $state({ status: "disconnected", tun_ip: null, profile_name: null });
  let sessionId  = $state(null);
  let activeTab  = $state("chat");
  let currentTool = $state(null);
  let tokenCount = $state(0);   // rough estimate: cost_usd * 200k

  onMount(async () => {
    await listen("vpn://state", (e) => { vpnState = e.payload; });

    await listen("claude://done", (e) => {
      if (e.payload?.session_id) sessionId = e.payload.session_id;
      currentTool = null;
    });

    await listen("claude://chunk", (e) => {
      const c = e.payload;
      if (c.kind === "tool_use") currentTool = c.tool_name;
      if (c.cost_usd != null) tokenCount += Math.round(c.cost_usd * 200000);
    });

    try { vpnState = await invoke("vpn_status"); } catch (_) {}
  });

  function handleProjectSelect(project) {
    activeProject = project;
    sessionId = null;
    currentTool = null;
    tokenCount = 0;
    if (project) {
      invoke("claude_set_context", {
        projectId: project.id,
        workDir: `/home/kali/penligent/projects/${project.name}/workspace`,
      }).catch(console.error);
    }
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
      <button class="pl-tab" class:active={activeTab === "settings"}
        onclick={() => activeTab = "settings"}>Settings</button>
    </div>
    <div class="pl-app-name">Penligent Local 0.1.0</div>
  </div>

  <div class="pl-main" style="display:{activeTab === 'chat' ? 'flex' : 'none'}">
    <div class="pl-sidebar">
      <Sidebar {activeProject} onSelect={handleProjectSelect} />
    </div>
    <Chat project={activeProject} {sessionId} />
  </div>

  <div class="pl-main" style="display:{activeTab === 'settings' ? 'flex' : 'none'}">
    <Settings {vpnState} />
  </div>

  <StatusBar {vpnState} {currentTool} {tokenCount} />
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
  }

  .pl-main {
    flex: 1;
    display: flex;
    min-height: 0;
    overflow: hidden;
  }

  .pl-sidebar {
    width: 220px;
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow-y: auto;
  }
</style>
