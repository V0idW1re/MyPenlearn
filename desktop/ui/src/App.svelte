<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { homeDir } from "@tauri-apps/api/path";
  import Sidebar from "./lib/Sidebar.svelte";
  import Chat from "./routes/Chat.svelte";
  import Findings from "./lib/Findings.svelte";
  import NextSteps from "./lib/NextSteps.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import Settings from "./lib/Settings.svelte";
  import ApprovalModal from "./lib/ApprovalModal.svelte";
  import Workspace from "./lib/Workspace.svelte";
  import Replay from "./lib/Replay.svelte";
  import CommandPalette from "./lib/CommandPalette.svelte";
  import ShortcutHelp from "./lib/ShortcutHelp.svelte";

  let activeProject = $state(null);
  let vpnState   = $state({ status: "disconnected", tun_ip: null, profile_name: null });
  let vpnDropped = $state(null);
  let resumableSession = $state(null);   // { id, claude_session_id, started_at, workDir, vpn_state }
  let wikiViolation = $state(null);      // { message, wiki_tool_called, wiki_tag_seen }
  let sessionId  = $state(null);
  let activeTab  = $state("chat");
  let currentTool = $state(null);
  // Detected model id from Claude Code stream-json. Null until the first
  // assistant event arrives in a turn; StatusBar shows a placeholder in
  // the meantime. Survives across turns inside a project.
  let currentModel = $state(null);
  // Per-turn and cumulative session token usage. Real numbers come from the
  // backend's `claude://usage` event (parsed from Claude Code stream-json
  // `result.usage`). Reset on project switch / clear; turn resets when sending.
  let turnUsage    = $state({ input: 0, output: 0, cache_read: 0, cache_creation: 0, cost_usd: 0 });
  let sessionUsage = $state({ input: 0, output: 0, cache_read: 0, cache_creation: 0, cost_usd: 0 });
  let pendingApproval = $state(null);
  let approvalPollTimer = null;
  let activeDbSessionId = $state(null);
  let mcpStatus  = $state({ state: "checking", tool_count: 0, error: null });
  let htbMcpStatus = $state({ state: "checking", error: null });
  let mcpPollTimer = null;

  // Command palette + shortcuts help
  let paletteOpen = $state(false);
  let helpOpen    = $state(false);

  // Resizable sidebar widths. Persisted via save_config_value so they survive
  // restarts. Defaults match the previous fixed values: 220 left, 240 right.
  const SIDEBAR_MIN  = 160, SIDEBAR_MAX  = 480;
  const FINDINGS_MIN = 200, FINDINGS_MAX = 560;
  let sidebarWidth  = $state(220);
  let findingsWidth = $state(240);
  let resizing = $state(null); // "sidebar" | "findings" | null

  // Throttle config writes during a drag so we don't spam the disk.
  let widthSaveTimer = null;
  function scheduleWidthSave() {
    if (widthSaveTimer) clearTimeout(widthSaveTimer);
    widthSaveTimer = setTimeout(() => {
      invoke("save_config_value", { key: "ui_sidebar_width",  value: String(sidebarWidth)  }).catch(() => {});
      invoke("save_config_value", { key: "ui_findings_width", value: String(findingsWidth) }).catch(() => {});
    }, 400);
  }

  function startResize(which, e) {
    resizing = which;
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }
  function onResizeMove(e) {
    if (!resizing) return;
    if (resizing === "sidebar") {
      // mouse X is the new right edge of the sidebar — clamp to range.
      const next = Math.max(SIDEBAR_MIN, Math.min(SIDEBAR_MAX, e.clientX));
      sidebarWidth = next;
    } else if (resizing === "findings") {
      // findings panel is right-anchored: width = window.right - mouse X.
      const next = Math.max(FINDINGS_MIN, Math.min(FINDINGS_MAX, window.innerWidth - e.clientX));
      findingsWidth = next;
    }
  }
  function endResize() {
    if (!resizing) return;
    resizing = null;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    scheduleWidthSave();
  }

  // MCP-down detection. When the periodic health check flips from ok → error
  // we halt the in-flight Claude turn (no point letting the agent fire tool
  // calls into a dead server) and surface a blocking modal so the user can
  // see what happened without having to notice the status-bar dot.
  let mcpPrevState = $state(null);
  let mcpDownModalOpen = $state(false);
  let mcpHaltedTurn    = $state(false);
  let mcpRechecking    = $state(false);
  // Mirror state for HTB MCP. Separate modal source = "penlearn" | "htb"
  // so the message reflects which server actually died.
  let htbPrevState = $state(null);
  let mcpDownSource = $state("penlearn");

  $effect(() => {
    const cur = mcpStatus?.state;
    if (cur === "ok") {
      // Recovery — auto-dismiss the modal so the user can keep working.
      if (mcpDownModalOpen && mcpDownSource === "penlearn") {
        mcpDownModalOpen = false;
        mcpHaltedTurn = false;
      }
      mcpPrevState = "ok";
    } else if (cur === "error") {
      if (mcpPrevState === "ok") {
        // Fresh transition from healthy → broken. Halt any in-flight turn.
        invoke("claude_halt").then(halted => {
          mcpHaltedTurn = !!halted;
        }).catch(e => console.error("claude_halt failed:", e));
        mcpDownSource = "penlearn";
        mcpDownModalOpen = true;
      } else if (mcpPrevState === null) {
        // First poll after launch showed error — surface the modal but don't
        // claim we "halted" anything (nothing was running).
        mcpDownSource = "penlearn";
        mcpDownModalOpen = true;
      }
      mcpPrevState = "error";
    } else {
      // "checking" — leave prev state alone, modal stays open or closed as-is.
    }
  });

  // Same protection for HTB MCP. The user explicitly asked: "stop the ai if
  // they not appear". Only fires when state was previously ok — a user with
  // no token (state "no_token") is excluded entirely.
  $effect(() => {
    const cur = htbMcpStatus?.state;
    if (cur === "no_token" || cur === "checking") {
      htbPrevState = cur;
      if (mcpDownSource === "htb" && cur === "no_token") {
        mcpDownModalOpen = false;
        mcpHaltedTurn = false;
      }
      return;
    }
    if (cur === "ok") {
      if (mcpDownModalOpen && mcpDownSource === "htb") {
        mcpDownModalOpen = false;
        mcpHaltedTurn = false;
      }
      htbPrevState = "ok";
    } else if (cur === "missing" || cur === "error") {
      if (htbPrevState === "ok") {
        invoke("claude_halt").then(halted => {
          mcpHaltedTurn = !!halted;
        }).catch(e => console.error("claude_halt failed:", e));
        mcpDownSource = "htb";
        mcpDownModalOpen = true;
      }
      htbPrevState = cur;
    }
  });

  async function mcpRecheck() {
    if (mcpRechecking) return;
    mcpRechecking = true;
    await pollMcpHealth();
    mcpRechecking = false;
  }

  // Focus the chat input from anywhere
  function focusChatInput() {
    activeTab = "chat";
    // wait one tick for the chat panel to be visible, then focus the textarea
    requestAnimationFrame(() => {
      const ta = document.querySelector(".pl-input");
      ta?.focus();
    });
  }

  // Commands exposed to the palette + shortcuts. Each `action` mutates app
  // state directly — no event bus needed.
  let paletteCommands = $derived([
    { id: "tab-chat",     label: "Go to Chat",      hotkey: "Ctrl+1", keywords: "chat tab message", action: () => activeTab = "chat" },
    { id: "tab-work",     label: "Go to Workspace", hotkey: "Ctrl+2", keywords: "workspace files tab", action: () => activeTab = "workspace" },
    { id: "tab-replay",   label: "Go to Replay",    hotkey: "Ctrl+3", keywords: "replay walkthrough study how steps", action: () => activeTab = "replay" },
    { id: "tab-settings", label: "Go to Settings",  hotkey: "Ctrl+4", keywords: "settings preferences config tab", action: () => activeTab = "settings" },
    { id: "focus-input",  label: "Focus chat input", hotkey: "Ctrl+J", keywords: "focus input message type", action: focusChatInput },
    { id: "help",         label: "Show keyboard shortcuts", hotkey: "?", keywords: "help shortcuts keys", action: () => helpOpen = true },
    ...(activeProject ? [
      { id: "clear-chat",   label: `Clear chat for "${activeProject.name}"`, keywords: "clear reset chat", action: () => {
        invoke("clear_messages", { projectId: activeProject.id }).catch(() => {});
        invoke("claude_clear_session").catch(() => {});
        // Force a project re-select to reload (empty) history
        const p = activeProject; activeProject = null; setTimeout(() => activeProject = p, 0);
      } },
    ] : []),
    { id: "vpn-connect",  label: "VPN: Reconnect last profile", keywords: "vpn connect reconnect openvpn", action: () => invoke("vpn_reconnect").catch(console.error) },
    { id: "vpn-disconnect", label: "VPN: Disconnect", keywords: "vpn disconnect off stop", action: () => invoke("vpn_disconnect").catch(() => {}) },
    { id: "mcp-recheck",  label: "MCP: Re-run health check", keywords: "mcp health check tools refresh", action: () => pollMcpHealth() },
    { id: "rerun-wizard", label: "Re-run first-run setup wizard", keywords: "wizard setup onboarding htb vpn token first-run", action: wzReopen },
  ]);

  // Global keyboard shortcuts. Skip when typing in an input/textarea unless
  // the binding is explicitly modifier-based (Ctrl+X, etc.) — that way `?`
  // and bare-letter shortcuts never clobber typing.
  function onGlobalKey(e) {
    // If a modal is already open and consumes Escape, that's handled locally.
    const isMod = e.ctrlKey || e.metaKey;
    const target = e.target;
    const inField = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

    // Ctrl+K — palette (always)
    if (isMod && (e.key === "k" || e.key === "K")) {
      e.preventDefault(); paletteOpen = !paletteOpen; return;
    }
    // Ctrl+, — Settings
    if (isMod && e.key === ",") { e.preventDefault(); activeTab = "settings"; return; }
    // Ctrl+J — focus chat input
    if (isMod && (e.key === "j" || e.key === "J")) { e.preventDefault(); focusChatInput(); return; }
    // Ctrl+1/2/3/4 — tabs
    if (isMod && e.key === "1") { e.preventDefault(); activeTab = "chat"; return; }
    if (isMod && e.key === "2") { e.preventDefault(); activeTab = "workspace"; return; }
    if (isMod && e.key === "3") { e.preventDefault(); activeTab = "replay"; return; }
    if (isMod && e.key === "4") { e.preventDefault(); activeTab = "settings"; return; }
    // ? — help (only when not typing)
    if (!inField && !isMod && e.key === "?") { e.preventDefault(); helpOpen = true; return; }
    // Esc — close palette / help (modal-local Esc handlers are fine too; this is a fallback)
    if (e.key === "Escape") {
      if (paletteOpen) { paletteOpen = false; return; }
      if (helpOpen)    { helpOpen    = false; return; }
    }
  }

  // First-run wizard state. Steps 0..3 (welcome → claude → sudoers → summary).
  // HTB token + OVPN profile were removed: both fields are better-served by
  // Settings (which the user is going to open anyway), and duplicating them
  // in the wizard misled users into thinking they were "done" when they still
  // had to click Connect / Save & Register in Settings.
  let wizardOpen  = $state(false);
  let wizardStep  = $state(0);
  let wzSudoersDone = $state(false);
  let wzSudoersErr  = $state("");
  let wzBusy = $state(false);
  let wzClaudeInstalled = $state(false);
  let wzClaudeInstalling = $state(false);
  let wzClaudeErr = $state("");
  let wzClaudeVersion = $state("");

  function wzReset() {
    wizardStep = 0;
    wzSudoersDone = false;
    wzSudoersErr = "";
    wzBusy = false;
    wzClaudeInstalled = false;
    wzClaudeInstalling = false;
    wzClaudeErr = "";
    wzClaudeVersion = "";
  }

  function wzReopen() {
    wzReset();
    wizardOpen = true;
    wzCheckClaude();
  }

  async function pollMcpHealth() {
    mcpStatus = { ...mcpStatus, state: "checking" };
    try {
      const result = await invoke("mcp_health_check");
      mcpStatus = {
        state: result.ok ? "ok" : "error",
        tool_count: result.tool_count ?? 0,
        error: result.error ?? null,
      };
    } catch (e) {
      mcpStatus = { state: "error", tool_count: 0, error: String(e) };
    }
    // Piggyback on the same 15s timer for HTB MCP — both are cheap (file reads,
    // no network) and they fail/recover together often enough (claude install
    // overwrites settings.json AND clears registrations) that polling them
    // independently would be wasteful.
    try {
      const htb = await invoke("htb_mcp_health_check");
      htbMcpStatus = { state: htb.state ?? "error", error: htb.error ?? null };
    } catch (e) {
      htbMcpStatus = { state: "error", error: String(e) };
    }
  }

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

    // Wiki-rule violations from the Rust streaming layer: emitted when a turn
    // ran an active tool without consulting the wiki and without a [wiki: ...]
    // citation tag. Non-blocking — just surfaces a banner the operator can
    // dismiss or use to call the agent out on the next turn.
    await listen("claude://wiki-violation", (e) => {
      wikiViolation = e.payload ?? null;
    });

    await listen("claude://chunk", (e) => {
      const c = e.payload;
      if (c.kind === "tool_use") currentTool = c.tool_name;
      // Surface approvals quickly when the agent calls approve_intent
      if (c.tool_name === "approve_intent") setTimeout(pollApprovals, 800);
    });

    await listen("claude://model", (e) => {
      const m = e.payload?.model;
      if (m && typeof m === "string") currentModel = m;
    });

    await listen("claude://usage", (e) => {
      const u = e.payload ?? {};
      turnUsage = u;
      sessionUsage = {
        input:          sessionUsage.input          + (u.input          ?? 0),
        output:         sessionUsage.output         + (u.output         ?? 0),
        cache_read:     sessionUsage.cache_read     + (u.cache_read     ?? 0),
        cache_creation: sessionUsage.cache_creation + (u.cache_creation ?? 0),
        cost_usd:       sessionUsage.cost_usd       + (u.cost_usd       ?? 0),
      };
    });

    try { vpnState = await invoke("vpn_status"); } catch (_) {}

    pollMcpHealth();
    mcpPollTimer = setInterval(pollMcpHealth, 15000);

    try {
      const z = await invoke("load_config_value", { key: "ui_zoom" });
      if (z) document.documentElement.style.zoom = parseFloat(z);
    } catch (_) {}

    // Load saved sidebar widths
    try {
      const sw = await invoke("load_config_value", { key: "ui_sidebar_width" });
      if (sw) {
        const n = parseInt(sw, 10);
        if (Number.isFinite(n) && n >= SIDEBAR_MIN && n <= SIDEBAR_MAX) sidebarWidth = n;
      }
      const fw = await invoke("load_config_value", { key: "ui_findings_width" });
      if (fw) {
        const n = parseInt(fw, 10);
        if (Number.isFinite(n) && n >= FINDINGS_MIN && n <= FINDINGS_MAX) findingsWidth = n;
      }
    } catch (_) {}

    try {
      const done = await invoke("load_config_value", { key: "setup_complete" });
      if (!done) { wizardOpen = true; wzCheckClaude(); }
    } catch (_) {
      wizardOpen = true; wzCheckClaude();
    }

    // Poll for approvals every 5 seconds when a project is active
    approvalPollTimer = setInterval(() => { if (activeProject) pollApprovals(); }, 5000);

    return () => {
      if (approvalPollTimer) clearInterval(approvalPollTimer);
      if (mcpPollTimer) clearInterval(mcpPollTimer);
    };
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
    currentModel = null;
    turnUsage    = { input: 0, output: 0, cache_read: 0, cache_creation: 0, cost_usd: 0 };
    sessionUsage = { input: 0, output: 0, cache_read: 0, cache_creation: 0, cost_usd: 0 };
    pendingApproval = null;
    resumableSession = null;
    activeDbSessionId = null;
    if (!project) return;
    setTimeout(pollApprovals, 300);
    const selectedId = project.id;
    const home = await homeDir();
    const workDir = `${home}/penlearn/projects/${project.name}/workspace`;
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

  async function wzCheckClaude() {
    try {
      const v = await invoke("get_claude_version");
      wzClaudeVersion = (v ?? "").toString().trim();
      wzClaudeInstalled = !!wzClaudeVersion;
    } catch (_) {
      wzClaudeInstalled = false;
      wzClaudeVersion = "";
    }
  }

  async function wzInstallClaude() {
    wzClaudeInstalling = true;
    wzClaudeErr = "";
    try {
      await invoke("install_claude_code");
      await wzCheckClaude();
      if (!wzClaudeInstalled) {
        wzClaudeErr = "Installer reported success but ~/.local/bin/claude is still missing. Open a terminal and run: curl -fsSL https://claude.ai/install.sh | bash";
      }
    } catch (e) {
      wzClaudeErr = String(e);
    } finally {
      wzClaudeInstalling = false;
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

  let wzFinishErr = $state("");

  async function wzFinish() {
    wzBusy = true;
    wzFinishErr = "";
    try {
      await invoke("save_config_value", { key: "setup_complete", value: "1" });
      wizardOpen = false;
    } catch (e) {
      wzFinishErr = `setup_complete flag: ${e}`;
    } finally {
      wzBusy = false;
    }
  }
</script>

<svelte:window onkeydown={onGlobalKey} onpointermove={onResizeMove} onpointerup={endResize} />

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
      <button class="pl-tab" class:active={activeTab === "replay"}
        onclick={() => activeTab = "replay"}>Replay</button>
      <button class="pl-tab" class:active={activeTab === "settings"}
        onclick={() => activeTab = "settings"}>Settings</button>
    </div>
    <div class="pl-app-name">
      {#if activeProject}
        <span class="pl-crumb">Penlearn</span>
        <span class="pl-crumb-sep">/</span>
        <span class="pl-engagement">{activeProject.name}</span>
      {:else}
        Penlearn Local
      {/if}
    </div>
  </div>

  <div class="pl-main" style="display:{activeTab === 'chat' ? 'flex' : 'none'}">
    <div class="pl-sidebar" style="width:{sidebarWidth}px">
      <Sidebar {activeProject} onSelect={handleProjectSelect} />
    </div>
    <div class="pl-resize-handle" class:active={resizing === 'sidebar'}
         onpointerdown={(e) => startResize('sidebar', e)}
         aria-label="Resize left sidebar" role="separator" aria-orientation="vertical"></div>
    <Chat project={activeProject} {sessionId} />
    <div class="pl-resize-handle" class:active={resizing === 'findings'}
         onpointerdown={(e) => startResize('findings', e)}
         aria-label="Resize findings panel" role="separator" aria-orientation="vertical"></div>
    <div class="pl-findings-wrap" style="width:{findingsWidth}px">
      <Findings project={activeProject} />
      <NextSteps project={activeProject} />
    </div>
  </div>

  <div class="pl-main" style="display:{activeTab === 'workspace' ? 'flex' : 'none'}">
    <Workspace project={activeProject} onSwitchToChat={() => activeTab = "chat"} />
  </div>

  <div class="pl-main" style="display:{activeTab === 'replay' ? 'flex' : 'none'}">
    <Replay project={activeProject} active={activeTab === 'replay'} onSwitchToChat={() => activeTab = "chat"} />
  </div>

  <div class="pl-main" style="display:{activeTab === 'settings' ? 'flex' : 'none'}">
    <Settings {vpnState} active={activeTab === 'settings'} />
  </div>

  <StatusBar {vpnState} {currentTool} {currentModel} {turnUsage} {sessionUsage} {mcpStatus} {htbMcpStatus} />

  {#if pendingApproval}
    <ApprovalModal approval={pendingApproval} onDecide={handleApprovalDecide} />
  {/if}

  <CommandPalette bind:open={paletteOpen} commands={paletteCommands} />
  <ShortcutHelp   bind:open={helpOpen} />

  {#if mcpDownModalOpen}
    <div class="pl-mcp-down-backdrop" role="presentation">
      <div class="pl-mcp-down-modal" role="dialog" aria-modal="true" aria-label="MCP server offline">
        <div class="pl-mcp-down-icon">⚠</div>
        <h3 class="pl-mcp-down-title">
          {mcpDownSource === "htb" ? "HTB MCP not available" : "MCP server is offline"}
        </h3>
        <p class="pl-mcp-down-msg">
          {#if mcpDownSource === "htb"}
            The HackTheBox MCP server is not registered with Claude Code. The agent can't reach HTB machine/CTF tools.
          {:else}
            The Penlearn MCP server is not responding. The agent has no tools while it's down.
          {/if}
        </p>
        {#if mcpHaltedTurn}
          <p class="pl-mcp-down-halt">The running agent turn was halted to prevent failed tool calls.</p>
        {/if}
        {#if (mcpDownSource === "htb" ? htbMcpStatus?.error : mcpStatus?.error)}
          <pre class="pl-mcp-down-err">{mcpDownSource === "htb" ? htbMcpStatus.error : mcpStatus.error}</pre>
        {/if}
        <p class="pl-mcp-down-actions-hint">
          {#if mcpDownSource === "htb"}
            Open <strong>Settings → Diagnostics</strong> and click Fix next to "HTB MCP registered", or re-save your token under HackTheBox.
          {:else}
            Try the MCP debug recipe from the README, then click <strong>Recheck now</strong>. If that fails, restart Penlearn.
          {/if}
        </p>
        <div class="pl-mcp-down-actions">
          <button class="pl-mcp-down-btn-secondary" onclick={() => mcpDownModalOpen = false}>Dismiss</button>
          <button class="pl-mcp-down-btn-primary" onclick={mcpRecheck} disabled={mcpRechecking}>
            {mcpRechecking ? "Checking…" : "Recheck now"}
          </button>
        </div>
      </div>
    </div>
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

  {#if wikiViolation}
    <div class="pl-wiki-warn">
      <span class="pl-wiki-warn-icon">&#9888;</span>
      <span class="pl-wiki-warn-text">
        <strong>Wiki rule skipped this turn.</strong>
        {wikiViolation.message ?? "Agent ran an active tool without a wiki_query or [wiki: …] citation."}
      </span>
      <button class="pl-vpn-dismiss" onclick={() => wikiViolation = null}>&#x2715;</button>
    </div>
  {/if}

  {#if wizardOpen}
    <div class="pl-wizard-backdrop">
      <div class="pl-wizard">
        <div class="pl-wiz-header">
          <span class="pl-wiz-title">
            {#if wizardStep === 0}Welcome to Penlearn Local
            {:else if wizardStep === 3}Setup complete
            {:else}Setup — step {wizardStep} of 2{/if}
          </span>
          {#if wizardStep >= 1 && wizardStep <= 2}
            <div class="pl-wiz-steps">
              {#each [1,2] as s}
                <span class="pl-wiz-dot" class:active={s === wizardStep} class:done={s < wizardStep}></span>
              {/each}
            </div>
          {/if}
        </div>

        <div class="pl-wiz-body">
          {#if wizardStep === 0}
            <p class="pl-wiz-welcome-lead">A self-hosted, autonomous penetration testing agent running entirely on your machine.</p>
            <ul class="pl-wiz-welcome-bullets">
              <li><b>Step 1 — Claude Code</b> &nbsp;<span class="pl-wiz-meta">(required)</span> &nbsp;the agent runtime</li>
              <li><b>Step 2 — OpenVPN privilege</b> &nbsp;<span class="pl-wiz-meta">(recommended)</span> &nbsp;passwordless VPN start/stop</li>
            </ul>
            <p class="pl-wiz-hint">Your HTB API token and <code>.ovpn</code> profile are set up in <b>Settings</b> after this wizard — that's the single source of truth for both.</p>
            <p class="pl-wiz-hint" style="margin-top:6px">Every step is skippable. You can re-run this wizard anytime from <kbd>Ctrl+K</kbd> → "Re-run first-run setup".</p>

          {:else if wizardStep === 1}
            <p class="pl-wiz-label">Claude Code <span class="pl-wiz-meta">(required)</span></p>
            <p class="pl-wiz-hint">Penlearn drives <code>~/.local/bin/claude</code> as its agent runtime. Without it the HTB MCP can't register and chat won't run.</p>
            {#if wzClaudeInstalled}
              <span class="pl-wiz-ok">&#10003; Installed{wzClaudeVersion ? ` · ${wzClaudeVersion}` : ""}</span>
            {:else}
              <button class="pl-wiz-action-btn" onclick={wzInstallClaude} disabled={wzClaudeInstalling}>
                {wzClaudeInstalling ? "Installing…" : "Install Claude Code"}
              </button>
              <p class="pl-wiz-hint" style="margin-top:8px">Runs <code>curl -fsSL https://claude.ai/install.sh | bash</code>. Needs internet. After install you'll still need to <code>claude login</code> once in a terminal.</p>
              {#if wzClaudeErr}
                <pre class="pl-wiz-err-block">{wzClaudeErr}</pre>
              {/if}
            {/if}

          {:else if wizardStep === 2}
            <p class="pl-wiz-label">OpenVPN privilege <span class="pl-wiz-meta">(recommended)</span></p>
            <p class="pl-wiz-hint">Installs a narrow sudoers rule so the agent can start/stop OpenVPN without a password prompt. Only <code>/usr/sbin/openvpn</code> is permitted; the rule lives in <code>/etc/sudoers.d/penlearn-openvpn</code>.</p>
            {#if wzSudoersDone}
              <span class="pl-wiz-ok">&#10003; Installed</span>
            {:else}
              <button class="pl-wiz-action-btn" onclick={wzInstallSudoers} disabled={wzBusy}>
                {wzBusy ? "Installing…" : "Install sudoers rule"}
              </button>
              {#if wzSudoersErr}
                <pre class="pl-wiz-err-block">{wzSudoersErr}</pre>
              {/if}
            {/if}

          {:else if wizardStep === 3}
            <p class="pl-wiz-welcome-lead">Ready to launch. Here's what's set up:</p>
            <div class="pl-wiz-summary">
              <div class="pl-wiz-sum-row">
                <span class="pl-wiz-sum-icon">{wzClaudeInstalled ? "✓" : "—"}</span>
                <span class="pl-wiz-sum-label">Claude Code</span>
                <span class="pl-wiz-sum-val">{wzClaudeInstalled ? (wzClaudeVersion || "installed") : "missing"}</span>
              </div>
              <div class="pl-wiz-sum-row">
                <span class="pl-wiz-sum-icon">{wzSudoersDone ? "✓" : "—"}</span>
                <span class="pl-wiz-sum-label">OpenVPN sudoers</span>
                <span class="pl-wiz-sum-val">{wzSudoersDone ? "installed" : "skipped"}</span>
              </div>
            </div>
            <p class="pl-wiz-hint" style="margin-top:10px">Next: open <b>Settings</b> to paste your HTB API token and add a <code>.ovpn</code> profile.</p>
            {#if wzFinishErr}
              <pre class="pl-wiz-err-block">{wzFinishErr}</pre>
            {/if}
          {/if}
        </div>

        <div class="pl-wiz-actions">
          {#if wizardStep === 0}
            <button class="pl-wiz-skip" onclick={() => { wizardStep = 3; }}>Skip all</button>
            <button class="pl-wiz-next" onclick={() => wizardStep++}>Get started →</button>
          {:else if wizardStep >= 1 && wizardStep <= 2}
            <button class="pl-wiz-back" onclick={() => wizardStep--} disabled={wzBusy || wzClaudeInstalling} type="button">← Back</button>
            <button class="pl-wiz-skip" onclick={() => wizardStep++} disabled={wzBusy || wzClaudeInstalling} type="button">Skip</button>
            <button class="pl-wiz-next" onclick={() => wizardStep++} disabled={wzBusy || wzClaudeInstalling} type="button">Next →</button>
          {:else}
            <button class="pl-wiz-back" onclick={() => wizardStep = 2} disabled={wzBusy} type="button">← Back</button>
            <button class="pl-wiz-next" onclick={wzFinish} disabled={wzBusy} type="button">
              {wzBusy ? "Saving…" : "Finish setup"}
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

  .pl-wiki-warn {
    position: fixed;
    bottom: 72px;
    left: 50%;
    transform: translateX(-50%);
    max-width: 720px;
    background: #1d2733;
    border: 1px solid #388bfd;
    border-radius: 6px;
    color: #e6edf3;
    font-size: 12px;
    padding: 8px 14px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    z-index: 500;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  }
  .pl-wiki-warn-icon { color: #58a6ff; font-size: 14px; line-height: 18px; }
  .pl-wiki-warn-text { flex: 1; line-height: 1.45; }
  .pl-wiki-warn-text strong { color: #58a6ff; }
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
    /* width set inline from $state(sidebarWidth) — see App.svelte markup */
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow-y: auto;
  }

  .pl-findings-wrap {
    /* width set inline from $state(findingsWidth) */
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow: hidden;
  }
  /* Child Findings component fills the wrapper */
  .pl-findings-wrap > :global(.pl-findings) {
    width: 100% !important;
    flex: 1 1 auto;
    min-height: 0;
  }
  .pl-findings-wrap > :global(.pl-next) {
    flex: 0 0 auto;
  }

  .pl-resize-handle {
    flex: 0 0 4px;
    background: transparent;
    cursor: col-resize;
    position: relative;
    z-index: 5;
    transition: background 0.1s;
  }
  .pl-resize-handle::before {
    /* visible 1px guide line in the middle of the 4px hit-target */
    content: "";
    position: absolute;
    left: 50%;
    top: 0; bottom: 0;
    width: 1px;
    transform: translateX(-0.5px);
    background: #30363d;
  }
  .pl-resize-handle:hover,
  .pl-resize-handle.active {
    background: rgba(88, 166, 255, 0.15);
  }
  .pl-resize-handle:hover::before,
  .pl-resize-handle.active::before {
    background: #58a6ff;
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

  /* ── new polish ──────────────────────────────────────────── */

  .pl-wiz-back {
    background: transparent; border: 1px solid #30363d;
    color: #8b949e; padding: 6px 12px;
    border-radius: 6px; cursor: pointer;
    font-size: 12px; font-family: inherit;
    margin-right: auto;
  }
  .pl-wiz-back:hover:not(:disabled) { color: #c9d1d9; border-color: #484f58; }
  .pl-wiz-back:disabled { opacity: 0.4; cursor: not-allowed; }

  .pl-wiz-welcome-lead {
    font-size: 13px;
    color: #c9d1d9;
    line-height: 1.5;
    margin-bottom: 4px;
  }
  .pl-wiz-welcome-bullets {
    list-style: none;
    padding-left: 0;
    margin: 4px 0;
    font-size: 12px;
    color: #c9d1d9;
    line-height: 1.8;
  }
  .pl-wiz-welcome-bullets li { padding-left: 0; }
  .pl-wiz-hint code {
    background: #161b22; padding: 1px 5px;
    border-radius: 3px; font-size: 11px;
    color: #c9d1d9;
  }
  .pl-wiz-hint kbd {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    background: #161b22;
    border: 1px solid #21262d;
    color: #8b949e;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 10px;
  }
  .pl-wiz-meta {
    color: #6e7681;
    font-weight: 400;
    font-size: 11px;
  }

  .pl-wiz-summary {
    background: #010409;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 4px 0;
  }
  .pl-wiz-sum-row {
    display: grid;
    grid-template-columns: 28px 1fr 2fr;
    align-items: center;
    padding: 7px 14px;
    font-size: 12px;
    border-bottom: 1px solid #161b22;
  }
  .pl-wiz-sum-row:last-child { border-bottom: 0; }
  .pl-wiz-sum-icon {
    color: #3fb950;
    font-weight: 600;
  }
  .pl-wiz-sum-row:has(.pl-wiz-sum-icon:empty),
  .pl-wiz-sum-row .pl-wiz-sum-icon:not(:empty) { /* no-op, keeps selector valid */ }
  .pl-wiz-sum-label { color: #8b949e; }
  .pl-wiz-sum-val   { color: #c9d1d9; font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 11px; }

  .pl-wiz-err-block {
    background: #1c0a0a;
    border: 1px solid #5d1f1f;
    border-radius: 4px;
    padding: 8px 10px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    color: #ff7b72;
    margin: 8px 0 0;
    white-space: pre-wrap;
    word-break: break-word;
  }

  /* ── MCP-down modal ──────────────────────────────────────── */

  .pl-mcp-down-backdrop {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.65);
    display: flex; align-items: center; justify-content: center;
    z-index: 1100;  /* above command palette / help */
  }
  .pl-mcp-down-modal {
    width: 460px; max-width: 90vw;
    background: #0d1117;
    border: 1px solid #5d1f1f;
    border-radius: 8px;
    box-shadow: 0 12px 48px rgba(0,0,0,0.6);
    padding: 18px 22px 14px;
  }
  .pl-mcp-down-icon {
    color: #f85149;
    font-size: 24px;
    line-height: 1;
    margin-bottom: 8px;
  }
  .pl-mcp-down-title {
    color: #f85149;
    font-size: 15px;
    font-weight: 600;
    margin: 0 0 8px;
  }
  .pl-mcp-down-msg {
    color: #c9d1d9;
    font-size: 13px;
    margin: 4px 0;
    line-height: 1.5;
  }
  .pl-mcp-down-halt {
    color: #f0b132;
    font-size: 12px;
    margin: 8px 0;
    background: #261b07;
    border: 1px solid #4d390a;
    border-radius: 4px;
    padding: 6px 10px;
  }
  .pl-mcp-down-err {
    background: #1c0a0a;
    border: 1px solid #5d1f1f;
    border-radius: 4px;
    padding: 8px 10px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    color: #ff7b72;
    margin: 8px 0;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 140px;
    overflow-y: auto;
  }
  .pl-mcp-down-actions-hint {
    color: #8b949e;
    font-size: 11px;
    margin: 10px 0 12px;
    line-height: 1.5;
  }
  .pl-mcp-down-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .pl-mcp-down-btn-secondary {
    background: transparent;
    border: 1px solid #30363d;
    color: #8b949e;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
  }
  .pl-mcp-down-btn-secondary:hover { color: #c9d1d9; border-color: #484f58; }
  .pl-mcp-down-btn-primary {
    background: #1f6feb;
    border: none;
    color: #fff;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12px; font-weight: 600;
    font-family: inherit;
    cursor: pointer;
  }
  .pl-mcp-down-btn-primary:hover:not(:disabled) { background: #388bfd; }
  .pl-mcp-down-btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
