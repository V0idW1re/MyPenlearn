<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  let { project, active = true, onSwitchToChat } = $props();

  // Slideshow over the persisted agent timeline. One step per assistant turn:
  // the user prompt that triggered it, the tools called, the agent's "what
  // this means" insight, and any findings the turn produced. The goal is
  // "here is the path that worked" — not a transcript dump.

  let steps        = $state([]);
  let cursor       = $state(0);          // current step idx
  let loading      = $state(false);
  let err          = $state("");
  let filter       = $state("active");   // "all" | "active" | "wins"

  let visibleSteps = $derived.by(() => {
    if (filter === "all") return steps;
    if (filter === "wins") return steps.filter(s => s.finding_ids?.length);
    return steps.filter(s => s.has_active_tool || (s.finding_ids?.length ?? 0) > 0);
  });

  let current = $derived(visibleSteps[cursor] ?? null);

  $effect(() => {
    if (!project?.id || !active) return;
    refresh();
  });

  async function refresh() {
    loading = true;
    err = "";
    try {
      steps = await invoke("load_replay_steps", { projectId: project.id });
      cursor = 0;
    } catch (e) {
      err = String(e);
      steps = [];
    } finally {
      loading = false;
    }
  }

  function fmtArgs(jsonStr) {
    if (!jsonStr) return "";
    try {
      const obj = JSON.parse(jsonStr);
      if (!obj || typeof obj !== "object") return String(jsonStr);
      const pairs = Object.entries(obj).map(([k, v]) => {
        const sv = typeof v === "string" ? v : JSON.stringify(v);
        return `${k}=${sv.length > 90 ? sv.slice(0, 87) + "…" : sv}`;
      });
      return pairs.join("  ");
    } catch {
      return jsonStr.length > 180 ? jsonStr.slice(0, 177) + "…" : jsonStr;
    }
  }

  function copyToChat(toolName, jsonStr) {
    // The user wants to "do it themselves" — drop the tool call into the
    // chat box (parent owns the chat input). For v1 we just put a friendly
    // string on the clipboard.
    const args = fmtArgs(jsonStr);
    const txt = `${toolName}${args ? " " + args : ""}`;
    navigator.clipboard?.writeText(txt).catch(() => {});
  }

  function shortText(t, n = 280) {
    if (!t) return "";
    return t.length > n ? t.slice(0, n - 1) + "…" : t;
  }

  function activeToolName(step) {
    return step.tools?.find(t => isActive(t.name))?.name ?? null;
  }

  function isActive(name) {
    if (!name) return false;
    const base = name.split("__").pop();
    const bookkeep = ["plan_", "list_", "record_finding", "update_finding",
                      "verify_finding", "workspace_", "task_", "scope_", "audit_log",
                      "ttp_lookup", "risk_summary", "map_", "approve_intent",
                      "htb_machines_search", "htb_machine_info", "htb_machines_get_active"];
    if (bookkeep.some(p => base.startsWith(p))) return false;
    return !["ToolSearch", "Read", "Grep", "Glob"].includes(base);
  }

  function phaseTag(toolName) {
    if (!toolName) return null;
    const b = toolName.split("__").pop();
    if (b.startsWith("port_scan") || b.startsWith("rustscan") || b.startsWith("masscan")) return "RECON";
    if (b.startsWith("subdomain") || b.startsWith("dns_") || b.startsWith("vhost_") || b.startsWith("ssl_check")) return "RECON";
    if (b.startsWith("http_probe") || b.startsWith("tech_detect") || b.startsWith("security_headers") || b.startsWith("waf_detect")) return "RECON";
    if (b.startsWith("dir_brute") || b.startsWith("feroxbuster") || b.startsWith("dirsearch") || b.startsWith("nikto") || b.startsWith("nuclei")) return "ENUM";
    if (b.startsWith("check_sensitive") || b.startsWith("crt_sh") || b.startsWith("osint")) return "RECON";
    if (b.startsWith("smb_") || b.startsWith("ldap_") || b.startsWith("snmp_") || b.startsWith("ftp_")) return "ENUM";
    if (b.startsWith("sqli") || b.startsWith("xss") || b.startsWith("lfi") || b.startsWith("ssrf") || b.startsWith("ssti") || b.startsWith("xxe") || b.startsWith("cmdi") || b.startsWith("idor")) return "EXPLOIT";
    if (b.startsWith("hydra") || b.startsWith("john") || b.startsWith("hashcat")) return "AUTH";
    if (b.startsWith("Bash")) return "CUSTOM";
    return "ACTION";
  }

  const PHASE_COLOR = {
    RECON:    "#58a6ff",
    ENUM:     "#d29922",
    EXPLOIT:  "#f85149",
    AUTH:     "#a371f7",
    CUSTOM:   "#8b949e",
    ACTION:   "#3fb950",
  };

  function prev() {
    if (cursor > 0) cursor--;
  }
  function next() {
    if (cursor < visibleSteps.length - 1) cursor++;
  }

  function onKey(e) {
    if (!active) return;
    if (e.target?.matches?.("input, textarea, [contenteditable]")) return;
    if (e.key === "ArrowLeft")  { prev(); }
    if (e.key === "ArrowRight") { next(); }
  }
</script>

<svelte:window onkeydown={onKey} />

<div class="pl-replay">
  <div class="pl-replay-head">
    <div class="pl-replay-title">
      <h2>Replay</h2>
      <span class="pl-replay-sub">How this engagement actually unfolded — one step at a time</span>
    </div>
    <div class="pl-replay-controls">
      <select class="pl-replay-filter" bind:value={filter}>
        <option value="active">Active tool turns only</option>
        <option value="wins">Wins (turns that recorded findings)</option>
        <option value="all">All turns</option>
      </select>
      <button class="pl-replay-refresh" onclick={refresh} disabled={loading}>
        {loading ? "Loading…" : "↻ Refresh"}
      </button>
    </div>
  </div>

  {#if err}
    <div class="pl-replay-err">{err}</div>
  {/if}

  {#if visibleSteps.length === 0 && !loading}
    <div class="pl-replay-empty">
      <p class="pl-replay-empty-head">No replay yet for this engagement.</p>
      <p class="pl-replay-empty-body">
        Once you run a turn in chat, this tab shows the path the agent took:
        what user prompt triggered it, what tool ran, what it found, and a one-line
        insight for "why this matters". Step through with ← → arrow keys.
      </p>
      <p class="pl-replay-empty-body" style="margin-top:8px">
        Filter is currently <strong>{filter}</strong> — switch to <em>All turns</em>
        if you want to see bookkeeping lookups too.
      </p>
    </div>
  {/if}

  {#if current}
    {@const tool = activeToolName(current) ?? current.tools?.[0]?.name}
    {@const phase = phaseTag(tool)}
    {@const stepNum = cursor + 1}

    <div class="pl-replay-card">
      <div class="pl-replay-card-head">
        <span class="pl-replay-step">Step {stepNum} of {visibleSteps.length}</span>
        {#if phase}
          <span class="pl-replay-phase" style="background:{PHASE_COLOR[phase]}22;color:{PHASE_COLOR[phase]};border-color:{PHASE_COLOR[phase]}66">
            {phase}
          </span>
        {/if}
        {#if current.finding_ids?.length}
          <span class="pl-replay-finding-badge" title="Findings recorded this turn">
            ⚑ {current.finding_ids.length} finding{current.finding_ids.length > 1 ? "s" : ""}
          </span>
        {/if}
        <span class="pl-replay-spacer"></span>
        <span class="pl-replay-when">turn {current.turn_idx} · {new Date(current.created_at * 1000).toLocaleString()}</span>
      </div>

      {#if current.user_prompt}
        <div class="pl-replay-section">
          <div class="pl-replay-section-label">You said</div>
          <div class="pl-replay-user">{shortText(current.user_prompt, 320)}</div>
        </div>
      {/if}

      {#if current.tools?.length}
        <div class="pl-replay-section">
          <div class="pl-replay-section-label">Tool{current.tools.length > 1 ? "s" : ""} called</div>
          {#each current.tools as t (t.name + t.input_json)}
            <div class="pl-replay-tool">
              <div class="pl-replay-tool-head">
                <span class="pl-replay-tool-ps">$</span>
                <span class="pl-replay-tool-name" class:active={isActive(t.name)}>{t.name}</span>
                {#if !isActive(t.name)}
                  <span class="pl-replay-bookkeep">bookkeeping</span>
                {/if}
                <button class="pl-replay-copy" onclick={() => copyToChat(t.name, t.input_json)} title="Copy this tool call to clipboard">
                  ⧉ Copy
                </button>
              </div>
              {#if fmtArgs(t.input_json)}
                <div class="pl-replay-tool-args">{fmtArgs(t.input_json)}</div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}

      {#if current.insight}
        <div class="pl-replay-section">
          <div class="pl-replay-section-label">Why this matters</div>
          <div class="pl-replay-insight">{current.insight}</div>
        </div>
      {/if}

      {#if !current.insight && current.text}
        <div class="pl-replay-section">
          <div class="pl-replay-section-label">Agent said (excerpt)</div>
          <div class="pl-replay-text">{shortText(current.text, 480)}</div>
        </div>
      {/if}

      <div class="pl-replay-nav">
        <button class="pl-replay-nav-btn" onclick={prev} disabled={cursor === 0}>
          ← Previous
        </button>
        <div class="pl-replay-progress">
          <span class="pl-replay-progress-bar">
            <span class="pl-replay-progress-fill" style="width: {((cursor + 1) / Math.max(1, visibleSteps.length)) * 100}%"></span>
          </span>
        </div>
        <button class="pl-replay-nav-btn" onclick={next} disabled={cursor >= visibleSteps.length - 1}>
          Next →
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .pl-replay {
    flex: 1;
    overflow-y: auto;
    padding: 20px 28px;
    max-width: 820px;
    width: 100%;
    margin: 0 auto;
  }
  .pl-replay-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
    padding-bottom: 14px;
    border-bottom: 1px solid #21262d;
  }
  .pl-replay-title h2 {
    margin: 0;
    font-size: 16px;
    color: #c9d1d9;
  }
  .pl-replay-sub {
    color: #6e7681;
    font-size: 11px;
    display: block;
    margin-top: 2px;
  }
  .pl-replay-controls {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
  .pl-replay-filter, .pl-replay-refresh {
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 4px;
    padding: 4px 10px;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
  }
  .pl-replay-refresh:hover { border-color: #58a6ff; color: #58a6ff; }
  .pl-replay-err {
    background: #2d1a1a;
    border: 1px solid #f85149;
    border-radius: 4px;
    color: #f85149;
    padding: 8px 12px;
    font-size: 12px;
    margin-bottom: 12px;
  }
  .pl-replay-empty {
    text-align: center;
    color: #6e7681;
    padding: 40px 0;
  }
  .pl-replay-empty-head {
    color: #c9d1d9;
    font-size: 13px;
    margin-bottom: 8px;
  }
  .pl-replay-empty-body {
    font-size: 12px;
    line-height: 1.5;
    max-width: 540px;
    margin: 0 auto;
  }

  .pl-replay-card {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 20px 22px;
  }
  .pl-replay-card-head {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 18px;
    padding-bottom: 12px;
    border-bottom: 1px solid #21262d;
  }
  .pl-replay-step {
    font-size: 12px;
    font-weight: 600;
    color: #c9d1d9;
  }
  .pl-replay-phase {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 2px 8px;
    border-radius: 3px;
    border: 1px solid;
  }
  .pl-replay-finding-badge {
    font-size: 11px;
    color: #f85149;
    background: #2d1a1a;
    border: 1px solid #f8514944;
    padding: 2px 8px;
    border-radius: 3px;
  }
  .pl-replay-spacer { flex: 1; }
  .pl-replay-when {
    font-size: 10px;
    color: #6e7681;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

  .pl-replay-section {
    margin-bottom: 16px;
  }
  .pl-replay-section-label {
    font-size: 10px;
    color: #6e7681;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    margin-bottom: 6px;
    font-weight: 600;
  }
  .pl-replay-user {
    background: #1d2733;
    border-left: 3px solid #58a6ff;
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.5;
  }
  .pl-replay-tool {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 8px 12px;
    margin-bottom: 6px;
  }
  .pl-replay-tool-head {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }
  .pl-replay-tool-ps {
    color: #6e7681;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  .pl-replay-tool-name {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 12px;
    color: #c9d1d9;
  }
  .pl-replay-tool-name.active { color: #3fb950; }
  .pl-replay-bookkeep {
    font-size: 9px;
    color: #6e7681;
    background: #21262d;
    padding: 1px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .pl-replay-copy {
    margin-left: auto;
    background: transparent;
    border: 1px solid #30363d;
    color: #8b949e;
    border-radius: 3px;
    padding: 2px 8px;
    font-size: 10px;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-replay-copy:hover { border-color: #58a6ff; color: #58a6ff; }
  .pl-replay-tool-args {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    color: #8b949e;
    word-break: break-all;
    padding-left: 16px;
    line-height: 1.5;
  }
  .pl-replay-insight {
    background: #1f2a1d;
    border-left: 3px solid #3fb950;
    padding: 10px 14px;
    border-radius: 0 4px 4px 0;
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.55;
  }
  .pl-replay-text {
    background: #161b22;
    border-left: 3px solid #6e7681;
    padding: 10px 14px;
    border-radius: 0 4px 4px 0;
    color: #8b949e;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre-wrap;
  }

  .pl-replay-nav {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 22px;
    padding-top: 14px;
    border-top: 1px solid #21262d;
  }
  .pl-replay-nav-btn {
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 12px;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-replay-nav-btn:hover:not(:disabled) {
    border-color: #58a6ff;
    color: #58a6ff;
  }
  .pl-replay-nav-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .pl-replay-progress {
    flex: 1;
  }
  .pl-replay-progress-bar {
    display: block;
    height: 4px;
    background: #21262d;
    border-radius: 2px;
    overflow: hidden;
  }
  .pl-replay-progress-fill {
    display: block;
    height: 100%;
    background: linear-gradient(90deg, #58a6ff, #3fb950);
    transition: width 0.2s ease;
  }
</style>
