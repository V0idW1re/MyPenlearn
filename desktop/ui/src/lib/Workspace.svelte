<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";

  let { project, onSwitchToChat } = $props();

  let wsTab   = $state("files");   // "files" | "notes" | "plan" | "attack"
  let files   = $state([]);
  let loading = $state(false);
  let error   = $state("");
  let uploading = $state(false);

  // File preview state
  let previewFileId = $state(null);
  let previewContent = $state("");
  let previewLoading = $state(false);

  // Notes state
  let notesContent = $state("");
  let notesSaved   = $state(true);
  let notesSaving  = $state(false);
  let notesTimer   = null;

  // Plan state
  let plan      = $state(null);
  let planSteps = $state([]);
  let planLoading = $state(false);

  let unlisten, unlistenPlan;

  const STEP_ICON  = { pending: "○", in_progress: "→", done: "✓", skipped: "—", failed: "✗" };
  const STEP_COLOR = { pending: "#484f58", in_progress: "#9fef00", done: "#3fb950", skipped: "#30363d", failed: "#f85149" };

  const VERB_LABELS = {
    passive_recon: "Passive Recon", active_recon: "Active Recon",
    subdomain_enum: "Subdomain Enum", port_scan: "Port Scan",
    dir_brute: "Dir Brute", http_probe: "HTTP Probe", tech_detect: "Tech Detect",
    sqli_detect: "SQLi Detect", xss_probe: "XSS Probe", ssrf_probe: "SSRF Probe",
    lfi_probe: "LFI Probe", auth_test: "Auth Test", session_test: "Session Test",
    bac_test: "BAC Test", exploit_run: "Exploit", privesc: "Priv Esc",
    post_exploit: "Post Exploit", lateral_move: "Lateral Move",
    evidence_collect: "Evidence Collect", report_generate: "Report Generate", custom: "Custom",
  };

  const VERB_PHASE = {
    passive_recon: "Recon", active_recon: "Recon", subdomain_enum: "Recon",
    port_scan: "Recon", dir_brute: "Recon", http_probe: "Recon", tech_detect: "Recon",
    sqli_detect: "Discovery", xss_probe: "Discovery", ssrf_probe: "Discovery",
    lfi_probe: "Discovery", auth_test: "Discovery", session_test: "Discovery", bac_test: "Discovery",
    exploit_run: "Exploit",
    privesc: "Post-Exploit", post_exploit: "Post-Exploit",
    lateral_move: "Post-Exploit", evidence_collect: "Post-Exploit",
    report_generate: "Report", custom: "Custom",
  };

  const PHASE_COLOR = {
    Recon: "#388bfd", Discovery: "#bc8cff", Exploit: "#f85149",
    "Post-Exploit": "#fb8500", Report: "#3fb950", Custom: "#8b949e",
  };

  const IMPACT_LABEL = {
    exploit_run:      "HOST COMPROMISE",
    privesc:          "PRIV ESC",
    lateral_move:     "LATERAL MOVE",
    evidence_collect: "EVIDENCE",
    report_generate:  "REPORT",
  };

  const KIND_COLOR = {
    nda:           "#f85149",
    scope:         "#58a6ff",
    machine_info:  "#bc8cff",
    writeup:       "#3fb950",
    reference:     "#8b949e",
    notes:         "#d29922",
  };

  const KIND_OPTIONS = ["", "nda", "scope", "machine_info", "writeup", "reference", "notes"];

  function kindColor(k) { return KIND_COLOR[k] ?? "#484f58"; }

  function fmtDate(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function shortHash(h) { return h ? h.slice(0, 8) : "—"; }

  function fmtTimestamp(ts) {
    if (!ts) return "";
    return new Date(ts * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function fmtDuration(startTs, endTs) {
    const secs = Math.max(0, endTs - startTs);
    if (secs < 60) return `${secs}s`;
    return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  }

  function fmtElapsed(secs) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${String(s).padStart(2, '0')}`;
  }

  function shortPath(p) {
    if (!p) return "—";
    const parts = p.split("/");
    const idx = parts.findIndex(x => x === "workspace");
    return idx >= 0 ? parts.slice(idx).join("/") : parts.slice(-3).join("/");
  }

  async function refresh() {
    if (!project) { files = []; return; }
    loading = true; error = "";
    try {
      files = await invoke("list_workspace_files", { projectId: project.id });
    } catch (e) { error = String(e); }
    finally { loading = false; }
  }

  async function addFile() {
    if (!project) return;
    uploading = true;
    try {
      const path = await open({
        title: "Add file to workspace",
        multiple: false,
      });
      if (!path) return;
      await invoke("add_workspace_file", {
        projectId: project.id,
        projectName: project.name,
        srcPath: path,
        kind: "",
      });
      await refresh();
    } catch (e) { error = String(e); }
    finally { uploading = false; }
  }

  async function loadNotes() {
    if (!project) { notesContent = ""; return; }
    try {
      notesContent = await invoke("read_project_notes", { projectName: project.name }) ?? "";
    } catch (_) { notesContent = ""; }
    notesSaved = true;
  }

  function onNotesInput(e) {
    notesContent = e.target.value;
    notesSaved = false;
    if (notesTimer) clearTimeout(notesTimer);
    notesTimer = setTimeout(saveNotes, 1500);
  }

  async function saveNotes() {
    if (!project) return;
    notesSaving = true;
    try {
      await invoke("write_project_notes", { projectName: project.name, content: notesContent });
      notesSaved = true;
    } catch (_) {}
    finally { notesSaving = false; }
  }

  async function loadPlan() {
    if (!project) { plan = null; planSteps = []; return; }
    const pid = project.id;
    planLoading = true;
    try {
      const p = await invoke("get_current_plan", { projectId: pid });
      if (project?.id !== pid) return;
      plan = p;
      planSteps = p ? await invoke("get_plan_steps", { planId: p.id }) : [];
      if (project?.id !== pid) { plan = null; planSteps = []; }
    } catch (_) { plan = null; planSteps = []; }
    finally { planLoading = false; }
  }

  async function togglePreview(f) {
    if (previewFileId === f.id) { previewFileId = null; return; }
    previewFileId = f.id;
    previewContent = "";
    previewLoading = true;
    try {
      const data = await invoke("read_workspace_file", { path: f.path });
      previewContent = data ?? "";
    } catch (_) { previewContent = "(could not read file)"; }
    finally { previewLoading = false; }
  }

  async function generateReport() {
    if (!project) return;
    try {
      await invoke("claude_send", {
        message: `Please generate a full engagement report for project ${project.name} using the generate_report tool. Write exec-summary.md, fix-list.md, and controls.json to workspace/report/.`
      });
      onSwitchToChat?.();
    } catch (e) { error = String(e); }
  }

  function buildKillChain(steps) {
    const ROOT_W = 152, ROOT_H = 58;
    // NODE_H bumped 70 → 96 so an in-progress step that needs phase-pill +
    // verb + target + footer (T+5:45 · running… · HOST COMPROMISE) actually
    // fits without the footer overflowing on top of the target line.
    const NODE_W = 160, NODE_H = 96;
    const ROOT_GAP  = 52;   // gap between root right-edge and first node left-edge
    const MIN_GAP   = 44;   // minimum gap between nodes
    const LANE_H    = 112;  // vertical spacing between lanes (was 88 — bumped to match new NODE_H)
    const PAD_X = 20, PAD_Y = 20;
    const PX_PER_SEC = 3.5; // horizontal scale for time

    const startedTimes = steps.filter(s => s.started_at).map(s => s.started_at);
    const baseTime = startedTimes.length > 0 ? Math.min(...startedTimes) : null;

    // Greedy lane assignment based on time overlap
    const laneEnd = [];
    const nodeInfos = steps.map(step => {
      const startT = step.started_at ?? null;
      const endT   = step.ended_at   ?? null;
      let lane = 0;
      if (startT !== null) {
        lane = laneEnd.length;
        for (let i = 0; i < laneEnd.length; i++) {
          if (laneEnd[i] <= startT) { lane = i; break; }
        }
      }
      laneEnd[lane] = endT ?? (startT ? startT + 60 : (laneEnd[lane] ?? 0) + 60);
      return { step, lane, startT, endT };
    });

    // X positions: time-based with minimum spacing enforced
    const stepStartX = PAD_X + ROOT_W + ROOT_GAP;
    let cursor = stepStartX - NODE_W - MIN_GAP;
    const xPos = nodeInfos.map(ni => {
      let x;
      if (ni.startT !== null && baseTime !== null) {
        const tb = stepStartX + (ni.startT - baseTime) * PX_PER_SEC;
        x = Math.max(cursor + NODE_W + MIN_GAP, tb);
      } else {
        x = cursor + NODE_W + MIN_GAP;
      }
      cursor = x;
      return x;
    });

    const nLanes  = Math.max(...nodeInfos.map(n => n.lane), 0) + 1;
    const totalW  = (xPos.length > 0 ? Math.max(...xPos) + NODE_W : PAD_X + ROOT_W) + PAD_X;
    const totalH  = nLanes * LANE_H + PAD_Y * 2;

    const rootY    = PAD_Y;
    const rootMidY = rootY + ROOT_H / 2;
    const rootRX   = PAD_X + ROOT_W;

    const nodes = nodeInfos.map((ni, i) => {
      const x = xPos[i];
      const y = PAD_Y + ni.lane * LANE_H;
      return {
        ...ni, x, y,
        midY:    y + NODE_H / 2,
        rightX:  x + NODE_W,
        elapsed: (ni.startT !== null && baseTime !== null) ? ni.startT - baseTime : null,
        duration: (ni.startT && ni.endT) ? ni.endT - ni.startT : null,
      };
    });

    // Edges
    const edges = [];
    if (nodes.length > 0) {
      const x2 = nodes[0].x, y2 = nodes[0].midY;
      const mx = (rootRX + x2) / 2;
      edges.push({ d: `M ${rootRX},${rootMidY} C ${mx},${rootMidY} ${mx},${y2} ${x2},${y2}`, done: false, live: nodes[0].step.status === 'in_progress' });
    }
    for (let i = 0; i < nodes.length - 1; i++) {
      const a = nodes[i], b = nodes[i+1];
      const mx = (a.rightX + b.x) / 2;
      edges.push({
        d:    `M ${a.rightX},${a.midY} C ${mx},${a.midY} ${mx},${b.midY} ${b.x},${b.midY}`,
        done: a.step.status === 'done',
        live: b.step.status === 'in_progress',
      });
    }

    return { nodes, edges, totalW, totalH, ROOT_W, ROOT_H, NODE_W, NODE_H, rootX: PAD_X, rootY, rootMidY };
  }

  // U7: previously the $effect cleared the debounce timer on project switch
  // without flushing — fast tab switches lost unsaved notes. Now we flush
  // synchronously via the captured project name in the effect's cleanup,
  // which runs BEFORE the next effect body sees the new project.
  let lastNotesProjectName = null;
  let lastNotesContent     = "";

  $effect(() => {
    if (project) {
      refresh(); loadNotes(); loadPlan();
      lastNotesProjectName = project.name;
    } else {
      files = []; notesContent = ""; plan = null; planSteps = [];
      lastNotesProjectName = null;
    }
    return () => {
      // Cleanup fires before next $effect run / on component destroy.
      if (notesTimer) {
        clearTimeout(notesTimer);
        notesTimer = null;
        if (lastNotesProjectName && !notesSaved) {
          // Fire-and-forget; we cannot await inside a cleanup. Use the
          // captured project name + content, not the (possibly already-new)
          // reactive values.
          invoke("write_project_notes", {
            projectName: lastNotesProjectName,
            content: lastNotesContent,
          }).catch(() => {});
        }
      }
    };
  });

  // Track the latest content seen by the debounce so the cleanup above
  // can flush it without racing the new project's loadNotes() reset.
  $effect(() => { lastNotesContent = notesContent; });

  onMount(async () => {
    unlistenPlan = await listen("claude://chunk", (e) => {
      const c = e.payload;
      if (c.kind === "tool_use" && (
        c.tool_name === "plan_create" ||
        c.tool_name === "plan_update_step" ||
        c.tool_name === "plan_next_step"
      )) {
        setTimeout(() => { if (project) loadPlan(); }, 700);
      }
    });
    unlisten = await listen("claude://done", () => {
      if (project) loadPlan();
    });
  });
  onDestroy(() => {
    unlisten?.();
    unlistenPlan?.();
    if (notesTimer) { clearTimeout(notesTimer); notesTimer = null; }
  });
</script>

<div class="pl-workspace">
  <div class="pl-ws-header">
    <div class="pl-ws-tabs">
      <button class="pl-ws-tab" class:active={wsTab === 'files'}  onclick={() => wsTab = 'files'}>Files</button>
      <button class="pl-ws-tab" class:active={wsTab === 'notes'}  onclick={() => wsTab = 'notes'}>Notes</button>
      <button class="pl-ws-tab" class:active={wsTab === 'plan'}   onclick={() => wsTab = 'plan'}>Plan</button>
      <button class="pl-ws-tab pl-ws-tab-attack" class:active={wsTab === 'attack'} onclick={() => wsTab = 'attack'}>Attack Path</button>
    </div>
    {#if project && wsTab === 'files'}
      <div class="pl-ws-actions">
        <button class="pl-ws-btn" onclick={addFile} disabled={uploading}>
          {uploading ? "…" : "+ Add File"}
        </button>
        <button class="pl-ws-refresh" onclick={refresh} disabled={loading}>
          {loading ? "…" : "↻"}
        </button>
        <button class="pl-ws-report-btn" onclick={generateReport} title="Ask agent to generate engagement report">
          Report
        </button>
      </div>
    {/if}
    {#if project && wsTab === 'notes'}
      <span class="pl-ws-save-status">
        {notesSaving ? "Saving…" : notesSaved ? "Saved" : "Unsaved"}
      </span>
    {/if}
    {#if project && (wsTab === 'plan' || wsTab === 'attack')}
      <button class="pl-ws-refresh" onclick={loadPlan} disabled={planLoading}>
        {planLoading ? "…" : "↻"}
      </button>
    {/if}
  </div>

  {#if wsTab === 'files'}
    {#if !project}
      <div class="pl-ws-empty">Select an engagement to view workspace files.</div>
    {:else if loading}
      <div class="pl-ws-empty">Loading…</div>
    {:else if error}
      <div class="pl-ws-empty pl-ws-error">{error}</div>
    {:else if files.length === 0}
      <div class="pl-ws-empty">
        No tracked files yet. Use <strong>+ Add File</strong> or write via <code>workspace_write</code>.
      </div>
    {:else}
      <div class="pl-ws-list">
        {#each files as f (f.id)}
          <div class="pl-ws-row" class:previewing={previewFileId === f.id}>
            <button class="pl-ws-row-btn" onclick={() => togglePreview(f)}>
              <div class="pl-ws-main">
                <span class="pl-ws-name" title={f.path}>{f.filename}</span>
                {#if f.kind}
                  <span class="pl-ws-kind" style="color:{kindColor(f.kind)};border-color:{kindColor(f.kind)}">{f.kind}</span>
                {/if}
                <span class="pl-ws-preview-icon">{previewFileId === f.id ? '▴' : '▾'}</span>
              </div>
              <div class="pl-ws-meta">
                <code class="pl-ws-hash" title={f.sha256}>{shortHash(f.sha256)}</code>
                <span class="pl-ws-sep">·</span>
                <span class="pl-ws-path" title={f.path}>{shortPath(f.path)}</span>
                <span class="pl-ws-sep">·</span>
                <span class="pl-ws-date">{fmtDate(f.added_at)}</span>
              </div>
            </button>
            {#if previewFileId === f.id}
              <div class="pl-ws-preview">
                {#if previewLoading}
                  <span class="pl-ws-preview-loading">Loading…</span>
                {:else}
                  <pre class="pl-ws-preview-text">{previewContent}</pre>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

  {:else if wsTab === 'notes'}
    {#if !project}
      <div class="pl-ws-empty">Select an engagement to edit notes.</div>
    {:else}
      <textarea
        class="pl-notes-editor"
        placeholder="Markdown notes for this engagement…&#10;&#10;The agent can also write here via workspace_write."
        value={notesContent}
        oninput={onNotesInput}
      ></textarea>
    {/if}

  {:else if wsTab === 'plan'}
    {#if !project}
      <div class="pl-ws-empty">Select an engagement to view the plan.</div>
    {:else if planLoading}
      <div class="pl-ws-empty">Loading…</div>
    {:else if !plan}
      <div class="pl-ws-empty">No plan yet.<br>The agent creates a plan automatically when it starts working.</div>
    {:else}
      <div class="pl-plan">
        <div class="pl-plan-header">
          <span class="pl-plan-objective">{plan.objective}</span>
          <span class="pl-plan-version">v{plan.version}</span>
        </div>
        {#if plan.constraints_json}
          {@const c = (() => { try { return JSON.parse(plan.constraints_json); } catch { return null; } })()}
          {#if c}
            <div class="pl-plan-constraints">
              {#each Object.entries(c) as [k, v]}
                <span class="pl-plan-constraint">{k}: {v}</span>
              {/each}
            </div>
          {/if}
        {/if}
        <div class="pl-plan-steps">
          {#each planSteps as s (s.id)}
            <div class="pl-plan-step" class:active={s.status === 'in_progress'}>
              <span class="pl-step-icon" style="color:{STEP_COLOR[s.status] ?? '#484f58'}">{STEP_ICON[s.status] ?? '?'}</span>
              <span class="pl-step-verb">{s.verb}</span>
              {#if s.target}
                <span class="pl-step-target">{s.target}</span>
              {/if}
              <span class="pl-step-status" style="color:{STEP_COLOR[s.status] ?? '#484f58'}">{s.status}</span>
            </div>
          {/each}
          {#if planSteps.length === 0}
            <div class="pl-ws-empty" style="padding:12px 0">No steps defined yet.</div>
          {/if}
        </div>
      </div>
    {/if}

  {:else if wsTab === 'attack'}
    {#if !project}
      <div class="pl-ws-empty">Select an engagement to view the attack path.</div>
    {:else if planLoading}
      <div class="pl-ws-empty">Loading…</div>
    {:else if !plan || planSteps.length === 0}
      <div class="pl-ws-empty">
        No attack path yet.<br>The agent builds one automatically when it starts working.
      </div>
    {:else}
      {@const layout = buildKillChain(planSteps)}
      {@const doneCount = planSteps.filter(s => s.status === 'done').length}
      {@const isRunning = planSteps.some(s => s.status === 'in_progress')}
      <div class="ck-wrap">
        <div class="ck-canvas" style="width:{layout.totalW}px; height:{layout.totalH}px">

          <svg class="ck-svg" width={layout.totalW} height={layout.totalH}>
            <defs>
              <marker id="ck-arr"   markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                <polygon points="0 0,8 3,0 6" fill="#30363d"/>
              </marker>
              <marker id="ck-arr-g" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                <polygon points="0 0,8 3,0 6" fill="#3fb95088"/>
              </marker>
              <marker id="ck-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                <polygon points="0 0,8 3,0 6" fill="#388bfd"/>
              </marker>
            </defs>
            {#each layout.edges as e}
              <path d={e.d}
                    stroke={e.done ? '#3fb95055' : e.live ? '#388bfd99' : '#21262d'}
                    stroke-width={e.live ? 2 : 1.5}
                    fill="none"
                    marker-end={e.done ? 'url(#ck-arr-g)' : e.live ? 'url(#ck-arr-b)' : 'url(#ck-arr)'}/>
            {/each}
          </svg>

          <!-- Objective / root node -->
          <div class="ck-root"
               style="left:{layout.rootX}px; top:{layout.rootY}px; width:{layout.ROOT_W}px; height:{layout.ROOT_H}px">
            <div class="ck-root-label">OBJECTIVE</div>
            <div class="ck-root-obj">{plan.objective}</div>
            <div class="ck-root-bar-wrap">
              <div class="ck-root-bar">
                <div class="ck-root-fill" style="width:{Math.round(doneCount / planSteps.length * 100)}%"></div>
              </div>
              <span class="ck-root-count">{doneCount}/{planSteps.length}</span>
              {#if isRunning}<span class="ck-root-live">● live</span>{/if}
            </div>
          </div>

          <!-- Step / kill-chain nodes -->
          {#each layout.nodes as n}
            {@const phase = VERB_PHASE[n.step.verb] ?? 'Custom'}
            {@const pc = PHASE_COLOR[phase] ?? '#484f58'}
            {@const isProof = n.step.status === 'done' && (n.step.verb === 'exploit_run' || n.step.verb === 'privesc' || n.step.verb === 'auth_test')}
            {@const impact = IMPACT_LABEL[n.step.verb]}
            <div class="ck-node"
                 class:ck-live={n.step.status === 'in_progress'}
                 class:ck-done={n.step.status === 'done'}
                 class:ck-fail={n.step.status === 'failed'}
                 class:ck-skip={n.step.status === 'skipped'}
                 style="left:{n.x}px; top:{n.y}px; width:{layout.NODE_W}px; height:{layout.NODE_H}px;
                        border-left-color:{pc}">
              <div class="ck-node-top">
                <span class="ck-phase-pip"
                      style="background:{pc}18; color:{pc}; border-color:{pc}44">{phase}</span>
                <span class="ck-icon" style="color:{STEP_COLOR[n.step.status] ?? '#484f58'}">{STEP_ICON[n.step.status] ?? '?'}</span>
                {#if n.step.status === 'in_progress'}<span class="ck-pulse"></span>{/if}
              </div>
              <div class="ck-verb" class:ck-verb-live={n.step.status === 'in_progress'}>
                {VERB_LABELS[n.step.verb] ?? n.step.verb}
              </div>
              {#if n.step.target}
                <div class="ck-target">{n.step.target}</div>
              {/if}
              <div class="ck-foot">
                {#if n.elapsed !== null}
                  <span class="ck-elapsed">T+{fmtElapsed(n.elapsed)}</span>
                {/if}
                {#if n.duration !== null}
                  <span class="ck-dur">{n.duration}s</span>
                {:else if n.step.status === 'in_progress'}
                  <span class="ck-dur-live">running…</span>
                {/if}
                {#if isProof}
                  <span class="ck-proof">PROOF</span>
                {/if}
                {#if impact && (n.step.status === 'done' || n.step.status === 'in_progress')}
                  <span class="ck-impact">{impact}</span>
                {/if}
              </div>
            </div>
          {/each}

        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .pl-workspace {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: #0d1117;
    padding: 16px 20px;
    overflow: hidden;
    gap: 0;
  }

  .pl-ws-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
    gap: 8px;
    flex-shrink: 0;
  }

  .pl-ws-tabs {
    display: flex;
    gap: 2px;
    flex: 1;
  }

  .pl-ws-tab {
    background: none;
    border: none;
    border-radius: 4px;
    color: #8b949e;
    font-size: 12px;
    font-weight: 500;
    font-family: inherit;
    padding: 4px 10px;
    cursor: pointer;
  }
  .pl-ws-tab:hover { background: #1c2128; color: #c9d1d9; }
  .pl-ws-tab.active { background: #21262d; color: #e6edf3; }

  .pl-ws-actions { display: flex; gap: 4px; align-items: center; }

  .pl-ws-btn {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #c9d1d9;
    cursor: pointer;
    font-size: 11px;
    font-weight: 500;
    font-family: inherit;
    padding: 3px 10px;
    white-space: nowrap;
  }
  .pl-ws-btn:hover:not(:disabled) { background: #30363d; }
  .pl-ws-btn:disabled { opacity: 0.4; cursor: default; }

  .pl-ws-save-status { font-size: 11px; color: #6e7681; white-space: nowrap; }

  .pl-ws-refresh {
    background: none;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #8b949e;
    cursor: pointer;
    font-size: 14px;
    padding: 2px 8px;
    font-family: inherit;
    line-height: 1.4;
  }
  .pl-ws-refresh:hover:not(:disabled) { color: #c9d1d9; border-color: #484f58; }
  .pl-ws-refresh:disabled { opacity: 0.4; cursor: default; }

  .pl-notes-editor {
    flex: 1;
    width: 100%;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 5px;
    color: #c9d1d9;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 12px;
    line-height: 1.6;
    padding: 12px 14px;
    resize: none;
    outline: none;
    min-height: 200px;
  }
  .pl-notes-editor:focus { border-color: #30363d; }
  .pl-notes-editor::placeholder { color: #484f58; }

  .pl-ws-empty {
    color: #6e7681;
    font-size: 12px;
    line-height: 1.6;
    padding: 24px 0;
    text-align: center;
  }
  .pl-ws-empty code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #9fef00;
    font-size: 11px;
  }
  .pl-ws-error { color: #f85149; }

  .pl-ws-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  .pl-ws-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 5px;
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .pl-ws-row:hover { border-color: #30363d; }

  .pl-ws-main {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pl-ws-name {
    font-size: 12px;
    color: #c9d1d9;
    font-weight: 500;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pl-ws-kind {
    font-size: 10px;
    font-weight: 600;
    border: 1px solid;
    border-radius: 3px;
    padding: 1px 5px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }

  .pl-ws-meta {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    color: #6e7681;
    flex-wrap: wrap;
  }

  .pl-ws-hash {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    color: #8b949e;
    background: #21262d;
    padding: 1px 4px;
    border-radius: 3px;
  }

  .pl-ws-path {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 260px;
  }

  .pl-ws-sep { color: #30363d; }
  .pl-ws-date { white-space: nowrap; }

  .pl-ws-row { padding: 0; }
  .pl-ws-row-btn {
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    cursor: pointer;
    font-family: inherit;
    font-size: inherit;
    color: inherit;
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .pl-ws-row.previewing { border-color: #30363d; }
  .pl-ws-preview-icon { font-size: 9px; color: #484f58; margin-left: auto; flex-shrink: 0; }

  .pl-ws-preview {
    border-top: 1px solid #21262d;
    padding: 8px 12px;
    max-height: 200px;
    overflow-y: auto;
  }
  .pl-ws-preview-text {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    color: #8b949e;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
  }
  .pl-ws-preview-loading { font-size: 11px; color: #484f58; }

  .pl-ws-report-btn {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #8b949e;
    cursor: pointer;
    font-size: 11px;
    font-weight: 500;
    font-family: inherit;
    padding: 3px 10px;
  }
  .pl-ws-report-btn:hover { color: #c9d1d9; border-color: #484f58; }

  .pl-plan {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-height: 0;
    overflow-y: auto;
  }
  .pl-plan-header {
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }
  .pl-plan-objective {
    font-size: 13px;
    color: #e6edf3;
    font-weight: 500;
    flex: 1;
    line-height: 1.45;
  }
  .pl-plan-version {
    font-size: 10px;
    color: #484f58;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    flex-shrink: 0;
    padding-top: 2px;
  }
  .pl-plan-constraints {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .pl-plan-constraint {
    font-size: 10px;
    color: #8b949e;
    background: #21262d;
    border-radius: 3px;
    padding: 2px 6px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  .pl-plan-steps {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .pl-plan-step {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 5px 8px;
    border-radius: 4px;
    background: #161b22;
    border: 1px solid #21262d;
  }
  .pl-plan-step.active { border-color: #388bfd44; background: #161d2e; }
  .pl-step-icon {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    flex-shrink: 0;
    width: 12px;
    text-align: center;
  }
  .pl-step-verb {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    color: #c9d1d9;
    flex-shrink: 0;
  }
  .pl-step-target {
    font-size: 11px;
    color: #8b949e;
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pl-step-status {
    font-size: 9px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }

  /* ── Kill-Chain Attack Path ──────────────────────────────────────── */

  .pl-ws-tab-attack.active { color: #9fef00; background: rgba(159,239,0,0.07); }
  .pl-ws-tab-attack:hover:not(.active) { color: rgba(159,239,0,0.6); }

  .ck-wrap {
    flex: 1;
    overflow: auto;
    min-height: 0;
    padding: 4px 0;
  }

  .ck-canvas {
    position: relative;
    min-width: 100%;
  }

  .ck-svg {
    position: absolute;
    top: 0; left: 0;
    pointer-events: none;
    z-index: 0;
  }

  /* Root / Objective node */
  .ck-root {
    position: absolute;
    z-index: 1;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 7px;
    padding: 9px 12px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    overflow: hidden;
    box-shadow: 0 2px 14px rgba(0,0,0,0.45);
  }

  .ck-root-label {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 7px;
    color: #484f58;
    letter-spacing: 0.16em;
    text-transform: uppercase;
  }

  .ck-root-obj {
    font-size: 11px;
    color: #e6edf3;
    font-weight: 500;
    line-height: 1.35;
    flex: 1;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
  }

  .ck-root-bar-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .ck-root-bar {
    flex: 1;
    height: 2px;
    background: #21262d;
    border-radius: 1px;
    overflow: hidden;
  }

  .ck-root-fill {
    height: 100%;
    background: linear-gradient(90deg, #238636, #3fb950);
    border-radius: 1px;
    transition: width 0.4s ease;
  }

  .ck-root-count {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 9px;
    color: #484f58;
    flex-shrink: 0;
  }

  .ck-root-live {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 9px;
    color: #9fef00;
    flex-shrink: 0;
    animation: ck-blink 1.4s step-end infinite;
  }

  /* Step nodes */
  .ck-node {
    position: absolute;
    z-index: 1;
    background: #161b22;
    border: 1px solid #21262d;
    border-left: 3px solid #484f58;
    border-radius: 0 6px 6px 0;
    padding: 7px 10px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow: hidden;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .ck-live {
    border-color: #9fef0030 !important;
    border-left-color: #9fef00 !important;
    background: rgba(159,239,0,0.04) !important;
    box-shadow: 0 0 18px rgba(159,239,0,0.08);
  }

  .ck-done { opacity: 0.58; }
  .ck-skip { opacity: 0.26; }
  .ck-fail {
    border-color: #f8514930 !important;
    background: rgba(248,81,73,0.05) !important;
  }

  .ck-node-top {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }

  .ck-phase-pip {
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.09em;
    border: 1px solid;
    border-radius: 3px;
    padding: 1px 4px;
    text-transform: uppercase;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .ck-icon {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    margin-left: auto;
    flex-shrink: 0;
  }

  .ck-pulse {
    width: 5px; height: 5px;
    background: #9fef00;
    border-radius: 50%;
    flex-shrink: 0;
    animation: ck-pulse 1.4s ease-in-out infinite;
  }

  .ck-verb {
    font-size: 11px;
    font-weight: 600;
    color: #c9d1d9;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .ck-verb-live { color: #9fef00; }

  .ck-target {
    font-size: 9px;
    color: #484f58;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .ck-foot {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
    margin-top: 1px;
    /* Cap the foot — IMPACT badges + running… + duration combined sometimes
       wrap; with overflow:hidden on .ck-node and a tight height that used to
       push content on top of the target line. Bumped node height + this cap
       keep things readable when the foot wraps. */
    max-height: 28px;
    overflow: hidden;
  }

  .ck-elapsed {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 8px;
    color: #388bfd;
  }

  .ck-dur {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 8px;
    color: #30363d;
  }

  .ck-dur-live {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 8px;
    color: #9fef0066;
  }

  .ck-proof {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.12em;
    color: #3fb950;
    border: 1px solid #3fb95055;
    border-radius: 2px;
    padding: 1px 4px;
    background: rgba(63,185,80,0.08);
  }

  .ck-impact {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.1em;
    color: #f85149;
    text-transform: uppercase;
  }

  @keyframes ck-pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.15; transform: scale(0.5); }
  }

  @keyframes ck-blink { 50% { opacity: 0; } }
</style>
