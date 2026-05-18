<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";

  let { project, onSwitchToChat } = $props();

  let wsTab   = $state("files");   // "files" | "notes" | "plan"
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

  let unlisten;

  const STEP_ICON = { pending: "○", in_progress: "→", done: "✓", skipped: "—", failed: "✗" };
  const STEP_COLOR = { pending: "#484f58", in_progress: "#58a6ff", done: "#3fb950", skipped: "#484f58", failed: "#f85149" };

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
    planLoading = true;
    try {
      plan = await invoke("get_current_plan", { projectId: project.id });
      planSteps = plan ? await invoke("get_plan_steps", { planId: plan.id }) : [];
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

  $effect(() => {
    if (project) { refresh(); loadNotes(); loadPlan(); }
    else { files = []; notesContent = ""; plan = null; planSteps = []; }
  });

  onMount(async () => {
    unlisten = await listen("claude://done", () => {
      if (project) loadPlan();
    });
  });
  onDestroy(() => { unlisten?.(); });
</script>

<div class="pl-workspace">
  <div class="pl-ws-header">
    <div class="pl-ws-tabs">
      <button class="pl-ws-tab" class:active={wsTab === 'files'} onclick={() => wsTab = 'files'}>Files</button>
      <button class="pl-ws-tab" class:active={wsTab === 'notes'} onclick={() => wsTab = 'notes'}>Notes</button>
      <button class="pl-ws-tab" class:active={wsTab === 'plan'}  onclick={() => wsTab = 'plan'}>Plan</button>
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
    {#if project && wsTab === 'plan'}
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

  {:else}
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
</style>
