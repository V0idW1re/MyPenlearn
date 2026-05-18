<script>
  import { invoke } from "@tauri-apps/api/core";

  let { project } = $props();

  let files = $state([]);
  let loading = $state(false);
  let error = $state("");

  const KIND_COLOR = {
    nda:           "#f85149",
    scope:         "#58a6ff",
    machine_info:  "#bc8cff",
    writeup:       "#3fb950",
    reference:     "#8b949e",
    notes:         "#d29922",
  };

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
    loading = true;
    error = "";
    try {
      files = await invoke("list_workspace_files", { projectId: project.id });
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => { if (project) refresh(); else files = []; });
</script>

<div class="pl-workspace">
  <div class="pl-ws-header">
    <span class="pl-ws-title">Workspace Files</span>
    {#if project}
      <button class="pl-ws-refresh" onclick={refresh} disabled={loading}>
        {loading ? "…" : "↻"}
      </button>
    {/if}
  </div>

  {#if !project}
    <div class="pl-ws-empty">Select an engagement to view workspace files.</div>
  {:else if loading}
    <div class="pl-ws-empty">Loading…</div>
  {:else if error}
    <div class="pl-ws-empty pl-ws-error">{error}</div>
  {:else if files.length === 0}
    <div class="pl-ws-empty">
      No tracked files yet. Files written via <code>workspace_write</code> will appear here.
    </div>
  {:else}
    <div class="pl-ws-list">
      {#each files as f (f.id)}
        <div class="pl-ws-row">
          <div class="pl-ws-main">
            <span class="pl-ws-name" title={f.path}>{f.filename}</span>
            {#if f.kind}
              <span class="pl-ws-kind" style="color:{kindColor(f.kind)};border-color:{kindColor(f.kind)}">{f.kind}</span>
            {/if}
          </div>
          <div class="pl-ws-meta">
            <code class="pl-ws-hash" title={f.sha256}>{shortHash(f.sha256)}</code>
            <span class="pl-ws-sep">·</span>
            <span class="pl-ws-path" title={f.path}>{shortPath(f.path)}</span>
            <span class="pl-ws-sep">·</span>
            <span class="pl-ws-date">{fmtDate(f.added_at)}</span>
          </div>
        </div>
      {/each}
    </div>
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
    overflow-y: auto;
  }

  .pl-ws-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
  }

  .pl-ws-title {
    font-size: 13px;
    font-weight: 600;
    color: #e6edf3;
    letter-spacing: 0.01em;
  }

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
</style>
