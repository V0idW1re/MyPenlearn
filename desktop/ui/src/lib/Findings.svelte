<script>
  import { onMount, onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  let { project } = $props();

  const SEV_COLOR = {
    critical: "#f85149",
    high:     "#fb8500",
    medium:   "#d29922",
    low:      "#3fb950",
    info:     "#388bfd",
  };

  const SEV_PRIORITY = {
    critical: "P0",
    high:     "P1",
    medium:   "P2",
    low:      "P3",
    info:     "P4",
  };

  const SEV_LEVELS = [
    ["critical", "P0", "#f85149"],
    ["high",     "P1", "#fb8500"],
    ["medium",   "P2", "#d29922"],
    ["low",      "P3", "#3fb950"],
    ["info",     "P4", "#388bfd"],
  ];

  let findings    = $state([]);
  let openFinding = $state(null);
  let unlisten;

  $effect(() => {
    const pid = project?.id;
    findings = [];
    openFinding = null;
    if (pid) load(pid);
  });

  async function load(pid) {
    try { findings = await invoke("list_findings", { projectId: pid }); }
    catch (_) { findings = []; }
  }

  onMount(async () => {
    unlisten = await listen("claude://done", () => {
      if (project?.id) load(project.id);
    });
  });

  onDestroy(() => { unlisten?.(); });
</script>

<div class="pl-findings">
  <div class="pl-find-head">
    <span class="pl-rail-label">Findings</span>
    {#if findings.length > 0}
      <span class="pl-find-count">{findings.length}</span>
    {/if}
  </div>

  {#if findings.length > 0}
    <div class="pl-sev-bar">
      {#each SEV_LEVELS as [sev, prio, color]}
        {@const cnt = findings.filter(f => f.severity === sev).length}
        {#if cnt > 0}
          <span class="pl-sev-chip" style="color:{color}">
            {prio}<span class="pl-chip-sep">·</span>{cnt}
          </span>
        {/if}
      {/each}
    </div>
  {/if}

  <div class="pl-find-list">
    {#if !project}
      <div class="pl-find-empty">No engagement selected.</div>
    {:else if findings.length === 0}
      <div class="pl-find-empty">No findings yet.</div>
    {:else}
      {#each findings as f (f.id)}
        <button
          class="pl-finding"
          class:open={openFinding === f.id}
          style="border-left-color:{SEV_COLOR[f.severity] ?? '#8b949e'}"
          onclick={() => { openFinding = openFinding === f.id ? null : f.id; }}
        >
          <div class="pl-finding-row">
            <span class="pl-priority" style="color:{SEV_COLOR[f.severity] ?? '#8b949e'}">
              {SEV_PRIORITY[f.severity] ?? "P?"}
            </span>
            <span class="pl-sev-badge"
              style="color:{SEV_COLOR[f.severity] ?? '#8b949e'}; border-color:{SEV_COLOR[f.severity] ?? '#8b949e'}33">
              {f.severity.toUpperCase().slice(0, 4)}
            </span>
            <span class="pl-finding-title">{f.title}</span>
          </div>
          {#if openFinding === f.id}
            {#if f.description}
              <div class="pl-finding-detail">{f.description}</div>
            {/if}
            <div class="pl-finding-meta">
              <span class="pl-meta-status"
                class:verified={f.status === 'verified'}
                class:fp={f.status === 'false_positive'}>
                {f.status}
              </span>
            </div>
          {/if}
        </button>
      {/each}
    {/if}
  </div>
</div>

<style>
  .pl-findings {
    width: 240px;
    background: #161b22;
    border-left: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    overflow: hidden;
  }

  .pl-find-head {
    padding: 14px 14px 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-shrink: 0;
    border-bottom: 1px solid #21262d;
  }

  .pl-rail-label {
    font-size: 10px;
    color: #484f58;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-weight: 600;
  }

  .pl-find-count {
    background: #21262d;
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 11px;
    color: #8b949e;
    font-weight: 500;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

  .pl-sev-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 7px 14px;
    border-bottom: 1px solid #1c2128;
    flex-shrink: 0;
    background: #0d1117;
  }

  .pl-sev-chip {
    display: flex;
    align-items: center;
    gap: 3px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
  }

  .pl-chip-sep {
    color: #30363d;
    font-weight: 400;
  }

  .pl-find-list {
    flex: 1;
    overflow-y: auto;
    padding: 6px 8px;
  }

  .pl-find-empty {
    color: #484f58;
    font-size: 12px;
    padding: 20px 8px;
    text-align: center;
  }

  .pl-finding {
    background: #1c2128;
    border: 1px solid #30363d;
    border-left: 3px solid;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 6px;
    cursor: pointer;
    width: 100%;
    text-align: left;
    font-family: inherit;
    font-size: inherit;
    color: inherit;
    transition: background 0.1s;
  }
  .pl-finding:hover { background: #21262d; }
  .pl-finding.open  { background: #21262d; }

  .pl-finding-row {
    display: flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
  }

  .pl-priority {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    flex-shrink: 0;
    min-width: 18px;
  }

  .pl-sev-badge {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid;
    background: transparent;
    flex-shrink: 0;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

  .pl-finding-title {
    font-size: 12px;
    color: #e6edf3;
    font-weight: 500;
    flex: 1;
    line-height: 1.35;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .pl-finding-detail {
    font-size: 11px;
    color: #8b949e;
    margin-top: 6px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .pl-finding-meta { margin-top: 6px; }

  .pl-meta-status {
    display: inline-block;
    font-size: 9px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #484f58;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border: 1px solid #30363d;
    border-radius: 3px;
    padding: 1px 5px;
  }
  .pl-meta-status.verified { color: #3fb950; border-color: rgba(63,185,80,0.3); }
  .pl-meta-status.fp       { color: #484f58; text-decoration: line-through; }
</style>
