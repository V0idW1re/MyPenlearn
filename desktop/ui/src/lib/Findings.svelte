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

  const STATUS_LABEL = {
    open:           "OPEN",
    verified:       "VERIFIED",
    false_positive: "FP",
  };

  const STATUS_COLOR = {
    open:           "#8b949e",
    verified:       "#3fb950",
    false_positive: "#484f58",
  };

  let findings    = $state([]);
  let openFinding = $state(null);
  let execResults = $state([]);
  let execOpen    = $state(false);
  let evidenceMap = $state({});  // risk_item_id -> array of artifacts
  let unlisten;

  $effect(() => {
    const pid = project?.id;
    findings = [];
    openFinding = null;
    execResults = [];
    evidenceMap = {};
    if (pid) load(pid);
  });

  async function load(pid) {
    try { findings = await invoke("list_findings", { projectId: pid }); }
    catch (_) { findings = []; }
    try { execResults = await invoke("list_execution_results", { projectId: pid }); }
    catch (_) { execResults = []; }
  }

  async function loadEvidence(riskItemId) {
    if (evidenceMap[riskItemId]) return;
    try {
      const arts = await invoke("list_evidence_artifacts", { riskItemId });
      evidenceMap = { ...evidenceMap, [riskItemId]: arts };
    } catch (_) { evidenceMap = { ...evidenceMap, [riskItemId]: [] }; }
  }

  function fmtTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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
            {#if f.chain_position != null}
              <span class="pl-chain-badge" title="Attack chain step {f.chain_position}">→{f.chain_position}</span>
            {/if}
            <span class="pl-stage-dot"
              style="background:{STATUS_COLOR[f.status] ?? '#8b949e'}"
              title={f.status}
            ></span>
          </div>
          {#if openFinding === f.id}
            {#if f.description}
              <div class="pl-finding-detail">{f.description}</div>
            {/if}
            {#if f.impact}
              <div class="pl-finding-impact">{f.impact}</div>
            {/if}
            {#if openFinding === f.id}
              {loadEvidence(f.id)}
              {@const arts = evidenceMap[f.id] || []}
              {#if arts.length > 0}
                <div class="pl-evidence">
                  {#each arts as a (a.id)}
                    <div class="pl-evidence-row" title={a.path}>
                      <span class="pl-ev-kind">{a.kind}</span>
                      <span class="pl-ev-path">{a.path.split("/").slice(-2).join("/")}</span>
                      <span class="pl-ev-hash">{a.sha256.slice(0,8)}</span>
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
            <div class="pl-finding-meta">
              <span class="pl-meta-status"
                class:verified={f.status === 'verified'}
                class:fp={f.status === 'false_positive'}>
                {STATUS_LABEL[f.status] ?? f.status}
              </span>
              {#if f.ttp_category}
                <span class="pl-meta-ttp">{f.ttp_category}</span>
              {/if}
              {#if f.cve_id}
                <span class="pl-meta-tag">{f.cve_id}</span>
              {/if}
              {#if f.mitre_id}
                <span class="pl-meta-tag">{f.mitre_id}</span>
              {/if}
              {#if f.owasp_asvs_id}
                <span class="pl-meta-asvs">{f.owasp_asvs_id}</span>
              {/if}
            </div>
            {#if f.compliance_controls}
              {@const ctrl = (() => { try { return JSON.parse(f.compliance_controls); } catch { return null; } })()}
              {#if ctrl}
                <div class="pl-compliance">
                  {#each Object.entries(ctrl) as [fw, items]}
                    <div class="pl-compliance-row">
                      <span class="pl-compliance-fw">{fw.replace('_', ' ')}</span>
                      <span class="pl-compliance-items">{Array.isArray(items) ? items.join(', ') : items}</span>
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
          {/if}
        </button>
      {/each}
    {/if}
  </div>

  {#if execResults.length > 0}
    <div class="pl-exec-section">
      <button class="pl-exec-head" onclick={() => execOpen = !execOpen}>
        <span class="pl-rail-label">Runs</span>
        <span class="pl-find-count">{execResults.length}</span>
        <span class="pl-exec-chevron">{execOpen ? '▴' : '▾'}</span>
      </button>
      {#if execOpen}
        <div class="pl-exec-list">
          {#each execResults.slice(0, 20) as r (r.id)}
            <div class="pl-exec-row">
              <span class="pl-exec-tool">{r.tool_name}</span>
              <span class="pl-exec-exit" class:ok={r.exit_code === 0} class:fail={r.exit_code !== 0 && r.exit_code != null}>
                {r.exit_code != null ? r.exit_code : '—'}
              </span>
              <span class="pl-exec-time">{fmtTime(r.started_at)}</span>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
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

  .pl-chain-badge {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 9px;
    font-weight: 700;
    color: #58a6ff;
    flex-shrink: 0;
    letter-spacing: 0.02em;
  }

  .pl-stage-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    opacity: 0.75;
  }

  .pl-finding-detail {
    font-size: 11px;
    color: #8b949e;
    margin-top: 6px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .pl-finding-impact {
    font-size: 11px;
    color: #d29922;
    margin-top: 5px;
    line-height: 1.4;
    font-style: italic;
  }

  .pl-finding-meta {
    margin-top: 6px;
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }

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

  .pl-meta-tag {
    display: inline-block;
    font-size: 9px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #58a6ff;
    letter-spacing: 0.04em;
    border: 1px solid rgba(88,166,255,0.25);
    border-radius: 3px;
    padding: 1px 5px;
  }

  .pl-meta-ttp {
    display: inline-block;
    font-size: 9px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #bc8cff;
    letter-spacing: 0.04em;
    border: 1px solid rgba(188,140,255,0.25);
    border-radius: 3px;
    padding: 1px 5px;
    text-transform: uppercase;
  }

  .pl-meta-asvs {
    display: inline-block;
    font-size: 9px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #56d364;
    letter-spacing: 0.04em;
    border: 1px solid rgba(86,211,100,0.25);
    border-radius: 3px;
    padding: 1px 5px;
  }

  .pl-compliance {
    margin-top: 6px;
    border-top: 1px solid #21262d;
    padding-top: 5px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .pl-compliance-row {
    display: flex;
    gap: 5px;
    align-items: baseline;
    min-width: 0;
  }

  .pl-compliance-fw {
    font-size: 8px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #484f58;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .pl-compliance-items {
    font-size: 9px;
    color: #6e7681;
    line-height: 1.35;
    word-break: break-word;
  }

  .pl-evidence {
    margin-top: 6px;
    border-top: 1px solid #21262d;
    padding-top: 5px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .pl-evidence-row {
    display: flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
  }
  .pl-ev-kind {
    font-size: 8px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #d29922;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }
  .pl-ev-path {
    font-size: 9px;
    color: #6e7681;
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  .pl-ev-hash {
    font-size: 8px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #484f58;
    flex-shrink: 0;
  }

  .pl-exec-section {
    border-top: 1px solid #21262d;
    flex-shrink: 0;
  }
  .pl-exec-head {
    width: 100%;
    padding: 8px 14px;
    display: flex;
    align-items: center;
    gap: 6px;
    background: none;
    border: none;
    cursor: pointer;
    font-family: inherit;
  }
  .pl-exec-head:hover { background: #1c2128; }
  .pl-exec-chevron { font-size: 9px; color: #484f58; margin-left: auto; }

  .pl-exec-list {
    max-height: 160px;
    overflow-y: auto;
    padding: 2px 8px 6px;
  }
  .pl-exec-row {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 3px 4px;
    border-radius: 3px;
    min-width: 0;
  }
  .pl-exec-row:hover { background: #1c2128; }
  .pl-exec-tool {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 9px;
    color: #8b949e;
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pl-exec-exit {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 9px;
    color: #484f58;
    flex-shrink: 0;
    min-width: 14px;
    text-align: right;
  }
  .pl-exec-exit.ok   { color: #3fb950; }
  .pl-exec-exit.fail { color: #f85149; }
  .pl-exec-time {
    font-size: 9px;
    color: #484f58;
    flex-shrink: 0;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
</style>
