<script>
  import { onMount, onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  let { project } = $props();

  // System-prompt protocol: after each significant tool, the agent emits
  //   ## Next Steps
  //   1. [HIGH YIELD] <action>
  //      Why: <reason>
  //      Cost: <estimate>
  //   2. [MEDIUM] ...
  // Then STOPs. We parse that block out of the streamed assistant text so the
  // operator can click an option instead of typing "do step 1" — which is what
  // the first-test user explicitly asked for.
  let items     = $state([]);    // { idx, tag, action, why, cost }
  let busy      = $state(false);
  let lastSent  = $state(null);  // idx of the option the user clicked this turn
  let collapsed = $state(false);

  let assistantBuf = "";
  let unlistenChunk, unlistenDone;

  const TAG_COLOR = {
    "HIGH YIELD": "#3fb950",
    HIGH:         "#3fb950",
    MEDIUM:       "#d29922",
    LOW:          "#8b949e",
  };

  function parseNextSteps(text) {
    if (!text) return [];
    // Take the LAST occurrence — the agent may produce multiple blocks across
    // a long turn (one per finding/phase boundary); only the most recent is
    // actionable.
    const idx = text.lastIndexOf("## Next Steps");
    if (idx === -1) return [];
    let block = text.slice(idx + "## Next Steps".length);
    const stopIdx = block.search(/\n## |\nLet me know when you have completed/);
    if (stopIdx !== -1) block = block.slice(0, stopIdx);

    const out = [];
    const itemRe = /^\s*(\d+)\.\s*\[([^\]]+)\]\s*(.+?)\s*$/;
    const lines = block.split("\n");
    let cur = null;
    for (const raw of lines) {
      const m = raw.match(itemRe);
      if (m) {
        if (cur) out.push(cur);
        cur = { idx: Number(m[1]), tag: m[2].trim().toUpperCase(), action: m[3], why: "", cost: "" };
        continue;
      }
      if (!cur) continue;
      const why = raw.match(/^\s*Why:\s*(.+?)\s*$/i);
      if (why) { cur.why = (cur.why ? cur.why + " " : "") + why[1]; continue; }
      const cost = raw.match(/^\s*Cost:\s*(.+?)\s*$/i);
      if (cost) { cur.cost = (cur.cost ? cur.cost + " " : "") + cost[1]; continue; }
      if (raw.trim() && !cur.why && !cur.cost) cur.action += " " + raw.trim();
    }
    if (cur) out.push(cur);
    return out;
  }

  onMount(async () => {
    unlistenChunk = await listen("claude://chunk", (e) => {
      const c = e.payload;
      if (c.kind === "text" && typeof c.text === "string") {
        assistantBuf += c.text;
      } else if (c.kind === "tool_use") {
        // A new tool_use means the agent moved past the previous Next Steps
        // block (it ran one of them or pivoted) — clear so stale options
        // don't linger as if still actionable.
        if (items.length) items = [];
        lastSent = null;
        busy = false;
      }
    });
    unlistenDone = await listen("claude://done", () => {
      const parsed = parseNextSteps(assistantBuf);
      if (parsed.length) items = parsed;
      assistantBuf = "";
      busy = false;
    });
  });

  onDestroy(() => { unlistenChunk?.(); unlistenDone?.(); });

  // Reset on project switch — Next Steps from project A are meaningless in B.
  $effect(() => {
    project?.id;
    items = [];
    assistantBuf = "";
    busy = false;
    lastSent = null;
  });

  async function pick(item) {
    if (busy || !project) return;
    busy = true;
    lastSent = item.idx;
    const msg = `Proceed with step ${item.idx}: ${item.action}`;
    try {
      await invoke("claude_send", { message: msg });
    } catch (_) {
      busy = false;
      lastSent = null;
    }
  }
</script>

{#if items.length > 0}
  <div class="pl-next" class:pl-next-collapsed={collapsed}>
    <button
      class="pl-next-head"
      onclick={() => (collapsed = !collapsed)}
      aria-expanded={!collapsed}
      title={collapsed ? "Expand Next Steps" : "Collapse Next Steps"}
    >
      <span class="pl-next-caret">{collapsed ? "▸" : "▾"}</span>
      <span class="pl-rail-label">Next Steps</span>
      <span class="pl-next-count">{items.length}</span>
      {#if !collapsed}
        <span class="pl-next-hint">click to run</span>
      {/if}
    </button>
    {#if !collapsed}
      <div class="pl-next-list">
        {#each items as it (it.idx)}
          <button
            class="pl-next-item"
            class:pl-next-active={lastSent === it.idx}
            disabled={busy}
            onclick={() => pick(it)}
            title={[it.why && `Why: ${it.why}`, it.cost && `Cost: ${it.cost}`].filter(Boolean).join("\n") || it.action}
          >
            <span class="pl-next-tag" style="color:{TAG_COLOR[it.tag] ?? '#8b949e'}; border-color:{TAG_COLOR[it.tag] ?? '#8b949e'}">{it.tag}</span>
            <span class="pl-next-action">{it.action}</span>
            {#if it.cost}<span class="pl-next-cost">{it.cost}</span>{/if}
          </button>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<style>
  .pl-next {
    border-top: 1px solid #21262d;
    padding: 10px 12px 12px;
    background: #0d1117;
    max-height: 40%;
    overflow-y: auto;
  }
  .pl-next-collapsed {
    max-height: none;
    padding: 6px 12px;
    overflow: hidden;
  }
  .pl-next-head {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    width: 100%;
    background: transparent;
    border: none;
    padding: 0;
    cursor: pointer;
    color: inherit;
    font-family: inherit;
    text-align: left;
  }
  .pl-next-collapsed .pl-next-head {
    margin-bottom: 0;
  }
  .pl-next-head:hover .pl-rail-label {
    color: #c9d1d9;
  }
  .pl-next-caret {
    font-size: 10px;
    color: #6e7681;
    width: 10px;
    display: inline-block;
  }
  .pl-next-count {
    font-size: 10px;
    color: #6e7681;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0 6px;
    line-height: 14px;
    min-width: 16px;
    text-align: center;
  }
  .pl-rail-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #6e7681;
  }
  .pl-next-hint {
    font-size: 10px;
    color: #484f58;
    margin-left: auto;
  }
  .pl-next-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .pl-next-item {
    display: grid;
    grid-template-columns: auto 1fr;
    grid-template-rows: auto auto auto;
    grid-column-gap: 8px;
    align-items: start;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 5px;
    padding: 7px 9px;
    text-align: left;
    cursor: pointer;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 12px;
    transition: border-color 0.1s, background 0.1s;
  }
  .pl-next-item:hover:not(:disabled) {
    background: #1c2128;
    border-color: #58a6ff;
  }
  .pl-next-item:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .pl-next-active {
    border-color: #58a6ff !important;
    background: #1f2937 !important;
  }
  .pl-next-tag {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.04em;
    padding: 1px 5px;
    border: 1px solid;
    border-radius: 3px;
    align-self: center;
    grid-row: 1 / 2;
    grid-column: 1 / 2;
    line-height: 1.4;
    white-space: nowrap;
  }
  .pl-next-action {
    color: #c9d1d9;
    line-height: 1.35;
    grid-row: 1 / 2;
    grid-column: 2 / 3;
  }
  .pl-next-cost {
    grid-row: 2 / 3;
    grid-column: 2 / 3;
    font-size: 10px;
    color: #6e7681;
    margin-top: 3px;
  }
</style>
