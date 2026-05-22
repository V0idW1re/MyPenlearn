<script>
  import { onMount, tick } from "svelte";

  let { open = $bindable(false), commands = [] } = $props();

  let query  = $state("");
  let active = $state(0);
  let inputEl;

  // Reset state every time the palette opens
  $effect(() => {
    if (open) {
      query  = "";
      active = 0;
      tick().then(() => inputEl?.focus());
    }
  });

  // Score = sum over query tokens of (label hit / keywords hit / hotkey hit)
  function score(cmd, q) {
    if (!q) return 1; // show all when empty
    const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return 1;
    const hay = (cmd.label + " " + (cmd.keywords ?? "") + " " + (cmd.hotkey ?? "")).toLowerCase();
    let s = 0;
    for (const t of tokens) {
      const i = hay.indexOf(t);
      if (i === -1) return 0;        // require all tokens present
      s += (i === 0 ? 3 : 1);        // prefix matches rank higher
    }
    return s;
  }

  let filtered = $derived(
    commands
      .map(c => ({ cmd: c, s: score(c, query) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 12)
      .map(x => x.cmd)
  );

  $effect(() => {
    // keep active index inside bounds when filter changes
    if (active >= filtered.length) active = Math.max(0, filtered.length - 1);
  });

  function close() { open = false; }

  function run(cmd) {
    if (!cmd) return;
    close();
    // Defer so the close animation / state change settles before the action runs
    queueMicrotask(() => { try { cmd.action?.(); } catch (e) { console.error(e); } });
  }

  function onKey(e) {
    if (e.key === "Escape")    { e.preventDefault(); close(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); active = Math.min(filtered.length - 1, active + 1); return; }
    if (e.key === "ArrowUp")   { e.preventDefault(); active = Math.max(0, active - 1); return; }
    if (e.key === "Enter")     { e.preventDefault(); run(filtered[active]); return; }
  }
</script>

{#if open}
  <div class="pl-cmd-backdrop" onclick={close} role="presentation">
    <div class="pl-cmd-modal" onclick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Command palette">
      <input
        bind:this={inputEl}
        bind:value={query}
        class="pl-cmd-input"
        type="text"
        placeholder="Search commands…"
        onkeydown={onKey}
        spellcheck="false"
        autocomplete="off"
      />
      <div class="pl-cmd-list">
        {#each filtered as cmd, i}
          <button
            class="pl-cmd-item"
            class:active={i === active}
            onmouseenter={() => active = i}
            onclick={() => run(cmd)}
          >
            <span class="pl-cmd-label">{cmd.label}</span>
            {#if cmd.hotkey}
              <span class="pl-cmd-hotkey">{cmd.hotkey}</span>
            {/if}
          </button>
        {/each}
        {#if filtered.length === 0}
          <div class="pl-cmd-empty">No matching commands.</div>
        {/if}
      </div>
      <div class="pl-cmd-foot">
        <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
        <span><kbd>↵</kbd> run</span>
        <span><kbd>Esc</kbd> close</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .pl-cmd-backdrop {
    position: fixed; inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex; align-items: flex-start; justify-content: center;
    padding-top: 12vh;
    z-index: 1000;
  }
  .pl-cmd-modal {
    width: 560px;
    max-width: 90vw;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    overflow: hidden;
    display: flex; flex-direction: column;
  }
  .pl-cmd-input {
    width: 100%;
    padding: 14px 16px;
    background: transparent;
    border: 0;
    border-bottom: 1px solid #21262d;
    color: #e6edf3;
    font-size: 14px;
    font-family: inherit;
    outline: none;
    box-sizing: border-box;
  }
  .pl-cmd-list {
    max-height: 50vh;
    overflow-y: auto;
    padding: 6px 0;
  }
  .pl-cmd-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 8px 14px;
    background: transparent;
    border: 0;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 13px;
    text-align: left;
    cursor: pointer;
    transition: background 0.05s;
  }
  .pl-cmd-item.active {
    background: #1f2937;
    color: #e6edf3;
  }
  .pl-cmd-label { flex: 1; }
  .pl-cmd-hotkey {
    color: #8b949e;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    background: #161b22;
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid #21262d;
  }
  .pl-cmd-empty {
    padding: 16px;
    color: #8b949e;
    text-align: center;
    font-size: 13px;
  }
  .pl-cmd-foot {
    display: flex;
    gap: 14px;
    padding: 8px 14px;
    background: #010409;
    color: #6e7681;
    font-size: 11px;
    border-top: 1px solid #21262d;
  }
  .pl-cmd-foot kbd {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    background: #161b22;
    border: 1px solid #21262d;
    color: #8b949e;
    padding: 1px 5px;
    border-radius: 3px;
    margin-right: 4px;
  }
</style>
