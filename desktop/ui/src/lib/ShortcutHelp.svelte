<script>
  let { open = $bindable(false) } = $props();

  const GROUPS = [
    {
      name: "Global",
      items: [
        { keys: ["Ctrl", "K"],      label: "Open command palette" },
        { keys: ["?"],              label: "Show this help" },
        { keys: ["Esc"],            label: "Close modal / palette" },
      ],
    },
    {
      name: "Navigation",
      items: [
        { keys: ["Ctrl", "1"],      label: "Switch to Chat tab" },
        { keys: ["Ctrl", "2"],      label: "Switch to Workspace tab" },
        { keys: ["Ctrl", "3"],      label: "Switch to Settings tab" },
        { keys: ["Ctrl", ","],      label: "Open Settings" },
      ],
    },
    {
      name: "Chat",
      items: [
        { keys: ["Ctrl", "J"],      label: "Focus chat input" },
        { keys: ["Enter"],          label: "Send message" },
        { keys: ["Shift", "Enter"], label: "Newline in chat input" },
      ],
    },
  ];

  function onKey(e) {
    if (e.key === "Escape") { e.preventDefault(); open = false; }
  }
</script>

<svelte:window onkeydown={open ? onKey : null} />

{#if open}
  <div class="pl-help-backdrop" onclick={() => open = false} role="presentation">
    <div class="pl-help-modal" onclick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
      <div class="pl-help-head">
        <span class="pl-help-title">Keyboard Shortcuts</span>
        <button class="pl-help-close" onclick={() => open = false} aria-label="Close">×</button>
      </div>
      <div class="pl-help-body">
        {#each GROUPS as g}
          <div class="pl-help-group">
            <div class="pl-help-group-name">{g.name}</div>
            {#each g.items as it}
              <div class="pl-help-row">
                <span class="pl-help-keys">
                  {#each it.keys as k, j}
                    {#if j > 0}<span class="pl-help-plus">+</span>{/if}
                    <kbd>{k}</kbd>
                  {/each}
                </span>
                <span class="pl-help-label">{it.label}</span>
              </div>
            {/each}
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}

<style>
  .pl-help-backdrop {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.55);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000;
  }
  .pl-help-modal {
    width: 480px; max-width: 90vw;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    overflow: hidden;
  }
  .pl-help-head {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px;
    border-bottom: 1px solid #21262d;
  }
  .pl-help-title {
    color: #e6edf3;
    font-size: 13px;
    font-weight: 600;
  }
  .pl-help-close {
    background: transparent; border: 0; color: #8b949e;
    font-size: 18px; cursor: pointer; padding: 0 4px;
  }
  .pl-help-close:hover { color: #e6edf3; }
  .pl-help-body { padding: 8px 14px 14px; }
  .pl-help-group { margin-top: 10px; }
  .pl-help-group-name {
    color: #8b949e;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 4px;
    padding-bottom: 3px;
    border-bottom: 1px dashed #21262d;
  }
  .pl-help-row {
    display: flex; align-items: center;
    padding: 5px 0;
    font-size: 12px;
  }
  .pl-help-keys { width: 160px; flex-shrink: 0; }
  .pl-help-label { color: #c9d1d9; }
  .pl-help-plus { color: #484f58; margin: 0 3px; font-size: 11px; }
  kbd {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    background: #161b22;
    border: 1px solid #21262d;
    color: #8b949e;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
  }
</style>
