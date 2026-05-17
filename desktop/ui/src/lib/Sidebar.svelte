<script>
  import { invoke } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";

  let { activeProject, onSelect } = $props();

  const KINDS = {
    htb_machine:        { name: "HTB Machine", icon: "🖥",  color: "#9fef00", desc: "training labs" },
    htb_ctf:            { name: "CTF Event",   icon: "🚩",  color: "#f85149", desc: "time-bound flag hunting" },
    bug_bounty:         { name: "Bug Bounty",  icon: "🐛",  color: "#d29922", desc: "public scope" },
    authorized_pentest: { name: "Pentest",     icon: "📋",  color: "#58a6ff", desc: "authorized engagement" },
  };

  let projects    = $state([]);
  let modalStep   = $state(0);   // 0=closed 1=pick-kind 2=name
  let pickedKind  = $state("");
  let newName     = $state("");
  let creating    = $state(false);

  // Context menu
  let ctxMenu     = $state(null);  // { x, y, proj }
  let savedId     = $state(null);  // project id that just showed "Saved ✓"

  // Rename inline
  let renamingId  = $state(null);
  let renameVal   = $state("");

  // Delete confirm
  let deleteTarget = $state(null);  // project to delete

  onMount(async () => {
    try { projects = await invoke("list_projects"); } catch (_) {}
    document.addEventListener("click", closeCtx);
    document.addEventListener("contextmenu", handleDocCtx);
  });

  onDestroy(() => {
    document.removeEventListener("click", closeCtx);
    document.removeEventListener("contextmenu", handleDocCtx);
  });

  // Close ctx menu unless the click was inside it or on a project button
  function closeCtx(e) {
    if (!e.target.closest(".ctx-menu")) ctxMenu = null;
  }

  function handleDocCtx(e) {
    if (!e.target.closest(".pl-project")) ctxMenu = null;
  }

  function openCtx(e, proj) {
    e.preventDefault();
    e.stopPropagation();
    ctxMenu = { x: e.clientX, y: e.clientY, proj };
  }

  // --- New project modal ---
  function openModal() { modalStep = 1; pickedKind = ""; newName = ""; }
  function closeModal() { modalStep = 0; }

  async function createProject() {
    if (!newName.trim()) return;
    creating = true;
    try {
      const project = await invoke("create_project", {
        name: newName.trim(), target: "", kind: pickedKind,
      });
      projects = [...projects, project];
      closeModal();
      onSelect(project);
    } catch (_) {}
    finally { creating = false; }
  }

  // --- Rename ---
  function startRename(proj) {
    ctxMenu = null;
    renamingId = proj.id;
    renameVal = proj.name;
  }

  async function commitRename() {
    if (!renameVal.trim() || !renamingId) { renamingId = null; return; }
    try {
      const updated = await invoke("rename_project", { id: renamingId, name: renameVal.trim() });
      projects = projects.map(p => p.id === updated.id ? updated : p);
      if (activeProject?.id === updated.id) onSelect(updated);
    } catch (_) {}
    renamingId = null;
  }

  function renameKey(e) {
    if (e.key === "Enter") commitRename();
    if (e.key === "Escape") renamingId = null;
  }

  // --- Delete ---
  function askDelete(proj) {
    ctxMenu = null;
    deleteTarget = proj;
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await invoke("delete_project", { id: deleteTarget.id });
      projects = projects.filter(p => p.id !== deleteTarget.id);
      if (activeProject?.id === deleteTarget.id) onSelect(null);
    } catch (_) {}
    deleteTarget = null;
  }

  // --- Save feedback ---
  function showSaved(proj) {
    ctxMenu = null;
    savedId = proj.id;
    setTimeout(() => { savedId = null; }, 1500);
  }

  // Svelte action: focus and select input on mount
  function focusOnMount(node) {
    node.focus();
    node.select();
    return {};
  }
</script>

<div class="sidebar-inner">
  <div class="pl-side-head">
    <span class="pl-side-label">Engagements</span>
    <button class="pl-plus" onclick={openModal} aria-label="New project">+</button>
  </div>

  <div class="pl-projects">
    {#each projects as proj (proj.id)}
      {@const k = KINDS[proj.kind]}
      {#if renamingId === proj.id}
        <!-- Inline rename input -->
        <div class="pl-project rename-row">
          <span class="pl-kind-dot" style="background:{k?.color ?? '#8b949e'}"></span>
          <input
            class="rename-input"
            bind:value={renameVal}
            onkeydown={renameKey}
            onblur={commitRename}
            use:focusOnMount
          />
        </div>
      {:else}
        <button
          class="pl-project"
          class:active={activeProject?.id === proj.id}
          style="border-left-color:{activeProject?.id === proj.id ? (k?.color ?? '#8b949e') : 'transparent'}"
          onclick={() => onSelect(proj)}
          oncontextmenu={(e) => openCtx(e, proj)}
        >
          <span class="pl-kind-dot" style="background:{k?.color ?? '#8b949e'}"></span>
          <div class="pl-project-info">
            <div class="pl-project-name">
              {proj.name}
              {#if savedId === proj.id}<span class="saved-badge">✓ Saved</span>{/if}
            </div>
            {#if proj.target}
              <div class="pl-project-target">{proj.target}</div>
            {/if}
          </div>
        </button>
      {/if}
    {:else}
      <div class="pl-empty">No engagements yet.</div>
    {/each}
  </div>
</div>

<!-- Context menu — no onclick needed; closeCtx checks .ctx-menu before closing -->
{#if ctxMenu}
  <div
    class="ctx-menu"
    style="left:{ctxMenu.x}px;top:{ctxMenu.y}px"
  >
    <button class="ctx-item" onclick={() => startRename(ctxMenu.proj)}>
      <span class="ctx-icon">✏</span> Rename
    </button>
    <button class="ctx-item" onclick={() => showSaved(ctxMenu.proj)}>
      <span class="ctx-icon">✓</span> Save
    </button>
    <div class="ctx-sep"></div>
    <button class="ctx-item danger" onclick={() => askDelete(ctxMenu.proj)}>
      <span class="ctx-icon">🗑</span> Delete
    </button>
  </div>
{/if}

<!-- Delete confirmation modal -->
{#if deleteTarget}
  <div class="pl-modal-bg" role="dialog" aria-modal="true" tabindex="-1"
    onclick={(e) => { if (e.target === e.currentTarget) deleteTarget = null; }}
    onkeydown={(e) => { if (e.key === "Escape") deleteTarget = null; }}>
    <div class="pl-modal">
      <h2>Delete "{deleteTarget.name}"?</h2>
      <p class="delete-warn">This will permanently remove the engagement and its chat history. Findings will also be deleted.</p>
      <div class="pl-modal-actions">
        <button class="pl-btn" onclick={() => deleteTarget = null}>Cancel</button>
        <button class="pl-btn pl-btn-danger" onclick={confirmDelete}>Delete</button>
      </div>
    </div>
  </div>
{/if}

<!-- New project modal -->
{#if modalStep > 0}
  <div class="pl-modal-bg" role="dialog" aria-modal="true" tabindex="-1"
    onclick={(e) => { if (e.target === e.currentTarget) closeModal(); }}
    onkeydown={(e) => { if (e.key === "Escape") closeModal(); }}>
    <div class="pl-modal">
      {#if modalStep === 1}
        <h2>What are you doing?</h2>
        <div class="pl-kind-grid">
          {#each Object.entries(KINDS) as [id, k]}
            <button class="pl-kind-card" onclick={() => { pickedKind = id; modalStep = 2; }}>
              <div class="pl-kind-icon" style="color:{k.color}">{k.icon}</div>
              <div class="pl-kind-name">{k.name}</div>
              <div class="pl-kind-desc">{k.desc}</div>
            </button>
          {/each}
        </div>
        <div class="pl-modal-actions">
          <button class="pl-btn" onclick={closeModal}>Cancel</button>
        </div>
      {:else}
        {@const k = KINDS[pickedKind]}
        <div class="modal-pill-row">
          <span class="pl-pill" style="border-color:{k.color};color:{k.color}">{k.icon}&nbsp;&nbsp;{k.name}</span>
        </div>
        <h2>Name your engagement</h2>
        <div class="pl-field">
          <span class="pl-field-label">Project name</span>
          <span class="pl-field-hint">The agent will discover targets automatically.</span>
          <input class="pl-text-input" placeholder="e.g. Cap" bind:value={newName}
            onkeydown={(e) => e.key === "Enter" && createProject()} />
        </div>
        <div class="pl-modal-actions">
          <button class="pl-btn" onclick={() => { modalStep = 1; }}>Back</button>
          <button class="pl-btn pl-btn-primary" onclick={createProject}
            disabled={creating || !newName.trim()}>
            {creating ? "Creating…" : "Create project"}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .sidebar-inner {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .pl-side-head {
    padding: 14px 14px 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }

  .pl-side-label {
    font-size: 11px;
    color: #6e7681;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 500;
  }

  .pl-plus {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    width: 22px; height: 22px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    line-height: 1;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .pl-plus:hover { background: #30363d; color: #fff; }

  .pl-projects {
    padding: 4px 6px;
    overflow-y: auto;
    flex: 1;
  }

  .pl-project {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    border-left: 2px solid transparent;
    border-top: none; border-right: none; border-bottom: none;
    margin-bottom: 2px;
    background: none;
    width: 100%;
    text-align: left;
    font-family: inherit;
    font-size: inherit;
    color: inherit;
  }
  .pl-project:hover { background: #1c2128; }
  .pl-project.active { background: #1c2128; }

  .rename-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 10px;
    margin-bottom: 2px;
  }

  .rename-input {
    flex: 1;
    background: #0d1117;
    border: 1px solid #58a6ff;
    border-radius: 4px;
    color: #e6edf3;
    padding: 4px 6px;
    font-size: 13px;
    font-family: inherit;
    outline: none;
  }

  .pl-kind-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .pl-project-info { flex: 1; min-width: 0; }

  .pl-project-name {
    font-size: 13px;
    color: #e6edf3;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .pl-project-target {
    font-size: 11px;
    color: #6e7681;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .saved-badge {
    font-size: 10px;
    color: #9fef00;
    font-weight: 500;
    opacity: 0.85;
  }

  .pl-empty {
    color: #6e7681;
    font-size: 12px;
    padding: 16px 8px;
    text-align: center;
  }

  /* Context menu */
  .ctx-menu {
    position: fixed;
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px;
    min-width: 140px;
    z-index: 100;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  }

  .ctx-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 10px;
    background: none;
    border: none;
    color: #c9d1d9;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
    border-radius: 4px;
    text-align: left;
  }
  .ctx-item:hover { background: #30363d; }
  .ctx-item.danger { color: #f85149; }
  .ctx-item.danger:hover { background: rgba(248,81,73,0.1); }

  .ctx-icon { font-size: 12px; width: 14px; text-align: center; }

  .ctx-sep {
    height: 1px;
    background: #30363d;
    margin: 4px 0;
  }

  /* Delete confirm & new-project modals */
  .pl-modal-bg {
    background: rgba(1, 4, 9, 0.7);
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }

  .pl-modal {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 22px;
    width: 400px;
    max-width: 90vw;
  }

  .pl-modal h2 {
    font-size: 16px;
    color: #e6edf3;
    margin: 0 0 12px;
    font-weight: 500;
  }

  .delete-warn {
    font-size: 12px;
    color: #8b949e;
    margin: 0 0 16px;
    line-height: 1.5;
  }

  .pl-kind-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  .pl-kind-card {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px 12px;
    cursor: pointer;
    text-align: center;
    font-family: inherit;
    color: inherit;
  }
  .pl-kind-card:hover { background: #1c2128; border-color: #8b949e; }

  .pl-kind-icon { font-size: 22px; margin-bottom: 6px; line-height: 1; }
  .pl-kind-name { font-size: 13px; color: #e6edf3; font-weight: 500; }
  .pl-kind-desc { font-size: 11px; color: #6e7681; margin-top: 2px; }

  .pl-modal-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 16px;
  }

  .pl-btn {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    font-weight: 500;
  }
  .pl-btn:hover { background: #30363d; }

  .pl-btn-primary { background: #238636; border-color: #238636; color: #fff; }
  .pl-btn-primary:hover:not(:disabled) { background: #2ea043; }
  .pl-btn-primary:disabled { opacity: 0.5; cursor: default; }

  .pl-btn-danger { background: #da3633; border-color: #da3633; color: #fff; }
  .pl-btn-danger:hover { background: #f85149; border-color: #f85149; }

  .modal-pill-row { display: flex; align-items: center; margin-bottom: 14px; }

  .pl-pill {
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    border: 1px solid;
    background: transparent;
    font-weight: 500;
  }

  .pl-field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin-bottom: 14px;
  }
  .pl-field:last-of-type { margin-bottom: 0; }

  .pl-field-label { font-size: 12px; color: #c9d1d9; font-weight: 500; }
  .pl-field-hint { font-size: 11px; color: #6e7681; line-height: 1.5; }

  .pl-text-input {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #c9d1d9;
    padding: 7px 10px;
    font-size: 12px;
    font-family: "JetBrains Mono", monospace;
    outline: none;
    width: 100%;
  }
  .pl-text-input:focus { border-color: #58a6ff; }
</style>
