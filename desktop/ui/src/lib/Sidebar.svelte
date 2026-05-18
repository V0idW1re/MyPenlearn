<script>
  import { invoke } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";

  let { activeProject, onSelect } = $props();

  const KINDS = {
    htb_machine:        { name: "HTB Machine", color: "#9fef00", desc: "training labs" },
    htb_ctf:            { name: "CTF Event",   color: "#f85149", desc: "time-bound flag hunting" },
    bug_bounty:         { name: "Bug Bounty",  color: "#d29922", desc: "public scope" },
    authorized_pentest: { name: "Pentest",     color: "#58a6ff", desc: "authorized engagement" },
  };

  const KIND_ICONS = {
    htb_machine: "🖥", htb_ctf: "🚩", bug_bounty: "🐛", authorized_pentest: "📋",
  };

  let projects    = $state([]);
  let modalStep   = $state(0);
  let pickedKind  = $state("");
  let newName     = $state("");
  let creating    = $state(false);
  let createError = $state("");
  let ctxMenu     = $state(null);
  let savedId     = $state(null);
  let renamingId  = $state(null);
  let renameVal   = $state("");
  let deleteTarget = $state(null);

  onMount(async () => {
    try { projects = await invoke("list_projects"); } catch (_) {}
    document.addEventListener("click", closeCtx);
    document.addEventListener("contextmenu", handleDocCtx);
  });

  onDestroy(() => {
    document.removeEventListener("click", closeCtx);
    document.removeEventListener("contextmenu", handleDocCtx);
  });

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

  function openModal() { modalStep = 1; pickedKind = ""; newName = ""; createError = ""; }
  function closeModal() { modalStep = 0; }

  async function createProject() {
    if (!newName.trim()) return;
    creating = true;
    createError = "";
    try {
      const project = await invoke("create_project", { name: newName.trim(), target: "", kind: pickedKind });
      projects = [...projects, project];
      closeModal();
      onSelect(project);
    } catch (e) {
      createError = String(e);
    } finally { creating = false; }
  }

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

  function askDelete(proj) { ctxMenu = null; deleteTarget = proj; }

  async function confirmDelete() {
    if (!deleteTarget) return;
    try {
      await invoke("delete_project", { id: deleteTarget.id });
      projects = projects.filter(p => p.id !== deleteTarget.id);
      if (activeProject?.id === deleteTarget.id) onSelect(null);
    } catch (_) {}
    deleteTarget = null;
  }

  function showSaved(proj) {
    ctxMenu = null;
    savedId = proj.id;
    setTimeout(() => { savedId = null; }, 1500);
  }

  function focusOnMount(node) { node.focus(); node.select(); return {}; }
</script>

<div class="sidebar-inner">
  <div class="pl-side-head">
    <span class="pl-side-label">Engagements</span>
    <div class="pl-side-right">
      {#if projects.length > 0}
        <span class="pl-side-count">{projects.length}</span>
      {/if}
      <button class="pl-plus" onclick={openModal} aria-label="New engagement">+</button>
    </div>
  </div>

  <div class="pl-projects">
    {#each projects as proj (proj.id)}
      {@const k = KINDS[proj.kind]}
      {#if renamingId === proj.id}
        <div class="pl-project rename-row">
          <span class="pl-dot" style="background:{k?.color ?? '#8b949e'}"></span>
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
          style="--kc:{k?.color ?? '#8b949e'}"
          onclick={() => onSelect(proj)}
          oncontextmenu={(e) => openCtx(e, proj)}
        >
          <span class="pl-dot" style="background:{k?.color ?? '#8b949e'}"></span>
          <div class="pl-project-info">
            <div class="pl-project-name">
              {proj.name}
              {#if savedId === proj.id}<span class="saved-badge">✓</span>{/if}
            </div>
            <div class="pl-project-meta">
              <span class="pl-kind-tag">{k?.name ?? proj.kind}</span>
              {#if proj.target}
                <span class="meta-sep">·</span>
                <span class="pl-project-ip">{proj.target}</span>
              {/if}
            </div>
          </div>
        </button>
      {/if}
    {:else}
      <div class="pl-empty">No engagements yet.</div>
    {/each}
  </div>
</div>

{#if ctxMenu}
  <div class="ctx-menu" style="left:{ctxMenu.x}px;top:{ctxMenu.y}px">
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

{#if modalStep > 0}
  <div class="pl-modal-bg" role="dialog" aria-modal="true" tabindex="-1"
    onclick={(e) => { if (e.target === e.currentTarget) closeModal(); }}
    onkeydown={(e) => { if (e.key === "Escape") closeModal(); }}>
    <div class="pl-modal">
      {#if modalStep === 1}
        <h2>New Engagement</h2>
        <p class="modal-sub">Select the type of engagement to begin.</p>
        <div class="pl-kind-grid">
          {#each Object.entries(KINDS) as [id, k]}
            <button class="pl-kind-card" style="--kc:{k.color}" onclick={() => { pickedKind = id; modalStep = 2; }}>
              <div class="pl-kind-icon">{KIND_ICONS[id]}</div>
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
          <span class="pl-pill" style="border-color:{k.color};color:{k.color}">{KIND_ICONS[pickedKind]}&nbsp;&nbsp;{k.name}</span>
        </div>
        <h2>Name your engagement</h2>
        <div class="pl-field">
          <span class="pl-field-label">Project name</span>
          <span class="pl-field-hint">Used as the workspace directory name. Keep it short and filesystem-safe.</span>
          <input class="pl-text-input" placeholder="e.g. Cap" bind:value={newName}
            onkeydown={(e) => e.key === "Enter" && createProject()} />
          {#if createError}
            <span class="pl-field-error">{createError}</span>
          {/if}
        </div>
        <div class="pl-modal-actions">
          <button class="pl-btn" onclick={() => { modalStep = 1; }}>Back</button>
          <button class="pl-btn pl-btn-primary" onclick={createProject}
            disabled={creating || !newName.trim()}>
            {creating ? "Creating…" : "Create engagement"}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .sidebar-inner { display: flex; flex-direction: column; height: 100%; }

  /* ── Header ──────────────────────────────────────────────────── */

  .pl-side-head {
    padding: 14px 14px 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
    border-bottom: 1px solid #21262d;
  }

  .pl-side-right { display: flex; align-items: center; gap: 6px; }
  .pl-side-count {
    font-size: 10px;
    color: #484f58;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

  .pl-side-label {
    font-size: 10px;
    color: #484f58;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-weight: 600;
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
    transition: background 0.1s;
  }
  .pl-plus:hover { background: #30363d; color: #fff; }

  /* ── Project list ────────────────────────────────────────────── */

  .pl-projects { padding: 6px 6px; overflow-y: auto; flex: 1; }

  .pl-project {
    display: flex;
    align-items: flex-start;
    gap: 9px;
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
    transition: background 0.1s, border-color 0.1s;
  }
  .pl-project:hover { background: #1c2128; border-left-color: var(--kc); }
  .pl-project.active { background: #1c2128; border-left-color: var(--kc); }

  .rename-row {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 10px;
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

  .pl-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    margin-top: 4px;
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

  .pl-project-meta {
    display: flex;
    align-items: center;
    gap: 5px;
    margin-top: 2px;
    min-width: 0;
  }

  .pl-kind-tag {
    font-size: 10px;
    color: #484f58;
    font-weight: 500;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .meta-sep { font-size: 10px; color: #30363d; flex-shrink: 0; }

  .pl-project-ip {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    color: #6e7681;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .saved-badge { font-size: 10px; color: #9fef00; font-weight: 600; }

  .pl-empty { color: #484f58; font-size: 12px; padding: 20px 8px; text-align: center; }

  /* ── Context menu ────────────────────────────────────────────── */

  .ctx-menu {
    position: fixed;
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px;
    min-width: 140px;
    z-index: 100;
    box-shadow: 0 8px 24px rgba(0,0,0,0.5);
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
  .ctx-sep { height: 1px; background: #30363d; margin: 4px 0; }

  /* ── Modals ──────────────────────────────────────────────────── */

  .pl-modal-bg {
    background: rgba(1,4,9,0.75);
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
    width: 420px;
    max-width: 90vw;
  }

  .pl-modal h2 { font-size: 16px; color: #e6edf3; margin: 0 0 4px; font-weight: 600; }

  .modal-sub { font-size: 12px; color: #6e7681; margin: 0 0 16px; }

  .delete-warn { font-size: 12px; color: #8b949e; margin: 0 0 16px; line-height: 1.5; }

  .pl-kind-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 0; }

  .pl-kind-card {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px 12px;
    cursor: pointer;
    text-align: center;
    font-family: inherit;
    color: inherit;
    transition: background 0.1s, border-color 0.1s;
  }
  .pl-kind-card:hover { background: #1c2128; border-color: var(--kc); }

  .pl-kind-icon { font-size: 22px; margin-bottom: 6px; line-height: 1; }
  .pl-kind-name { font-size: 13px; color: #e6edf3; font-weight: 500; }
  .pl-kind-desc { font-size: 11px; color: #6e7681; margin-top: 2px; }

  .pl-modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }

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
    transition: background 0.1s;
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

  .pl-field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 14px; }
  .pl-field:last-of-type { margin-bottom: 0; }

  .pl-field-label { font-size: 12px; color: #c9d1d9; font-weight: 500; }
  .pl-field-hint  { font-size: 11px; color: #6e7681; line-height: 1.5; }
  .pl-field-error { font-size: 11px; color: #f85149; line-height: 1.5; }

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
    transition: border-color 0.12s;
  }
  .pl-text-input:focus { border-color: #58a6ff; }
</style>
