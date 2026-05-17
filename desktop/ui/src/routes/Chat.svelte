<script>
  import { onMount, onDestroy, tick } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  let { project, sessionId } = $props();

  const KINDS = {
    htb_machine:        { name: "HTB Machine", color: "#9fef00" },
    htb_ctf:            { name: "CTF Event",   color: "#f85149" },
    bug_bounty:         { name: "Bug Bounty",  color: "#d29922" },
    authorized_pentest: { name: "Pentest",     color: "#388bfd" },
  };

  const SEV_COLOR = {
    critical: "#f85149",
    high:     "#fb8500",
    medium:   "#d29922",
    low:      "#3fb950",
    info:     "#388bfd",
  };

  let messages     = $state([]);
  let pendingParts = $state([]);
  let input        = $state("");
  let sending      = $state(false);
  let scrollEl     = $state(null);
  let textareaEl   = $state(null);
  let unlistenChunk, unlistenDone;
  let findings     = $state([]);
  let openFinding  = $state(null);

  // Reset textarea height when input is cleared programmatically
  $effect(() => {
    if (textareaEl && !input) {
      textareaEl.style.height = "22px";
    }
  });

  $effect(() => {
    const pid = project?.id;
    pendingParts = [];
    findings = [];
    openFinding = null;
    if (pid) {
      loadHistory(pid);
      loadFindings();
    } else {
      messages = [];
    }
  });

  async function loadHistory(pid) {
    messages = [];
    try {
      const rows = await invoke("load_messages", { projectId: pid });
      messages = rows.map(r => ({ role: r.role, parts: JSON.parse(r.content) }));
    } catch (_) { messages = []; }
  }

  async function loadFindings() {
    if (!project?.id) return;
    try { findings = await invoke("list_findings", { projectId: project.id }); }
    catch (_) { findings = []; }
  }

  async function persistMessage(role, parts) {
    if (!project?.id) return;
    try {
      await invoke("save_message", {
        projectId: project.id,
        role,
        content: JSON.stringify(parts),
      });
    } catch (_) {}
  }

  onMount(async () => {
    unlistenChunk = await listen("claude://chunk", (event) => {
      const c = event.payload;
      if (c.kind === "text") {
        const last = pendingParts.at(-1);
        if (last?.kind === "text") {
          pendingParts = [...pendingParts.slice(0, -1), { ...last, text: last.text + c.text }];
        } else {
          pendingParts = [...pendingParts, { kind: "text", text: c.text }];
        }
      } else if (c.kind === "tool_use") {
        pendingParts = [...pendingParts, { kind: "tool_use", tool_name: c.tool_name, tool_input: c.tool_input }];
      } else if (c.kind === "error") {
        pendingParts = [...pendingParts, { kind: "error", text: c.text }];
      }
      scrollToBottom();
    });

    unlistenDone = await listen("claude://done", () => {
      if (pendingParts.length > 0) {
        const parts = pendingParts;
        messages = [...messages, { role: "assistant", parts }];
        persistMessage("assistant", parts);
        pendingParts = [];
      }
      sending = false;
      scrollToBottom();
      loadFindings();
    });
  });

  onDestroy(() => {
    unlistenChunk?.();
    unlistenDone?.();
  });

  async function send() {
    const text = input.trim();
    if (!text || sending || !project) return;
    input = "";
    sending = true;
    pendingParts = [];
    const userParts = [{ kind: "text", text }];
    messages = [...messages, { role: "user", parts: userParts }];
    persistMessage("user", userParts);
    await tick();
    scrollToBottom();
    try {
      await invoke("claude_send", { message: text });
    } catch (e) {
      messages = [...messages, { role: "assistant", parts: [{ kind: "error", text: String(e) }] }];
      sending = false;
    }
  }

  function handleKey(e) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  }

  async function scrollToBottom() {
    await tick();
    scrollEl?.scrollTo({ top: scrollEl.scrollHeight, behavior: "smooth" });
  }

  // Textarea auto-resize action
  function autosize(node) {
    function resize() {
      node.style.height = "22px";
      node.style.height = Math.min(node.scrollHeight, 140) + "px";
    }
    node.addEventListener("input", resize);
    resize();
    return { destroy() { node.removeEventListener("input", resize); } };
  }

  // ── Markdown renderer (zero dependencies) ───────────────────────────────────
  function esc(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderInline(s) {
    let h = esc(s);
    // Inline code
    h = h.replace(/`([^`\n]{1,400})`/g, '<code class="pl-ic">$1</code>');
    // Bold
    h = h.replace(/\*\*([^*\n]{1,300})\*\*/g, "<strong>$1</strong>");
    return h;
  }

  function renderMarkdown(text) {
    if (!text) return "";
    const out = [];
    const re = /```(\w*)\n?([\s\S]*?)```/g;
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) out.push(renderInline(text.slice(last, m.index)));
      const code = m[2].replace(/\n$/, "");
      out.push(`<pre class="pl-code-block"><code>${esc(code)}</code></pre>`);
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push(renderInline(text.slice(last)));
    return out.join("");
  }

  // Truncate long tool args for display
  function fmtArgs(args) {
    if (!args) return "";
    const s = Object.entries(args)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("  ");
    return s.length > 180 ? s.slice(0, 177) + "…" : s;
  }
</script>

{#if project}
  {@const k = KINDS[project.kind]}

  <!-- Chat column -->
  <div class="pl-chat">
    <div class="pl-chat-head">
      <span class="pl-chat-title">{project.name}</span>
      <span class="pl-pill" style="border-color:{k?.color ?? '#8b949e'};color:{k?.color ?? '#8b949e'}">
        {k?.name ?? project.kind}
      </span>
    </div>

    <div class="pl-messages" bind:this={scrollEl}>
      {#each messages as msg}
        {#if msg.role === "user"}
          {#each msg.parts as part}
            {#if part.kind === "text"}
              <div class="pl-msg">
                <div class="pl-avatar user">U</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">You</div>
                  <div class="pl-msg-text">{part.text}</div>
                </div>
              </div>
            {/if}
          {/each}
        {:else}
          {#each msg.parts as part}
            {#if part.kind === "text"}
              <div class="pl-msg">
                <div class="pl-avatar ai">C</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">Claude · Sonnet 4.6</div>
                  <div class="pl-msg-text">{@html renderMarkdown(part.text)}</div>
                </div>
              </div>
            {:else if part.kind === "tool_use"}
              <div class="pl-msg pl-msg-tool">
                <div class="pl-avatar tool">⚙</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">tool</div>
                  <div class="pl-tool-call">
                    <span class="pl-tool-name">{part.tool_name}</span>
                    {#if fmtArgs(part.tool_input)}
                      <span class="pl-tool-args">{fmtArgs(part.tool_input)}</span>
                    {/if}
                  </div>
                </div>
              </div>
            {:else if part.kind === "error"}
              <div class="pl-msg">
                <div class="pl-avatar ai">C</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">error</div>
                  <div class="pl-msg-error">{part.text}</div>
                </div>
              </div>
            {/if}
          {/each}
        {/if}
      {/each}

      <!-- Streaming / pending -->
      {#if sending}
        {#if pendingParts.length > 0}
          {#each pendingParts as part}
            {#if part.kind === "text"}
              <div class="pl-msg">
                <div class="pl-avatar ai">C</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">Claude · Sonnet 4.6</div>
                  <div class="pl-msg-text">
                    {@html renderMarkdown(part.text)}<span class="pl-cursor">▌</span>
                  </div>
                </div>
              </div>
            {:else if part.kind === "tool_use"}
              <div class="pl-msg pl-msg-tool">
                <div class="pl-avatar tool">⚙</div>
                <div class="pl-msg-body">
                  <div class="pl-msg-author">tool</div>
                  <div class="pl-tool-call">
                    <span class="pl-tool-name">{part.tool_name}</span>
                    {#if fmtArgs(part.tool_input)}
                      <span class="pl-tool-args">{fmtArgs(part.tool_input)}</span>
                    {/if}
                    <span class="pl-tool-spin">…</span>
                  </div>
                </div>
              </div>
            {/if}
          {/each}
        {:else}
          <div class="pl-msg">
            <div class="pl-avatar ai">C</div>
            <div class="pl-msg-body">
              <div class="pl-thinking">
                <span class="d"></span><span class="d"></span><span class="d"></span>
              </div>
            </div>
          </div>
        {/if}
      {/if}
    </div>

    <!-- Input -->
    <div class="pl-input-area">
      <div class="pl-input-wrap" class:focused={false}>
        <textarea
          class="pl-input"
          placeholder={sending ? "Claude is thinking…" : "Tell the agent what to do…  (Shift+Enter for newline)"}
          bind:value={input}
          bind:this={textareaEl}
          onkeydown={handleKey}
          disabled={sending}
          rows="1"
          use:autosize
        ></textarea>
        <button class="pl-send" onclick={send} disabled={sending || !input.trim()} aria-label="Send message">
          Send
        </button>
      </div>
    </div>
  </div>

  <!-- Findings rail -->
  <div class="pl-findings">
    <div class="pl-find-head">
      <span class="pl-rail-label">Findings</span>
      {#if findings.length > 0}
        <span class="pl-find-count">{findings.length}</span>
      {/if}
    </div>
    <div class="pl-find-list">
      {#if findings.length === 0}
        <div class="pl-empty">No findings yet.</div>
      {:else}
        {#each findings as f (f.id)}
          <button
            class="pl-finding"
            class:open={openFinding === f.id}
            style="border-left-color:{SEV_COLOR[f.severity] ?? '#8b949e'}"
            onclick={() => { openFinding = openFinding === f.id ? null : f.id; }}
          >
            <div class="pl-finding-row">
              <span class="pl-sev-badge" style="color:{SEV_COLOR[f.severity]}; border-color:{SEV_COLOR[f.severity]}20">
                {f.severity.toUpperCase().slice(0,4)}
              </span>
              <span class="pl-finding-title">{f.title}</span>
            </div>
            {#if openFinding === f.id && f.description}
              <div class="pl-finding-detail">{f.description}</div>
            {/if}
          </button>
        {/each}
      {/if}
    </div>
  </div>

{:else}
  <div class="pl-no-project">
    <div class="pl-empty-state">
      <div class="pl-empty-icon">⬡</div>
      <div class="pl-empty-title">Penligent Local</div>
      <div class="pl-empty-sub">Select or create an engagement to begin.</div>
    </div>
  </div>
{/if}

<style>
  .pl-chat {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    background: #0d1117;
  }

  .pl-chat-head {
    padding: 12px 18px;
    border-bottom: 1px solid #30363d;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
    background: #010409;
  }

  .pl-chat-title {
    font-size: 13px;
    font-weight: 600;
    color: #e6edf3;
    letter-spacing: 0.01em;
  }

  .pl-pill {
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 11px;
    border: 1px solid;
    background: transparent;
    font-weight: 500;
  }

  /* ── Messages ─────────────────────────────────────────────────── */

  .pl-messages {
    flex: 1;
    overflow-y: auto;
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .pl-msg { display: flex; gap: 10px; }
  .pl-msg-tool { opacity: 0.85; }

  .pl-avatar {
    width: 26px; height: 26px;
    border-radius: 4px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 500;
    margin-top: 1px;
  }
  .pl-avatar.user { background: #1f6feb; color: #fff; }
  .pl-avatar.ai   { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
  .pl-avatar.tool { background: #0d1117; color: #9fef00; border: 1px solid rgba(159,239,0,0.3); }

  .pl-msg-body { flex: 1; min-width: 0; }

  .pl-msg-author {
    font-size: 11px;
    color: #6e7681;
    margin-bottom: 4px;
    font-weight: 500;
  }

  .pl-msg-text {
    font-size: 13px;
    line-height: 1.6;
    color: #c9d1d9;
    white-space: pre-wrap;
    word-break: break-word;
  }

  /* Elements injected by renderMarkdown */
  :global(.pl-code-block) {
    background: #010409;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 12px 14px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 12px;
    line-height: 1.55;
    overflow-x: auto;
    margin: 8px 0;
    color: #c9d1d9;
    white-space: pre;
    display: block;
  }

  :global(.pl-ic) {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 3px;
    padding: 1px 5px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 0.88em;
    color: #9fef00;
    white-space: nowrap;
  }

  .pl-msg-error {
    font-size: 12px;
    color: #f85149;
    background: rgba(248,81,73,0.08);
    border: 1px solid rgba(248,81,73,0.2);
    border-radius: 6px;
    padding: 8px 12px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    line-height: 1.5;
  }

  .pl-tool-call {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 10px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    line-height: 1.5;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: baseline;
  }
  .pl-tool-name { color: #9fef00; font-weight: 500; }
  .pl-tool-args { color: #8b949e; word-break: break-all; }
  .pl-tool-spin { color: #484f58; animation: blink 1s step-end infinite; }

  /* ── Thinking / cursor ───────────────────────────────────────── */

  .pl-thinking {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 6px 0;
  }
  .pl-thinking .d {
    width: 4px; height: 4px;
    border-radius: 50%;
    background: #484f58;
    animation: plBlink 1.3s ease-in-out infinite;
  }
  .pl-thinking .d:nth-child(2) { animation-delay: 0.18s; }
  .pl-thinking .d:nth-child(3) { animation-delay: 0.36s; }
  @keyframes plBlink { 0%, 60%, 100% { opacity: 0.2; } 30% { opacity: 1; } }

  :global(.pl-cursor) {
    display: inline;
    color: #388bfd;
    animation: blink 1s step-end infinite;
  }
  @keyframes blink { 50% { opacity: 0; } }

  /* ── Input area ──────────────────────────────────────────────── */

  .pl-input-area {
    padding: 12px 18px;
    border-top: 1px solid #30363d;
    flex-shrink: 0;
  }

  .pl-input-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px 10px;
    transition: border-color 0.12s;
  }
  .pl-input-wrap:focus-within { border-color: #58a6ff; }

  .pl-input {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    color: #c9d1d9;
    font-size: 13px;
    font-family: inherit;
    resize: none;
    line-height: 1.5;
    min-height: 22px;
    max-height: 140px;
    overflow-y: auto;
  }
  .pl-input:disabled { opacity: 0.45; }
  .pl-input::placeholder { color: #484f58; }

  .pl-send {
    background: #238636;
    color: #fff;
    border: none;
    padding: 5px 12px;
    border-radius: 4px;
    cursor: pointer;
    flex-shrink: 0;
    font-size: 12px;
    font-weight: 500;
    font-family: inherit;
    transition: background 0.12s;
  }
  .pl-send:hover:not(:disabled) { background: #2ea043; }
  .pl-send:disabled { opacity: 0.35; cursor: default; }

  /* ── Findings rail ───────────────────────────────────────────── */

  .pl-findings {
    width: 240px;
    background: #161b22;
    border-left: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .pl-find-head {
    padding: 14px 14px 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-shrink: 0;
  }

  .pl-rail-label {
    font-size: 11px;
    color: #6e7681;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 500;
  }

  .pl-find-count {
    background: #21262d;
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 11px;
    color: #8b949e;
    font-weight: 500;
  }

  .pl-find-list {
    flex: 1;
    overflow-y: auto;
    padding: 4px 8px;
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

  .pl-finding-row { display: flex; align-items: center; gap: 6px; }

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
  }

  .pl-finding-detail {
    font-size: 11px;
    color: #8b949e;
    margin-top: 6px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .pl-empty {
    color: #484f58;
    font-size: 12px;
    padding: 20px 8px;
    text-align: center;
  }

  /* ── Empty state ─────────────────────────────────────────────── */

  .pl-no-project {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0d1117;
  }

  .pl-empty-state {
    text-align: center;
    user-select: none;
  }

  .pl-empty-icon {
    font-size: 36px;
    color: #21262d;
    margin-bottom: 12px;
    line-height: 1;
  }

  .pl-empty-title {
    font-size: 15px;
    font-weight: 600;
    color: #30363d;
    margin-bottom: 6px;
    letter-spacing: 0.02em;
  }

  .pl-empty-sub {
    font-size: 12px;
    color: #30363d;
  }
</style>
