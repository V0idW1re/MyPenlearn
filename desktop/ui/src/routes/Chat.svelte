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

  let messages     = $state([]);
  let pendingParts = $state([]);
  let input        = $state("");
  let sending      = $state(false);
  let scrollEl     = $state(null);
  let textareaEl   = $state(null);
  let atBottom     = $state(true);
  let unlistenChunk, unlistenDone;

  $effect(() => {
    if (textareaEl && !input) textareaEl.style.height = "22px";
  });

  $effect(() => {
    const pid = project?.id;
    pendingParts = [];
    if (pid) loadHistory(pid);
    else messages = [];
  });

  async function loadHistory(pid) {
    messages = [];
    try {
      const rows = await invoke("load_messages", { projectId: pid });
      messages = rows.map(r => ({ role: r.role, parts: JSON.parse(r.content) }));
    } catch (_) { messages = []; }
  }

  async function persistMessage(role, parts) {
    if (!project?.id) return;
    try { await invoke("save_message", { projectId: project.id, role, content: JSON.stringify(parts) }); }
    catch (_) {}
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
    });
  });

  onDestroy(() => { unlistenChunk?.(); unlistenDone?.(); });

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

  function clearSession() {
    messages = [];
    pendingParts = [];
    sending = false;
    invoke("claude_clear_session").catch(() => {});
  }

  function handleKey(e) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  }

  async function scrollToBottom() {
    await tick();
    scrollEl?.scrollTo({ top: scrollEl.scrollHeight, behavior: "smooth" });
  }

  function onScroll() {
    if (!scrollEl) return;
    atBottom = (scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight) < 80;
  }

  function autosize(node) {
    function resize() {
      node.style.height = "22px";
      node.style.height = Math.min(node.scrollHeight, 140) + "px";
    }
    node.addEventListener("input", resize);
    resize();
    return { destroy() { node.removeEventListener("input", resize); } };
  }

  // Event delegation: copy buttons injected by renderMarkdown
  function codeCopy(node) {
    function onClick(e) {
      const btn = e.target.closest(".pl-copy-btn");
      if (!btn) return;
      const code = btn.closest(".pl-code-wrap")?.querySelector("code")?.textContent ?? "";
      navigator.clipboard.writeText(code).then(() => {
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = "Copy"; }, 1500);
      }).catch(() => {});
    }
    node.addEventListener("click", onClick);
    return { destroy() { node.removeEventListener("click", onClick); } };
  }

  // ── Markdown renderer ─────────────────────────────────────────────────────

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function renderInline(s) {
    let h = esc(s);
    h = h.replace(/`([^`\n]{1,400})`/g, '<code class="pl-ic">$1</code>');
    h = h.replace(/\*\*([^*\n]{1,300})\*\*/g, "<strong>$1</strong>");
    h = h.replace(/\*([^*\n]{1,300})\*/g, "<em>$1</em>");
    h = h.replace(/~~([^~\n]{1,300})~~/g, "<del>$1</del>");
    return h;
  }

  function renderTextBlock(raw) {
    const lines = raw.split("\n");
    const out = [];
    let inUl = false, inOl = false;
    const flush = () => {
      if (inUl) { out.push("</ul>"); inUl = false; }
      if (inOl) { out.push("</ol>"); inOl = false; }
    };
    for (const line of lines) {
      const h3 = line.match(/^### (.+)/);
      const h2 = line.match(/^## (.+)/);
      const h1 = line.match(/^# (.+)/);
      if (h3) { flush(); out.push(`<div class="pl-h3">${renderInline(h3[1])}</div>`); continue; }
      if (h2) { flush(); out.push(`<div class="pl-h2">${renderInline(h2[1])}</div>`); continue; }
      if (h1) { flush(); out.push(`<div class="pl-h1">${renderInline(h1[1])}</div>`); continue; }
      if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) { flush(); out.push('<div class="pl-hr"></div>'); continue; }
      if (/^> /.test(line)) { flush(); out.push(`<div class="pl-bq">${renderInline(line.slice(2))}</div>`); continue; }
      const ulM = line.match(/^[\-\*\+] (.*)/);
      if (ulM) {
        if (inOl) { out.push("</ol>"); inOl = false; }
        if (!inUl) { out.push('<ul class="pl-ul">'); inUl = true; }
        out.push(`<li>${renderInline(ulM[1])}</li>`);
        continue;
      }
      const olM = line.match(/^\d+[\.\)] (.*)/);
      if (olM) {
        if (inUl) { out.push("</ul>"); inUl = false; }
        if (!inOl) { out.push('<ol class="pl-ol">'); inOl = true; }
        out.push(`<li>${renderInline(olM[1])}</li>`);
        continue;
      }
      flush();
      if (!line.trim()) { out.push('<div class="pl-gap"></div>'); continue; }
      out.push(`<div class="pl-line">${renderInline(line)}</div>`);
    }
    flush();
    return out.join("");
  }

  function renderCodeBlock(lang, code) {
    const langTag = lang ? `<span class="pl-code-lang">${esc(lang)}</span>` : "<span></span>";
    return (
      `<div class="pl-code-wrap">` +
      `<div class="pl-code-head">${langTag}<button class="pl-copy-btn">Copy</button></div>` +
      `<pre class="pl-code-block"><code>${esc(code)}</code></pre>` +
      `</div>`
    );
  }

  const ACTION_PHRASE = "Let me know when you have completed these steps and I will continue.";

  function renderMarkdown(text) {
    if (!text) return "";
    let body = text;
    let hasAction = false;
    const aIdx = text.lastIndexOf(ACTION_PHRASE);
    if (aIdx !== -1) {
      body = text.slice(0, aIdx).trimEnd();
      hasAction = true;
    }
    const out = [];
    const re = /```(\w*)\n?([\s\S]*?)```/g;
    let last = 0, m;
    while ((m = re.exec(body)) !== null) {
      if (m.index > last) out.push(renderTextBlock(body.slice(last, m.index)));
      out.push(renderCodeBlock(m[1] || "", m[2].replace(/\n$/, "")));
      last = m.index + m[0].length;
    }
    if (last < body.length) out.push(renderTextBlock(body.slice(last)));
    if (hasAction) {
      out.push(
        `<div class="pl-action-req">` +
        `<span class="pl-action-icon">⚠</span>` +
        `<span>Manual action required — complete the steps above, then respond here.</span>` +
        `</div>`
      );
    }
    return out.join("");
  }

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

  <div class="pl-chat">
    <div class="pl-chat-head">
      <span class="pl-chat-title">{project.name}</span>
      <span class="pl-pill" style="border-color:{k?.color ?? '#8b949e'};color:{k?.color ?? '#8b949e'}">
        {k?.name ?? project.kind}
      </span>
      <div class="pl-head-right">
        {#if project.target}
          <span class="pl-target">{project.target}</span>
        {/if}
        <button class="pl-clear-btn" onclick={clearSession}>Clear</button>
      </div>
    </div>

    <div class="pl-session-strip">
      <span>{messages.length} {messages.length === 1 ? 'message' : 'messages'}</span>
      {#if sessionId}
        <span class="s-sep">·</span>
        <span class="s-id">sid:{sessionId.slice(-8)}</span>
      {/if}
    </div>

    <div class="pl-chat-body">
      <div class="pl-messages" bind:this={scrollEl} use:codeCopy onscroll={onScroll}>
        {#each messages as msg}
          {#if msg.role === "user"}
            {#each msg.parts as part}
              {#if part.kind === "text"}
                <div class="pl-msg">
                  <div class="pl-avatar user">U</div>
                  <div class="pl-msg-body">
                    <div class="pl-msg-author pl-author-user">You</div>
                    <div class="pl-user-bubble">{part.text}</div>
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
                    <div class="pl-msg-author pl-author-ai">Claude · Sonnet 4.6</div>
                    <div class="pl-msg-md">{@html renderMarkdown(part.text)}</div>
                  </div>
                </div>
              {:else if part.kind === "tool_use"}
                <div class="pl-msg pl-msg-tool">
                  <div class="pl-avatar tool">⚙</div>
                  <div class="pl-msg-body">
                    <div class="pl-msg-author pl-author-tool">tool</div>
                    <div class="pl-tool-call">
                      <div class="pl-tool-hd">
                        <span class="pl-tool-ps">$</span>
                        <span class="pl-tool-nm">{part.tool_name}</span>
                      </div>
                      {#if fmtArgs(part.tool_input)}
                        <div class="pl-tool-argv">{fmtArgs(part.tool_input)}</div>
                      {/if}
                    </div>
                  </div>
                </div>
              {:else if part.kind === "error"}
                <div class="pl-msg">
                  <div class="pl-avatar ai">C</div>
                  <div class="pl-msg-body">
                    <div class="pl-msg-author pl-author-err">error</div>
                    <div class="pl-msg-error">{part.text}</div>
                  </div>
                </div>
              {/if}
            {/each}
          {/if}
        {/each}

        {#if sending}
          {#if pendingParts.length > 0}
            {#each pendingParts as part}
              {#if part.kind === "text"}
                <div class="pl-msg">
                  <div class="pl-avatar ai">C</div>
                  <div class="pl-msg-body">
                    <div class="pl-msg-author pl-author-ai">Claude · Sonnet 4.6</div>
                    <div class="pl-msg-md">{@html renderMarkdown(part.text)}<span class="pl-cursor">▌</span></div>
                  </div>
                </div>
              {:else if part.kind === "tool_use"}
                <div class="pl-msg pl-msg-tool">
                  <div class="pl-avatar tool">⚙</div>
                  <div class="pl-msg-body">
                    <div class="pl-msg-author pl-author-tool">tool</div>
                    <div class="pl-tool-call pl-tool-live">
                      <div class="pl-tool-hd">
                        <span class="pl-tool-ps">$</span>
                        <span class="pl-tool-nm">{part.tool_name}</span>
                        <span class="pl-tool-running">running</span>
                      </div>
                      {#if fmtArgs(part.tool_input)}
                        <div class="pl-tool-argv">{fmtArgs(part.tool_input)}</div>
                      {/if}
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
                  <span class="pl-think-ps">›</span>
                  <span class="pl-think-text">processing</span>
                  <span class="pl-think-cursor">█</span>
                </div>
              </div>
            </div>
          {/if}
        {/if}
      </div>

      {#if !atBottom}
        <button class="pl-scroll-btn" onclick={scrollToBottom} aria-label="Scroll to bottom">↓</button>
      {/if}
    </div>

    <div class="pl-input-area">
      <div class="pl-input-wrap">
        <textarea
          class="pl-input"
          placeholder={sending ? "Claude is thinking…" : "Message the agent…"}
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
      <div class="pl-input-hint">Shift+Enter for newline</div>
    </div>
  </div>

{:else}
  <div class="pl-no-project">
    <div class="pl-empty-state">
      <div class="pl-empty-logo">
        <span class="pl-logo-bracket">[</span>
        <span class="pl-logo-text">PENLIGENT</span>
        <span class="pl-logo-bracket">]</span>
      </div>
      <div class="pl-empty-tag">autonomous penetration testing</div>
      <div class="pl-empty-hints">
        <div class="pl-hint-row">→ create an engagement in the sidebar to begin</div>
        <div class="pl-hint-row">→ connect vpn before targeting lab machines</div>
        <div class="pl-hint-row">→ findings and session history are stored per engagement</div>
      </div>
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

  /* ── Header ──────────────────────────────────────────────────── */

  .pl-chat-head {
    padding: 12px 18px;
    border-bottom: 1px solid #30363d;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
    background: #010409;
  }

  .pl-chat-title { font-size: 14px; font-weight: 500; color: #e6edf3; }

  .pl-pill {
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    border: 1px solid;
    background: transparent;
    font-weight: 500;
  }

  .pl-head-right {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .pl-target {
    font-family: "JetBrains Mono", monospace;
    color: #8b949e;
    font-size: 12px;
  }

  .pl-clear-btn {
    background: transparent;
    border: 1px solid #30363d;
    color: #6e7681;
    font-size: 11px;
    font-family: inherit;
    padding: 3px 10px;
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.1s, color 0.1s, border-color 0.1s;
  }
  .pl-clear-btn:hover { background: #1c2128; color: #c9d1d9; border-color: #8b949e; }

  /* ── Messages ─────────────────────────────────────────────────── */

  .pl-chat-body {
    flex: 1;
    position: relative;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .pl-messages {
    flex: 1;
    overflow-y: auto;
    padding: 20px 20px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .pl-msg { display: flex; gap: 11px; }

  .pl-avatar {
    width: 28px; height: 28px;
    border-radius: 5px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
    margin-top: 1px;
    letter-spacing: 0;
  }
  .pl-avatar.user { background: linear-gradient(135deg, #1f6feb, #388bfd); color: #fff; }
  .pl-avatar.ai   { background: #161b22; color: #adbac7; border: 1px solid #30363d; }
  .pl-avatar.tool { background: #060a0f; color: rgba(159,239,0,0.7); border: 1px solid rgba(159,239,0,0.2); font-size: 12px; }

  .pl-msg-body { flex: 1; min-width: 0; }

  .pl-msg-author {
    font-size: 11px;
    color: #6e7681;
    margin-bottom: 5px;
    font-weight: 500;
    letter-spacing: 0.01em;
  }
  .pl-author-user { color: #4d8ef0; }
  .pl-author-ai   { color: #adbac7; }
  .pl-author-tool { color: rgba(159,239,0,0.55); font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; }
  .pl-author-err  { color: #f85149; }

  .pl-user-bubble {
    font-size: 13px;
    line-height: 1.6;
    color: #c9d1d9;
    background: linear-gradient(135deg, rgba(31,111,235,0.1) 0%, rgba(31,111,235,0.04) 100%);
    border: 1px solid rgba(31,111,235,0.15);
    border-radius: 8px;
    padding: 10px 14px;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .pl-msg-md {
    font-size: 13px;
    line-height: 1.55;
    color: #c9d1d9;
    word-break: break-word;
  }

  /* ── Markdown elements (injected HTML) ───────────────────────── */

  :global(.pl-line) { display: block; line-height: 1.6; }
  :global(.pl-gap)  { height: 8px; display: block; }

  :global(.pl-h1) { display: block; font-size: 16px; font-weight: 600; color: #e6edf3; margin: 14px 0 6px; line-height: 1.3; }
  :global(.pl-h2) { display: block; font-size: 14px; font-weight: 600; color: #e6edf3; margin: 12px 0 5px; padding-bottom: 5px; border-bottom: 1px solid #21262d; line-height: 1.3; }
  :global(.pl-h3) { display: block; font-size: 13px; font-weight: 600; color: #e6edf3; margin: 10px 0 4px; line-height: 1.3; }

  :global(.pl-ul), :global(.pl-ol) { padding-left: 20px; margin: 4px 0; }
  :global(.pl-ul li), :global(.pl-ol li) { line-height: 1.6; color: #c9d1d9; margin: 2px 0; font-size: 13px; }
  :global(.pl-ul li::marker), :global(.pl-ol li::marker) { color: #484f58; }

  :global(.pl-hr) { display: block; border: none; border-top: 1px solid #30363d; margin: 10px 0; }

  :global(.pl-bq) {
    display: block;
    border-left: 3px solid #30363d;
    padding: 3px 12px;
    color: #8b949e;
    font-style: italic;
    margin: 6px 0;
  }

  :global(.pl-msg-md strong) { color: #e6edf3; font-weight: 600; }
  :global(.pl-msg-md em)     { font-style: italic; }
  :global(.pl-msg-md del)    { color: #6e7681; text-decoration: line-through; }

  /* Code block */
  :global(.pl-code-wrap) {
    margin: 10px 0;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid #21262d;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  }
  :global(.pl-code-head) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 12px;
    background: #0d1117;
    border-bottom: 1px solid #21262d;
  }
  :global(.pl-code-lang) {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10px;
    color: #6e7681;
    letter-spacing: 0.04em;
  }
  :global(.pl-copy-btn) {
    background: transparent;
    border: none;
    color: #484f58;
    font-size: 10px;
    font-family: inherit;
    cursor: pointer;
    padding: 0;
    transition: color 0.1s;
  }
  :global(.pl-copy-btn:hover) { color: #c9d1d9; }
  :global(.pl-code-wrap .pl-code-block) { margin: 0; border-radius: 0; border: none; }

  :global(.pl-code-block) {
    background: #060a0f;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 12px 14px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 12px;
    line-height: 1.55;
    overflow-x: auto;
    margin: 8px 0;
    color: #cdd9e5;
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

  /* ── Session strip ───────────────────────────────────────────── */

  .pl-session-strip {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 20px;
    background: #010409;
    border-bottom: 1px solid #161b22;
    font-size: 10px;
    color: #484f58;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    flex-shrink: 0;
    letter-spacing: 0.02em;
  }
  .s-sep { color: #30363d; }
  .s-id  { color: #484f58; }

  /* ── Tool call (terminal style) ──────────────────────────────── */

  .pl-tool-call {
    background: #060a0f;
    border: 1px solid #1c2128;
    border-left: 2px solid rgba(159,239,0,0.35);
    border-radius: 0 6px 6px 0;
    padding: 8px 12px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    line-height: 1.5;
  }
  .pl-tool-live {
    border-left-color: #9fef00;
    box-shadow: inset 3px 0 12px rgba(159,239,0,0.04);
  }

  .pl-tool-hd {
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .pl-tool-ps { color: #30363d; user-select: none; }
  .pl-tool-nm { color: #9fef00; font-weight: 600; }
  .pl-tool-running {
    margin-left: auto;
    font-size: 9px;
    color: rgba(159,239,0,0.6);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    animation: blink 1.5s step-end infinite;
  }
  .pl-tool-argv {
    color: #6e7681;
    margin-top: 4px;
    padding-left: 14px;
    word-break: break-all;
    line-height: 1.65;
    border-left: 1px solid #1c2128;
    margin-left: 2px;
  }

  /* ── Thinking / cursor ───────────────────────────────────────── */

  .pl-thinking {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 0;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
  }
  .pl-think-ps { color: #30363d; }
  .pl-think-text { color: #484f58; letter-spacing: 0.04em; }
  .pl-think-cursor {
    color: #388bfd;
    font-size: 10px;
    animation: blink 1s step-end infinite;
    opacity: 0.8;
  }

  :global(.pl-cursor) {
    display: inline;
    color: #388bfd;
    animation: blink 1s step-end infinite;
  }
  @keyframes blink { 50% { opacity: 0; } }

  /* ── Scroll button ───────────────────────────────────────────── */

  .pl-scroll-btn {
    position: absolute;
    bottom: 12px;
    right: 24px;
    width: 28px; height: 28px;
    border-radius: 50%;
    background: #21262d;
    border: 1px solid #30363d;
    color: #8b949e;
    font-size: 13px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    transition: background 0.1s, color 0.1s;
  }
  .pl-scroll-btn:hover { background: #30363d; color: #e6edf3; }

  /* ── Input ───────────────────────────────────────────────────── */

  .pl-input-area {
    padding: 10px 18px 8px;
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
  .pl-input-wrap:focus-within { border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.08); }

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

  .pl-input-hint {
    font-size: 10px;
    color: #21262d;
    text-align: right;
    margin-top: 4px;
    user-select: none;
  }


  /* ── Action required callout ─────────────────────────────────── */

  :global(.pl-action-req) {
    display: flex;
    align-items: flex-start;
    gap: 9px;
    background: rgba(210,153,34,0.07);
    border: 1px solid rgba(210,153,34,0.22);
    border-left: 3px solid #d29922;
    border-radius: 0 6px 6px 0;
    padding: 9px 12px;
    margin: 12px 0 4px;
    font-size: 12px;
    color: #d29922;
    line-height: 1.5;
  }
  :global(.pl-action-icon) { font-size: 13px; flex-shrink: 0; margin-top: 1px; }

  /* ── Empty state ─────────────────────────────────────────────── */

  .pl-no-project {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
      radial-gradient(ellipse 70% 45% at 50% 50%, rgba(88,166,255,0.035) 0%, transparent 70%),
      repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(88,166,255,0.018) 39px, rgba(88,166,255,0.018) 40px),
      repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(88,166,255,0.018) 39px, rgba(88,166,255,0.018) 40px),
      #0d1117;
  }

  .pl-empty-state { text-align: center; user-select: none; }

  .pl-empty-logo {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 0.18em;
    margin-bottom: 10px;
  }
  .pl-logo-bracket { color: rgba(88,166,255,0.3); }
  .pl-logo-text    { color: #30363d; }

  .pl-empty-tag {
    font-size: 10px;
    color: #21262d;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 30px;
  }

  .pl-empty-hints {
    display: flex;
    flex-direction: column;
    gap: 7px;
    align-items: flex-start;
    text-align: left;
  }

  .pl-hint-row {
    font-size: 11px;
    color: #30363d;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    letter-spacing: 0.02em;
  }
</style>
