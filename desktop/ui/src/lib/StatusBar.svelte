<script>
  let { vpnState, currentTool, currentModel, turnUsage, sessionUsage, mcpStatus, htbMcpStatus } = $props();

  // Translate a Claude Code model id ("claude-sonnet-4-5-20250929") into a
  // short, friendly label ("Sonnet 4.5"). Falls back to the raw id for
  // anything we don't recognise so a new family release still shows
  // something sensible instead of being hidden.
  function fmtModel(id) {
    if (!id || typeof id !== "string") return "Claude · waiting…";
    // claude-(opus|sonnet|haiku)-X-Y[-N]-YYYYMMDD or shorter id forms
    const m = id.match(/^claude-(opus|sonnet|haiku)-(\d+)(?:[-.](\d+))?/i);
    if (!m) return id;
    const family = m[1][0].toUpperCase() + m[1].slice(1);
    const major  = m[2];
    const minor  = m[3] ?? "0";
    return `${family} ${major}.${minor}`;
  }

  const DOT_COLOR = {
    connected:    "#3fb950",
    connecting:   "#febc2e",
    disconnected: "#484f58",
    error:        "#f85149",
  };

  const MCP_DOT = {
    ok:       "#3fb950",
    checking: "#febc2e",
    error:    "#f85149",
  };

  function vpnText(s) {
    if (s.status === "connected") {
      return s.tun_ip ? `VPN · tun0 · ${s.tun_ip}` : "VPN · connected";
    }
    if (s.status === "connecting") return "VPN · connecting…";
    if (s.status === "error")      return "VPN · error";
    return "VPN · off";
  }

  // Format a token count compactly: 0 → null (hide), <1k → raw, ≥1k → "X.Yk"
  function fmtTokens(n) {
    if (!n) return null;
    if (n < 1000) return String(n);
    return (n / 1000).toFixed(1) + "k";
  }

  function fmtCost(c) {
    if (!c) return null;
    if (c < 0.001) return `$${c.toFixed(4)}`;
    if (c < 0.01)  return `$${c.toFixed(4)}`;
    if (c < 1)     return `$${c.toFixed(3)}`;
    return `$${c.toFixed(2)}`;
  }

  function mcpLabel(s) {
    if (!s || s.state === "checking") return "MCP · …";
    if (s.state === "ok") return s.tool_count ? `MCP · ${s.tool_count} tools` : "MCP · ok";
    return "MCP · error";
  }

  function mcpDotColor(s) {
    if (!s || s.state === "checking") return MCP_DOT.checking;
    return s.state === "ok" ? MCP_DOT.ok : MCP_DOT.error;
  }

  // HTB MCP indicator. Only renders when the user has actually configured a
  // token (state !== "no_token") so a non-HTB user doesn't see a chip they
  // can't act on. "missing" = token saved but registration absent → agent
  // can't reach the HTB tool surface, and App.svelte halts any running turn.
  function htbLabel(s) {
    if (!s || s.state === "checking") return "HTB · …";
    if (s.state === "ok")             return "HTB MCP · ok";
    if (s.state === "missing")        return "HTB MCP · not registered";
    return "HTB MCP · error";
  }
  function htbDotColor(s) {
    if (!s || s.state === "checking") return MCP_DOT.checking;
    return s.state === "ok" ? MCP_DOT.ok : MCP_DOT.error;
  }

  // Derived display fields. `turnUsage` / `sessionUsage` always exist (defaulted
  // by App.svelte) but may be all-zero before the first turn completes.
  let turn    = $derived(turnUsage    ?? {});
  let session = $derived(sessionUsage ?? {});
  let hasTurn = $derived(!!(turn.input || turn.output || turn.cache_read));
</script>

<div class="pl-statusbar">
  <div class="pl-status-item">
    <span class="pl-dot" style="background:{DOT_COLOR[vpnState?.status] ?? '#484f58'}"></span>
    <span>{vpnText(vpnState ?? { status: "disconnected" })}</span>
  </div>

  <div class="pl-status-item" title={mcpStatus?.error ?? ""}>
    <span class="pl-dot" class:pulse={mcpStatus?.state === "checking"} style="background:{mcpDotColor(mcpStatus)}"></span>
    <span>{mcpLabel(mcpStatus)}</span>
  </div>

  {#if htbMcpStatus && htbMcpStatus.state !== "no_token"}
    <div class="pl-status-item" title={htbMcpStatus?.error ?? ""}>
      <span class="pl-dot" class:pulse={htbMcpStatus?.state === "checking"} style="background:{htbDotColor(htbMcpStatus)}"></span>
      <span>{htbLabel(htbMcpStatus)}</span>
    </div>
  {/if}

  {#if currentTool}
    <div class="pl-status-item">
      <span class="pl-dot pulse" style="background:#9fef00"></span>
      <span>Tool:</span>
      <code>{currentTool}</code>
    </div>
  {/if}

  <div class="pl-status-item ml-auto"
       title={hasTurn
         ? `Model: ${currentModel ?? "(unknown)"}\nTurn — in ${turn.input ?? 0}, out ${turn.output ?? 0}, cache-read ${turn.cache_read ?? 0}, cache-create ${turn.cache_creation ?? 0}\nSession — in ${session.input ?? 0}, out ${session.output ?? 0}, cache-read ${session.cache_read ?? 0}, cost ${fmtCost(session.cost_usd) ?? '$0'}`
         : (currentModel ?? "Model detected on first turn")}>
    <span>{fmtModel(currentModel)}</span>
    {#if hasTurn}
      <span class="sep">·</span>
      <span>turn</span>
      <code>{fmtTokens(turn.input + turn.output) ?? "0"}</code>
      {#if turn.cache_read}
        <span class="sep">·</span>
        <span class="cache">cache</span>
        <code class="cache">{fmtTokens(turn.cache_read)}</code>
      {/if}
      {#if fmtCost(turn.cost_usd)}
        <span class="sep">·</span>
        <code>{fmtCost(turn.cost_usd)}</code>
      {/if}
      <span class="sep">·</span>
      <span>session</span>
      <code>{fmtTokens(session.input + session.output) ?? "0"}</code>
      {#if fmtCost(session.cost_usd)}
        <span class="sep">·</span>
        <code>{fmtCost(session.cost_usd)}</code>
      {/if}
    {/if}
  </div>
</div>

<style>
  .pl-statusbar {
    height: 28px;
    background: #010409;
    border-top: 1px solid #30363d;
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 18px;
    font-size: 11px;
    color: #8b949e;
    flex-shrink: 0;
  }

  .pl-status-item {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }

  .ml-auto { margin-left: auto; }
  .sep { color: #30363d; }

  .pl-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
  }
  .pulse { animation: pulse 1.4s ease-in-out infinite; }

  code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #c9d1d9;
    font-size: 11px;
  }

  /* cache hits are wins — visually distinct from regular tokens */
  .cache       { color: #9fef00; }
  code.cache   { color: #9fef00; }
</style>
