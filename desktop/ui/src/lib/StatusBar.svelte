<script>
  let { vpnState, currentTool, tokenCount, mcpStatus } = $props();

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

  function fmtTokens(n) {
    if (!n || n < 100) return null;
    return (n / 1000).toFixed(1) + "k";
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

  {#if currentTool}
    <div class="pl-status-item">
      <span class="pl-dot pulse" style="background:#9fef00"></span>
      <span>Tool:</span>
      <code>{currentTool}</code>
    </div>
  {/if}

  <div class="pl-status-item ml-auto">
    <span>Sonnet 4.6</span>
    {#if fmtTokens(tokenCount)}
      <span class="sep">·</span>
      <code>{fmtTokens(tokenCount)}</code>
      <span>tokens</span>
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
</style>
