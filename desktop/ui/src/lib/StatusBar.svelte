<script>
  let { vpnState, currentTool, sessionCost } = $props();

  const DOT_COLOR = {
    connected:    "#3fb950",
    connecting:   "#febc2e",
    disconnected: "#484f58",
    error:        "#f85149",
  };

  function vpnText(s) {
    if (s.status === "connected") {
      return s.tun_ip ? `VPN · tun0 · ${s.tun_ip}` : "VPN · connected";
    }
    if (s.status === "connecting") return "VPN · connecting…";
    if (s.status === "error")      return "VPN · error";
    return "VPN · off";
  }

  function fmtCost(usd) {
    if (!usd || usd < 0.00001) return null;
    if (usd < 0.01) return `$${(usd * 100).toFixed(3)}¢`;
    return `$${usd.toFixed(4)}`;
  }
</script>

<div class="pl-statusbar">
  <div class="pl-status-item">
    <span class="pl-dot" style="background:{DOT_COLOR[vpnState?.status] ?? '#484f58'}"></span>
    <span>{vpnText(vpnState ?? { status: "disconnected" })}</span>
  </div>

  {#if currentTool}
    <div class="pl-status-item pl-tool-item">
      <span class="pl-dot pulse" style="background:#9fef00"></span>
      <code>{currentTool}</code>
    </div>
  {/if}

  <div class="pl-status-item ml-auto">
    <span>Sonnet 4.6</span>
    {#if fmtCost(sessionCost)}
      <span class="sep">·</span>
      <code>{fmtCost(sessionCost)}</code>
    {/if}
  </div>
</div>

<style>
  .pl-statusbar {
    height: 26px;
    background: #010409;
    border-top: 1px solid #21262d;
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 16px;
    font-size: 11px;
    color: #6e7681;
    flex-shrink: 0;
  }

  .pl-status-item {
    display: flex;
    align-items: center;
    gap: 5px;
    white-space: nowrap;
  }

  .pl-tool-item { color: #c9d1d9; }

  .ml-auto { margin-left: auto; }
  .sep { color: #30363d; }

  .pl-dot {
    width: 5px; height: 5px;
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
