<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { homeDir } from "@tauri-apps/api/path";

  let { vpnState, active = true } = $props();

  let htbToken        = $state("");
  let htbTokenVisible = $state(false);
  let htbTokenStatus  = $state(""); // "" | "saving" | "ok" | error string

  let ovpnPath      = $state("");
  let ovpnName      = $state("");
  let ovpnKind      = $state("");
  let ovpnRegion    = $state("");
  let vpnError      = $state("");
  let connecting    = $state(false);
  let vpnProfiles   = $state([]);
  let profileSaved  = $state(false);
  let autoReconnect = $state(false);

  let claudeVersion        = $state("");
  let claudeVersionLoading = $state(true);
  let claudeInstalling     = $state(false);
  let claudeInstallErr     = $state("");
  let toolCount            = $state(null);
  let toolCountLoading     = $state(false);

  // Diagnostics — reflects backend run_diagnostics(). Each item carries a
  // `fix` action id; the UI maps it to a Tauri invoke. Stays in sync via the
  // Settings-tab-activate $effect below.
  let diagItems    = $state([]);
  let diagLoading  = $state(false);
  let diagFixBusy  = $state(null);  // id of the item currently being repaired
  let diagFixErr   = $state("");

  let uiZoom = $state(1.0);

  // Refresh detection state every time the user navigates to Settings.
  // The Claude binary, MCP venv, or VPN profile list can change while the
  // app is open (user installs claude, edits ~/.claude/settings.json, etc.)
  // so a stale onMount-only read leaves "not found" stuck until restart.
  let mountedOnce = false;
  $effect(() => {
    if (!active) return;
    if (!mountedOnce) { mountedOnce = true; return; }
    fetchClaudeVersion();
    fetchToolCount();
    loadProfiles().then(autoLoadDefaultProfile);
    runDiagnostics();
  });

  function applyZoom(z) {
    document.documentElement.style.zoom = z;
  }

  async function saveZoom(z) {
    uiZoom = z;
    applyZoom(z);
    try { await invoke("save_config_value", { key: "ui_zoom", value: String(z) }); } catch (_) {}
  }

  onMount(async () => {
    try {
      const t = await invoke("load_config_value", { key: "htb_app_token" });
      if (t) htbToken = t;
    } catch (_) {}
    try {
      const ar = await invoke("load_config_value", { key: "vpn_auto_reconnect" });
      autoReconnect = ar === "true";
      if (autoReconnect) await invoke("vpn_set_auto_reconnect", { enabled: true });
    } catch (_) {}
    try {
      const z = await invoke("load_config_value", { key: "ui_zoom" });
      if (z) uiZoom = parseFloat(z);
    } catch (_) {}
    await loadProfiles();
    fetchClaudeVersion();
    fetchToolCount();
    autoLoadDefaultProfile();
    runDiagnostics();
  });

  async function runDiagnostics() {
    diagLoading = true;
    try { diagItems = await invoke("run_diagnostics"); }
    catch (e) { diagItems = []; diagFixErr = String(e); }
    finally { diagLoading = false; }
  }

  async function applyFix(item) {
    if (!item.fix || diagFixBusy) return;
    diagFixBusy = item.id;
    diagFixErr = "";
    try {
      if (item.fix === "install_claude") {
        await invoke("install_claude_code");
        await invoke("register_local_mcp_server").catch(() => {});
        await fetchClaudeVersion();
      } else if (item.fix === "register_local_mcp") {
        await invoke("register_local_mcp_server");
      } else if (item.fix === "register_htb_mcp") {
        if (!htbToken.trim()) throw new Error("No HTB token saved. Save one under HackTheBox first.");
        await invoke("register_htb_mcp_server", { token: htbToken.trim() });
      } else if (item.fix === "install_sudoers") {
        await invoke("install_sudoers_rule");
      } else {
        throw new Error(`Unknown fix action: ${item.fix}`);
      }
      await runDiagnostics();
    } catch (e) {
      diagFixErr = `${item.name}: ${e}`;
    } finally {
      diagFixBusy = null;
    }
  }

  async function fetchClaudeVersion() {
    claudeVersionLoading = true;
    try { claudeVersion = await invoke("get_claude_version"); }
    catch (_) { claudeVersion = ""; }
    finally { claudeVersionLoading = false; }
  }

  // One-click Claude Code installer. The .deb intentionally doesn't bundle
  // Claude (it's third-party + needs an Anthropic account), so when detection
  // fails we let the user install it from here. After install we re-register
  // the local Penlearn MCP server because the installer rewrites settings.json.
  async function installClaude() {
    if (claudeInstalling) return;
    claudeInstalling = true;
    claudeInstallErr = "";
    try {
      await invoke("install_claude_code");
      await invoke("register_local_mcp_server").catch(() => {});
      await fetchClaudeVersion();
    } catch (e) {
      claudeInstallErr = String(e);
    } finally {
      claudeInstalling = false;
    }
  }

  // First-launch UX: the wizard saves the .ovpn but doesn't connect. Without
  // this, the user lands in Settings with an empty path field and a disabled
  // Connect button — they have to click the saved profile row to populate it.
  // Auto-loading the default (or only) profile makes Connect immediately usable.
  function autoLoadDefaultProfile() {
    if (ovpnPath || vpnState?.status === "connected") return;
    const def = vpnProfiles.find(p => p.is_default) ?? (vpnProfiles.length === 1 ? vpnProfiles[0] : null);
    if (def) loadProfile(def);
  }

  async function fetchToolCount() {
    toolCountLoading = true;
    try { toolCount = await invoke("count_mcp_tools"); }
    catch (_) { toolCount = null; }
    finally { toolCountLoading = false; }
  }

  async function loadProfiles() {
    try { vpnProfiles = await invoke("list_vpn_profiles"); }
    catch (_) { vpnProfiles = []; }
  }

  async function saveToken() {
    if (!htbToken.trim()) return;
    htbTokenStatus = "saving";
    try {
      await invoke("save_config_value", { key: "htb_app_token", value: htbToken.trim() });
      await invoke("save_config_value", { key: "htb_mcp_token", value: htbToken.trim() });
      await invoke("register_htb_mcp_server", { token: htbToken.trim() });
      htbTokenStatus = "ok";
      setTimeout(() => { htbTokenStatus = ""; }, 3000);
    } catch (e) {
      htbTokenStatus = String(e);
      setTimeout(() => { htbTokenStatus = ""; }, 5000);
    }
  }

  async function saveProfile() {
    if (!ovpnPath) return;
    const name = ovpnName.trim() || ovpnPath.split("/").pop().replace(".ovpn", "");
    try {
      await invoke("save_vpn_profile", {
        name, ovpnPath,
        kind: ovpnKind || "",
        region: ovpnRegion.trim() || null,
      });
      profileSaved = true;
      setTimeout(() => { profileSaved = false; }, 2000);
      await loadProfiles();
    } catch (e) { vpnError = String(e); }
  }

  async function removeProfile(id) {
    try { await invoke("delete_vpn_profile", { id }); await loadProfiles(); }
    catch (_) {}
  }

  async function setDefaultProfile(id) {
    try { await invoke("set_default_vpn_profile", { id }); await loadProfiles(); }
    catch (_) {}
  }

  function loadProfile(p) {
    ovpnPath = p.ovpn_path;
    ovpnName = p.name;
    ovpnKind = p.kind || "";
    ovpnRegion = p.region || "";
  }

  async function toggleAutoReconnect() {
    autoReconnect = !autoReconnect;
    await invoke("save_config_value", { key: "vpn_auto_reconnect", value: String(autoReconnect) });
    await invoke("vpn_set_auto_reconnect", { enabled: autoReconnect });
  }

  async function browseOvpn() {
    const home = await homeDir();
    const path = await open({
      title: "Select .ovpn file",
      filters: [{ name: "OpenVPN Config", extensions: ["ovpn"] }],
      defaultPath: `${home}/Downloads`,
    });
    if (path) ovpnPath = path;
  }

  async function connectVpn() {
    if (!ovpnPath) return;
    connecting = true; vpnError = "";
    try {
      const profileName = ovpnName.trim() || ovpnPath.split("/").pop().replace(".ovpn", "");
      await invoke("vpn_connect", { ovpnPath, profileName });
    } catch (e) { vpnError = String(e); }
    finally { connecting = false; }
  }

  async function disconnectVpn() {
    vpnError = "";
    try { await invoke("vpn_disconnect"); }
    catch (e) { vpnError = String(e); }
  }
</script>

<div class="pl-settings">

  <!-- HackTheBox -->
  <section class="pl-section">
    <div class="pl-section-head">
      <h3>HackTheBox</h3>
      <span class="pl-section-sub">REST API + CTF MCP server</span>
    </div>

    <div class="pl-field">
      <div class="pl-field-header">
        <span class="pl-label">API Token</span>
        {#if htbTokenStatus === 'ok'}
          <span class="pl-badge pl-badge-ok">● registered</span>
        {:else if htbTokenStatus === 'saving'}
          <span class="pl-badge pl-badge-dim">saving…</span>
        {:else if htbToken && !htbTokenStatus}
          <span class="pl-badge pl-badge-dim">● saved</span>
        {/if}
      </div>
      <span class="pl-hint">HTB profile → Settings → API → create app token. Used for REST API and MCP server authentication.</span>
      <div class="pl-row">
        <div class="pl-input-wrap">
          <input
            class="pl-input pl-input-mono"
            type={htbTokenVisible ? "text" : "password"}
            placeholder="eyJ0eXAi…"
            bind:value={htbToken}
            onkeydown={(e) => e.key === 'Enter' && saveToken()}
          />
          <button class="pl-eye" onclick={() => htbTokenVisible = !htbTokenVisible}
            title={htbTokenVisible ? "Hide" : "Show"}>
            {htbTokenVisible ? "◉" : "○"}
          </button>
        </div>
        <button class="pl-btn pl-btn-primary" onclick={saveToken}
          disabled={!htbToken.trim() || htbTokenStatus === 'saving'}>
          {htbTokenStatus === 'saving' ? 'Saving…' : htbTokenStatus === 'ok' ? 'Saved ✓' : 'Save & Register'}
        </button>
      </div>
      {#if htbTokenStatus && htbTokenStatus !== 'saving' && htbTokenStatus !== 'ok'}
        <span class="pl-field-err">{htbTokenStatus}</span>
      {/if}
    </div>
  </section>

  <!-- OpenVPN -->
  <section class="pl-section">
    <div class="pl-section-head">
      <h3>OpenVPN</h3>
      <span class="pl-section-sub">One active tunnel at a time</span>
    </div>

    <div class="pl-field">
      <span class="pl-label">Add profile</span>
      <div class="pl-row">
        <!-- U5: was readonly — paste didn't work. Now editable alongside Browse. -->
        <input class="pl-input pl-input-mono" bind:value={ovpnPath} placeholder="Select or paste .ovpn path…" spellcheck="false" style="flex:1" />
        <button class="pl-btn" onclick={browseOvpn}>Browse</button>
        <button class="pl-btn pl-btn-primary" onclick={saveProfile} disabled={!ovpnPath}>
          {profileSaved ? "Saved ✓" : "Save"}
        </button>
      </div>
    </div>

    {#if vpnProfiles.length > 0}
      <div class="pl-field">
        <span class="pl-label">Saved profiles</span>
        <div class="pl-profiles">
          {#each vpnProfiles as p (p.id)}
            <div class="pl-profile-row" class:is-default={p.is_default}>
              <button class="pl-profile-load" onclick={() => loadProfile(p)}>
                {#if p.is_default}<span class="pl-default-star">★</span>{/if}
                <span class="pl-profile-name">{p.name}</span>
                {#if p.kind}<span class="pl-profile-tag">{p.kind.replace(/_/g, ' ')}</span>{/if}
                {#if p.region}<span class="pl-profile-region">{p.region}</span>{/if}
              </button>
              <button class="pl-profile-star" onclick={() => setDefaultProfile(p.id)} title="Set default">☆</button>
              <button class="pl-profile-del" onclick={() => removeProfile(p.id)} title="Delete">✕</button>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <div class="pl-field">
      <div class="pl-row" style="gap:10px">
        <span class="pl-label">Auto-reconnect on drop</span>
        <button class="pl-toggle" class:on={autoReconnect} onclick={toggleAutoReconnect}
          aria-label="Toggle auto-reconnect" style="margin-left:auto">
          <span class="pl-toggle-knob"></span>
        </button>
        <span class="pl-toggle-label">{autoReconnect ? 'On' : 'Off'}</span>
      </div>
    </div>

    <div class="pl-vpn-bar">
      {#if vpnState?.status === "connected"}
        <span class="pl-vpn-dot pl-vpn-on"></span>
        <span class="pl-vpn-label">{vpnState.profile_name ?? "Connected"} · <code>{vpnState.tun_ip ?? "—"}</code></span>
        <button class="pl-btn pl-btn-danger" onclick={disconnectVpn} style="margin-left:auto">Disconnect</button>
      {:else if vpnState?.status === "connecting"}
        <span class="pl-vpn-dot pl-vpn-pending"></span>
        <span class="pl-vpn-label">Connecting…</span>
      {:else}
        <span class="pl-vpn-dot pl-vpn-off"></span>
        <span class="pl-vpn-label">Not connected</span>
        <button class="pl-btn pl-btn-primary" onclick={connectVpn}
          disabled={connecting || !ovpnPath} style="margin-left:auto">
          {connecting ? "Connecting…" : "Connect"}
        </button>
      {/if}
      {#if vpnError}<span class="pl-field-err">{vpnError}</span>{/if}
    </div>
  </section>

  <!-- Appearance -->
  <section class="pl-section">
    <div class="pl-section-head">
      <h3>Appearance</h3>
      <span class="pl-section-sub">Display scaling</span>
    </div>

    <div class="pl-field">
      <div class="pl-field-header">
        <span class="pl-label">Text size</span>
        <span class="pl-zoom-pct">{Math.round(uiZoom * 100)}%</span>
      </div>
      <div class="pl-zoom-row">
        <span class="pl-zoom-hint">A</span>
        <input
          class="pl-zoom-slider"
          type="range"
          min="0.7"
          max="1.5"
          step="0.05"
          value={uiZoom}
          oninput={(e) => saveZoom(parseFloat(e.target.value))}
        />
        <span class="pl-zoom-hint" style="font-size:16px">A</span>
        <button class="pl-btn" onclick={() => saveZoom(1.0)} title="Reset to default">Reset</button>
      </div>
    </div>
  </section>

  <!-- Agent Runtime -->
  <section class="pl-section">
    <div class="pl-section-head">
      <h3>Agent Runtime</h3>
      <span class="pl-section-sub">Local-only · no cloud except Anthropic</span>
    </div>

    <div class="pl-runtime-grid">
      <div class="pl-rt-row">
        <span class="pl-rt-label">Claude Code</span>
        <code class="pl-rt-path">~/.local/bin/claude</code>
        <span class="pl-rt-right">
          {#if claudeInstalling}
            <span class="pl-rt-dim">installing…</span>
          {:else if claudeVersionLoading}
            <span class="pl-rt-dim">checking…</span>
          {:else if claudeVersion}
            <span class="pl-rt-ok">{claudeVersion}</span>
          {:else}
            <span class="pl-rt-warn">not found</span>
            <button class="pl-rt-install" onclick={installClaude} disabled={claudeInstalling} title="curl -fsSL https://claude.ai/install.sh | bash">
              Install
            </button>
          {/if}
          <button class="pl-rt-refresh" onclick={fetchClaudeVersion} disabled={claudeVersionLoading || claudeInstalling} title="Re-check">
            {claudeVersionLoading ? "…" : "↻"}
          </button>
        </span>
      </div>
      {#if claudeInstallErr}
        <pre class="pl-rt-err">{claudeInstallErr}</pre>
      {/if}

      <div class="pl-rt-row">
        <span class="pl-rt-label">MCP tools</span>
        <code class="pl-rt-path">penlearn_mcp</code>
        <span class="pl-rt-right">
          {#if toolCountLoading}
            <span class="pl-rt-dim">scanning…</span>
          {:else if toolCount !== null}
            <span class="pl-rt-ok">{toolCount} tools registered</span>
          {:else}
            <span class="pl-rt-warn">—</span>
          {/if}
          <button class="pl-rt-refresh" onclick={fetchToolCount} disabled={toolCountLoading} title="Rescan tools">
            {toolCountLoading ? "…" : "↻"}
          </button>
        </span>
      </div>

      <div class="pl-rt-row">
        <span class="pl-rt-label">Data dir</span>
        <code class="pl-rt-path">~/.local/share/penlearn-local</code>
        <span class="pl-rt-right pl-rt-ok">✓</span>
      </div>

      <div class="pl-rt-row">
        <span class="pl-rt-label">Sudoers rule</span>
        <code class="pl-rt-path">/etc/sudoers.d/penlearn-openvpn</code>
        <span class="pl-rt-right pl-rt-ok">✓ openvpn only</span>
      </div>
    </div>
  </section>

  <!-- Diagnostics -->
  <section class="pl-section">
    <div class="pl-section-head">
      <h3>Diagnostics</h3>
      <span class="pl-section-sub">Live checks · Fix repairs the failing item in place</span>
    </div>

    <div class="pl-diag-bar">
      <button class="pl-btn pl-btn-primary" onclick={runDiagnostics} disabled={diagLoading}>
        {diagLoading ? "Running…" : "Run all checks"}
      </button>
      {#if diagItems.length > 0}
        {@const failing = diagItems.filter(d => !d.ok).length}
        {#if failing === 0}
          <span class="pl-diag-summary pl-diag-ok">All {diagItems.length} checks pass</span>
        {:else}
          <span class="pl-diag-summary pl-diag-bad">{failing} of {diagItems.length} failing</span>
        {/if}
      {/if}
    </div>

    {#if diagFixErr}
      <pre class="pl-rt-err" style="margin-left:0">{diagFixErr}</pre>
    {/if}

    <div class="pl-diag-list">
      {#each diagItems as it (it.id)}
        <div class="pl-diag-row" class:pl-diag-row-bad={!it.ok}>
          <span class="pl-diag-status">{it.ok ? "✓" : "✗"}</span>
          <div class="pl-diag-body">
            <div class="pl-diag-name">{it.name}</div>
            <div class="pl-diag-hint">{it.hint}</div>
          </div>
          {#if !it.ok && it.fix}
            <button class="pl-rt-install" onclick={() => applyFix(it)} disabled={diagFixBusy === it.id}>
              {diagFixBusy === it.id ? "Fixing…" : "Fix"}
            </button>
          {/if}
        </div>
      {/each}
      {#if diagItems.length === 0 && !diagLoading}
        <div class="pl-diag-empty">No diagnostics yet — click "Run all checks".</div>
      {/if}
    </div>
  </section>

</div>

<style>
  .pl-settings {
    padding: 20px 28px;
    overflow-y: auto;
    flex: 1;
    max-width: 660px;
  }

  .pl-section {
    padding: 18px 0;
    border-bottom: 1px solid #21262d;
  }
  .pl-section:last-child { border-bottom: none; }

  .pl-section-head {
    display: flex;
    align-items: baseline;
    gap: 10px;
    margin-bottom: 14px;
  }
  .pl-section-head h3 {
    font-size: 13px;
    color: #e6edf3;
    font-weight: 600;
    margin: 0;
    letter-spacing: 0.01em;
    border-left: 2px solid #30363d;
    padding-left: 10px;
  }
  .pl-section-sub {
    font-size: 11px;
    color: #484f58;
  }

  .pl-field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin-bottom: 14px;
  }
  .pl-field:last-child { margin-bottom: 0; }

  .pl-field-header {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pl-label { font-size: 12px; color: #c9d1d9; font-weight: 500; }
  .pl-hint  { font-size: 11px; color: #6e7681; line-height: 1.5; }

  .pl-badge {
    font-size: 10px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 10px;
    letter-spacing: 0.04em;
  }
  .pl-badge-ok  { background: rgba(63,185,80,0.12); color: #3fb950; border: 1px solid rgba(63,185,80,0.25); }
  .pl-badge-dim { background: rgba(139,148,158,0.1); color: #8b949e; border: 1px solid #30363d; }

  .pl-row {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .pl-input-wrap {
    position: relative;
    flex: 1;
  }
  .pl-input-wrap .pl-input { width: 100%; padding-right: 30px; }

  .pl-eye {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: #484f58;
    cursor: pointer;
    font-size: 12px;
    padding: 0;
    line-height: 1;
  }
  .pl-eye:hover { color: #8b949e; }

  .pl-input {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 5px;
    color: #c9d1d9;
    padding: 7px 10px;
    font-size: 12px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.12s;
    box-sizing: border-box;
  }
  .pl-input:focus { border-color: #58a6ff; }
  .pl-input[readonly] { cursor: default; color: #8b949e; }
  .pl-input-mono { font-family: "JetBrains Mono", ui-monospace, monospace; }


  .pl-field-err { font-size: 11px; color: #f85149; margin-top: 2px; }

  .pl-btn {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 6px 14px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    font-weight: 500;
    white-space: nowrap;
    transition: background 0.12s;
  }
  .pl-btn:hover:not(:disabled) { background: #30363d; }
  .pl-btn:disabled { opacity: 0.45; cursor: default; }
  .pl-btn-primary { background: #238636; border-color: #238636; color: #fff; }
  .pl-btn-primary:hover:not(:disabled) { background: #2ea043; border-color: #2ea043; }
  .pl-btn-danger { background: transparent; border-color: #f85149; color: #f85149; }
  .pl-btn-danger:hover:not(:disabled) { background: rgba(248,81,73,0.1); }

  .pl-profiles {
    display: flex;
    flex-direction: column;
    gap: 3px;
    margin-top: 4px;
  }
  .pl-profile-row {
    display: flex;
    align-items: center;
    gap: 4px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 4px 6px;
  }
  .pl-profile-row.is-default { border-color: #388bfd; }
  .pl-profile-load {
    flex: 1;
    background: none;
    border: none;
    color: #c9d1d9;
    font-size: 12px;
    font-family: inherit;
    text-align: left;
    cursor: pointer;
    padding: 2px 4px;
    border-radius: 3px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .pl-profile-load:hover { background: #21262d; }
  .pl-default-star { color: #388bfd; font-size: 11px; }
  .pl-profile-name { font-weight: 500; }
  .pl-profile-tag {
    font-size: 10px; color: #8b949e;
    border: 1px solid #30363d; border-radius: 3px;
    padding: 0 5px; text-transform: capitalize;
  }
  .pl-profile-region {
    font-size: 10px; color: #6e7681;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  .pl-profile-star, .pl-profile-del {
    background: none; border: none;
    color: #484f58; cursor: pointer;
    font-size: 12px; padding: 2px 5px;
    border-radius: 3px; font-family: inherit; line-height: 1;
  }
  .pl-profile-star:hover { color: #388bfd; }
  .pl-profile-del:hover { color: #f85149; }

  .pl-toggle {
    width: 36px; height: 20px;
    background: #21262d; border: 1px solid #30363d;
    border-radius: 10px; cursor: pointer; padding: 0;
    position: relative; flex-shrink: 0;
    transition: background 0.15s, border-color 0.15s;
  }
  .pl-toggle.on { background: #238636; border-color: #238636; }
  .pl-toggle-knob {
    position: absolute;
    top: 2px; left: 2px;
    width: 14px; height: 14px;
    background: #8b949e; border-radius: 50%;
    transition: left 0.15s, background 0.15s;
  }
  .pl-toggle.on .pl-toggle-knob { left: 18px; background: #fff; }
  .pl-toggle-label { font-size: 11px; color: #6e7681; }
  .pl-toggle.on + .pl-toggle-label { color: #3fb950; }

  .pl-vpn-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-top: 4px;
  }
  .pl-vpn-dot {
    width: 7px; height: 7px;
    border-radius: 50%; flex-shrink: 0;
  }
  .pl-vpn-on      { background: #3fb950; box-shadow: 0 0 5px rgba(63,185,80,0.5); }
  .pl-vpn-pending { background: #febc2e; }
  .pl-vpn-off     { background: #484f58; }
  .pl-vpn-label   { font-size: 12px; color: #c9d1d9; }
  .pl-vpn-label code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px; color: #9fef00;
  }

  .pl-runtime-grid {
    display: flex;
    flex-direction: column;
    gap: 1px;
    border: 1px solid #21262d;
    border-radius: 6px;
    overflow: hidden;
  }
  .pl-rt-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    background: #0d1117;
    border-bottom: 1px solid #21262d;
  }
  .pl-rt-row:last-child { border-bottom: none; }
  .pl-rt-label {
    font-size: 11px;
    color: #6e7681;
    font-weight: 500;
    width: 90px;
    flex-shrink: 0;
  }
  .pl-rt-path {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 11px;
    color: #484f58;
    flex: 1;
  }
  .pl-rt-right {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    min-width: 140px;
    justify-content: flex-end;
  }
  .pl-rt-ok   { font-size: 11px; color: #3fb950; font-weight: 500; }
  .pl-rt-warn { font-size: 11px; color: #d29922; }
  .pl-rt-dim  { font-size: 11px; color: #484f58; }
  .pl-rt-refresh {
    background: none;
    border: 1px solid #30363d;
    color: #6e7681;
    cursor: pointer;
    font-size: 12px;
    padding: 1px 6px;
    border-radius: 3px;
    line-height: 1.4;
    font-family: inherit;
    transition: color 0.1s, border-color 0.1s;
  }
  .pl-rt-refresh:hover:not(:disabled) { color: #58a6ff; border-color: #58a6ff; }
  .pl-rt-refresh:disabled { opacity: 0.4; cursor: default; }
  .pl-rt-install {
    background: #1f6feb;
    border: 1px solid #388bfd;
    color: #fff;
    cursor: pointer;
    font-size: 11px;
    font-weight: 500;
    padding: 2px 8px;
    border-radius: 3px;
    line-height: 1.4;
    font-family: inherit;
  }
  .pl-rt-install:hover:not(:disabled) { background: #388bfd; }
  .pl-rt-install:disabled { opacity: 0.5; cursor: default; }
  .pl-rt-err {
    margin: 6px 0 0 142px;
    padding: 6px 8px;
    background: #2d1417;
    color: #f85149;
    border: 1px solid #5a2a2f;
    border-radius: 4px;
    font-size: 11px;
    white-space: pre-wrap;
    max-height: 120px;
    overflow: auto;
  }

  .pl-diag-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }
  .pl-diag-summary {
    font-size: 11px;
    font-weight: 500;
  }
  .pl-diag-ok  { color: #3fb950; }
  .pl-diag-bad { color: #f85149; }
  .pl-diag-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 6px;
  }
  .pl-diag-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 10px;
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 4px;
  }
  .pl-diag-row-bad {
    border-left: 3px solid #f85149;
  }
  .pl-diag-status {
    font-size: 14px;
    font-weight: 700;
    color: #3fb950;
    width: 14px;
    flex-shrink: 0;
  }
  .pl-diag-row-bad .pl-diag-status { color: #f85149; }
  .pl-diag-body { flex: 1; min-width: 0; }
  .pl-diag-name {
    font-size: 12px;
    color: #c9d1d9;
    font-weight: 500;
  }
  .pl-diag-hint {
    font-size: 11px;
    color: #6e7681;
    margin-top: 2px;
    word-break: break-word;
  }
  .pl-diag-empty {
    font-size: 11px;
    color: #6e7681;
    padding: 8px 4px;
  }

  .pl-zoom-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 4px;
  }
  .pl-zoom-slider {
    flex: 1;
    accent-color: #58a6ff;
    cursor: pointer;
    height: 4px;
  }
  .pl-zoom-hint {
    font-size: 11px;
    color: #6e7681;
    user-select: none;
    flex-shrink: 0;
  }
  .pl-zoom-pct {
    font-size: 11px;
    color: #58a6ff;
    font-weight: 600;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    margin-left: auto;
  }
</style>
