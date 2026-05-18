<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { homeDir } from "@tauri-apps/api/path";

  let { vpnState } = $props();

  let htbToken   = $state("");
  let tokenSaved = $state(false);
  let ovpnPath   = $state("");
  let ovpnName   = $state("");
  let vpnError   = $state("");
  let connecting = $state(false);
  let vpnProfiles = $state([]);
  let profileSaved = $state(false);

  onMount(async () => {
    try {
      const t = await invoke("load_config_value", { key: "htb_app_token" });
      if (t) htbToken = t;
    } catch (_) {}
    await loadProfiles();
  });

  async function loadProfiles() {
    try { vpnProfiles = await invoke("list_vpn_profiles"); }
    catch (_) { vpnProfiles = []; }
  }

  async function saveProfile() {
    if (!ovpnPath) return;
    const name = ovpnName.trim() || ovpnPath.split("/").pop().replace(".ovpn", "");
    try {
      await invoke("save_vpn_profile", { name, ovpnPath, kind: "" });
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

  function loadProfile(p) { ovpnPath = p.ovpn_path; ovpnName = p.name; }

  async function saveToken() {
    try {
      await invoke("save_config_value", { key: "htb_app_token", value: htbToken.trim() });
      tokenSaved = true;
      setTimeout(() => { tokenSaved = false; }, 2000);
    } catch (e) { console.error(e); }
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
    connecting = true;
    vpnError = "";
    try {
      const profileName = ovpnName.trim() || ovpnPath.split("/").pop().replace(".ovpn", "");
      await invoke("vpn_connect", { ovpnPath, profileName });
    } catch (e) {
      vpnError = String(e);
    } finally {
      connecting = false;
    }
  }

  async function disconnectVpn() {
    vpnError = "";
    try { await invoke("vpn_disconnect"); }
    catch (e) { vpnError = String(e); }
  }
</script>

<div class="pl-settings">

  <!-- HTB Credentials -->
  <section class="pl-section">
    <h3>HackTheBox credentials</h3>
    <p>Stored locally in <code>~/.local/share/penligent-local/config.json</code> and passed to the MCP server as <code>HTB_APP_TOKEN</code>.</p>

    <div class="pl-field">
      <span class="pl-label">HTB App Token <span class="dim">· Written by Diablo</span></span>
      <span class="pl-hint">HTB profile → Settings → API → create app token.</span>
      <div class="pl-row">
        <input
          class="pl-input"
          type="password"
          placeholder="eyJ0eXAi…"
          bind:value={htbToken}
          onkeydown={(e) => e.key === 'Enter' && saveToken()}
        />
        <button class="pl-btn pl-btn-primary" onclick={saveToken} disabled={!htbToken.trim()}>
          {tokenSaved ? "Saved ✓" : "Save"}
        </button>
      </div>
    </div>
  </section>

  <!-- OpenVPN -->
  <section class="pl-section">
    <h3>OpenVPN</h3>
    <p>Spawned as a managed subprocess. One active tunnel at a time.</p>

    <div class="pl-field">
      <span class="pl-label">Profile</span>
      <span class="pl-hint">Select a saved profile or browse for a .ovpn file.</span>
      <div class="pl-row">
        <input class="pl-input" bind:value={ovpnName} placeholder="Profile name (optional)" style="flex:0 0 140px" />
        <input class="pl-input" value={ovpnPath} placeholder="~/Downloads/lab.ovpn" readonly style="flex:1" />
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
              <button class="pl-profile-load" onclick={() => loadProfile(p)} title="Load this profile">
                {#if p.is_default}<span class="pl-default-star">★</span>{/if}
                {p.name}
                {#if p.kind}<span class="pl-profile-kind">{p.kind}</span>{/if}
              </button>
              <button class="pl-profile-star" onclick={() => setDefaultProfile(p.id)} title="Set as default">☆</button>
              <button class="pl-profile-del" onclick={() => removeProfile(p.id)} title="Delete">✕</button>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <div class="pl-field">
      <span class="pl-label">Privilege mode</span>
      <span class="pl-hint">Narrow sudoers rule — only <code>/usr/sbin/openvpn</code> runs without password.</span>
      <div class="pl-row">
        <code class="green">/etc/sudoers.d/penligent-openvpn</code>
        <span class="check ml-auto">✓</span>
      </div>
    </div>

    <div class="pl-vpn-actions">
      {#if vpnState?.status === "connected"}
        <span class="vpn-on">● Connected · {vpnState.tun_ip ?? "—"}</span>
        <button class="pl-btn" onclick={disconnectVpn}>Disconnect</button>
      {:else if vpnState?.status === "connecting"}
        <span class="vpn-pending">● Connecting…</span>
      {:else}
        <button class="pl-btn pl-btn-primary" onclick={connectVpn}
          disabled={connecting || !ovpnPath}>
          {connecting ? "Connecting…" : "Connect VPN"}
        </button>
      {/if}
      {#if vpnError}<span class="vpn-err">{vpnError}</span>{/if}
    </div>
  </section>

  <!-- Agent runtime -->
  <section class="pl-section">
    <h3>Agent runtime</h3>
    <p>Penligent delegates authentication to Claude Code. Run <code>claude</code> at least once to log in.</p>

    <div class="pl-field">
      <div class="pl-row">
        <span class="dim-label">Claude Code</span>
        <code class="green">~/.local/bin/claude</code>
        <span class="check ml-auto">✓</span>
      </div>
    </div>
    <div class="pl-field">
      <div class="pl-row">
        <span class="dim-label">MCP server</span>
        <code class="green">penligent-local</code>
        <span class="ok ml-auto">connected · 206 tools</span>
      </div>
    </div>
  </section>

</div>

<style>
  .pl-settings {
    padding: 20px 28px;
    overflow-y: auto;
    flex: 1;
    max-width: 640px;
  }

  .pl-section {
    padding: 18px 0;
    border-bottom: 1px solid #21262d;
  }
  .pl-section:last-child { border-bottom: none; }

  .pl-section h3 {
    font-size: 13px;
    color: #e6edf3;
    font-weight: 600;
    margin: 0 0 4px;
    letter-spacing: 0.01em;
    border-left: 2px solid #30363d;
    padding-left: 10px;
  }

  .pl-section p {
    font-size: 12px;
    color: #6e7681;
    margin: 0 0 14px;
    line-height: 1.55;
  }
  .pl-section p code, .pl-hint code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #9fef00;
    font-size: 11px;
    background: rgba(159,239,0,0.06);
    padding: 1px 4px;
    border-radius: 3px;
  }

  .pl-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 12px;
  }
  .pl-field:last-child { margin-bottom: 0; }

  .pl-label { font-size: 12px; color: #c9d1d9; font-weight: 500; }
  .dim { color: #6e7681; font-weight: 400; font-size: 11px; }
  .pl-hint { font-size: 11px; color: #6e7681; line-height: 1.5; }

  .pl-row {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .pl-input {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 5px;
    color: #c9d1d9;
    padding: 7px 10px;
    font-size: 12px;
    font-family: "JetBrains Mono", ui-monospace, monospace;
    outline: none;
    transition: border-color 0.12s;
  }
  .pl-input:focus { border-color: #58a6ff; }
  .pl-input[readonly] { cursor: default; color: #8b949e; }

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

  .pl-vpn-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
  }

  .vpn-on     { font-size: 12px; color: #3fb950; margin-right: auto; }
  .vpn-pending { font-size: 12px; color: #febc2e; margin-right: auto; }
  .vpn-err    { font-size: 11px; color: #f85149; }

  .green {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    color: #9fef00;
    font-size: 12px;
  }
  .check { color: #9fef00; font-size: 14px; font-weight: 500; }
  .ok    { font-size: 11px; color: #9fef00; font-weight: 500; }
  .dim-label { font-size: 12px; color: #6e7681; min-width: 90px; }
  .ml-auto { margin-left: auto; }

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
    padding: 3px 6px;
  }
  .pl-profile-row.is-default { border-color: #58a6ff; }
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
  .pl-default-star { color: #58a6ff; }
  .pl-profile-kind { font-size: 10px; color: #8b949e; border: 1px solid #30363d; border-radius: 3px; padding: 0 4px; }
  .pl-profile-star, .pl-profile-del {
    background: none;
    border: none;
    color: #8b949e;
    cursor: pointer;
    font-size: 12px;
    padding: 2px 4px;
    border-radius: 3px;
    font-family: inherit;
    line-height: 1;
  }
  .pl-profile-star:hover { color: #58a6ff; }
  .pl-profile-del:hover { color: #f85149; }
</style>
