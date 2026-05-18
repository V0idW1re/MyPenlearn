<script>
  import { invoke } from "@tauri-apps/api/core";

  let { approval, onDecide } = $props();

  let reason = $state("");
  let deciding = $state(false);

  async function decide(decision) {
    deciding = true;
    try {
      await invoke("decide_approval", {
        approvalId: approval.id,
        decision,
        note: reason || (decision === "approved" ? "Approved by operator." : "Denied by operator."),
      });
      onDecide?.(decision);
    } catch (e) {
      console.error("decide_approval failed:", e);
    } finally {
      deciding = false;
    }
  }
</script>

<div class="pl-modal-backdrop" onclick={(e) => { if (e.target === e.currentTarget) {} }}>
  <div class="pl-modal">
    <div class="pl-modal-header">
      <span class="pl-modal-icon">⚠</span>
      <span class="pl-modal-title">Approval Required</span>
    </div>

    <div class="pl-modal-body">
      <div class="pl-intent-row">
        <span class="pl-intent-label">Intent</span>
        <span class="pl-intent-value">{approval.intent}</span>
      </div>

      {#if approval.scope_json}
        <div class="pl-detail-row">
          <span class="pl-detail-label">Scope</span>
          <span class="pl-detail-value">{approval.scope_json}</span>
        </div>
      {/if}

      {#if approval.decision_note}
        <div class="pl-detail-row">
          <span class="pl-detail-label">Justification</span>
          <span class="pl-detail-value">{approval.decision_note}</span>
        </div>
      {/if}

      {#if approval.rate_limit}
        <div class="pl-detail-row">
          <span class="pl-detail-label">Rate limit</span>
          <span class="pl-detail-value">{approval.rate_limit} req/min</span>
        </div>
      {/if}

      {#if approval.time_window}
        <div class="pl-detail-row">
          <span class="pl-detail-label">Time window</span>
          <span class="pl-detail-value">{approval.time_window}s</span>
        </div>
      {/if}

      <div class="pl-reason-row">
        <label class="pl-reason-label" for="approval-reason">
          Decision note
          {#if approval.project_kind === 'authorized_pentest'}
            <span class="pl-sow-req">· SOW reference required for approval</span>
          {:else}
            <span class="pl-optional">(optional)</span>
          {/if}
        </label>
        <input
          id="approval-reason"
          class="pl-reason-input"
          type="text"
          placeholder="e.g. Approved per scope letter section 3.2"
          bind:value={reason}
          disabled={deciding}
        />
      </div>
    </div>

    <div class="pl-modal-actions">
      <button
        class="pl-btn pl-btn-deny"
        onclick={() => decide("denied")}
        disabled={deciding}
      >
        Deny
      </button>
      <button
        class="pl-btn pl-btn-approve"
        onclick={() => decide("approved")}
        disabled={deciding}
      >
        Approve
      </button>
    </div>
  </div>
</div>

<style>
  .pl-modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.65);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .pl-modal {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    width: 440px;
    max-width: 90vw;
    box-shadow: 0 16px 48px rgba(0,0,0,0.5);
    overflow: hidden;
  }

  .pl-modal-header {
    padding: 16px 18px 12px;
    border-bottom: 1px solid #21262d;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pl-modal-icon {
    font-size: 16px;
    color: #d29922;
  }

  .pl-modal-title {
    font-size: 14px;
    font-weight: 600;
    color: #e6edf3;
    letter-spacing: 0.01em;
  }

  .pl-modal-body {
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .pl-intent-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .pl-intent-label {
    font-size: 10px;
    color: #484f58;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    flex-shrink: 0;
    width: 80px;
  }

  .pl-intent-value {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 13px;
    font-weight: 700;
    color: #d29922;
    letter-spacing: 0.05em;
  }

  .pl-detail-row {
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }

  .pl-detail-label {
    font-size: 10px;
    color: #484f58;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    flex-shrink: 0;
    width: 80px;
    padding-top: 1px;
  }

  .pl-detail-value {
    font-size: 11px;
    color: #8b949e;
    line-height: 1.45;
    word-break: break-word;
  }

  .pl-reason-row {
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin-top: 4px;
  }

  .pl-reason-label {
    font-size: 10px;
    color: #484f58;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }

  .pl-reason-input {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 12px;
    font-family: inherit;
    padding: 7px 10px;
    outline: none;
    transition: border-color 0.15s;
  }
  .pl-reason-input:focus { border-color: #58a6ff; }
  .pl-reason-input:disabled { opacity: 0.5; }

  .pl-modal-actions {
    padding: 12px 18px 16px;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    border-top: 1px solid #21262d;
  }

  .pl-btn {
    padding: 7px 18px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid;
    font-family: inherit;
    transition: opacity 0.1s;
  }
  .pl-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .pl-btn-deny {
    background: transparent;
    border-color: #f85149;
    color: #f85149;
  }
  .pl-btn-deny:hover:not(:disabled) { background: rgba(248,81,73,0.1); }

  .pl-btn-approve {
    background: #238636;
    border-color: #2ea043;
    color: #fff;
  }
  .pl-btn-approve:hover:not(:disabled) { background: #2ea043; }

  .pl-sow-req { font-size: 10px; color: #d29922; font-weight: 400; text-transform: none; letter-spacing: 0; }
  .pl-optional { font-size: 10px; color: #484f58; font-weight: 400; text-transform: none; letter-spacing: 0; }
</style>
