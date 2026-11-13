<script lang="ts">
  import type {
    FirewallDirection,
    FirewallProtocol,
    FirewallRule,
    FirewallRuleAction,
  } from "../types";

  let {
    rule,
    saving = false,
    error = null,
    onSave,
    onCancel,
  }: {
    rule: FirewallRule;
    saving?: boolean;
    error?: string | null;
    onSave: (rule: FirewallRule) => void;
    onCancel: () => void;
  } = $props();

  type RuleForm = {
    id: number;
    name: string;
    enabled: boolean;
    action: FirewallRuleAction;
    direction: FirewallDirection;
    protocol: FirewallProtocol;
    local_address: string;
    local_port: string;
    remote_address: string;
    remote_port: string;
    interface: string;
    log: boolean;
    priority: number;
  };

  function toForm(source: FirewallRule): RuleForm {
    return {
      id: source.id ?? 0,
      name: source.name ?? "",
      enabled: source.enabled ?? true,
      action: source.action ?? "block",
      direction: source.direction ?? "in",
      protocol: source.protocol ?? "tcp",
      local_address: source.local_address ?? "",
      local_port: source.local_port ?? "",
      remote_address: source.remote_address ?? "",
      remote_port: source.remote_port ?? "",
      interface: source.interface ?? "",
      log: source.log ?? true,
      priority: source.priority ?? 0,
    };
  }

  function toRule(form: RuleForm): FirewallRule {
    return {
      id: form.id,
      name: form.name.trim(),
      enabled: form.enabled,
      action: form.action,
      direction: form.direction,
      protocol: form.protocol,
      local_address: form.local_address.trim() || null,
      local_port: form.local_port.trim() || null,
      remote_address: form.remote_address.trim() || null,
      remote_port: form.remote_port.trim() || null,
      interface: form.interface.trim() || null,
      log: form.log,
      priority: form.priority,
    };
  }

  const emptyForm: RuleForm = {
    id: 0,
    name: "",
    enabled: true,
    action: "block",
    direction: "in",
    protocol: "tcp",
    local_address: "",
    local_port: "",
    remote_address: "",
    remote_port: "",
    interface: "",
    log: true,
    priority: 0,
  };

  let form = $state<RuleForm>({ ...emptyForm });

  $effect(() => {
    form = toForm(rule);
  });

  const broad = $derived(
    !form.local_address &&
      !form.local_port &&
      !form.remote_address &&
      !form.remote_port &&
      !form.interface,
  );
  const portsDisabled = $derived(
    form.protocol === "icmp" || form.protocol === "icmp6",
  );
  const destructive = $derived(
    (form.action === "block" || form.action === "reject") &&
      (form.direction === "out" || form.direction === "both") &&
      broad,
  );
</script>

<section class="panel">
  <div class="panel-header">
    <h2>{form.id > 0 ? `Edit rule ${form.id}` : "New rule"}</h2>
    <div class="panel-tools">
      <button type="button" onclick={onCancel} disabled={saving}>Cancel</button>
      <button type="button" onclick={() => onSave(toRule(form))} disabled={saving || !form.name.trim()}>
        {saving ? "Saving..." : "Save rule"}
      </button>
    </div>
  </div>

  {#if error}<p class="banner error">{error}</p>{/if}

  <div class="rule-form">
    <label class="wide">
      <span>Name</span>
      <input type="text" bind:value={form.name} placeholder="Block SSH from guest network" />
    </label>

    <label>
      <span>Action</span>
      <select bind:value={form.action}>
        <option value="block">Block (drop)</option>
        <option value="reject">Reject (return)</option>
        <option value="allow">Allow (pass)</option>
      </select>
    </label>

    <label>
      <span>Direction</span>
      <select bind:value={form.direction}>
        <option value="in">Inbound</option>
        <option value="out">Outbound</option>
        <option value="both">Both</option>
      </select>
    </label>

    <label>
      <span>Protocol</span>
      <select bind:value={form.protocol}>
        <option value="any">Any</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="icmp">ICMP</option>
        <option value="icmp6">ICMPv6</option>
      </select>
    </label>

    <label>
      <span>Interface</span>
      <input type="text" bind:value={form.interface} placeholder="any" />
    </label>

    <label>
      <span>Local address / CIDR</span>
      <input type="text" bind:value={form.local_address} placeholder="any" />
    </label>

    <label>
      <span>Local port / range</span>
      <input type="text" bind:value={form.local_port} placeholder="any" disabled={portsDisabled} />
    </label>

    <label>
      <span>Remote address / CIDR</span>
      <input type="text" bind:value={form.remote_address} placeholder="any" />
    </label>

    <label>
      <span>Remote port / range</span>
      <input type="text" bind:value={form.remote_port} placeholder="any" disabled={portsDisabled} />
    </label>

    <label class="check">
      <input type="checkbox" bind:checked={form.enabled} />
      <span>Enabled</span>
    </label>

    <label class="check">
      <input type="checkbox" bind:checked={form.log} />
      <span>Log matched packets</span>
    </label>
  </div>

  {#if portsDisabled}
    <p class="detail-note rule-note">ICMP rules cannot specify ports.</p>
  {/if}
  {#if destructive}
    <p class="banner warning rule-note">
      This rule blocks broad outbound or bidirectional traffic. Apply only after
      confirming it will not cut off management or update access.
    </p>
  {/if}
</section>

<style>
  .rule-form {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr));
    gap: 12px;
    padding: 14px;
  }
  .rule-form label {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 12px;
  }
  .rule-form label.wide {
    grid-column: 1 / -1;
  }
  .rule-form label > span {
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
  }
  .rule-form input[type="text"],
  .rule-form select {
    width: 100%;
    border: 1px solid var(--border-strong);
    background: var(--input-bg);
    color: var(--text);
    border-radius: 7px;
    padding: 6px 9px;
    font: inherit;
  }
  .rule-form label.check {
    flex-direction: row;
    align-items: center;
    gap: 8px;
  }
  .rule-form label.check > span {
    text-transform: none;
    letter-spacing: 0;
    font-size: 12px;
    color: var(--text);
  }
  .rule-note {
    margin: 0 14px 14px;
  }
</style>
