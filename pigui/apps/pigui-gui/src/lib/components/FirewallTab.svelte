<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { formatBytes, formatTime } from "../display";
  import type {
    FirewallBlock,
    FirewallCounter,
    FirewallDirection,
    FirewallEvent,
    FirewallRule,
    FirewallRuleAction,
    FirewallState,
    FirewallStatusPayload,
  } from "../types";
  import FirewallRuleEditor from "./FirewallRuleEditor.svelte";

  let { onRefresh }: { onRefresh: () => Promise<void> } = $props();

  type RuleListResponse = { rules: FirewallRule[]; state: FirewallState };
  type BlockListResponse = { blocks: FirewallBlock[] };
  type CountersResponse = {
    data?: { block?: FirewallCounter[]; allow?: FirewallCounter[] };
  };
  type EventsResponse = { data?: { events?: FirewallEvent[] } };

  let status = $state<FirewallStatusPayload | null>(null);
  let rules = $state<FirewallRule[]>([]);
  let blocks = $state<FirewallBlock[]>([]);
  let counters = $state<FirewallCounter[]>([]);
  let events = $state<FirewallEvent[]>([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let message = $state<string | null>(null);
  let editing = $state<FirewallRule | null>(null);
  let editorSaving = $state(false);
  let editorError = $state<string | null>(null);
  let blockAddress = $state("");
  let blockDirection = $state<FirewallDirection>("both");
  let blockTtl = $state(3600);
  let blockReason = $state("");
  let blockError = $state<string | null>(null);

  const helper = $derived(status?.helper?.data ?? null);
  const pending = $derived(
    status ? status.state.generation !== status.state.applied_generation : false,
  );

  type CounterTotals = {
    packets: number;
    bytes: number;
    packetsIn: number;
    packetsOut: number;
    bytesIn: number;
    bytesOut: number;
  };

  const counterByRule = $derived.by(() => {
    const map = new Map<number, CounterTotals>();
    for (const counter of counters) {
      const match = /^pigui-rule-(\d+)/.exec(counter.label);
      if (!match) {
        continue;
      }
      const id = Number(match[1]);
      const entry =
        map.get(id) ??
        {
          packets: 0,
          bytes: 0,
          packetsIn: 0,
          packetsOut: 0,
          bytesIn: 0,
          bytesOut: 0,
        };
      entry.packets += counter.packets;
      entry.bytes += counter.bytes;
      entry.packetsIn += counter.packets_in;
      entry.packetsOut += counter.packets_out;
      entry.bytesIn += counter.bytes_in;
      entry.bytesOut += counter.bytes_out;
      map.set(id, entry);
    }
    return map;
  });

  function actionClass(action: FirewallRuleAction): string {
    if (action === "allow") {
      return "trusted";
    }
    if (action === "reject") {
      return "suspicious";
    }
    return "blocked";
  }

  function endpoint(address?: string | null, port?: string | null): string {
    if (!address && !port) {
      return "any";
    }
    return `${address || "any"}${port ? `:${port}` : ""}`;
  }

  function eventEndpoint(address?: string, port?: number): string {
    if (!address) {
      return "-";
    }
    return port ? `${address}:${port}` : address;
  }

  function eventKey(event: FirewallEvent): string {
    return (
      event.raw ??
      `${event.ts}:${event.anchor}:${event.rule_number}:${event.src}:${event.dst}`
    );
  }

  function blankRule(): FirewallRule {
    return {
      id: 0,
      name: "",
      enabled: true,
      action: "block",
      direction: "in",
      protocol: "tcp",
      local_address: null,
      local_port: null,
      remote_address: null,
      remote_port: null,
      interface: null,
      log: true,
      priority: 0,
    };
  }

  async function refresh() {
    try {
      const [nextStatus, ruleList, blockList] = await Promise.all([
        invoke<FirewallStatusPayload>("firewall_status"),
        invoke<RuleListResponse>("list_firewall_rules"),
        invoke<BlockListResponse>("list_firewall_blocks"),
      ]);
      status = nextStatus;
      rules = ruleList.rules;
      blocks = blockList.blocks;
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
    }
  }

  async function refreshCounters() {
    try {
      const counterList = await invoke<CountersResponse>("firewall_counters");
      counters = [
        ...(counterList.data?.block ?? []),
        ...(counterList.data?.allow ?? []),
      ];
    } catch {
      counters = [];
    }
  }

  async function pollEvents() {
    try {
      const result = await invoke<EventsResponse>("list_firewall_events", {
        limit: 100,
      });
      const incoming = result.data?.events ?? [];
      if (incoming.length === 0) {
        return;
      }
      const seen = new Set(events.map(eventKey));
      const next = [...incoming].reverse().filter((event) => {
        const key = eventKey(event);
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      });
      events = [...next, ...events].slice(0, 200);
    } catch {
      // Event polling failures are shown by the main firewall status.
    }
  }

  async function toggleEnabled() {
    if (!status) {
      return;
    }
    busy = true;
    error = null;
    message = null;
    try {
      await invoke("enable_firewall", { enabled: !status.state.enabled });
      await invoke("apply_firewall");
      message = status.state.enabled ? "Firewall disabled." : "Firewall enabled.";
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
      await refresh();
    } finally {
      busy = false;
    }
  }

  async function applyChanges() {
    busy = true;
    error = null;
    message = null;
    try {
      await invoke("apply_firewall");
      message = "Firewall rules applied.";
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
      await refresh();
    } finally {
      busy = false;
    }
  }

  async function resetAll() {
    if (!confirm("Remove all PIGUI firewall rules and blocks and flush the PIGUI PF anchors?")) {
      return;
    }
    busy = true;
    error = null;
    message = null;
    try {
      await invoke("reset_firewall");
      events = [];
      message = "Firewall reset.";
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
      await refresh();
    } finally {
      busy = false;
    }
  }

  function startAdd() {
    editorError = null;
    editing = blankRule();
  }

  function startEdit(rule: FirewallRule) {
    editorError = null;
    editing = { ...rule };
  }

  async function saveRule(rule: FirewallRule) {
    editorSaving = true;
    editorError = null;
    try {
      if (rule.id > 0) {
        await invoke("update_firewall_rule", { rule });
      } else {
        await invoke("create_firewall_rule", { rule });
      }
      editing = null;
      message = rule.id > 0 ? "Rule updated." : "Rule added.";
      await refresh();
      await onRefresh();
    } catch (cause) {
      editorError = String(cause);
    } finally {
      editorSaving = false;
    }
  }

  async function toggleRule(rule: FirewallRule) {
    busy = true;
    error = null;
    try {
      await invoke("update_firewall_rule", {
        rule: { ...rule, enabled: !rule.enabled },
      });
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function deleteRule(rule: FirewallRule) {
    if (!confirm(`Delete firewall rule "${rule.name}"?`)) {
      return;
    }
    busy = true;
    error = null;
    try {
      await invoke("delete_firewall_rule", { id: rule.id });
      if (editing?.id === rule.id) {
        editing = null;
      }
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function moveRule(index: number, delta: number) {
    const next = index + delta;
    if (next < 0 || next >= rules.length) {
      return;
    }
    const ids = rules.map((rule) => rule.id);
    [ids[index], ids[next]] = [ids[next], ids[index]];
    busy = true;
    error = null;
    try {
      await invoke("reorder_firewall_rules", { ids });
      await refresh();
      await onRefresh();
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function addBlock() {
    const address = blockAddress.trim();
    if (!address) {
      return;
    }
    const ttl = Number(blockTtl);
    if (!Number.isFinite(ttl) || ttl <= 0) {
      blockError = "TTL must be a positive number of seconds.";
      return;
    }
    busy = true;
    blockError = null;
    try {
      await invoke("add_firewall_block", {
        address,
        direction: blockDirection,
        ttlSecs: ttl,
        reason: blockReason.trim() || null,
      });
      blockAddress = "";
      blockReason = "";
      await refresh();
      await onRefresh();
    } catch (cause) {
      blockError = String(cause);
    } finally {
      busy = false;
    }
  }

  async function removeBlock(block: FirewallBlock) {
    busy = true;
    blockError = null;
    try {
      await invoke("remove_firewall_block", {
        id: block.id,
        address: null,
        direction: null,
      });
      await refresh();
      await onRefresh();
    } catch (cause) {
      blockError = String(cause);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void refresh();
    void pollEvents();
    void refreshCounters();
    const refreshTimer = setInterval(() => {
      if (!document.hidden) {
        void refresh();
      }
    }, 10_000);
    const eventTimer = setInterval(() => {
      if (!document.hidden) {
        void pollEvents();
      }
    }, 5_000);
    const counterTimer = setInterval(() => {
      if (!document.hidden) {
        void refreshCounters();
      }
    }, 15_000);
    return () => {
      clearInterval(refreshTimer);
      clearInterval(eventTimer);
      clearInterval(counterTimer);
    };
  });
</script>

{#if error}
  <section class="banner error">{error}</section>
{/if}
{#if message}
  <section class="banner">{message}</section>
{/if}
{#if status?.state.last_error}
  <section class="banner warning">
    <strong>Last apply error</strong>
    {status.state.last_error}
  </section>
{/if}
{#if status?.helper_error}
  <section class="banner warning">
    <strong>Helper unavailable</strong>
    {status.helper_error}
  </section>
{/if}

{#if loading && !status}
  <section class="banner">Loading firewall state...</section>
{:else if status}
  <section class="panel">
    <div class="panel-header">
      <h2>PIGUI Firewall</h2>
      <div class="panel-tools">
        <button type="button" onclick={() => void toggleEnabled()} disabled={busy}>
          {status.state.enabled ? "Disable firewall" : "Enable firewall"}
        </button>
        <button type="button" onclick={() => void applyChanges()} disabled={busy || !pending}>
          {pending ? "Apply changes" : "Applied"}
        </button>
        <button type="button" onclick={() => void resetAll()} disabled={busy}>Reset</button>
      </div>
    </div>

    <div class="capabilities">
      <article>
        <span class="label">Enforcement</span>
        <span class:ok={status.state.enabled} class:warn={!status.state.enabled} class="value">
          {status.state.enabled ? "On" : "Off"}
        </span>
        <span class="hint">PIGUI-owned PF anchors</span>
      </article>
      <article>
        <span class="label">Packet filter</span>
        <span class:ok={helper?.pf_enabled} class:warn={!helper?.pf_enabled} class="value">
          {helper?.pf_enabled ? "Enabled" : "Disabled"}
        </span>
        <span class="hint">system-wide PF state</span>
      </article>
      <article>
        <span class="label">Rule set</span>
        <span class:warn={pending} class="value">{pending ? "Pending" : "Current"}</span>
        <span class="hint">generation {status.state.applied_generation}/{status.state.generation}</span>
      </article>
      <article>
        <span class="label">Rules</span>
        <span class="value">{status.rule_count}</span>
        <span class="hint">{status.state.mode} mode</span>
      </article>
      <article>
        <span class="label">Dynamic blocks</span>
        <span class="value">{status.block_count}</span>
        <span class="hint">active TTL entries</span>
      </article>
      <article>
        <span class="label">Log reader</span>
        <span class:ok={helper?.pflog_reader_running} class:warn={!helper?.pflog_reader_running} class="value">
          {helper?.pflog_reader_running ? "Reading" : "Idle"}
        </span>
        <span class="hint">{helper?.pflog_interface ?? "pflog1"}</span>
      </article>
    </div>

    <div class="firewall-helper">
      <span>block anchor {helper?.block_anchor_loaded ? "loaded" : "empty"}</span>
      <span>allow anchor {helper?.allow_anchor_loaded ? "loaded" : "empty"}</span>
      <span>PF reference {helper?.pf_enabled_by_pigui ? "held by PIGUI" : "not held"}</span>
      {#if status.state.applied_at}
        <span>applied {formatTime(status.state.applied_at)}</span>
      {/if}
    </div>
  </section>

  <section class="panel">
    <div class="panel-header">
      <h2>Rules <span class="hint">first match wins, top to bottom</span></h2>
      <div class="panel-tools">
        <button type="button" onclick={startAdd} disabled={busy}>Add rule</button>
        <button type="button" onclick={() => void applyChanges()} disabled={busy || !pending}>
          Apply
        </button>
      </div>
    </div>
    <div class="table-wrap tall">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Name</th>
            <th>Action</th>
            <th>Direction</th>
            <th>Protocol</th>
            <th>Local</th>
            <th>Remote</th>
            <th>Interface</th>
            <th>Log</th>
            <th>Enabled</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule, index (rule.id)}
            {@const totals = counterByRule.get(rule.id)}
            <tr>
              <td class="mono">{index + 1}</td>
              <td>{rule.name}</td>
              <td><span class="tag {actionClass(rule.action)}">{rule.action}</span></td>
              <td>{rule.direction}</td>
              <td>{rule.protocol}</td>
              <td class="mono">{endpoint(rule.local_address, rule.local_port)}</td>
              <td class="mono">{endpoint(rule.remote_address, rule.remote_port)}</td>
              <td class="mono">{rule.interface ?? "any"}</td>
              <td>{rule.log ? "yes" : "no"}</td>
              <td><span class="tag {rule.enabled ? "trusted" : "ignored"}">{rule.enabled ? "on" : "off"}</span></td>
              <td class="mono">{totals?.packets ?? 0}</td>
              <td class="mono">{formatBytes(totals?.bytes ?? 0)}</td>
              <td>
                <div class="actions-cell">
                  <button type="button" title="Move up" onclick={() => void moveRule(index, -1)} disabled={busy || index === 0}>↑</button>
                  <button type="button" title="Move down" onclick={() => void moveRule(index, 1)} disabled={busy || index === rules.length - 1}>↓</button>
                  <button type="button" onclick={() => startEdit(rule)} disabled={busy}>Edit</button>
                  <button type="button" onclick={() => void toggleRule(rule)} disabled={busy}>{rule.enabled ? "Disable" : "Enable"}</button>
                  <button type="button" onclick={() => void deleteRule(rule)} disabled={busy}>Delete</button>
                </div>
              </td>
            </tr>
          {:else}
            <tr>
              <td class="empty" colspan="13">
                No PIGUI firewall rules yet. Add a rule, then Apply.
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  {#if editing}
    <FirewallRuleEditor
      rule={editing}
      saving={editorSaving}
      error={editorError}
      onSave={(rule) => void saveRule(rule)}
      onCancel={() => {
        editing = null;
        editorError = null;
      }}
    />
  {/if}

  <section class="panel">
    <div class="panel-header">
      <h2>Dynamic blocks <span class="hint">IP/CIDR with TTL</span></h2>
    </div>
    <div class="form-row">
      <input type="text" bind:value={blockAddress} placeholder="192.0.2.10 or 2001:db8::/32" />
      <select bind:value={blockDirection} aria-label="Block direction">
        <option value="both">Both</option>
        <option value="in">Inbound</option>
        <option value="out">Outbound</option>
      </select>
      <label class="ttl">
        <span>TTL (seconds)</span>
        <input type="number" min="1" max="604800" step="60" bind:value={blockTtl} />
      </label>
      <input type="text" bind:value={blockReason} placeholder="reason (optional)" />
      <button type="button" onclick={() => void addBlock()} disabled={busy || !blockAddress.trim()}>
        Add block
      </button>
    </div>
    {#if blockError}<p class="banner error form-error">{blockError}</p>{/if}
    <div class="table-wrap short">
      <table>
        <thead>
          <tr>
            <th>Address</th>
            <th>Direction</th>
            <th>Expires</th>
            <th>TTL</th>
            <th>Reason</th>
            <th>Source</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each blocks as block (block.id)}
            <tr>
              <td class="mono">{block.address}</td>
              <td>{block.direction}</td>
              <td class="mono">{formatTime(block.expires_at)}</td>
              <td>{block.ttl_secs}s</td>
              <td>{block.reason ?? "-"}</td>
              <td>{block.source}</td>
              <td>
                <button type="button" onclick={() => void removeBlock(block)} disabled={busy}>
                  Remove
                </button>
              </td>
            </tr>
          {:else}
            <tr><td class="empty" colspan="7">No active dynamic blocks.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <div class="panel-header">
      <h2>Recent blocked events <span class="hint">live pflog buffer</span></h2>
      <div class="panel-tools">
        <button type="button" onclick={() => { events = []; }}>Clear view</button>
      </div>
    </div>
    <div class="table-wrap tall">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Direction</th>
            <th>Interface</th>
            <th>Proto</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Rule</th>
          </tr>
        </thead>
        <tbody>
          {#each events as event (eventKey(event))}
            <tr>
              <td class="mono">{formatTime(event.ts)}</td>
              <td><span class="tag {event.action === "pass" ? "trusted" : "blocked"}">{event.action}</span></td>
              <td>{event.direction || "-"}</td>
              <td class="mono">{event.interface ?? "-"}</td>
              <td>{event.proto ?? "-"}</td>
              <td class="mono">{eventEndpoint(event.src, event.src_port)}</td>
              <td class="mono">{eventEndpoint(event.dst, event.dst_port)}</td>
              <td class="mono">{event.rule_label ?? "dynamic"}</td>
            </tr>
          {:else}
            <tr>
              <td class="empty" colspan="8">
                No events in the helper buffer. Enable the firewall and Apply to
                start the pflog reader.
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .firewall-helper {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    padding: 0 14px 14px;
    color: var(--text-muted);
    font-size: 12px;
  }
  .actions-cell {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
  }
  .actions-cell button {
    padding: 3px 7px;
    font-size: 11px;
  }
  .form-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    padding: 12px 14px;
  }
  .form-row input[type="text"] {
    width: min(260px, 40vw);
  }
  .form-row label.ttl {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .form-row input[type="number"] {
    width: 110px;
    border: 1px solid var(--border-strong);
    background: var(--input-bg);
    color: var(--text);
    border-radius: 7px;
    padding: 6px 9px;
    font: inherit;
  }
  .form-error {
    margin: 0 14px 12px;
  }
</style>
