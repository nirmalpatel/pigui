<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  interface SnortCapabilities {
    binary?: string;
    source?: string;
    version?: string;
    control_socket: boolean;
    shell: boolean;
    extractor: boolean;
    alert_json: boolean;
    config_valid?: boolean;
    config_path?: string;
    daq_modules: string[];
    warnings: string[];
  }

  interface StatusPayload {
    capabilities: SnortCapabilities;
    db_path: string;
    alert_json: string;
    socket_path: string;
    uptime_secs: number;
    alerts_ingested: number;
    parse_errors: number;
    alert_count: number;
    destination_count: number;
    degraded: string[];
  }

  interface AlertRecord {
    id: number;
    event_ts: number;
    ts_text?: string;
    gid: number;
    sid: number;
    rev: number;
    priority?: number;
    class?: string;
    msg?: string;
    proto?: string;
    src_ip?: string;
    src_port?: number;
    dst_ip?: string;
    dst_port?: number;
    action?: string;
    app_id?: string;
    service?: string;
    rule?: string;
    direction?: string;
    pkt_num?: number;
    ingested_at: number;
  }

  interface AlertList {
    alerts: AlertRecord[];
    total: number;
  }

  interface Destination {
    ip: string;
    first_seen: number;
    last_seen: number;
    bytes_in: number;
    bytes_out: number;
    connection_count: number;
    process_count: number;
    alert_count: number;
    reputation: number;
    blocked: boolean;
  }

  interface DestinationList {
    destinations: Destination[];
    total: number;
  }

  let status = $state<StatusPayload | null>(null);
  let alerts = $state<AlertRecord[]>([]);
  let destinations = $state<Destination[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let lastUpdated = $state("");
  let alertFilter = $state("");
  let destinationFilter = $state("");

  const filteredAlerts = $derived(
    alerts.filter((alert) => {
      if (!alertFilter.trim()) return true;
      const needle = alertFilter.toLowerCase();
      return [
        alert.msg,
        alert.sid,
        alert.src_ip,
        alert.dst_ip,
        alert.action,
        alert.proto,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    }),
  );

  const filteredDestinations = $derived(
    destinations.filter((destination) => {
      if (!destinationFilter.trim()) return true;
      return destination.ip
        .toLowerCase()
        .includes(destinationFilter.toLowerCase());
    }),
  );

  async function refresh() {
    refreshing = true;
    try {
      const [nextStatus, nextAlerts, nextDestinations] = await Promise.all([
        invoke<StatusPayload>("get_status"),
        invoke<AlertList>("list_alerts", { limit: 200 }),
        invoke<DestinationList>("list_destinations", { limit: 200 }),
      ]);
      status = nextStatus;
      alerts = nextAlerts.alerts;
      destinations = nextDestinations.destinations;
      error = null;
      lastUpdated = new Date().toLocaleTimeString();
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  function formatTime(seconds: number): string {
    if (!seconds) return "-";
    return new Date(seconds * 1000).toLocaleString();
  }

  function endpoint(ip?: string, port?: number): string {
    if (!ip) return "-";
    return port ? `${ip}:${port}` : ip;
  }

  onMount(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 2000);
    return () => clearInterval(timer);
  });
</script>

<main>
  <header>
    <div class="brand">
      <span class="logo">PI</span>
      <div>
        <h1>PIGUI</h1>
        <p>Snort telemetry, process attribution, and firewall control</p>
      </div>
    </div>
    <div class="actions">
      {#if status}
        <span class="pill" class:degraded={status.degraded.length > 0}>
          {status.degraded.length > 0 ? "degraded" : "healthy"}
        </span>
      {/if}
      <span class="updated">
        {lastUpdated ? `updated ${lastUpdated}` : "connecting..."}
      </span>
      <button onclick={() => void refresh()} disabled={refreshing}>
        {refreshing ? "Refreshing" : "Refresh"}
      </button>
    </div>
  </header>

  {#if error}
    <section class="banner error">
      <strong>Daemon unreachable.</strong>
      {error}
      <p>Start the daemon with <code>scripts/run-dev.sh</code> or <code>cargo run -p pigui-daemon</code>.</p>
    </section>
  {:else if loading}
    <section class="banner">Connecting to pigui-daemon...</section>
  {/if}

  {#if status}
    {#if status.degraded.length > 0}
      <section class="banner warning">
        <strong>Degraded capabilities</strong>
        <ul>
          {#each status.degraded as reason}
            <li>{reason}</li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="capabilities">
      <article>
        <span class="label">Snort</span>
        <span class="value">{status.capabilities.version ?? "not found"}</span>
        <span class="hint">{status.capabilities.binary ?? "set PIGUI_SNORT_BIN"}</span>
      </article>
      <article>
        <span class="label">Control socket</span>
        <span class="value" class:ok={status.capabilities.control_socket}>
          {status.capabilities.control_socket ? "available" : "unavailable"}
        </span>
        <span class="hint">{status.capabilities.source ?? "unknown source"}</span>
      </article>
      <article>
        <span class="label">Extractor</span>
        <span class="value" class:ok={status.capabilities.extractor}>
          {status.capabilities.extractor ? "available" : "unavailable"}
        </span>
        <span class="hint">connection and hostname telemetry</span>
      </article>
      <article>
        <span class="label">Configuration</span>
        <span class="value" class:ok={status.capabilities.config_valid === true}>
          {status.capabilities.config_valid === true
            ? "validated"
            : status.capabilities.config_valid === false
              ? "invalid"
              : "not checked"}
        </span>
        <span class="hint">{status.capabilities.config_path ?? "no config"}</span>
      </article>
      <article>
        <span class="label">Alerts</span>
        <span class="value">{status.alert_count}</span>
        <span class="hint">{status.alerts_ingested} ingested, {status.parse_errors} parse errors</span>
      </article>
      <article>
        <span class="label">Destinations</span>
        <span class="value">{status.destination_count}</span>
        <span class="hint">derived from stored alerts</span>
      </article>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Alerts</h2>
        <input
          type="search"
          placeholder="Filter alerts"
          bind:value={alertFilter}
        />
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>SID</th>
              <th>Priority</th>
              <th>Proto</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Action</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredAlerts as alert (alert.id)}
              <tr>
                <td class="mono">{formatTime(alert.event_ts)}</td>
                <td class="mono">{alert.sid}</td>
                <td>{alert.priority ?? "-"}</td>
                <td>{alert.proto ?? "-"}</td>
                <td class="mono">{endpoint(alert.src_ip, alert.src_port)}</td>
                <td class="mono">{endpoint(alert.dst_ip, alert.dst_port)}</td>
                <td>
                  <span class="tag" class:blocked={alert.action === "blocked"}>
                    {alert.action ?? "-"}
                  </span>
                </td>
                <td>{alert.msg ?? "-"}</td>
              </tr>
            {:else}
              <tr>
                <td class="empty" colspan="8">No alerts ingested yet.</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Destinations</h2>
        <input
          type="search"
          placeholder="Filter destinations"
          bind:value={destinationFilter}
        />
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>Alerts</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th>Block state</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredDestinations as destination (destination.ip)}
              <tr>
                <td class="mono">{destination.ip}</td>
                <td>{destination.alert_count}</td>
                <td class="mono">{formatTime(destination.first_seen)}</td>
                <td class="mono">{formatTime(destination.last_seen)}</td>
                <td>
                  <span class="tag" class:blocked={destination.blocked}>
                    {destination.blocked ? "blocked" : "not blocked"}
                  </span>
                </td>
              </tr>
            {:else}
              <tr>
                <td class="empty" colspan="5">No destinations observed yet.</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <footer>
      <span>database <code>{status.db_path}</code></span>
      <span>socket <code>{status.socket_path}</code></span>
      <span>uptime {status.uptime_secs}s</span>
    </footer>
  {/if}
</main>

<style>
  main {
    max-width: 1440px;
    margin: 0 auto;
    padding: 22px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .logo {
    width: 42px;
    height: 42px;
    display: grid;
    place-items: center;
    border-radius: 12px;
    background: linear-gradient(135deg, #266ca8, #38b28e);
    font-weight: 700;
    letter-spacing: 0.5px;
  }

  h1 {
    margin: 0;
    font-size: 22px;
    letter-spacing: 0.3px;
  }

  header p {
    margin: 2px 0 0;
    color: #8b98a6;
    font-size: 12px;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .updated {
    color: #8b98a6;
    font-size: 12px;
  }

  .pill {
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 12px;
    background: rgba(56, 178, 142, 0.16);
    color: #6ee7b7;
    border: 1px solid rgba(56, 178, 142, 0.35);
  }

  .pill.degraded {
    background: rgba(245, 158, 11, 0.14);
    color: #fbbf24;
    border-color: rgba(245, 158, 11, 0.35);
  }

  .banner {
    border: 1px solid #2d3945;
    background: #151c23;
    border-radius: 10px;
    padding: 12px 14px;
    color: #c3ccd6;
  }

  .banner ul {
    margin: 8px 0 0;
    padding-left: 20px;
  }

  .banner.error {
    border-color: rgba(239, 68, 68, 0.45);
    background: rgba(127, 29, 29, 0.18);
  }

  .banner.warning {
    border-color: rgba(245, 158, 11, 0.45);
    background: rgba(120, 53, 15, 0.16);
  }

  .banner p {
    margin: 6px 0 0;
    color: #9aa7b5;
  }

  .capabilities {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 10px;
  }

  .capabilities article {
    border: 1px solid #232d38;
    background: #141a21;
    border-radius: 10px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .label {
    color: #8b98a6;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
  }

  .value {
    font-size: 16px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .value.ok {
    color: #6ee7b7;
  }

  .hint {
    color: #74808d;
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .panel {
    border: 1px solid #232d38;
    background: #141a21;
    border-radius: 12px;
    overflow: hidden;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 14px;
    border-bottom: 1px solid #232d38;
  }

  h2 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.2px;
  }

  input[type="search"] {
    width: min(280px, 45vw);
    border: 1px solid #2d3945;
    background: #10161c;
    color: #e5e9ee;
    border-radius: 7px;
    padding: 6px 9px;
    font: inherit;
  }

  .table-wrap {
    max-height: 340px;
    overflow: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }

  th {
    position: sticky;
    top: 0;
    z-index: 1;
    text-align: left;
    font-weight: 600;
    color: #9aa7b5;
    background: #18202a;
    padding: 9px 12px;
    border-bottom: 1px solid #232d38;
    white-space: nowrap;
  }

  td {
    padding: 8px 12px;
    border-bottom: 1px solid #1c242d;
    white-space: nowrap;
  }

  tbody tr:hover {
    background: #18202a;
  }

  .mono {
    font-family: "SF Mono", ui-monospace, Menlo, monospace;
    font-size: 11.5px;
  }

  .tag {
    display: inline-block;
    border-radius: 999px;
    padding: 2px 8px;
    background: rgba(148, 163, 184, 0.12);
    color: #cbd5e1;
    border: 1px solid rgba(148, 163, 184, 0.2);
  }

  .tag.blocked {
    background: rgba(239, 68, 68, 0.14);
    color: #fca5a5;
    border-color: rgba(239, 68, 68, 0.35);
  }

  .empty {
    text-align: center;
    color: #74808d;
    padding: 24px;
  }

  footer {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    color: #74808d;
    font-size: 11px;
    padding: 4px 2px 12px;
  }
</style>
