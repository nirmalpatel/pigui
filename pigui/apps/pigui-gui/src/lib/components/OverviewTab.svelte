<script lang="ts">
  import { endpoint, formatBytes, formatTime } from "../display";
  import type {
    AlertRecord,
    Destination,
    Process,
    StatusPayload,
  } from "../types";

  let {
    status,
    processes,
    destinations,
    alerts,
    needsReviewCount,
    onSetupCapture,
  }: {
    status: StatusPayload;
    processes: Process[];
    destinations: Destination[];
    alerts: AlertRecord[];
    needsReviewCount: number;
    onSetupCapture: () => void;
  } = $props();

  const topProcesses = $derived(
    [...processes]
      .sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out))
      .slice(0, 6),
  );

  const topDestinations = $derived(
    [...destinations]
      .sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out))
      .slice(0, 6),
  );
</script>

{#if !status.snort_running}
  <section class="banner warning">
    <strong>Live capture is off.</strong>
    <p>
      The daemon is running, but Snort is not. Register and approve the
      privileged helper, then start capture from the Capture tab.
    </p>
    <div class="actions">
      <button type="button" onclick={onSetupCapture}>Set up live capture</button>
    </div>
  </section>
{/if}

<section class="capabilities">
  <article>
    <span class="label">Snort</span>
    <span class="value" class:warn={!status.snort_running}>
      {status.snort_running ? "capturing" : "offline"}
    </span>
    <span class="hint">{status.capabilities.version ?? "not found"} · {status.snort_interface ?? "no interface"}</span>
  </article>
  <article>
    <span class="label">Active flows</span>
    <span class="value">{status.active_flows}</span>
    <span class="hint">from nettop on {status.snort_interface ?? "all interfaces"}</span>
  </article>
  <article>
    <span class="label">Processes</span>
    <span class="value">{status.active_processes}</span>
    <span class="hint">with active connections</span>
  </article>
  <article>
    <span class="label">Alerts</span>
    <span class="value">{status.alert_count}</span>
    <span class="hint">{status.alerts_ingested} ingested · {status.parse_errors} parse errors</span>
  </article>
  <article>
    <span class="label">Extractor rows</span>
    <span class="value">{status.extractor_ingested}</span>
    <span class="hint">completed flows and hostnames</span>
  </article>
  <article>
    <span class="label">Destinations</span>
    <span class="value">{status.destination_count}</span>
    <span class="hint">known remote endpoints</span>
  </article>
  <article>
    <span class="label">DNS records</span>
    <span class="value">{status.dns_count}</span>
    <span class="hint">{status.tls_count} TLS · {status.http_count} HTTP · {status.quic_count} QUIC</span>
  </article>
  <article>
    <span class="label">Domains</span>
    <span class="value">{status.domain_count}</span>
    <span class="hint">registrable domains observed</span>
  </article>
  <article>
    <span class="label">Needs review</span>
    <span class="value" class:warn={needsReviewCount > 0}>{needsReviewCount}</span>
    <span class="hint">unknown or flagged domains</span>
  </article>
</section>

<div class="grid">
  <section class="panel">
    <div class="panel-header">
      <h2>Top processes</h2>
    </div>
    <div class="table-wrap short">
      <table>
        <thead><tr><th>Process</th><th>PID</th><th>Conns</th><th>nettop traffic</th></tr></thead>
        <tbody>
          {#each topProcesses as process (process.pid)}
            <tr>
              <td>{process.name}</td>
              <td class="mono">{process.pid}</td>
              <td>{process.connection_count}</td>
              <td>{formatBytes(process.bytes_in + process.bytes_out)}</td>
            </tr>
          {:else}
            <tr><td class="empty" colspan="4">No live processes yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <div class="panel-header">
      <h2>Top destinations</h2>
    </div>
    <div class="table-wrap short">
      <table>
        <thead><tr><th>Destination</th><th>Procs</th><th>Snort / live traffic</th></tr></thead>
        <tbody>
          {#each topDestinations as destination (destination.ip)}
            <tr>
              <td>
                <div class="mono">{destination.ip}</div>
                {#if destination.hostname}<div class="sub">{destination.hostname}</div>{/if}
              </td>
              <td>{destination.process_count}</td>
              <td class="mono">{formatBytes(destination.bytes_in + destination.bytes_out)} / {formatBytes(destination.live_bytes_in + destination.live_bytes_out)}</td>
            </tr>
          {:else}
            <tr><td class="empty" colspan="3">No destinations yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
</div>

<section class="panel fill">
  <div class="panel-header">
    <h2>Recent alerts</h2>
  </div>
  <div class="table-wrap tall">
    <table>
      <thead><tr><th>Time</th><th>SID</th><th>Source</th><th>Destination</th><th>Action</th><th>Message</th></tr></thead>
      <tbody>
        {#each alerts.slice(0, 8) as alert (alert.id)}
          <tr>
            <td class="mono">{formatTime(alert.event_ts)}</td>
            <td class="mono">{alert.sid}</td>
            <td class="mono">{endpoint(alert.src_ip, alert.src_port)}</td>
            <td class="mono">{endpoint(alert.dst_ip, alert.dst_port)}</td>
            <td><span class="tag" class:blocked={alert.action === "blocked"}>{alert.action ?? "-"}</span></td>
            <td>{alert.msg ?? "-"}</td>
          </tr>
        {:else}
          <tr><td class="empty" colspan="6">No alerts yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
