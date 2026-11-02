<script lang="ts">
  import { endpoint, formatTime } from "../display";
  import { filterItems } from "../filter";
  import {
    sortBy,
    toggleSort,
    type SortColumns,
    type SortState,
  } from "../sort";
  import type { AlertRecord } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let { alerts }: { alerts: AlertRecord[] } = $props();

  let filter = $state("");
  let alertSort = $state<SortState | null>(null);

  const alertColumns: SortColumns<AlertRecord> = {
    time: (alert) => alert.event_ts,
    sid: (alert) => alert.sid,
    priority: (alert) => alert.priority,
    proto: (alert) => alert.proto,
    source: (alert) => endpoint(alert.src_ip, alert.src_port),
    destination: (alert) => endpoint(alert.dst_ip, alert.dst_port),
    action: (alert) => alert.action,
    message: (alert) => alert.msg,
  };

  const sortedAlerts = $derived(
    sortBy(
      filterItems(alerts, filter, (alert) => [
        alert.msg,
        alert.sid,
        alert.src_ip,
        alert.dst_ip,
        alert.action,
        alert.proto,
      ]),
      alertSort,
      alertColumns,
    ),
  );
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>Alerts</h2>
    <input type="search" placeholder="Filter alerts" bind:value={filter} />
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <SortHeader label="Time" column="time" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="SID" column="sid" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Priority" column="priority" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Proto" column="proto" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Source" column="source" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Destination" column="destination" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Action" column="action" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
          <SortHeader label="Message" column="message" sort={alertSort} onToggle={(key) => (alertSort = toggleSort(alertSort, key))} />
        </tr>
      </thead>
      <tbody>
        {#each sortedAlerts as alert (alert.id)}
          <tr>
            <td class="mono">{formatTime(alert.event_ts)}</td>
            <td class="mono">{alert.sid}</td>
            <td>{alert.priority ?? "-"}</td>
            <td>{alert.proto ?? "-"}</td>
            <td class="mono">{endpoint(alert.src_ip, alert.src_port)}</td>
            <td class="mono">{endpoint(alert.dst_ip, alert.dst_port)}</td>
            <td><span class="tag" class:blocked={alert.action === "blocked"}>{alert.action ?? "-"}</span></td>
            <td>{alert.msg ?? "-"}</td>
          </tr>
        {:else}
          <tr><td class="empty" colspan="8">No alerts ingested yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
