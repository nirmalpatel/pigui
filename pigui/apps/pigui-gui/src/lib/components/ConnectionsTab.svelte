<script lang="ts">
  import {
    endpoint,
    formatBytes,
    formatTime,
  } from "../display";
  import { filterItems } from "../filter";
  import {
    sortBy,
    toggleSort,
    type SortColumns,
    type SortState,
  } from "../sort";
  import type { Connection, Flow } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let { flows, connections }: { flows: Flow[]; connections: Connection[] } =
    $props();

  let filter = $state("");
  let flowSort = $state<SortState | null>(null);
  let connectionSort = $state<SortState | null>(null);

  const flowColumns: SortColumns<Flow> = {
    process: (flow) => flow.process_name,
    pid: (flow) => flow.pid,
    proto: (flow) => flow.proto,
    local: (flow) => endpoint(flow.client_ip, flow.client_port),
    remote: (flow) => endpoint(flow.server_ip, flow.server_port),
    state: (flow) => flow.state,
    interface: (flow) => flow.interface,
    traffic: (flow) => flow.bytes_ab + flow.bytes_ba,
    seen: (flow) => flow.last_seen,
  };

  const connectionColumns: SortColumns<Connection> = {
    time: (connection) => connection.ts,
    process: (connection) => connection.process_name,
    pid: (connection) => connection.pid,
    proto: (connection) => connection.proto,
    remote: (connection) =>
      endpoint(connection.server_ip, connection.server_port),
    service: (connection) => connection.service,
    state: (connection) => connection.conn_state,
    traffic: (connection) => connection.bytes_ab + connection.bytes_ba,
  };

  const sortedFlows = $derived(
    sortBy(
      filterItems(flows, filter, (flow) => [
        flow.process_name,
        flow.proto,
        flow.state,
        flow.client_ip,
        flow.server_ip,
        flow.server_port,
        flow.interface,
      ]),
      flowSort,
      flowColumns,
    ),
  );

  const sortedConnections = $derived(
    sortBy(
      filterItems(connections, filter, (connection) => [
        connection.process_name,
        connection.proto,
        connection.server_ip,
        connection.service,
        connection.conn_state,
      ]),
      connectionSort,
      connectionColumns,
    ),
  );
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>Live process connections</h2>
    <input type="search" placeholder="Filter live process connections" bind:value={filter} />
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <SortHeader label="Process" column="process" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="PID" column="pid" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Protocol" column="proto" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Local" column="local" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Remote" column="remote" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="State" column="state" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Interface" column="interface" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Sent / received" column="traffic" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
          <SortHeader label="Last seen" column="seen" sort={flowSort} onToggle={(key) => (flowSort = toggleSort(flowSort, key))} />
        </tr>
      </thead>
      <tbody>
        {#each sortedFlows as flow (flow.id)}
          <tr>
            <td>{flow.process_name ?? "-"}</td>
            <td class="mono">{flow.pid ?? "-"}</td>
            <td>{flow.proto}</td>
            <td class="mono">{endpoint(flow.client_ip, flow.client_port)}</td>
            <td class="mono">{endpoint(flow.server_ip, flow.server_port)}</td>
            <td>{flow.state ?? "-"}</td>
            <td>{flow.interface ?? "-"}</td>
            <td class="mono">{formatBytes(flow.bytes_ab)} / {formatBytes(flow.bytes_ba)}</td>
            <td class="mono">{formatTime(flow.last_seen)}</td>
          </tr>
        {:else}
          <tr><td class="empty" colspan="9">No live process connections yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<section class="panel fill">
  <div class="panel-header">
    <h2>Completed Snort connections</h2>
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <SortHeader label="Time" column="time" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="Process" column="process" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="PID" column="pid" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="Protocol" column="proto" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="Remote" column="remote" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="Service" column="service" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="State" column="state" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
          <SortHeader label="Sent / received" column="traffic" sort={connectionSort} onToggle={(key) => (connectionSort = toggleSort(connectionSort, key))} />
        </tr>
      </thead>
      <tbody>
        {#each sortedConnections as connection (connection.id)}
          <tr>
            <td class="mono">{formatTime(connection.ts)}</td>
            <td>{connection.process_name ?? "-"}</td>
            <td class="mono">{connection.pid ?? "-"}</td>
            <td>{connection.proto ?? "-"}</td>
            <td class="mono">{endpoint(connection.server_ip, connection.server_port)}</td>
            <td>{connection.service ?? "-"}</td>
            <td>{connection.conn_state ?? "-"}</td>
            <td class="mono">{formatBytes(connection.bytes_ab)} / {formatBytes(connection.bytes_ba)}</td>
          </tr>
        {:else}
          <tr><td class="empty" colspan="8">No completed Snort connections yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
