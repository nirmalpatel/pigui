<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    domainLabel,
    flagLabel,
    formatBytes,
    formatTime,
    trustOrder,
  } from "../display";
  import { filterItems } from "../filter";
  import {
    sortBy,
    toggleSort,
    type SortColumns,
    type SortState,
  } from "../sort";
  import type {
    Destination,
    DestinationDetail,
    DestinationProcess,
    ListQueryState,
  } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let {
    destinations,
    onQuery,
  }: {
    destinations: Destination[];
    onQuery?: (query: ListQueryState) => void;
  } = $props();

  let filter = $state("");
  let destinationSort = $state<SortState | null>(null);

  function emitQuery() {
    onQuery?.({
      q: filter.trim() || undefined,
      sort: destinationSort?.key,
      dir: destinationSort?.direction,
    });
  }

  function toggleDestinationSort(key: string) {
    destinationSort = toggleSort(destinationSort, key);
    emitQuery();
  }
  let destinationProcessSort = $state<SortState | null>(null);
  let expandedDestination = $state<string | null>(null);
  let destinationDetail = $state<DestinationDetail | null>(null);
  let detailLoading = $state(false);

  const destinationColumns: SortColumns<Destination> = {
    ip: (destination) => destination.ip,
    domains: (destination) => domainLabel(destination.domains),
    trust: (destination) => trustOrder[destination.trust_state],
    flags: (destination) => destination.flags.length,
    processes: (destination) => destination.process_count,
    connections: (destination) => destination.connection_count,
    alerts: (destination) => destination.alert_count,
    bytes_in: (destination) => destination.bytes_in,
    bytes_out: (destination) => destination.bytes_out,
    first_seen: (destination) => destination.first_seen,
    last_seen: (destination) => destination.last_seen,
  };

  const destinationProcessColumns: SortColumns<DestinationProcess> = {
    process: (process) => process.process_name,
    pid: (process) => process.pid,
    traffic: (process) =>
      process.snort_bytes_in +
      process.snort_bytes_out +
      process.live_bytes_in +
      process.live_bytes_out,
    connections: (process) => process.connection_count,
    last_seen: (process) => process.last_seen,
  };

  const sortedDestinations = $derived(
    sortBy(
      filterItems(destinations, filter, (destination) => [
        destination.ip,
        destination.hostname,
        destination.trust_state,
        ...destination.domains.map((domain) => domain.domain),
      ]),
      destinationSort,
      destinationColumns,
    ),
  );

  const sortedDestinationProcesses = $derived(
    sortBy(
      destinationDetail?.processes ?? [],
      destinationProcessSort,
      destinationProcessColumns,
    ),
  );

  async function toggleDestination(ip: string) {
    if (expandedDestination === ip) {
      expandedDestination = null;
      destinationDetail = null;
      return;
    }
    expandedDestination = ip;
    destinationDetail = null;
    detailLoading = true;
    try {
      destinationDetail = await invoke<DestinationDetail>("destination_detail", {
        ip,
      });
    } catch (cause) {
      console.warn("Unable to load destination detail", cause);
      expandedDestination = null;
    } finally {
      detailLoading = false;
    }
  }
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>Destinations <span class="hint">Snort + process correlation</span></h2>
    <input type="search" placeholder="Filter destinations" bind:value={filter} oninput={emitQuery} />
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <th></th>
          <SortHeader label="IP" column="ip" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Domains" column="domains" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Trust" column="trust" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Review" column="flags" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Processes" column="processes" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Snort connections" column="connections" sort={destinationSort} onToggle={toggleDestinationSort} />
          <th>Process connections</th>
          <SortHeader label="Snort alerts" column="alerts" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Snort received" column="bytes_in" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Snort sent" column="bytes_out" sort={destinationSort} onToggle={toggleDestinationSort} />
          <th>Process received / sent</th>
          <SortHeader label="First seen" column="first_seen" sort={destinationSort} onToggle={toggleDestinationSort} />
          <SortHeader label="Last seen" column="last_seen" sort={destinationSort} onToggle={toggleDestinationSort} />
        </tr>
      </thead>
      <tbody>
        {#each sortedDestinations as destination (destination.ip)}
          <tr
            class="clickable"
            class:open={expandedDestination === destination.ip}
            onclick={() => void toggleDestination(destination.ip)}
          >
            <td class="expand">{expandedDestination === destination.ip ? "−" : "+"}</td>
            <td class="mono">{destination.ip}</td>
            <td>{domainLabel(destination.domains)}</td>
            <td><span class="tag {destination.trust_state}">{destination.trust_state}</span></td>
            <td>{destination.flags.length ? destination.flags.map(flagLabel).join(", ") : "-"}</td>
            <td>{destination.process_count}</td>
            <td>{destination.connection_count}</td>
            <td>{destination.live_connection_count}</td>
            <td>{destination.alert_count}</td>
            <td>{formatBytes(destination.bytes_in)}</td>
            <td>{formatBytes(destination.bytes_out)}</td>
            <td class="mono">{formatBytes(destination.live_bytes_in)} / {formatBytes(destination.live_bytes_out)}</td>
            <td class="mono">{formatTime(destination.first_seen)}</td>
            <td class="mono">{formatTime(destination.last_seen)}</td>
          </tr>
          {#if expandedDestination === destination.ip}
            <tr class="detail-row">
              <td colspan="14">
                <div class="detail-block">
                  <div class="detail-heading">Processes using this destination</div>
                  {#if destinationDetail}
                    <table class="inner">
                      <thead>
                        <tr>
                          <SortHeader label="Process" column="process" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                          <SortHeader label="PID" column="pid" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                          <SortHeader label="Snort received / sent" column="traffic" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                          <SortHeader label="Process received / sent" column="traffic" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                          <SortHeader label="Connections" column="connections" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                          <SortHeader label="Last seen" column="last_seen" sort={destinationProcessSort} onToggle={(key) => (destinationProcessSort = toggleSort(destinationProcessSort, key))} />
                        </tr>
                      </thead>
                      <tbody>
                        {#each sortedDestinationProcesses as process (process.pid ?? process.process_name)}
                          <tr>
                            <td>{process.process_name ?? "-"}</td>
                            <td class="mono">{process.pid ?? "-"}</td>
                            <td class="mono">{formatBytes(process.snort_bytes_in)} / {formatBytes(process.snort_bytes_out)}</td>
                            <td class="mono">{formatBytes(process.live_bytes_in)} / {formatBytes(process.live_bytes_out)}</td>
                            <td>{process.connection_count}</td>
                            <td class="mono">{formatTime(process.last_seen)}</td>
                          </tr>
                        {:else}
                          <tr><td class="empty" colspan="6">No process attribution for this destination.</td></tr>
                        {/each}
                      </tbody>
                    </table>
                  {:else}
                    <div class="detail-note">
                      {detailLoading ? "Loading processes..." : "No processes."}
                    </div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {:else}
          <tr><td class="empty" colspan="14">No destinations yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
