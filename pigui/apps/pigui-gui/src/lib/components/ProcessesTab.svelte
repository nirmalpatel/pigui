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
    Process,
    ProcessDestination,
    ProcessDetail,
  } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let { processes }: { processes: Process[] } = $props();

  let filter = $state("");
  let processSort = $state<SortState | null>(null);
  let processDestinationSort = $state<SortState | null>(null);
  let expandedProcess = $state<number | null>(null);
  let processDetail = $state<ProcessDetail | null>(null);
  let detailLoading = $state(false);

  const processColumns: SortColumns<Process> = {
    process: (process) => process.name,
    pid: (process) => process.pid,
    user: (process) => process.user,
    connections: (process) => process.connection_count,
    bytes_in: (process) => process.bytes_in,
    bytes_out: (process) => process.bytes_out,
    path: (process) => process.path,
    last_seen: (process) => process.last_seen,
  };

  const processDestinationColumns: SortColumns<ProcessDestination> = {
    destination: (destination) => destination.ip,
    domains: (destination) => domainLabel(destination.domains),
    trust: (destination) => trustOrder[destination.trust_state],
    flags: (destination) => destination.flags.length,
    traffic: (destination) => destination.bytes_in + destination.bytes_out,
    connections: (destination) => destination.connection_count,
    last_seen: (destination) => destination.last_seen,
  };

  const sortedProcesses = $derived(
    sortBy(
      filterItems(processes, filter, (process) => [
        process.name,
        process.pid,
        process.user,
        process.path,
      ]),
      processSort,
      processColumns,
    ),
  );

  const sortedProcessDestinations = $derived(
    sortBy(
      processDetail?.destinations ?? [],
      processDestinationSort,
      processDestinationColumns,
    ),
  );

  async function toggleProcess(pid: number) {
    if (expandedProcess === pid) {
      expandedProcess = null;
      processDetail = null;
      return;
    }
    expandedProcess = pid;
    processDetail = null;
    detailLoading = true;
    try {
      processDetail = await invoke<ProcessDetail>("process_detail", { pid });
    } catch (cause) {
      console.warn("Unable to load process detail", cause);
      expandedProcess = null;
    } finally {
      detailLoading = false;
    }
  }
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>Processes</h2>
    <input type="search" placeholder="Filter processes" bind:value={filter} />
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <th></th>
          <SortHeader label="Process" column="process" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="PID" column="pid" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="User" column="user" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="Connections" column="connections" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="Bytes in" column="bytes_in" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="Bytes out" column="bytes_out" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="Path" column="path" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
          <SortHeader label="Last seen" column="last_seen" sort={processSort} onToggle={(key) => (processSort = toggleSort(processSort, key))} />
        </tr>
      </thead>
      <tbody>
        {#each sortedProcesses as process (process.pid)}
          <tr
            class="clickable"
            class:open={expandedProcess === process.pid}
            onclick={() => void toggleProcess(process.pid)}
          >
            <td class="expand">{expandedProcess === process.pid ? "−" : "+"}</td>
            <td>{process.name}</td>
            <td class="mono">{process.pid}</td>
            <td>{process.user ?? "-"}</td>
            <td>{process.connection_count}</td>
            <td>{formatBytes(process.bytes_in)}</td>
            <td>{formatBytes(process.bytes_out)}</td>
            <td class="mono path">{process.path ?? "-"}</td>
            <td class="mono">{formatTime(process.last_seen)}</td>
          </tr>
          {#if expandedProcess === process.pid}
            <tr class="detail-row">
              <td colspan="9">
                <div class="detail-block">
                  <div class="detail-heading">Destinations and domains</div>
                  {#if processDetail}
                    <table class="inner">
                      <thead>
                        <tr>
                          <SortHeader label="Destination" column="destination" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Domains" column="domains" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Trust" column="trust" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Flags" column="flags" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Traffic in/out" column="traffic" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Conns" column="connections" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                          <SortHeader label="Last seen" column="last_seen" sort={processDestinationSort} onToggle={(key) => (processDestinationSort = toggleSort(processDestinationSort, key))} />
                        </tr>
                      </thead>
                      <tbody>
                        {#each sortedProcessDestinations as destination (destination.ip)}
                          <tr>
                            <td class="mono">{destination.ip}</td>
                            <td>{domainLabel(destination.domains)}</td>
                            <td><span class="tag {destination.trust_state}">{destination.trust_state}</span></td>
                            <td>{destination.flags.length ? destination.flags.map(flagLabel).join(", ") : "-"}</td>
                            <td class="mono">{formatBytes(destination.bytes_in)} / {formatBytes(destination.bytes_out)}</td>
                            <td>{destination.connection_count}</td>
                            <td class="mono">{formatTime(destination.last_seen)}</td>
                          </tr>
                        {:else}
                          <tr><td class="empty" colspan="7">No attributed destinations for this process.</td></tr>
                        {/each}
                      </tbody>
                    </table>
                  {:else}
                    <div class="detail-note">
                      {detailLoading ? "Loading destinations..." : "No destinations."}
                    </div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {:else}
          <tr><td class="empty" colspan="9">No processes captured yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
