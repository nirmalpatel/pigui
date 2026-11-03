<script lang="ts">
  import { formatTime, numericValue } from "../display";
  import { filterItems } from "../filter";
  import {
    sortBy,
    toggleSort,
    type SortColumns,
    type SortState,
  } from "../sort";
  import type { DnsObservation, ListQueryState } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let {
    dnsObservations,
    onQuery,
  }: {
    dnsObservations: DnsObservation[];
    onQuery?: (query: ListQueryState) => void;
  } = $props();

  let filter = $state("");
  let dnsSort = $state<SortState | null>(null);

  function emitQuery() {
    onQuery?.({
      q: filter.trim() || undefined,
      sort: dnsSort?.key,
      dir: dnsSort?.direction,
    });
  }

  function toggleDnsSort(key: string) {
    dnsSort = toggleSort(dnsSort, key);
    emitQuery();
  }

  const dnsColumns: SortColumns<DnsObservation> = {
    time: (observation) => observation.ts,
    client: (observation) => observation.client_ip,
    query: (observation) => observation.query,
    type: (observation) => observation.qtype,
    rcode: (observation) => observation.rcode,
    answers: (observation) => observation.answers,
    ttl: (observation) => numericValue(observation.ttl),
  };

  const sortedDns = $derived(
    sortBy(
      filterItems(dnsObservations, filter, (observation) => [
        observation.query,
        observation.answers,
        observation.qtype,
        observation.rcode,
        observation.client_ip,
      ]),
      dnsSort,
      dnsColumns,
    ),
  );
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>DNS queries <span class="hint">Snort telemetry</span></h2>
    <input type="search" placeholder="Filter DNS queries" bind:value={filter} oninput={emitQuery} />
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <SortHeader label="Time" column="time" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="Client" column="client" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="Query" column="query" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="Type" column="type" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="Rcode" column="rcode" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="Answers" column="answers" sort={dnsSort} onToggle={toggleDnsSort} />
          <SortHeader label="TTL" column="ttl" sort={dnsSort} onToggle={toggleDnsSort} />
        </tr>
      </thead>
      <tbody>
        {#each sortedDns as observation (observation.id)}
          <tr>
            <td class="mono">{formatTime(observation.ts)}</td>
            <td class="mono">{observation.client_ip ?? "-"}</td>
            <td class="domain">{observation.query ?? "-"}</td>
            <td>{observation.qtype ?? "-"}</td>
            <td>{observation.rcode ?? "-"}</td>
            <td class="mono">{observation.answers ?? "-"}</td>
            <td class="mono">{observation.ttl ?? "-"}</td>
          </tr>
        {:else}
          <tr>
            <td class="empty" colspan="7">
              No DNS queries yet. Snort telemetry must see DNS responses on port 53
              while capture is running; DoH/DoT traffic will not appear here.
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
