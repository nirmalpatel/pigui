<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import AlertsTab from "./lib/components/AlertsTab.svelte";
  import CaptureTab from "./lib/components/CaptureTab.svelte";
  import ConnectionsTab from "./lib/components/ConnectionsTab.svelte";
  import DestinationsTab from "./lib/components/DestinationsTab.svelte";
  import DnsTab from "./lib/components/DnsTab.svelte";
  import DomainsTab from "./lib/components/DomainsTab.svelte";
  import Header from "./lib/components/Header.svelte";
  import OverviewTab from "./lib/components/OverviewTab.svelte";
  import ProcessesTab from "./lib/components/ProcessesTab.svelte";
  import TabNav from "./lib/components/TabNav.svelte";
  import { needsReview } from "./lib/display";
  import type {
    AlertList,
    AlertRecord,
    Connection,
    ConnectionList,
    Destination,
    DestinationList,
    DnsList,
    DnsObservation,
    DomainList,
    DomainSummary,
    Flow,
    FlowList,
    Process,
    ProcessList,
    StatusPayload,
    Tab,
    WatchedDomain,
    WatchedList,
  } from "./lib/types";

  let tab = $state<Tab>("overview");
  let status = $state<StatusPayload | null>(null);
  let alerts = $state<AlertRecord[]>([]);
  let destinations = $state<Destination[]>([]);
  let flows = $state<Flow[]>([]);
  let processes = $state<Process[]>([]);
  let connections = $state<Connection[]>([]);
  let domains = $state<DomainSummary[]>([]);
  let dnsObservations = $state<DnsObservation[]>([]);
  let watchedDomains = $state<WatchedDomain[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let lastUpdated = $state("");
  let startingDaemon = $state(false);

  const needsReviewCount = $derived(
    domains.filter((domain) => needsReview(domain)).length,
  );

  async function refresh() {
    refreshing = true;
    try {
      const [
        nextStatus,
        nextAlerts,
        nextDestinations,
        nextFlows,
        nextProcesses,
        nextConnections,
        nextDomains,
        nextDns,
        nextWatched,
      ] = await Promise.all([
        invoke<StatusPayload>("get_status"),
        invoke<AlertList>("list_alerts", { limit: 200 }),
        invoke<DestinationList>("list_destinations", { limit: 200 }),
        invoke<FlowList>("list_flows", { limit: 300 }),
        invoke<ProcessList>("list_processes", { limit: 200 }),
        invoke<ConnectionList>("list_connections", { limit: 200 }),
        invoke<DomainList>("list_domains", { limit: 300 }),
        invoke<DnsList>("list_dns", { limit: 500 }),
        invoke<WatchedList>("list_watched_domains"),
      ]);
      status = nextStatus;
      alerts = nextAlerts.alerts;
      destinations = nextDestinations.destinations;
      flows = nextFlows.flows;
      processes = nextProcesses.processes;
      connections = nextConnections.connections;
      domains = nextDomains.domains;
      dnsObservations = nextDns.observations;
      watchedDomains = nextWatched.watched;
      error = null;
      lastUpdated = new Date().toLocaleTimeString();
    } catch (cause) {
      error = String(cause);
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  async function startDaemon() {
    startingDaemon = true;
    try {
      await invoke<string>("start_daemon");
      await refresh();
    } catch (cause) {
      error = String(cause);
    } finally {
      startingDaemon = false;
    }
  }

  onMount(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 2000);
    return () => {
      clearInterval(timer);
    };
  });
</script>

<main>
  <Header
    {status}
    {lastUpdated}
    {refreshing}
    onRefresh={() => void refresh()}
  />

  <div class="content">
    {#if error}
      <section class="banner error">
        <strong>Daemon unreachable.</strong>
        {error}
        <p>
          The packaged app starts its bundled daemon automatically. If it did not,
          start it now. In development, use <code>scripts/run-dev.sh</code> or
          <code>cargo run -p pigui-daemon</code>.
        </p>
        <button type="button" onclick={() => void startDaemon()} disabled={startingDaemon}>
          {startingDaemon ? "Starting..." : "Start daemon"}
        </button>
      </section>
    {:else if loading}
      <section class="banner">Connecting to pigui-daemon...</section>
    {/if}

    {#if status}
      {#if status.collector_error}
        <section class="banner warning">
          <strong>Collector error</strong>
          {status.collector_error}
        </section>
      {/if}
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
      {#if status.extractor_idle}
        <section class="banner warning">
          <strong>Extractor is not producing telemetry.</strong>
          Alerts are arriving but no DNS, TLS, HTTP, QUIC, or connection records have
          been ingested. Stop Snort, regenerate the configuration, and restart live capture.
        </section>
      {/if}

      <TabNav
        {tab}
        flows={flows.length}
        processes={processes.length}
        destinations={destinations.length}
        needsReview={needsReviewCount}
        dns={dnsObservations.length}
        alerts={alerts.length}
        onSelect={(next) => {
          tab = next;
        }}
      />

      {#if tab === "overview"}
        <OverviewTab
          {status}
          {processes}
          {destinations}
          {alerts}
          {needsReviewCount}
          onSetupCapture={() => {
            tab = "capture";
          }}
        />
      {:else if tab === "connections"}
        <ConnectionsTab {flows} {connections} />
      {:else if tab === "processes"}
        <ProcessesTab {processes} />
      {:else if tab === "destinations"}
        <DestinationsTab {destinations} />
      {:else if tab === "domains"}
        <DomainsTab {domains} {watchedDomains} onRefresh={refresh} />
      {:else if tab === "dns"}
        <DnsTab {dnsObservations} />
      {:else if tab === "alerts"}
        <AlertsTab {alerts} />
      {:else if tab === "capture"}
        <CaptureTab {status} onRefresh={refresh} />
      {/if}
    {/if}
  </div>

  {#if status}
    <footer>
      <span>database <code>{status.db_path}</code></span>
      <span>socket <code>{status.socket_path}</code></span>
      <span>uptime {status.uptime_secs}s</span>
    </footer>
  {/if}
</main>
