<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import AlertsTab from "./lib/components/AlertsTab.svelte";
  import CaptureTab from "./lib/components/CaptureTab.svelte";
  import ConnectionsTab from "./lib/components/ConnectionsTab.svelte";
  import DestinationsTab from "./lib/components/DestinationsTab.svelte";
  import DnsTab from "./lib/components/DnsTab.svelte";
  import DomainsTab from "./lib/components/DomainsTab.svelte";
  import FirewallTab from "./lib/components/FirewallTab.svelte";
  import Header from "./lib/components/Header.svelte";
  import OverviewTab from "./lib/components/OverviewTab.svelte";
  import PaginationBar from "./lib/components/PaginationBar.svelte";
  import ProcessesTab from "./lib/components/ProcessesTab.svelte";
  import SettingsTab from "./lib/components/SettingsTab.svelte";
  import TabNav from "./lib/components/TabNav.svelte";
  import { degradedReasonLabel, needsReview } from "./lib/display";
  import type {
    AlertList,
    AlertRecord,
    AppSettings,
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
    ListQueryState,
    ProcessList,
    StatusPayload,
    Tab,
    WatchedDomain,
    WatchedList,
  } from "./lib/types";

  let tab = $state<Tab>("overview");
  let status = $state<StatusPayload | null>(null);
  let settings = $state<AppSettings | null>(null);
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
  let autoCaptureError = $state<string | null>(null);
  let lastAutoCaptureAttempt = 0;

  let alertsOffset = $state(0);
  let alertsLimit = $state(200);
  let alertsTotal = $state(0);
  let destinationsOffset = $state(0);
  let destinationsLimit = $state(200);
  let destinationsTotal = $state(0);
  let flowsOffset = $state(0);
  let flowsLimit = $state(300);
  let flowsTotal = $state(0);
  let processesOffset = $state(0);
  let processesLimit = $state(200);
  let processesTotal = $state(0);
  let connectionsOffset = $state(0);
  let connectionsLimit = $state(200);
  let connectionsTotal = $state(0);
  let domainsOffset = $state(0);
  let domainsLimit = $state(300);
  let domainsTotal = $state(0);
  let dnsOffset = $state(0);
  let dnsLimit = $state(500);
  let dnsTotal = $state(0);

  let alertsQuery = $state<ListQueryState>({});
  let destinationsQuery = $state<ListQueryState>({});
  let processesQuery = $state<ListQueryState>({});
  let connectionsQuery = $state<ListQueryState>({});
  let domainsQuery = $state<ListQueryState>({});
  let dnsQuery = $state<ListQueryState>({});

  const pageSize = $derived(settings?.ui.page_size ?? 200);
  const refreshMs = $derived(settings?.ui.refresh_ms ?? 2000);

  const needsReviewCount = $derived(
    domains.filter((domain) => needsReview(domain)).length,
  );

  const dbTotals = $derived<Partial<Record<Tab, number>>>({
    connections: (status?.active_flows ?? 0) + (status?.connection_count ?? 0),
    processes: status?.active_processes ?? 0,
    destinations: status?.destination_count ?? 0,
    domains: status?.domain_count ?? 0,
    dns: status?.dns_count ?? 0,
    alerts: status?.alert_count ?? 0,
    firewall: status?.firewall_rule_count ?? 0,
  });

  const activePage = $derived.by(() => {
    switch (tab) {
      case "alerts":
        return {
          total: alertsTotal,
          offset: alertsOffset,
          loaded: alerts.length,
          dbTotal: dbTotals.alerts ?? 0,
          filtering: Boolean(alertsQuery.q),
        };
      case "destinations":
        return {
          total: destinationsTotal,
          offset: destinationsOffset,
          loaded: destinations.length,
          dbTotal: dbTotals.destinations ?? 0,
          filtering: Boolean(destinationsQuery.q),
        };
      case "connections":
        return {
          total: flowsTotal + connectionsTotal,
          offset: flowsOffset,
          loaded: flows.length + connections.length,
          dbTotal: dbTotals.connections ?? 0,
          filtering: Boolean(connectionsQuery.q),
        };
      case "processes":
        return {
          total: processesTotal,
          offset: processesOffset,
          loaded: processes.length,
          dbTotal: dbTotals.processes ?? 0,
          filtering: Boolean(processesQuery.q),
        };
      case "domains":
        return {
          total: domainsTotal,
          offset: domainsOffset,
          loaded: domains.length,
          dbTotal: dbTotals.domains ?? 0,
          filtering: Boolean(domainsQuery.q || domainsQuery.trust),
        };
      case "dns":
        return {
          total: dnsTotal,
          offset: dnsOffset,
          loaded: dnsObservations.length,
          dbTotal: dbTotals.dns ?? 0,
          filtering: Boolean(dnsQuery.q),
        };
      default:
        return null;
    }
  });

  function pageLimits(size: number) {
    alertsLimit = size;
    destinationsLimit = size;
    flowsLimit = size;
    processesLimit = size;
    connectionsLimit = size;
    domainsLimit = size;
    dnsLimit = size;
  }

  function resetPages() {
    const size = pageSize;
    pageLimits(size);
    alertsOffset = 0;
    destinationsOffset = 0;
    flowsOffset = 0;
    processesOffset = 0;
    connectionsOffset = 0;
    domainsOffset = 0;
    dnsOffset = 0;
  }

  async function loadSettings() {
    try {
      settings = await invoke<AppSettings>("get_settings");
      pageLimits(pageSize);
    } catch (cause) {
      console.warn("Unable to load settings", cause);
    }
  }

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
        invoke<AlertList>("list_alerts", { limit: alertsLimit, offset: alertsOffset, ...alertsQuery }),
        invoke<DestinationList>("list_destinations", { limit: destinationsLimit, offset: destinationsOffset, ...destinationsQuery }),
        invoke<FlowList>("list_flows", { limit: flowsLimit, offset: flowsOffset, ...connectionsQuery }),
        invoke<ProcessList>("list_processes", { limit: processesLimit, offset: processesOffset, ...processesQuery }),
        invoke<ConnectionList>("list_connections", { limit: connectionsLimit, offset: connectionsOffset, ...connectionsQuery }),
        invoke<DomainList>("list_domains", { limit: domainsLimit, offset: domainsOffset, ...domainsQuery }),
        invoke<DnsList>("list_dns", { limit: dnsLimit, offset: dnsOffset, ...dnsQuery }),
        invoke<WatchedList>("list_watched_domains"),
      ]);
      status = nextStatus;
      alerts = nextAlerts.alerts;
      alertsTotal = nextAlerts.total;
      destinations = nextDestinations.destinations;
      destinationsTotal = nextDestinations.total;
      flows = nextFlows.flows;
      flowsTotal = nextFlows.total;
      processes = nextProcesses.processes;
      processesTotal = nextProcesses.total;
      connections = nextConnections.connections;
      connectionsTotal = nextConnections.total;
      domains = nextDomains.domains;
      domainsTotal = nextDomains.total;
      dnsObservations = nextDns.observations;
      dnsTotal = nextDns.total;
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

  function changePage(delta: -1 | 1) {
    const offsetFor = (offset: number) =>
      Math.max(0, offset + delta * pageSize);
    switch (tab) {
      case "alerts":
        alertsOffset = offsetFor(alertsOffset);
        alertsLimit = pageSize;
        break;
      case "destinations":
        destinationsOffset = offsetFor(destinationsOffset);
        destinationsLimit = pageSize;
        break;
      case "processes":
        processesOffset = offsetFor(processesOffset);
        processesLimit = pageSize;
        break;
      case "domains":
        domainsOffset = offsetFor(domainsOffset);
        domainsLimit = pageSize;
        break;
      case "dns":
        dnsOffset = offsetFor(dnsOffset);
        dnsLimit = pageSize;
        break;
      case "connections": {
        const nextOffset = offsetFor(flowsOffset);
        flowsOffset = nextOffset;
        connectionsOffset = nextOffset;
        flowsLimit = pageSize;
        connectionsLimit = pageSize;
        break;
      }
    }
    void refresh();
  }

  function applyQuery(
    kind: "alerts" | "destinations" | "processes" | "domains" | "dns" | "connections",
    query: ListQueryState,
  ) {
    switch (kind) {
      case "alerts":
        alertsQuery = query;
        alertsOffset = 0;
        alertsLimit = pageSize;
        break;
      case "destinations":
        destinationsQuery = query;
        destinationsOffset = 0;
        destinationsLimit = pageSize;
        break;
      case "processes":
        processesQuery = query;
        processesOffset = 0;
        processesLimit = pageSize;
        break;
      case "domains":
        domainsQuery = query;
        domainsOffset = 0;
        domainsLimit = pageSize;
        break;
      case "dns":
        dnsQuery = query;
        dnsOffset = 0;
        dnsLimit = pageSize;
        break;
      case "connections":
        connectionsQuery = query;
        flowsOffset = 0;
        connectionsOffset = 0;
        flowsLimit = pageSize;
        connectionsLimit = pageSize;
        break;
    }
    void refresh();
  }

  async function maybeAutoCapture() {
    if (!status || status.environment !== "prod" || status.capture_running) {
      autoCaptureError = null;
      return;
    }
    const now = Date.now();
    if (now - lastAutoCaptureAttempt < 10_000) {
      return;
    }
    lastAutoCaptureAttempt = now;
    try {
      await invoke("ensure_capture");
      autoCaptureError = null;
      await refresh();
    } catch (cause) {
      autoCaptureError = String(cause);
    }
  }

  function handleSettingsChanged(next: AppSettings) {
    settings = next;
    resetPages();
    void refresh();
  }

  onMount(() => {
    void loadSettings();
    void refresh().then(() => maybeAutoCapture());
  });

  $effect(() => {
    const interval = setInterval(
      () => void refresh().then(() => maybeAutoCapture()),
      refreshMs,
    );
    return () => clearInterval(interval);
  });
</script>

<main>
  <Header
    {status}
    {settings}
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
          <strong>Process collector error</strong>
          {status.collector_error}
        </section>
      {/if}
      {#if status.degraded.length > 0}
        <section class="banner warning">
          <strong>Degraded capabilities</strong>
          <ul>
            {#each status.degraded as reason}
              <li>{degradedReasonLabel(reason)}</li>
            {/each}
          </ul>
        </section>
      {/if}
      {#if status.extractor_idle}
        <section class="banner warning">
          <strong>Snort telemetry is not arriving.</strong>
          Snort alerts are arriving but no connection, DNS, TLS, HTTP, or QUIC
          records have been ingested. Stop Snort, regenerate the configuration,
          and restart capture.
        </section>
      {/if}

      <TabNav
        {tab}
        totals={dbTotals}
        onSelect={(next) => {
          tab = next;
        }}
      />

      {#if activePage}
        <PaginationBar
          total={activePage.total}
          dbTotal={activePage.dbTotal}
          offset={activePage.offset}
          loaded={activePage.loaded}
          filtering={activePage.filtering}
          loading={refreshing}
          onPrev={() => changePage(-1)}
          onNext={() => changePage(1)}
        />
      {/if}

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
        <ConnectionsTab
          {flows}
          {connections}
          onQuery={(query) => applyQuery("connections", query)}
        />
      {:else if tab === "processes"}
        <ProcessesTab {processes} onQuery={(query) => applyQuery("processes", query)} />
      {:else if tab === "destinations"}
        <DestinationsTab {destinations} onQuery={(query) => applyQuery("destinations", query)} />
      {:else if tab === "domains"}
        <DomainsTab {domains} {watchedDomains} onRefresh={refresh} onQuery={(query) => applyQuery("domains", query)} />
      {:else if tab === "dns"}
        <DnsTab {dnsObservations} onQuery={(query) => applyQuery("dns", query)} />
      {:else if tab === "alerts"}
        <AlertsTab {alerts} onQuery={(query) => applyQuery("alerts", query)} />
      {:else if tab === "firewall"}
        <FirewallTab onRefresh={refresh} />
      {:else if tab === "capture"}
        <CaptureTab {status} {autoCaptureError} onRefresh={refresh} />
      {:else if tab === "settings"}
        {#if settings}
          <SettingsTab {settings} onChanged={handleSettingsChanged} />
        {:else}
          <section class="panel fill"><p class="detail-note">Loading settings...</p></section>
        {/if}
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
