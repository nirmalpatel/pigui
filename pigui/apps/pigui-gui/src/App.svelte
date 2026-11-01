<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  type ThemeMode = "system" | "light" | "dark";

  interface AppSettings {
    theme: ThemeMode;
  }

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
    mode: string;
    snort_running: boolean;
    snort_pid?: number;
    snort_interface?: string;
    active_flows: number;
    active_processes: number;
    extractor_ingested: number;
    extractor_file: string;
    extractor_size: number;
    extractor_modified?: number;
    extractor_last_ingest?: number;
    extractor_idle: boolean;
    dns_count: number;
    tls_count: number;
    http_count: number;
    quic_count: number;
    domain_count: number;
    collector_error?: string;
  }

  interface AlertRecord {
    id: number;
    event_ts: number;
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
    service?: string;
    rule?: string;
    ingested_at: number;
  }

  interface AlertList {
    alerts: AlertRecord[];
    total: number;
  }

  interface DnsObservation {
    id: number;
    ts: number;
    client_ip?: string;
    query?: string;
    qtype?: string;
    rcode?: string;
    answers?: string;
    ttl?: string;
  }

  interface DnsList {
    observations: DnsObservation[];
    total: number;
  }

  interface WatchedDomain {
    domain: string;
    registrable_domain: string;
    enabled: boolean;
    last_resolved_at?: number;
    last_error?: string;
  }

  interface WatchedList {
    watched: WatchedDomain[];
  }

  type TrustState = "unknown" | "trusted" | "suspicious" | "ignored";
  type ReviewFlag =
    | "new_domain"
    | "no_domain"
    | "invalid_tls"
    | "alerts"
    | "unknown_trust";

  interface EndpointDomain {
    domain: string;
    registrable_domain: string;
    source: string;
    server_port?: number;
    trust_state: TrustState;
    first_seen: number;
    last_seen: number;
  }

  interface DomainSummary {
    domain: string;
    hostnames: string[];
    sources: string[];
    trust_state: TrustState;
    first_seen: number;
    last_seen: number;
    observation_count: number;
    endpoint_count: number;
    process_count: number;
    flags: ReviewFlag[];
  }

  interface DomainList {
    domains: DomainSummary[];
    total: number;
  }

  interface Destination {
    ip: string;
    hostname?: string;
    first_seen: number;
    last_seen: number;
    bytes_in: number;
    bytes_out: number;
    connection_count: number;
    process_count: number;
    alert_count: number;
    blocked: boolean;
    domains: EndpointDomain[];
    trust_state: TrustState;
    flags: ReviewFlag[];
  }

  interface DestinationList {
    destinations: Destination[];
    total: number;
  }

  interface DestinationProcess {
    pid?: number;
    process_name?: string;
    bytes_in: number;
    bytes_out: number;
    connection_count: number;
    last_seen: number;
  }

  interface DestinationDetail {
    destination: Destination;
    processes: DestinationProcess[];
    recent_alerts: AlertRecord[];
  }

  interface ProcessDestination {
    ip: string;
    domains: EndpointDomain[];
    trust_state: TrustState;
    flags: ReviewFlag[];
    bytes_in: number;
    bytes_out: number;
    connection_count: number;
    last_seen: number;
  }

  interface ProcessDetail {
    process: Process;
    destinations: ProcessDestination[];
  }

  interface Flow {
    id: number;
    proto: string;
    client_ip: string;
    client_port: number;
    server_ip: string;
    server_port: number;
    pid?: number;
    process_name?: string;
    interface?: string;
    state?: string;
    bytes_ab: number;
    bytes_ba: number;
    first_seen: number;
    last_seen: number;
  }

  interface FlowList {
    flows: Flow[];
    total: number;
  }

  interface Process {
    pid: number;
    name: string;
    path?: string;
    user?: string;
    first_seen: number;
    last_seen: number;
    bytes_in: number;
    bytes_out: number;
    connection_count: number;
  }

  interface ProcessList {
    processes: Process[];
    total: number;
  }

  interface Connection {
    id: number;
    uid?: string;
    ts: number;
    proto?: string;
    client_ip?: string;
    client_port?: number;
    server_ip?: string;
    server_port?: number;
    service?: string;
    conn_state?: string;
    duration?: number;
    bytes_ab: number;
    bytes_ba: number;
    pid?: number;
    process_name?: string;
  }

  interface ConnectionList {
    connections: Connection[];
    total: number;
  }

  type Tab =
    | "overview"
    | "connections"
    | "processes"
    | "destinations"
    | "domains"
    | "dns"
    | "alerts"
    | "capture";

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
  let watchedInput = $state("");
  let domainTrustFilter = $state("all");
  let expandedProcess = $state<number | null>(null);
  let processDetail = $state<ProcessDetail | null>(null);
  let expandedDestination = $state<string | null>(null);
  let destinationDetail = $state<DestinationDetail | null>(null);
  let detailLoading = $state(false);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let lastUpdated = $state("");
  let filter = $state("");
  let themeMode = $state<ThemeMode>(cachedTheme());
  let systemDark = $state(
    typeof window !== "undefined" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches,
  );

  const filteredFlows = $derived(filterItems(flows, filter, (flow) => [
    flow.process_name,
    flow.proto,
    flow.state,
    flow.client_ip,
    flow.server_ip,
    flow.server_port,
    flow.interface,
  ]));

  const filteredProcesses = $derived(
    filterItems(processes, filter, (process) => [
      process.name,
      process.pid,
      process.user,
      process.path,
    ]),
  );

  const filteredDestinations = $derived(
    filterItems(destinations, filter, (destination) => [
      destination.ip,
      destination.hostname,
      destination.trust_state,
      ...destination.domains.map((domain) => domain.domain),
    ]),
  );

  const filteredDomains = $derived.by(() => {
    const text = filter.trim().toLowerCase();
    return domains.filter((domain) => {
      const matchesTrust =
        domainTrustFilter === "all" ||
        (domainTrustFilter === "needs_review"
          ? needsReview(domain)
          : domain.trust_state === domainTrustFilter);
      const matchesText =
        !text ||
        [domain.domain, ...domain.hostnames].some((value) =>
          value.toLowerCase().includes(text),
        );
      return matchesTrust && matchesText;
    });
  });

  const needsReviewCount = $derived(
    domains.filter((domain) => needsReview(domain)).length,
  );

  const filteredDns = $derived(
    filterItems(dnsObservations, filter, (observation) => [
      observation.query,
      observation.answers,
      observation.qtype,
      observation.rcode,
      observation.client_ip,
    ]),
  );

  const filteredAlerts = $derived(
    filterItems(alerts, filter, (alert) => [
      alert.msg,
      alert.sid,
      alert.src_ip,
      alert.dst_ip,
      alert.action,
      alert.proto,
    ]),
  );

  const filteredConnections = $derived(
    filterItems(connections, filter, (connection) => [
      connection.process_name,
      connection.proto,
      connection.server_ip,
      connection.service,
      connection.conn_state,
    ]),
  );

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

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "connections", label: "Connections" },
    { id: "processes", label: "Processes" },
    { id: "destinations", label: "Destinations" },
    { id: "domains", label: "Domains" },
    { id: "dns", label: "DNS" },
    { id: "alerts", label: "Alerts" },
    { id: "capture", label: "Capture" },
  ];

  const themeOptions: { id: ThemeMode; label: string }[] = [
    { id: "system", label: "System" },
    { id: "light", label: "Light" },
    { id: "dark", label: "Dark" },
  ];

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

  function filterItems<T>(
    items: T[],
    needle: string,
    values: (item: T) => unknown[],
  ): T[] {
    const text = needle.trim().toLowerCase();
    if (!text) return items;
    return items.filter((item) =>
      values(item)
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(text)),
    );
  }

  function formatTime(seconds: number): string {
    if (!seconds) return "-";
    return new Date(seconds * 1000).toLocaleTimeString();
  }

  function formatBytes(bytes: number): string {
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function endpoint(ip?: string, port?: number): string {
    if (!ip) return "-";
    return port ? `${ip}:${port}` : ip;
  }

  function needsReview(item: {
    trust_state: TrustState;
    flags: ReviewFlag[];
  }): boolean {
    if (item.trust_state === "ignored") return false;
    if (item.trust_state === "unknown" || item.trust_state === "suspicious") {
      return true;
    }
    return item.flags.some(
      (flag) =>
        flag === "no_domain" || flag === "invalid_tls" || flag === "alerts",
    );
  }

  function domainLabel(list: EndpointDomain[]): string {
    if (!list.length) return "no domain";
    const names = list.slice(0, 3).map((domain) => domain.domain);
    const extra = list.length > 3 ? ` +${list.length - 3}` : "";
    return `${names.join(", ")}${extra}`;
  }

  function flagLabel(flag: ReviewFlag): string {
    switch (flag) {
      case "new_domain":
        return "new";
      case "no_domain":
        return "no domain";
      case "invalid_tls":
        return "invalid TLS";
      case "alerts":
        return "alerts";
      case "unknown_trust":
        return "unknown";
    }
  }

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

  async function setTrust(domain: string, state: TrustState) {
    try {
      await invoke("set_domain_trust", {
        registrableDomain: domain,
        state,
        note: null,
      });
      await refresh();
    } catch (cause) {
      console.warn("Unable to update domain trust", cause);
    }
  }

  async function addWatchedDomain() {
    const domain = watchedInput.trim();
    if (!domain) return;
    try {
      await invoke("add_watched_domain", { domain });
      watchedInput = "";
      await refresh();
    } catch (cause) {
      console.warn("Unable to add watched domain", cause);
    }
  }

  async function removeWatchedDomain(domain: string) {
    try {
      await invoke("remove_watched_domain", { domain });
      await refresh();
    } catch (cause) {
      console.warn("Unable to remove watched domain", cause);
    }
  }

  function resetDetails() {
    expandedProcess = null;
    processDetail = null;
    expandedDestination = null;
    destinationDetail = null;
    detailLoading = false;
  }

  function isThemeMode(value: unknown): value is ThemeMode {
    return value === "system" || value === "light" || value === "dark";
  }

  function cachedTheme(): ThemeMode {
    try {
      const value = localStorage.getItem("pigui.theme");
      return isThemeMode(value) ? value : "system";
    } catch {
      return "system";
    }
  }

  function applyTheme() {
    const effective =
      themeMode === "system" ? (systemDark ? "dark" : "light") : themeMode;
    document.documentElement.dataset.theme = effective;
    document.documentElement.style.colorScheme = effective;
    try {
      localStorage.setItem("pigui.theme", themeMode);
    } catch {
    }
  }

  async function loadSettings() {
    try {
      const settings = await invoke<AppSettings>("get_settings");
      if (isThemeMode(settings.theme)) {
        themeMode = settings.theme;
      }
    } catch (cause) {
      console.warn("Unable to load UI settings", cause);
    }
  }

  async function selectTheme(mode: ThemeMode) {
    themeMode = mode;
    try {
      await invoke("update_settings", { theme: mode });
    } catch (cause) {
      console.warn("Unable to persist theme setting", cause);
    }
  }

  $effect(() => {
    applyTheme();
  });

  onMount(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    systemDark = media.matches;
    const handleScheme = (event: MediaQueryListEvent) => {
      systemDark = event.matches;
    };
    media.addEventListener("change", handleScheme);
    void loadSettings();
    void refresh();
    const timer = setInterval(() => void refresh(), 2000);
    return () => {
      media.removeEventListener("change", handleScheme);
      clearInterval(timer);
    };
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
        <span class="pill" class:degraded={status.degraded.length > 0 || !status.snort_running}>
          {status.snort_running ? (status.degraded.length > 0 ? "degraded" : "live") : "snort offline"}
        </span>
        <span class="mode">{status.mode}</span>
      {/if}
      <span class="updated">
        {lastUpdated ? `updated ${lastUpdated}` : "connecting..."}
      </span>
      <div class="theme-switch" role="group" aria-label="Theme">
        {#each themeOptions as option}
          <button
            type="button"
            class:active={themeMode === option.id}
            aria-pressed={themeMode === option.id}
            title={`${option.label} theme`}
            onclick={() => void selectTheme(option.id)}
          >
            {option.label}
          </button>
        {/each}
      </div>
      <button
        class="refresh"
        onclick={() => void refresh()}
        disabled={refreshing}
        aria-busy={refreshing}
      >
        {refreshing ? "Refreshing" : "Refresh"}
      </button>
    </div>
  </header>

  <div class="content">
  {#if error}
    <section class="banner error">
      <strong>Daemon unreachable.</strong>
      {error}
      <p>Start the daemon with <code>scripts/run-live.sh</code> or <code>cargo run -p pigui-daemon</code>.</p>
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

    <nav class="tabs">
      {#each tabs as item}
        <button
          class:active={tab === item.id}
          onclick={() => {
            tab = item.id;
            filter = "";
            resetDetails();
          }}
        >
          {item.label}
          {#if item.id === "connections" && flows.length}
            <span class="count">{flows.length}</span>
          {:else if item.id === "processes" && processes.length}
            <span class="count">{processes.length}</span>
          {:else if item.id === "destinations" && destinations.length}
            <span class="count">{destinations.length}</span>
          {:else if item.id === "domains" && needsReviewCount > 0}
            <span class="count review-count">{needsReviewCount}</span>
          {:else if item.id === "dns" && dnsObservations.length}
            <span class="count">{dnsObservations.length}</span>
          {:else if item.id === "alerts" && alerts.length}
            <span class="count">{alerts.length}</span>
          {/if}
        </button>
      {/each}
    </nav>

    {#if tab === "overview"}
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
          <span class="value" class:warn={needsReviewCount > 0}>
            {needsReviewCount}
          </span>
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
              <thead><tr><th>Process</th><th>PID</th><th>Conns</th><th>Traffic</th></tr></thead>
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
              <thead><tr><th>Destination</th><th>Procs</th><th>Traffic</th></tr></thead>
              <tbody>
                {#each topDestinations as destination (destination.ip)}
                  <tr>
                    <td>
                      <div class="mono">{destination.ip}</div>
                      {#if destination.hostname}<div class="sub">{destination.hostname}</div>{/if}
                    </td>
                    <td>{destination.process_count}</td>
                    <td>{formatBytes(destination.bytes_in + destination.bytes_out)}</td>
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
    {:else if tab === "connections"}
      <section class="panel fill">
        <div class="panel-header">
          <h2>Live connections</h2>
          <input type="search" placeholder="Filter connections" bind:value={filter} />
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>Process</th><th>PID</th><th>Proto</th><th>Local</th><th>Remote</th>
                <th>State</th><th>Interface</th><th>Traffic out/in</th><th>Seen</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredFlows as flow (flow.id)}
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
                <tr><td class="empty" colspan="9">No live connections captured yet.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel fill">
        <div class="panel-header">
          <h2>Completed connections from Snort</h2>
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Process</th><th>PID</th><th>Proto</th><th>Remote</th>
                <th>Service</th><th>State</th><th>Traffic out/in</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredConnections as connection (connection.id)}
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
                <tr><td class="empty" colspan="8">No completed extractor records yet.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {:else if tab === "processes"}
      <section class="panel fill">
        <div class="panel-header">
          <h2>Processes</h2>
          <input type="search" placeholder="Filter processes" bind:value={filter} />
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th></th><th>Process</th><th>PID</th><th>User</th><th>Connections</th>
                <th>Bytes in</th><th>Bytes out</th><th>Path</th><th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredProcesses as process (process.pid)}
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
                              <tr><th>Destination</th><th>Domains</th><th>Trust</th><th>Flags</th><th>Traffic in/out</th><th>Conns</th><th>Last seen</th></tr>
                            </thead>
                            <tbody>
                              {#each processDetail.destinations as destination (destination.ip)}
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
    {:else if tab === "destinations"}
      <section class="panel fill">
        <div class="panel-header">
          <h2>Destinations</h2>
          <input type="search" placeholder="Filter destinations" bind:value={filter} />
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th></th><th>IP</th><th>Domains</th><th>Trust</th><th>Flags</th><th>Processes</th>
                <th>Connections</th><th>Alerts</th><th>Bytes in</th><th>Bytes out</th>
                <th>First seen</th><th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredDestinations as destination (destination.ip)}
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
                  <td>{destination.alert_count}</td>
                  <td>{formatBytes(destination.bytes_in)}</td>
                  <td>{formatBytes(destination.bytes_out)}</td>
                  <td class="mono">{formatTime(destination.first_seen)}</td>
                  <td class="mono">{formatTime(destination.last_seen)}</td>
                </tr>
                {#if expandedDestination === destination.ip}
                  <tr class="detail-row">
                    <td colspan="12">
                      <div class="detail-block">
                        <div class="detail-heading">Processes using this destination</div>
                        {#if destinationDetail}
                          <table class="inner">
                            <thead>
                              <tr><th>Process</th><th>PID</th><th>Traffic in/out</th><th>Connections</th><th>Last seen</th></tr>
                            </thead>
                            <tbody>
                              {#each destinationDetail.processes as process (process.pid ?? process.process_name)}
                                <tr>
                                  <td>{process.process_name ?? "-"}</td>
                                  <td class="mono">{process.pid ?? "-"}</td>
                                  <td class="mono">{formatBytes(process.bytes_in)} / {formatBytes(process.bytes_out)}</td>
                                  <td>{process.connection_count}</td>
                                  <td class="mono">{formatTime(process.last_seen)}</td>
                                </tr>
                              {:else}
                                <tr><td class="empty" colspan="5">No process attribution for this destination.</td></tr>
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
                <tr><td class="empty" colspan="12">No destinations observed yet.</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {:else if tab === "domains"}
      <section class="panel">
        <div class="panel-header">
          <h2>Watched domains</h2>
          <div class="panel-tools">
            <input
              type="text"
              placeholder="spotify.com"
              bind:value={watchedInput}
              onkeydown={(event) => {
                if (event.key === "Enter") void addWatchedDomain();
              }}
            />
            <button onclick={() => void addWatchedDomain()} disabled={!watchedInput.trim()}>
              Watch
            </button>
          </div>
        </div>
        <div class="watch-list">
          {#each watchedDomains as watched (watched.domain)}
            <span class="watch-item">
              <span>{watched.domain}</span>
              {#if watched.last_error}
                <span class="watch-error">{watched.last_error}</span>
              {:else if watched.last_resolved_at}
                <span class="sub">resolved {formatTime(watched.last_resolved_at)}</span>
              {:else}
                <span class="sub">pending</span>
              {/if}
              <button onclick={() => void removeWatchedDomain(watched.domain)}>
                Remove
              </button>
            </span>
          {:else}
            <span class="detail-note">
              Add domains such as spotify.com to resolve them periodically and match observed IPs.
            </span>
          {/each}
        </div>
      </section>

      <section class="panel fill">
        <div class="panel-header">
          <h2>Domains</h2>
          <div class="panel-tools">
            <select bind:value={domainTrustFilter} aria-label="Trust filter">
              <option value="all">All domains</option>
              <option value="needs_review">Needs review</option>
              <option value="trusted">Trusted</option>
              <option value="unknown">Unknown</option>
              <option value="suspicious">Suspicious</option>
              <option value="ignored">Ignored</option>
            </select>
            <input type="search" placeholder="Filter domains" bind:value={filter} />
          </div>
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>Registrable domain</th><th>Hostnames</th><th>Sources</th><th>Trust</th><th>Flags</th>
                <th>IPs</th><th>Processes</th><th>Observed</th><th>First seen</th>
                <th>Last seen</th><th>Mark</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredDomains as domain (domain.domain)}
                <tr>
                  <td class="domain">{domain.domain}</td>
                  <td class="sub">{domain.hostnames.join(", ")}</td>
                  <td>{domain.sources.length ? domain.sources.join(", ") : "-"}</td>
                  <td><span class="tag {domain.trust_state}">{domain.trust_state}</span></td>
                  <td>{domain.flags.length ? domain.flags.map(flagLabel).join(", ") : "-"}</td>
                  <td>{domain.endpoint_count}</td>
                  <td>{domain.process_count}</td>
                  <td>{domain.observation_count}</td>
                  <td class="mono">{formatTime(domain.first_seen)}</td>
                  <td class="mono">{formatTime(domain.last_seen)}</td>
                  <td>
                    <select
                      value={domain.trust_state}
                      aria-label={`Trust ${domain.domain}`}
                      onchange={(event) =>
                        void setTrust(
                          domain.domain,
                          (event.currentTarget as HTMLSelectElement)
                            .value as TrustState,
                        )}
                    >
                      <option value="unknown">Unknown</option>
                      <option value="trusted">Trust</option>
                      <option value="suspicious">Suspicious</option>
                      <option value="ignored">Ignore</option>
                    </select>
                  </td>
                </tr>
              {:else}
                <tr>
                  <td class="empty" colspan="11">
                    No domains observed yet. Check the DNS tab and extractor health;
                    DNS must be captured on port 53 while PIGUI is running.
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {:else if tab === "dns"}
      <section class="panel fill">
        <div class="panel-header">
          <h2>DNS observations</h2>
          <input type="search" placeholder="Filter DNS" bind:value={filter} />
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Client</th><th>Query</th><th>Type</th>
                <th>Rcode</th><th>Answers</th><th>TTL</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredDns as observation (observation.id)}
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
                    No DNS observations yet. DNS responses must be observed on port 53
                    while capture is running; DoH/DoT traffic will not appear here.
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {:else if tab === "alerts"}
      <section class="panel fill">
        <div class="panel-header">
          <h2>Alerts</h2>
          <input type="search" placeholder="Filter alerts" bind:value={filter} />
        </div>
        <div class="table-wrap tall">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>SID</th><th>Priority</th><th>Proto</th><th>Source</th>
                <th>Destination</th><th>Action</th><th>Message</th>
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
    {:else if tab === "capture"}
      <section class="capture-grid">
        <article class="card">
          <span class="label">Capture mode</span>
          <span class="value">{status.mode}</span>
          <span class="hint">{status.snort_running ? "Snort is running" : "Snort is not running"}</span>
        </article>
        <article class="card">
          <span class="label">Interface</span>
          <span class="value">{status.snort_interface ?? "-"}</span>
          <span class="hint">PIGUI_SNORT_INTERFACE</span>
        </article>
        <article class="card">
          <span class="label">Snort PID</span>
          <span class="value">{status.snort_pid ?? "-"}</span>
          <span class="hint">{status.capabilities.version ?? "unknown version"}</span>
        </article>
        <article class="card">
          <span class="label">Control socket</span>
          <span class="value" class:ok={status.capabilities.control_socket}>
            {status.capabilities.control_socket ? "available" : "unavailable"}
          </span>
          <span class="hint">{status.capabilities.source ?? "unknown source"}</span>
        </article>
        <article class="card">
          <span class="label">Extractor</span>
          <span class="value" class:ok={status.capabilities.extractor && !status.extractor_idle} class:warn={status.extractor_idle}>
            {status.extractor_idle ? "idle" : status.capabilities.extractor ? "available" : "unavailable"}
          </span>
          <span class="hint">{status.extractor_ingested} rows · {formatBytes(status.extractor_size)}</span>
        </article>
        <article class="card">
          <span class="label">Extractor last record</span>
          <span class="value">{status.extractor_last_ingest ? formatTime(status.extractor_last_ingest) : "never"}</span>
          <span class="hint">{status.dns_count} DNS · {status.tls_count} TLS · {status.domain_count} domains</span>
        </article>
        <article class="card">
          <span class="label">Collector</span>
          <span class="value" class:ok={!status.collector_error}>
            {status.collector_error ? "error" : "healthy"}
          </span>
          <span class="hint">nettop every 1s</span>
        </article>
      </section>

      <section class="panel">
        <div class="panel-header"><h2>Runtime paths</h2></div>
        <div class="paths">
          <div><span class="label">database</span><code>{status.db_path}</code></div>
          <div><span class="label">daemon socket</span><code>{status.socket_path}</code></div>
          <div><span class="label">alert json</span><code>{status.alert_json}</code></div>
          <div><span class="label">extractor json</span><code>{status.extractor_file}</code></div>
          <div><span class="label">config</span><code>{status.capabilities.config_path ?? "-"}</code></div>
        </div>
      </section>
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

<style>
  main {
    height: 100dvh;
    width: 100%;
    padding: clamp(12px, 1.6vw, 24px);
    display: flex;
    flex-direction: column;
    gap: clamp(10px, 1.2vw, 16px);
    overflow: hidden;
  }
  header { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; flex-shrink: 0; }
  .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
  .logo { width: 42px; height: 42px; flex-shrink: 0; display: grid; place-items: center; border-radius: 12px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #fff; font-weight: 700; letter-spacing: 0.5px; }
  h1 { margin: 0; font-size: 22px; letter-spacing: 0.3px; }
  header p { margin: 2px 0 0; color: var(--text-muted); font-size: 12px; }
  .actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-left: auto; }
  .updated, .mode { color: var(--text-muted); font-size: 12px; white-space: nowrap; }
  .updated { min-width: 9.5rem; text-align: right; font-variant-numeric: tabular-nums; }
  .mode { text-transform: uppercase; letter-spacing: 0.6px; }
  .refresh { width: 7.5rem; }
  .pill { border-radius: 999px; padding: 4px 10px; font-size: 12px; background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok-border); white-space: nowrap; }
  .pill.degraded { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-border); }
  .theme-switch { display: inline-flex; gap: 2px; padding: 2px; border: 1px solid var(--border-strong); background: var(--surface-3); border-radius: 8px; }
  .theme-switch button { border: 1px solid transparent; background: transparent; color: var(--text-muted); border-radius: 6px; padding: 4px 9px; font-size: 12px; }
  .theme-switch button:hover { background: var(--surface-hover); color: var(--text); }
  .theme-switch button.active { background: var(--surface-2); border-color: var(--border-strong); color: var(--text); }
  .content { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; gap: clamp(10px, 1.2vw, 16px); }
  .banner { border: 1px solid var(--border-strong); background: var(--surface); border-radius: 10px; padding: 12px 14px; color: var(--text-code); flex-shrink: 0; }
  .banner ul { margin: 8px 0 0; padding-left: 20px; }
  .banner.error { border-color: var(--danger-border); background: var(--danger-bg-strong); }
  .banner.warning { border-color: var(--warn-border); background: var(--warn-bg-strong); }
  .banner p { margin: 6px 0 0; color: var(--text-muted); }
  .tabs { display: flex; gap: 6px; flex-wrap: wrap; border-bottom: 1px solid var(--border); padding-bottom: 8px; flex-shrink: 0; }
  .tabs button { border: 1px solid transparent; background: transparent; color: var(--text-muted); border-radius: 7px; padding: 6px 12px; }
  .tabs button:hover { background: var(--surface-3); color: var(--text); }
  .tabs button.active { background: var(--surface-3); color: var(--text); border-color: var(--border-strong); }
  .tabs .count { margin-left: 6px; font-size: 10px; color: var(--ok); }
  .capabilities { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 180px), 1fr)); gap: 10px; }
  .capabilities article, .card { border: 1px solid var(--border); background: var(--surface); border-radius: 10px; padding: 12px; display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .capture-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr)); gap: 10px; }
  .label { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; }
  .value { font-size: 17px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .value.ok { color: var(--ok); }
  .value.warn { color: var(--warn); }
  .hint { color: var(--text-faint); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 380px), 1fr)); gap: 12px; }
  .panel { border: 1px solid var(--border); background: var(--surface); border-radius: 12px; overflow: hidden; display: flex; flex-direction: column; min-width: 0; }
  .panel.fill { flex: 1; min-height: 0; }
  .panel-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  h2 { margin: 0; font-size: 14px; font-weight: 600; letter-spacing: 0.2px; }
  input[type="search"], input[type="text"] { width: min(280px, 45vw); border: 1px solid var(--border-strong); background: var(--input-bg); color: var(--text); border-radius: 7px; padding: 6px 9px; font: inherit; }
  .table-wrap { max-height: 360px; overflow: auto; min-width: 0; }
  .table-wrap.short { max-height: clamp(180px, 30vh, 320px); }
  .table-wrap.tall { max-height: clamp(240px, 45vh, 900px); }
  .panel.fill .table-wrap.tall { flex: 1; max-height: none; min-height: 180px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { position: sticky; top: 0; z-index: 1; text-align: left; font-weight: 600; color: var(--text-muted); background: var(--surface-2); padding: 9px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td.path { max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
  tbody tr:hover { background: var(--surface-2); }
  .mono { font-family: "SF Mono", ui-monospace, Menlo, monospace; font-size: 11.5px; }
  .sub { color: var(--text-faint); font-size: 11px; margin-top: 2px; }
  .tag { display: inline-block; border-radius: 999px; padding: 2px 8px; background: var(--tag-bg); color: var(--tag-text); border: 1px solid var(--tag-border); }
  .tag.blocked { background: var(--danger-bg); color: var(--danger); border-color: var(--danger-border); }
  .tag.trusted { background: var(--ok-bg); color: var(--ok); border-color: var(--ok-border); }
  .tag.unknown { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-border); }
  .tag.suspicious { background: var(--danger-bg); color: var(--danger); border-color: var(--danger-border); }
  .tag.ignored { background: var(--tag-bg); color: var(--text-faint); border-color: var(--tag-border); }
  .tag.trust { white-space: nowrap; }
  .review-count { color: var(--warn); }
  .panel-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  select { border: 1px solid var(--border-strong); background: var(--input-bg); color: var(--text); border-radius: 7px; padding: 6px 9px; font: inherit; }
  tr.clickable { cursor: pointer; }
  tr.clickable td.expand { color: var(--text-faint); font-weight: 600; width: 24px; text-align: center; }
  tr.open td { background: var(--surface-2); }
  tr.detail-row td { background: var(--surface-2); padding: 12px 14px; white-space: normal; }
  .detail-block { display: flex; flex-direction: column; gap: 8px; }
  .detail-heading { color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; }
  .detail-note { color: var(--text-muted); font-size: 12px; }
  .watch-list { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 14px; }
  .watch-item { display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--border); background: var(--surface-2); border-radius: 999px; padding: 4px 6px 4px 12px; font-size: 12px; }
  .watch-item button { padding: 2px 8px; font-size: 11px; border-radius: 999px; }
  .watch-error { color: var(--danger); font-size: 11px; }
  table.inner { font-size: 12px; }
  table.inner th { background: transparent; }
  table.inner td { white-space: nowrap; }
  .domain { font-weight: 600; }
  .empty { text-align: center; color: var(--text-faint); padding: 24px; white-space: normal; }
  .paths { display: flex; flex-direction: column; gap: 8px; padding: 14px; }
  .paths div { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }
  .paths code { color: var(--text-code); word-break: break-all; }
  footer { display: flex; flex-wrap: wrap; gap: 16px; color: var(--text-faint); font-size: 11px; padding: 4px 2px 0; flex-shrink: 0; }
  @media (max-width: 760px) {
    .tabs { flex-wrap: nowrap; overflow-x: auto; }
    .tabs button { white-space: nowrap; }
    header p { display: none; }
    .updated { display: none; }
    .content { gap: 10px; }
  }
  @media (max-width: 560px) {
    .actions { width: 100%; margin-left: 0; }
    .theme-switch { order: 3; }
    .paths div { flex-direction: column; gap: 2px; }
  }
</style>
