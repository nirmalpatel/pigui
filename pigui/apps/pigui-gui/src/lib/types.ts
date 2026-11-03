export type ThemeMode = "system" | "light" | "dark";

export interface ListQueryState {
  q?: string;
  sort?: string;
  dir?: "asc" | "desc";
}

export interface UiSettings {
  refresh_ms: number;
  page_size: number;
  detail_alert_limit: number;
  stale_after_secs: number;
}

export interface LimitSettings {
  max_page_size: number;
}

export interface CollectorSettings {
  poll_ms: number;
}

export interface RetentionSettings {
  flows_secs: number;
  processes_secs: number;
  alerts_days: number;
  connections_days: number;
  observations_days: number;
  domains_days: number;
  endpoints_days: number;
  ptr_days: number;
}

export interface ResolverSettings {
  loop_secs: number;
  ptr_batch: number;
  ptr_ok_ttl_secs: number;
  ptr_fail_ttl_secs: number;
  watched_batch: number;
  watched_interval_secs: number;
}

export interface MaintenanceSettings {
  interval_secs: number;
}

export interface AppSettings {
  theme: ThemeMode;
  ui: UiSettings;
  limits: LimitSettings;
  collector: CollectorSettings;
  retention: RetentionSettings;
  resolver: ResolverSettings;
  maintenance: MaintenanceSettings;
}

export interface TableCount {
  name: string;
  rows: number;
}

export interface MaintenanceStats {
  db_path: string;
  db_bytes: number;
  table_counts: TableCount[];
  last_run?: number;
  last_deleted: number;
}

export interface PruneResult {
  ran_at: number;
  deleted: TableCount[];
  total_deleted: number;
}

export interface SnortCapabilities {
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

export interface StatusPayload {
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
  environment: "dev" | "prod";
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

export interface AlertRecord {
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

export interface AlertList {
  alerts: AlertRecord[];
  total: number;
}

export interface DnsObservation {
  id: number;
  ts: number;
  client_ip?: string;
  query?: string;
  qtype?: string;
  rcode?: string;
  answers?: string;
  ttl?: string;
}

export interface DnsList {
  observations: DnsObservation[];
  total: number;
}

export interface WatchedDomain {
  domain: string;
  registrable_domain: string;
  enabled: boolean;
  last_resolved_at?: number;
  last_error?: string;
}

export interface WatchedList {
  watched: WatchedDomain[];
}

export type TrustState = "unknown" | "trusted" | "suspicious" | "ignored";
export type ReviewFlag =
  | "new_domain"
  | "no_domain"
  | "invalid_tls"
  | "alerts"
  | "unknown_trust";

export interface EndpointDomain {
  domain: string;
  registrable_domain: string;
  source: string;
  server_port?: number;
  trust_state: TrustState;
  first_seen: number;
  last_seen: number;
}

export interface DomainSummary {
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

export interface DomainList {
  domains: DomainSummary[];
  total: number;
}

export interface Destination {
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
  live_bytes_in: number;
  live_bytes_out: number;
  live_connection_count: number;
  domains: EndpointDomain[];
  trust_state: TrustState;
  flags: ReviewFlag[];
}

export interface DestinationList {
  destinations: Destination[];
  total: number;
}

export interface DestinationProcess {
  pid?: number;
  process_name?: string;
  snort_bytes_in: number;
  snort_bytes_out: number;
  live_bytes_in: number;
  live_bytes_out: number;
  snort_connection_count: number;
  live_connection_count: number;
  connection_count: number;
  last_seen: number;
}

export interface DestinationDetail {
  destination: Destination;
  processes: DestinationProcess[];
  recent_alerts: AlertRecord[];
}

export interface ProcessDestination {
  ip: string;
  domains: EndpointDomain[];
  trust_state: TrustState;
  flags: ReviewFlag[];
  snort_bytes_in: number;
  snort_bytes_out: number;
  live_bytes_in: number;
  live_bytes_out: number;
  snort_connection_count: number;
  live_connection_count: number;
  connection_count: number;
  last_seen: number;
}

export interface ProcessDetail {
  process: Process;
  destinations: ProcessDestination[];
}

export interface Flow {
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

export interface FlowList {
  flows: Flow[];
  total: number;
}

export interface Process {
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

export interface ProcessList {
  processes: Process[];
  total: number;
}

export interface Connection {
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

export interface ConnectionList {
  connections: Connection[];
  total: number;
}

export type Tab =
  | "overview"
  | "connections"
  | "processes"
  | "destinations"
  | "domains"
  | "dns"
  | "alerts"
  | "capture"
  | "settings";
