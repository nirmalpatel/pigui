import type {
  DomainSummary,
  EndpointDomain,
  ReviewFlag,
  TrustState,
} from "./types";

export const trustOrder: Record<TrustState, number> = {
  unknown: 0,
  suspicious: 1,
  trusted: 2,
  ignored: 3,
};

export function formatTime(seconds: number): string {
  if (!seconds) return "-";
  return new Date(seconds * 1000).toLocaleTimeString();
}

export function formatBytes(bytes: number): string {
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

export function endpoint(ip?: string, port?: number): string {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

export function needsReview(item: {
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

export function domainLabel(list: EndpointDomain[]): string {
  if (!list.length) return "no domain";
  const names = list.slice(0, 3).map((domain) => domain.domain);
  const extra = list.length > 3 ? ` +${list.length - 3}` : "";
  return `${names.join(", ")}${extra}`;
}

export function numericValue(value?: string): string | number {
  if (!value) return "";
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : value;
}

export function hostnamesFor(domain: DomainSummary): string[] {
  const seen = new Set<string>();
  for (const hostname of domain.hostnames) {
    const value = hostname.trim();
    if (value) seen.add(value);
  }
  return [...seen].sort((left, right) =>
    left.localeCompare(right, undefined, {
      numeric: true,
      sensitivity: "base",
    }),
  );
}

export function flagLabel(flag: ReviewFlag): string {
  switch (flag) {
    case "new_domain":
      return "new domain";
    case "no_domain":
      return "no domain";
    case "invalid_tls":
      return "invalid TLS";
    case "alerts":
      return "has alerts";
    case "unknown_trust":
      return "no trust set";
  }
}

export function evidenceLabel(source: string): string {
  switch (source) {
    case "dns":
      return "DNS";
    case "tls":
      return "TLS SNI";
    case "http":
      return "HTTP Host";
    case "quic":
      return "QUIC SNI";
    case "ptr":
      return "PTR";
    case "watched":
      return "Watched";
    case "legacy":
      return "Legacy";
    default:
      return source;
  }
}

export function evidenceLabels(sources: string[]): string[] {
  return [...new Set(sources.map(evidenceLabel))];
}

export function degradedReasonLabel(reason: string): string {
  if (reason.startsWith("extractor")) {
    return "Snort telemetry is unavailable; connection, DNS, TLS, HTTP, and QUIC records will not be collected.";
  }
  if (reason.startsWith("alert_json")) {
    return "Snort alerts are unavailable; alert ingestion is disabled.";
  }
  if (reason.startsWith("control socket unavailable")) {
    return "Snort control API is unavailable; PIGUI is using file-based capture and is not affected.";
  }
  if (reason.startsWith("snort configuration validation failed")) {
    return "Snort configuration validation failed.";
  }
  return reason;
}

export function captureModeLabel(mode?: string): string {
  switch (mode) {
    case "dev-helper":
      return "dev helper";
    case "helper":
      return "packaged helper";
    default:
      return mode || "not running";
  }
}
