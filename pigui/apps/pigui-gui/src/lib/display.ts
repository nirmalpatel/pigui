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
