<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    flagLabel,
    formatTime,
    hostnamesFor,
    needsReview,
    trustOrder,
  } from "../display";
  import {
    sortBy,
    toggleSort,
    type SortColumns,
    type SortState,
  } from "../sort";
  import type {
    DomainSummary,
    ListQueryState,
    TrustState,
    WatchedDomain,
  } from "../types";
  import SortHeader from "./SortHeader.svelte";

  let {
    domains,
    watchedDomains,
    onRefresh,
    onQuery,
  }: {
    domains: DomainSummary[];
    watchedDomains: WatchedDomain[];
    onRefresh: () => Promise<void>;
    onQuery?: (query: ListQueryState) => void;
  } = $props();

  let filter = $state("");
  let domainTrustFilter = $state("all");
  let domainSort = $state<SortState | null>(null);

  function emitQuery() {
    onQuery?.({
      q: filter.trim() || undefined,
      sort: domainSort?.key,
      dir: domainSort?.direction,
    });
  }

  function toggleDomainSort(key: string) {
    domainSort = toggleSort(domainSort, key);
    emitQuery();
  }
  let watchedInput = $state("");
  let expandedHostnames = $state<Record<string, boolean>>({});

  const domainColumns: SortColumns<DomainSummary> = {
    domain: (domain) => domain.domain,
    hostnames: (domain) => domain.hostnames.length,
    sources: (domain) => domain.sources.length,
    trust: (domain) => trustOrder[domain.trust_state],
    flags: (domain) => domain.flags.length,
    ips: (domain) => domain.endpoint_count,
    processes: (domain) => domain.process_count,
    observed: (domain) => domain.observation_count,
    first_seen: (domain) => domain.first_seen,
    last_seen: (domain) => domain.last_seen,
  };

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

  const sortedDomains = $derived(
    sortBy(filteredDomains, domainSort, domainColumns),
  );

  function toggleHostnames(domain: string) {
    expandedHostnames = {
      ...expandedHostnames,
      [domain]: !expandedHostnames[domain],
    };
  }

  async function setTrust(domain: string, state: TrustState) {
    try {
      await invoke("set_domain_trust", {
        registrableDomain: domain,
        state,
        note: null,
      });
      await onRefresh();
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
      await onRefresh();
    } catch (cause) {
      console.warn("Unable to add watched domain", cause);
    }
  }

  async function removeWatchedDomain(domain: string) {
    try {
      await invoke("remove_watched_domain", { domain });
      await onRefresh();
    } catch (cause) {
      console.warn("Unable to remove watched domain", cause);
    }
  }
</script>

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
      <input type="search" placeholder="Filter domains" bind:value={filter} oninput={emitQuery} />
    </div>
  </div>
  <div class="table-wrap tall">
    <table>
      <thead>
        <tr>
          <SortHeader label="Registrable domain" column="domain" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Hostnames" column="hostnames" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Sources" column="sources" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Trust" column="trust" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Flags" column="flags" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="IPs" column="ips" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Processes" column="processes" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Observed" column="observed" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="First seen" column="first_seen" sort={domainSort} onToggle={toggleDomainSort} />
          <SortHeader label="Last seen" column="last_seen" sort={domainSort} onToggle={toggleDomainSort} />
          <th>Mark</th>
        </tr>
      </thead>
      <tbody>
        {#each sortedDomains as domain (domain.domain)}
          {@const hostnames = hostnamesFor(domain)}
          {@const hostnameExpanded = expandedHostnames[domain.domain] ?? false}
          {@const visibleHostnames = hostnameExpanded
            ? hostnames
            : hostnames.slice(0, 6)}
          <tr>
            <td class="domain">{domain.domain}</td>
            <td class="sub hostnames">
              {#if hostnames.length}
                <div class="hostname-list" class:expanded={hostnameExpanded}>
                  {visibleHostnames.join(", ")}
                </div>
                {#if hostnames.length > 6}
                  <button
                    type="button"
                    class="hostname-toggle"
                    onclick={() => toggleHostnames(domain.domain)}
                  >
                    {hostnameExpanded
                      ? "Show less"
                      : `+${hostnames.length - 6} more`}
                  </button>
                {/if}
              {:else}
                -
              {/if}
            </td>
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
                    (event.currentTarget as HTMLSelectElement).value as TrustState,
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
