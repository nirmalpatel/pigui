<script lang="ts">
  import type { Tab } from "../types";

  let {
    tab,
    totals,
    onSelect,
  }: {
    tab: Tab;
    totals: Partial<Record<Tab, number>>;
    onSelect: (tab: Tab) => void;
  } = $props();

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "connections", label: "Connections" },
    { id: "processes", label: "Processes" },
    { id: "destinations", label: "Destinations" },
    { id: "domains", label: "Domains" },
    { id: "dns", label: "DNS" },
    { id: "alerts", label: "Alerts" },
    { id: "firewall", label: "Firewall" },
    { id: "capture", label: "Capture" },
    { id: "settings", label: "Settings" },
  ];
</script>

<nav class="tabs">
  {#each tabs as item}
    <button class:active={tab === item.id} onclick={() => onSelect(item.id)}>
      {item.label}
      {#if totals[item.id] !== undefined}
        <span class="count" title={`${totals[item.id]} rows in database`}>
          {totals[item.id]}
        </span>
      {/if}
    </button>
  {/each}
</nav>
