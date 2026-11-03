<script lang="ts">
  import type { Tab } from "../types";

  let {
    tab,
    flows,
    processes,
    destinations,
    needsReview,
    dns,
    alerts,
    onSelect,
  }: {
    tab: Tab;
    flows: number;
    processes: number;
    destinations: number;
    needsReview: number;
    dns: number;
    alerts: number;
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
    { id: "capture", label: "Capture" },
    { id: "settings", label: "Settings" },
  ];
</script>

<nav class="tabs">
  {#each tabs as item}
    <button class:active={tab === item.id} onclick={() => onSelect(item.id)}>
      {item.label}
      {#if item.id === "connections" && flows}
        <span class="count">{flows}</span>
      {:else if item.id === "processes" && processes}
        <span class="count">{processes}</span>
      {:else if item.id === "destinations" && destinations}
        <span class="count">{destinations}</span>
      {:else if item.id === "domains" && needsReview > 0}
        <span class="count review-count">{needsReview}</span>
      {:else if item.id === "dns" && dns}
        <span class="count">{dns}</span>
      {:else if item.id === "alerts" && alerts}
        <span class="count">{alerts}</span>
      {/if}
    </button>
  {/each}
</nav>
