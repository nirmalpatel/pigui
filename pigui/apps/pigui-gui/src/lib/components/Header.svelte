<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import type { AppSettings, StatusPayload, ThemeMode } from "../types";

  let {
    status,
    lastUpdated,
    refreshing,
    onRefresh,
  }: {
    status: StatusPayload | null;
    lastUpdated: string;
    refreshing: boolean;
    onRefresh: () => void;
  } = $props();

  const themeOptions: { id: ThemeMode; label: string }[] = [
    { id: "system", label: "System" },
    { id: "light", label: "Light" },
    { id: "dark", label: "Dark" },
  ];

  let themeMode = $state<ThemeMode>(cachedTheme());
  let systemDark = $state(
    typeof window !== "undefined" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches,
  );

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
    return () => {
      media.removeEventListener("change", handleScheme);
    };
  });
</script>

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
      <span class="mode">{status.environment}</span>
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
      onclick={onRefresh}
      disabled={refreshing}
      aria-busy={refreshing}
    >
      {refreshing ? "Refreshing" : "Refresh"}
    </button>
  </div>
</header>
