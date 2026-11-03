<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { formatBytes, formatTime } from "../display";
  import type {
    AppSettings,
    MaintenanceStats,
    PruneResult,
    ThemeMode,
  } from "../types";

  let {
    settings,
    onChanged,
  }: {
    settings: AppSettings;
    onChanged: (settings: AppSettings) => void;
  } = $props();

  function defaultSettings(): AppSettings {
    return {
      theme: "system",
      ui: {
        refresh_ms: 2000,
        page_size: 200,
        detail_alert_limit: 10,
        stale_after_secs: 600,
      },
      limits: { max_page_size: 1000 },
      collector: { poll_ms: 1000 },
      retention: {
        flows_secs: 600,
        processes_secs: 86400,
        alerts_days: 30,
        connections_days: 7,
        observations_days: 7,
        domains_days: 90,
        endpoints_days: 90,
        ptr_days: 30,
      },
      resolver: {
        loop_secs: 30,
        ptr_batch: 10,
        ptr_ok_ttl_secs: 86400,
        ptr_fail_ttl_secs: 21600,
        watched_batch: 10,
        watched_interval_secs: 900,
      },
      maintenance: { interval_secs: 300 },
    };
  }

  let draft = $state<AppSettings>(defaultSettings());
  let stats = $state<MaintenanceStats | null>(null);
  let busy = $state(false);
  let message = $state("");
  let error = $state("");

  const themeOptions: { id: ThemeMode; label: string }[] = [
    { id: "system", label: "System" },
    { id: "light", label: "Light" },
    { id: "dark", label: "Dark" },
  ];

  $effect(() => {
    draft = structuredClone(settings);
  });

  async function save() {
    busy = true;
    message = "";
    error = "";
    try {
      const next = await invoke<AppSettings>("update_settings", { patch: draft });
      draft = structuredClone(next);
      onChanged(next);
      message = "Settings saved.";
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function reset() {
    busy = true;
    message = "";
    error = "";
    try {
      const next = await invoke<AppSettings>("reset_settings");
      draft = structuredClone(next);
      onChanged(next);
      message = "Settings reset to defaults.";
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  async function loadStats() {
    try {
      stats = await invoke<MaintenanceStats>("maintenance_stats");
    } catch (cause) {
      error = String(cause);
    }
  }

  async function pruneNow() {
    if (!confirm("Delete rows older than the configured retention limits?")) {
      return;
    }
    busy = true;
    message = "";
    error = "";
    try {
      const result = await invoke<PruneResult>("prune_now");
      message = `Pruned ${result.total_deleted} rows.`;
      await loadStats();
    } catch (cause) {
      error = String(cause);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    void loadStats();
  });

  function setTheme(theme: ThemeMode) {
    draft.theme = theme;
  }
</script>

<section class="panel fill">
  <div class="panel-header">
    <h2>Settings</h2>
    <div class="actions">
      <button type="button" onclick={() => void reset()} disabled={busy}>Reset defaults</button>
      <button type="button" onclick={() => void save()} disabled={busy}>{busy ? "Saving..." : "Save"}</button>
    </div>
  </div>

  {#if message}<p class="detail-note">{message}</p>{/if}
  {#if error}<p class="banner error">{error}</p>{/if}

  <div class="settings-grid">
    <fieldset>
      <legend>Display</legend>
      <label>
        <span>Theme</span>
        <select value={draft.theme} onchange={(event) => setTheme((event.currentTarget as HTMLSelectElement).value as ThemeMode)}>
          {#each themeOptions as option}
            <option value={option.id}>{option.label}</option>
          {/each}
        </select>
      </label>
      <label>
        <span>Refresh interval (ms)</span>
        <input type="number" min="500" max="60000" step="100" bind:value={draft.ui.refresh_ms} />
      </label>
      <label>
        <span>Rows per page</span>
        <input type="number" min="1" max={draft.limits.max_page_size} bind:value={draft.ui.page_size} />
      </label>
      <label>
        <span>Detail alert limit</span>
        <input type="number" min="0" max="100" bind:value={draft.ui.detail_alert_limit} />
      </label>
      <label>
        <span>Stale threshold (seconds)</span>
        <input type="number" min="60" max="604800" bind:value={draft.ui.stale_after_secs} />
      </label>
    </fieldset>

    <fieldset>
      <legend>Collection</legend>
      <label>
        <span>nettop poll (ms)</span>
        <input type="number" min="250" max="60000" step="50" bind:value={draft.collector.poll_ms} />
      </label>
      <label>
        <span>Maximum page size</span>
        <input type="number" min="50" max="10000" bind:value={draft.limits.max_page_size} />
      </label>
      <label>
        <span>Maintenance interval (seconds)</span>
        <input type="number" min="30" max="86400" bind:value={draft.maintenance.interval_secs} />
      </label>
    </fieldset>

    <fieldset>
      <legend>Retention (days unless noted)</legend>
      <label><span>Alerts</span><input type="number" min="1" max="3650" bind:value={draft.retention.alerts_days} /></label>
      <label><span>Completed connections</span><input type="number" min="1" max="3650" bind:value={draft.retention.connections_days} /></label>
      <label><span>DNS/TLS/HTTP/QUIC</span><input type="number" min="1" max="3650" bind:value={draft.retention.observations_days} /></label>
      <label><span>Domains / mappings</span><input type="number" min="1" max="3650" bind:value={draft.retention.domains_days} /></label>
      <label><span>Endpoints</span><input type="number" min="1" max="3650" bind:value={draft.retention.endpoints_days} /></label>
      <label><span>PTR observations</span><input type="number" min="1" max="3650" bind:value={draft.retention.ptr_days} /></label>
      <label><span>Live flows (seconds)</span><input type="number" min="60" max="86400" bind:value={draft.retention.flows_secs} /></label>
      <label><span>Process rows (seconds)</span><input type="number" min="300" max="604800" bind:value={draft.retention.processes_secs} /></label>
    </fieldset>

    <fieldset>
      <legend>Resolver</legend>
      <label><span>Loop interval (seconds)</span><input type="number" min="5" max="3600" bind:value={draft.resolver.loop_secs} /></label>
      <label><span>PTR batch</span><input type="number" min="1" max="100" bind:value={draft.resolver.ptr_batch} /></label>
      <label><span>PTR success cache (seconds)</span><input type="number" min="60" max="2592000" bind:value={draft.resolver.ptr_ok_ttl_secs} /></label>
      <label><span>PTR failure cache (seconds)</span><input type="number" min="60" max="2592000" bind:value={draft.resolver.ptr_fail_ttl_secs} /></label>
      <label><span>Watched batch</span><input type="number" min="1" max="100" bind:value={draft.resolver.watched_batch} /></label>
      <label><span>Watched interval (seconds)</span><input type="number" min="60" max="604800" bind:value={draft.resolver.watched_interval_secs} /></label>
    </fieldset>
  </div>
</section>

<section class="panel">
  <div class="panel-header">
    <h2>Maintenance</h2>
    <div class="actions">
      <button type="button" onclick={() => void loadStats()} disabled={busy}>Refresh stats</button>
      <button type="button" onclick={() => void pruneNow()} disabled={busy}>Prune now</button>
    </div>
  </div>
  {#if stats}
    <div class="paths">
      <div><span class="label">database</span><code>{stats.db_path}</code></div>
      <div><span class="label">size</span><code>{formatBytes(stats.db_bytes)}</code></div>
      <div><span class="label">last run</span><code>{stats.last_run ? formatTime(stats.last_run) : "never"}</code></div>
      <div><span class="label">last deleted</span><code>{stats.last_deleted}</code></div>
    </div>
    <div class="table-wrap short">
      <table>
        <thead><tr><th>Table</th><th>Rows</th></tr></thead>
        <tbody>
          {#each stats.table_counts as entry}
            <tr><td class="mono">{entry.name}</td><td>{entry.rows}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <p class="detail-note">Loading maintenance stats...</p>
  {/if}
</section>
