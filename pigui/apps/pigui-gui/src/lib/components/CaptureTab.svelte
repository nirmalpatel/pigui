<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { captureModeLabel, formatBytes, formatTime } from "../display";
  import type { StatusPayload } from "../types";

  let {
    status,
    autoCaptureError = null,
    onRefresh,
  }: {
    status: StatusPayload;
    autoCaptureError?: string | null;
    onRefresh: () => Promise<void>;
  } = $props();

  let serviceStatus = $state("");
  let serviceBusy = $state(false);
  let serviceMessage = $state("");
  let serviceVersions = $state<ServiceVersions>({});
  let captureInterface = $state("");
  let helperOutput = $state("");
  let helperBusy = $state(false);

  type ServiceField = "agent" | "helper" | "bundle";

  type ServiceVersions = {
    app?: string;
    daemon?: string;
    helper?: string;
    agent?: string;
    helper_service?: string;
  };

  const helperState = $derived(serviceField(serviceStatus, "helper"));
  const helperApprovalRequired = $derived(
    helperState === "requires_approval" || serviceVersions.helper_service === "requires_approval",
  );

  function telemetryState(status: StatusPayload): string {
    if (!status.capabilities.extractor) {
      return "unsupported";
    }
    if (status.extractor_idle) {
      return "stale";
    }
    return status.extractor_ingested > 0 ? "receiving" : "waiting";
  }

  function serviceField(raw: string, field: ServiceField): string {
    try {
      const value = JSON.parse(raw) as Record<string, unknown>;
      return typeof value[field] === "string" ? (value[field] as string) : "unknown";
    } catch {
      return "unknown";
    }
  }

  function formatServiceStatus(raw: string): string {
    if (!raw) {
      return "not checked";
    }
    try {
      const value = JSON.parse(raw) as {
        agent?: string;
        helper?: string;
        bundle?: string;
      };
      return [
        `daemon: ${value.agent ?? "unknown"}`,
        `helper: ${value.helper ?? "unknown"}`,
        `bundle: ${value.bundle ?? "unknown"}`,
      ].join("\n");
    } catch {
      return raw;
    }
  }

  async function refreshServices() {
    try {
      serviceStatus = await invoke<string>("service_status");
    } catch (cause) {
      serviceStatus = String(cause);
    }
  }

  async function refreshVersions() {
    try {
      serviceVersions = await invoke<ServiceVersions>("service_versions");
    } catch (cause) {
      serviceVersions = { app: String(cause) };
    }
  }

  async function runServiceCommand(command: string) {
    serviceBusy = true;
    try {
      serviceStatus = await invoke<string>(command);
      await refreshVersions();
      await refreshHelper();
    } catch (cause) {
      serviceStatus = String(cause);
    } finally {
      serviceBusy = false;
    }
  }

  async function repairServices() {
    serviceBusy = true;
    serviceMessage = "";
    try {
      serviceMessage = await invoke<string>("service_reconcile");
      await refreshServices();
      await refreshVersions();
      await refreshHelper();
      await onRefresh();
    } catch (cause) {
      serviceMessage = String(cause);
    } finally {
      serviceBusy = false;
    }
  }

  async function openLoginItemsSettings() {
    try {
      await invoke("open_login_items_settings");
    } catch (cause) {
      serviceStatus = String(cause);
    }
  }

  async function refreshHelper() {
    helperBusy = true;
    try {
      helperOutput = JSON.stringify(await invoke<unknown>("helper_status"), null, 2);
    } catch (cause) {
      helperOutput = String(cause);
    } finally {
      helperBusy = false;
    }
  }

  async function enableCapture() {
    helperBusy = true;
    try {
      const interfaceName =
        captureInterface.trim() ||
        status.capture_interface ||
        status.snort_interface ||
        "en0";
      helperOutput = JSON.stringify(
        await invoke<unknown>("helper_enable_capture", { interface: interfaceName }),
        null,
        2,
      );
      await onRefresh();
    } catch (cause) {
      helperOutput = String(cause);
    } finally {
      helperBusy = false;
    }
  }

  async function disableCapture() {
    helperBusy = true;
    try {
      helperOutput = JSON.stringify(
        await invoke<unknown>("helper_disable_capture"),
        null,
        2,
      );
      await onRefresh();
    } catch (cause) {
      helperOutput = String(cause);
    } finally {
      helperBusy = false;
    }
  }

  onMount(() => {
    let interval: ReturnType<typeof setInterval> | undefined;
    if (status.environment === "prod") {
      void refreshServices();
      void refreshVersions();
      interval = setInterval(() => {
        void refreshServices();
        void refreshVersions();
      }, 5000);
    }
    void refreshHelper();
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  });
</script>

<section class="capture-grid">
  <article class="card">
    <span class="label">Packet capture</span>
    <span class="value" class:ok={status.capture_running} class:warn={!status.capture_running}>
      {status.capture_running ? "running" : "starting"}
    </span>
    <span class="hint">{captureModeLabel(status.capture_mode)} · {status.capture_interface ?? "auto"}</span>
  </article>
  <article class="card">
    <span class="label">Capture interface</span>
    <span class="value">{status.capture_interface ?? status.snort_interface ?? "auto-detect"}</span>
    <span class="hint">{status.capture_running ? "active interface" : "selected automatically"}</span>
  </article>
  <article class="card">
    <span class="label">Snort process ID</span>
    <span class="value">{status.snort_pid ?? "-"}</span>
    <span class="hint">{status.capabilities.version ?? "unknown version"}</span>
  </article>
  <article class="card">
    <span class="label">Snort telemetry</span>
    <span class="value" class:ok={telemetryState(status) === "receiving"} class:warn={["stale", "missing", "unsupported"].includes(telemetryState(status))}>
      {telemetryState(status)}
    </span>
    <span class="hint">{status.extractor_ingested} records this session · {formatBytes(status.extractor_size)}</span>
  </article>
  <article class="card">
    <span class="label">Last Snort record</span>
    <span class="value">{status.extractor_last_ingest ? formatTime(status.extractor_last_ingest) : "never"}</span>
    <span class="hint">database: {status.dns_count} DNS · {status.tls_count} TLS · {status.domain_count} domains</span>
  </article>
  <article class="card">
    <span class="label">Process collector</span>
    <span class="value" class:ok={!status.collector_error}>
      {status.collector_error ? "error" : "running"}
    </span>
    <span class="hint">nettop on {status.capture_interface ?? status.snort_interface ?? "all interfaces"}</span>
  </article>
</section>

<section class="panel">
  <div class="panel-header">
    <h2>Capture</h2>
    {#if helperApprovalRequired}
      <div class="actions">
        <button type="button" onclick={() => void openLoginItemsSettings()}>
          Approve in System Settings
        </button>
      </div>
    {/if}
  </div>
  <p class="hint capture-message">
    {#if status.capture_running}
      Capture is running on {status.capture_interface ?? "the active interface"}. PIGUI started it automatically.
    {:else if helperApprovalRequired}
      macOS is waiting for approval. Approve PIGUI in Login Items &amp; Extensions; capture starts by itself afterwards.
    {:else if autoCaptureError}
      PIGUI could not start capture automatically: {autoCaptureError}
    {:else}
      PIGUI is starting capture automatically. No action is required.
    {/if}
  </p>
</section>

<section class="panel">
  <details>
    <summary>Advanced and diagnostics</summary>
    <div class="advanced-body">
      <div class="service-state">
        <span class="pill" class:ok={helperState === "enabled"}>
          setup: {helperState}
        </span>
        <span class="pill">app: {serviceVersions.app ?? "unknown"}</span>
        <span class="pill">daemon: {serviceVersions.daemon || status.version || "unknown"}</span>
        <span class="pill">helper: {serviceVersions.helper || "unknown"}</span>
      </div>

      {#if status.environment === "prod"}
        <div class="actions">
          <button type="button" onclick={() => void repairServices()} disabled={serviceBusy}>
            Repair setup
          </button>
          <button type="button" onclick={() => void refreshServices()} disabled={serviceBusy}>
            Check setup
          </button>
          <button type="button" onclick={() => void openLoginItemsSettings()}>
            Open Login Items settings
          </button>
          <button type="button" onclick={() => void runServiceCommand("service_register_agent")} disabled={serviceBusy}>
            Register daemon
          </button>
          <button type="button" onclick={() => void runServiceCommand("service_register_helper")} disabled={serviceBusy}>
            Register capture helper
          </button>
          <button type="button" onclick={() => void runServiceCommand("service_unregister_helper")} disabled={serviceBusy}>
            Unregister capture helper
          </button>
        </div>
        {#if serviceMessage}
          <pre class="service-status">{serviceMessage}</pre>
        {/if}
        <pre class="service-status">{formatServiceStatus(serviceStatus)}</pre>
      {/if}

      <div class="actions">
        <input
          type="text"
          placeholder={status.capture_interface ?? status.snort_interface ?? "en0"}
          bind:value={captureInterface}
          aria-label="Capture interface"
        />
        <button type="button" onclick={() => void enableCapture()} disabled={helperBusy}>
          Start capture
        </button>
        <button type="button" onclick={() => void disableCapture()} disabled={helperBusy}>
          Stop capture
        </button>
        <button type="button" onclick={() => void refreshHelper()} disabled={helperBusy}>
          Helper status
        </button>
      </div>

      <p class="hint">
        PIGUI never asks for your password. macOS owns helper approval; no credential
        is passed to or stored by PIGUI.
      </p>

      <pre class="service-status">{helperOutput || "helper not queried"}</pre>

      <div class="paths">
        <div><span class="label">database</span><code>{status.db_path}</code></div>
        <div><span class="label">daemon socket</span><code>{status.socket_path}</code></div>
        <div><span class="label">Snort alerts file</span><code>{status.alert_json}</code></div>
        <div><span class="label">Snort telemetry file</span><code>{status.extractor_file}</code></div>
        <div><span class="label">active config</span><code>{status.snort_config_path ?? status.capabilities.config_path ?? "-"}</code></div>
        <div><span class="label">source config</span><code>{status.capabilities.config_path ?? "-"}</code></div>
        <div><span class="label">config hash</span><code>{status.snort_config_hash ?? "-"}</code></div>
        <div><span class="label">Snort control API</span><code>{status.capabilities.control_socket ? "available" : "unavailable"}</code></div>
      </div>
    </div>
  </details>
</section>
