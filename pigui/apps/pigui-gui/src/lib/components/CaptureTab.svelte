<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { formatBytes, formatTime } from "../display";
  import type { StatusPayload } from "../types";

  let {
    status,
    onRefresh,
  }: {
    status: StatusPayload;
    onRefresh: () => Promise<void>;
  } = $props();

  let serviceStatus = $state("");
  let serviceBusy = $state(false);
  let captureInterface = $state("");
  let helperOutput = $state("");
  let helperBusy = $state(false);

  type ServiceField = "agent" | "helper" | "bundle";

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

  async function runServiceCommand(command: string) {
    serviceBusy = true;
    try {
      serviceStatus = await invoke<string>(command);
    } catch (cause) {
      serviceStatus = String(cause);
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
        captureInterface.trim() || status.snort_interface || "en0";
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
    void refreshServices();
  });
</script>

<section class="capture-grid">
  <article class="card">
    <span class="label">Environment</span>
    <span class="value">{status.environment}</span>
    <span class="hint">
      {status.environment === "prod" ? "packaged app" : "source checkout"}
    </span>
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
    <span class="label">Capture</span>
    <span class="value" class:ok={status.capture_running} class:warn={!status.capture_running}>
      {status.capture_running ? "running" : "stopped"}
    </span>
    <span class="hint">{status.capture_mode ?? "no helper"} · {status.capture_interface ?? "no interface"}</span>
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
    <span class="hint">nettop on {status.capture_interface ?? status.snort_interface ?? "all interfaces"}</span>
  </article>
</section>

<section class="panel">
  <div class="panel-header">
    <h2>Background services</h2>
    <div class="actions">
      <button type="button" onclick={() => void refreshServices()} disabled={serviceBusy}>
        Check again
      </button>
      <button type="button" onclick={() => void openLoginItemsSettings()}>
        Open Login Items settings
      </button>
      <button type="button" onclick={() => void runServiceCommand("service_register_agent")} disabled={serviceBusy}>
        Register daemon
      </button>
      <button type="button" onclick={() => void runServiceCommand("service_register_helper")} disabled={serviceBusy}>
        Register helper
      </button>
      <button type="button" onclick={() => void runServiceCommand("service_unregister_helper")} disabled={serviceBusy}>
        Unregister helper
      </button>
    </div>
  </div>
  <div class="service-state">
    <span class="pill" class:ok={serviceField(serviceStatus, "agent") === "enabled"}>
      daemon approval: {serviceField(serviceStatus, "agent")}
    </span>
    <span class="pill" class:ok={serviceField(serviceStatus, "helper") === "enabled"}>
      helper approval: {serviceField(serviceStatus, "helper")}
    </span>
  </div>
  <ol class="setup-steps">
    <li>Click <strong>Register helper</strong>.</li>
    <li>Click <strong>Open Login Items settings</strong> and approve PIGUI.</li>
    <li>Click <strong>Check again</strong> until the helper shows <code>enabled</code>.</li>
    <li>Return to Capture control and click <strong>Enable capture</strong>.</li>
  </ol>
  <p class="hint">
    PIGUI never asks for your password. macOS owns approval; no credential
    is passed to or stored by PIGUI. Local unsigned builds may return
    <code>Operation not permitted</code>: use <code>scripts/run-dev.sh</code>
    for development, or sign/notarize and install in <code>/Applications</code>.
  </p>
  <pre class="service-status">{formatServiceStatus(serviceStatus)}</pre>
</section>

<section class="panel">
  <div class="panel-header">
    <h2>Capture control</h2>
    <div class="actions">
      <input
        type="text"
        placeholder={status.snort_interface ?? "en0"}
        bind:value={captureInterface}
        aria-label="Capture interface"
      />
      <button type="button" onclick={() => void enableCapture()} disabled={helperBusy}>
        Enable capture
      </button>
      <button type="button" onclick={() => void disableCapture()} disabled={helperBusy}>
        Disable capture
      </button>
      <button type="button" onclick={() => void refreshHelper()} disabled={helperBusy}>
        Helper status
      </button>
    </div>
  </div>
  <p class="hint">
    Capture requires the root helper to be registered and approved. The
    helper stages Snort into a root-owned payload and starts it; the
    unprivileged daemon only reads the resulting telemetry.
  </p>
  <pre class="service-status">{helperOutput || "helper not queried"}</pre>
</section>

<section class="panel">
  <div class="panel-header"><h2>Runtime paths</h2></div>
  <div class="paths">
    <div><span class="label">database</span><code>{status.db_path}</code></div>
    <div><span class="label">daemon socket</span><code>{status.socket_path}</code></div>
    <div><span class="label">alert json</span><code>{status.alert_json}</code></div>
    <div><span class="label">extractor json</span><code>{status.extractor_file}</code></div>
    <div><span class="label">config</span><code>{status.capabilities.config_path ?? "-"}</code></div>
    <div><span class="label">config hash</span><code>{status.snort_config_hash ?? "-"}</code></div>
  </div>
</section>
