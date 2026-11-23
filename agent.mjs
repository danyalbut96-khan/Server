#!/usr/bin/env node
import os from "node:os";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { getCapabilities, getLinuxIdentity, readLinuxMetrics, validateControlPlaneUrl } from "./src/agent/linux.mjs";
import { defaultStateDirectory, loadAgentState, saveAgentState } from "./src/agent/state.mjs";
import { detectPodmanRuntime } from "./src/agent/linux.mjs";
import { PodmanWorkloadRuntime } from "./src/agent/runtime.mjs";
import { loadNodeTunnelCredentials, startNodeTunnel } from "./src/agent/tunnel.mjs";

export const AGENT_VERSION = "0.1.0";
const DEFAULT_HEARTBEAT_SECONDS = 3;
const DEFAULT_POLL_SECONDS = 5;
const REQUEST_TIMEOUT_MS = 12_000;

export class AgentAuthenticationError extends Error {}

function log(level, message, fields = {}) {
  const safe = { ...fields };
  for (const key of ["credential", "secret", "lease_token", "token", "authorization"]) delete safe[key];
  process.stdout.write(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...safe }) + "\n");
}

async function requestJson(fetchImpl, url, { method = "GET", credential, body, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("request timeout")), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method,
      headers: {
        accept: "application/json",
        ...(credential ? { authorization: "Bearer " + credential } : {}),
        ...(body ? { "content-type": "application/json" } : {})
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: controller.signal,
      redirect: "error"
    });
    const text = await response.text();
    let payload = {};
    if (text) {
      try { payload = JSON.parse(text); } catch { throw new Error("Control plane returned a non-JSON response (HTTP " + response.status + ")."); }
    }
    if (!response.ok) {
      const message = payload?.error?.message || "Control-plane request failed with HTTP " + response.status + ".";
      if (response.status === 401 || response.status === 403) throw new AgentAuthenticationError(message);
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    clearTimeout(timer);
  }
}

export async function enrollNode({ controlPlaneUrl, enrollmentToken, nodeName, stateDirectory = defaultStateDirectory(), fetchImpl = fetch, getIdentity = getLinuxIdentity }) {
  const identity = getIdentity();
  const baseUrl = validateControlPlaneUrl(controlPlaneUrl);
  if (typeof enrollmentToken !== "string" || enrollmentToken.length < 16 || enrollmentToken.length > 256) throw new Error("A valid one-time enrollment token is required.");
  if (typeof nodeName !== "string" || !nodeName.trim() || nodeName.trim().length > 100) throw new Error("Node name must contain 1–100 characters.");
  const response = await requestJson(fetchImpl, baseUrl + "/api/v1/nodes/enroll", {
    method: "POST",
    body: {
      enrollment_token: enrollmentToken,
      name: nodeName.trim(),
      platform: identity.platform,
      architecture: identity.architecture,
      agent_version: AGENT_VERSION,
      capabilities: await getCapabilities()
    }
  });
  if (!response.node?.id || !response.credential?.secret) throw new Error("Enrollment response did not include a node ID and one-time credential.");
  const state = {
    node_id: response.node.id,
    credential: response.credential.secret,
    control_plane_url: baseUrl,
    node_name: nodeName.trim(),
    enrolled_at: new Date().toISOString()
  };
  await saveAgentState(stateDirectory, state);
  return { node: response.node, stateDirectory };
}

export async function executeWorkloadJob(job, { runtime } = {}) {
  if (!runtime) throw new Error("Workload runtime is not configured on this node.");
  if (!job || !["deploy", "stop", "restart"].includes(job.job_type) ||
      !job.payload || typeof job.payload !== "object" || Array.isArray(job.payload)) {
    throw new Error("Unsupported or malformed workload job.");
  }
  if (job.job_type === "deploy") return runtime.deploy(job.payload);
  if (job.job_type === "stop") {
    if (Object.keys(job.payload).length !== 1 || typeof job.payload.deployment_id !== "string") {
      throw new Error("Workload stop payload is malformed.");
    }
    return runtime.stop(job.payload.deployment_id);
  }
  const allowed = ["deployment_id", "container_port", "health_check_path", "health_check_timeout_seconds"];
  if (Object.keys(job.payload).some((key) => !allowed.includes(key)) ||
      typeof job.payload.deployment_id !== "string" ||
      !Number.isInteger(job.payload.container_port) ||
      typeof job.payload.health_check_path !== "string" ||
      !Number.isInteger(job.payload.health_check_timeout_seconds)) {
    throw new Error("Workload restart payload is malformed.");
  }
  return runtime.restart(job.payload.deployment_id, job.payload);
}

export async function executeDiagnostic(job, { fetchImpl = fetch, controlPlaneUrl, procRoot = "/proc", diskPath = "/" } = {}) {
  if (!job || !["probe", "collect_metrics"].includes(job.job_type) ||
      !job.payload || typeof job.payload !== "object" || Array.isArray(job.payload) || Object.keys(job.payload).length !== 0) {
    throw new Error("Unsupported or malformed diagnostic job.");
  }
  if (job.job_type === "probe") {
    const health = await requestJson(fetchImpl, controlPlaneUrl + "/api/health", { timeoutMs: 8000 });
    return { result_code: "control_plane_reachable", result_summary: "Control plane responded with status " + String(health.status || "unknown") + "." };
  }
  const resources = await readLinuxMetrics({ procRoot, diskPath });
  return { result_code: "metrics_collected", result_summary: JSON.stringify(resources).slice(0, 3900) };
}

async function acknowledge(fetchImpl, state, job, status, result = {}) {
  return requestJson(fetchImpl, state.control_plane_url + "/api/v1/nodes/" + state.node_id + "/jobs/" + job.job_id + "/ack", {
    method: "POST",
    credential: state.credential,
    body: {
      attempt_id: job.attempt_id,
      lease_token: job.lease_token,
      status,
      result_code: result.result_code ?? null,
      result_summary: result.result_summary ?? null,
      result_metadata: result.result_metadata ?? {}
    }
  });
}

export async function getNodeCapabilities(identity, env, tunnelConfigured, loadCapabilities = getCapabilities) {
  const capabilities = await loadCapabilities(identity);
  const forwardingReady = identity.platform === "linux" &&
    tunnelConfigured &&
    Boolean(env.CLOUDEXIFY_ROUTE_GRANT_PUBLIC_KEY);
  capabilities.ingress_tunnel = forwardingReady;
  capabilities.loopback_forwarder = forwardingReady;
  return capabilities;
}

export async function runAgent({ stateDirectory = defaultStateDirectory(), fetchImpl = fetch, signal, heartbeatSeconds = DEFAULT_HEARTBEAT_SECONDS, pollSeconds = DEFAULT_POLL_SECONDS, onLog = log, runtimeProbe = detectPodmanRuntime, env = process.env } = {}) {
  getLinuxIdentity();
  if (!Number.isInteger(heartbeatSeconds) || heartbeatSeconds < 3 || heartbeatSeconds > 300) throw new Error("Heartbeat interval must be between 3 and 300 seconds.");
  if (!Number.isInteger(pollSeconds) || pollSeconds < 3 || pollSeconds > 120) throw new Error("Poll interval must be between 3 and 120 seconds.");
  const state = await loadAgentState(stateDirectory);
  const identity = getLinuxIdentity();
  const tunnelVariables = ["CLOUDEXIFY_TUNNEL_URL", "CLOUDEXIFY_TUNNEL_CA", "CLOUDEXIFY_TUNNEL_CERT", "CLOUDEXIFY_TUNNEL_KEY"];
  const tunnelConfigured = tunnelVariables.some((key) => Boolean(env[key]));
  let tunnel = null;
  if (tunnelConfigured) {
    if (identity.platform !== "linux" || tunnelVariables.some((key) => !env[key])) {
      throw new Error("mTLS tunnel requires a qualified Linux node and all four CLOUDEXIFY_TUNNEL_* settings.");
    }
    if (!signal) throw new Error("An AbortSignal is required when the node tunnel is enabled.");
    const credentials = await loadNodeTunnelCredentials({
      nodeId: state.node_id,
      caPath: env.CLOUDEXIFY_TUNNEL_CA,
      certPath: env.CLOUDEXIFY_TUNNEL_CERT,
      keyPath: env.CLOUDEXIFY_TUNNEL_KEY
    });
    tunnel = startNodeTunnel({
      nodeId: state.node_id,
      gatewayUrl: env.CLOUDEXIFY_TUNNEL_URL,
      credentials,
      signal,
      routeGrantPublicKey: env.CLOUDEXIFY_ROUTE_GRANT_PUBLIC_KEY || null,
      onState: (status) => onLog(status === "rejected" ? "error" : "info", "Node mTLS tunnel state changed", { node_id: state.node_id, tunnel_status: status })
    });
    onLog("info", "Outbound mTLS tunnel supervisor started", { node_id: state.node_id });
  }
  let nextHeartbeat = 0;
  let nextPoll = 0;
  let lastCpuMetrics = null;
  let runtimeReconciled = false;
  const workloadRuntime = new PodmanWorkloadRuntime({ runtimeProbe: identity.platform === "linux" ? runtimeProbe : async () => ({ ready: false, rootless: false, cgroup_version: null, cgroup_v2_available: false }) });
  onLog("info", "Linux/Android node agent started", { node_id: state.node_id, node_name: state.node_name, platform: identity.platform, architecture: identity.architecture, version: AGENT_VERSION });

  try {
  while (!signal?.aborted) {
    const now = Date.now();
    try {
      if (now >= nextHeartbeat) {
        const resources = await readLinuxMetrics();
        const heartbeat = await requestJson(fetchImpl, state.control_plane_url + "/api/v1/nodes/" + state.node_id + "/heartbeat", {
          method: "POST",
          credential: state.credential,
          body: { agent_version: AGENT_VERSION, health_status: "healthy", resources, capabilities: await getNodeCapabilities(identity, env, tunnelConfigured) }
        });
        onLog("info", "Heartbeat accepted", { node_id: state.node_id, status: heartbeat.node?.status || "unknown", metric_count: Object.keys(resources).length });
        nextHeartbeat = Date.now() + heartbeatSeconds * 1000;
        if (!runtimeReconciled) {
          try {
            const reconciliation = await requestJson(fetchImpl, state.control_plane_url + "/api/v1/nodes/" + state.node_id + "/runtime/reconcile", {
              method: "POST",
              credential: state.credential,
              body: {}
            });
            runtimeReconciled = true;
            onLog("info", "Runtime reconciliation accepted", { node_id: state.node_id, reconciled_jobs: reconciliation.reconciled_jobs || 0 });
          } catch (error) {
            if (error instanceof AgentAuthenticationError) throw error;
            onLog("warn", "Runtime reconciliation failed; agent will retry", { node_id: state.node_id, error: error.message });
          }
        }
      }
    } catch (error) {
      if (error instanceof AgentAuthenticationError) throw error;
      onLog("warn", "Heartbeat failed; agent will retry", { node_id: state.node_id, error: error.message });
      nextHeartbeat = Date.now() + Math.min(heartbeatSeconds * 1000, 15_000);
    }

    try {
      if (Date.now() >= nextPoll) {
        const claimed = await requestJson(fetchImpl, state.control_plane_url + "/api/v1/nodes/" + state.node_id + "/jobs/claim", {
          method: "POST",
          credential: state.credential,
          body: { limit: 1, lease_seconds: 120 }
        });
        for (const job of claimed.jobs || []) {
          try {
            await acknowledge(fetchImpl, state, job, "accepted");
            await acknowledge(fetchImpl, state, job, "running");
            const result = ["probe", "collect_metrics"].includes(job.job_type)
              ? await executeDiagnostic(job, { fetchImpl, controlPlaneUrl: state.control_plane_url })
              : await executeWorkloadJob(job, { runtime: workloadRuntime });
            await acknowledge(fetchImpl, state, job, "succeeded", result);
            onLog("info", "Diagnostic job completed", { node_id: state.node_id, job_id: job.job_id, job_type: job.job_type, result_code: result.result_code });
          } catch (error) {
            if (error instanceof AgentAuthenticationError) throw error;
            try {
              const runtimeUnavailable = ["deploy", "stop", "restart"].includes(job.job_type) && /not qualified|not configured/i.test(error.message);
              await acknowledge(fetchImpl, state, job, runtimeUnavailable ? "rejected" : "failed", {
                result_code: runtimeUnavailable ? "runtime_not_qualified" : "job_execution_failed",
                result_summary: String(error.message).slice(0, 1000)
              });
            } catch (ackError) {
              onLog("warn", "Could not submit diagnostic failure result", { node_id: state.node_id, job_id: job.job_id, error: ackError.message });
            }
            onLog("warn", "Diagnostic job failed", { node_id: state.node_id, job_id: job.job_id, error: error.message });
          }
        }
        nextPoll = Date.now() + pollSeconds * 1000;
      }
    } catch (error) {
      if (error instanceof AgentAuthenticationError) throw error;
      onLog("warn", "Job polling failed; agent will retry", { node_id: state.node_id, error: error.message });
      nextPoll = Date.now() + Math.min(pollSeconds * 1000, 15_000);
    }

    const wait = Math.max(250, Math.min(nextHeartbeat, nextPoll) - Date.now());
    try { await sleep(wait, undefined, { signal }); }
    catch (error) { if (!signal?.aborted) throw error; }
  }
  } finally {
    if (tunnel) {
      tunnel.close();
      await tunnel.done;
    }
  }
  onLog("info", "Linux/Android node agent stopped", { node_id: state.node_id });
}

function usage() {
  process.stdout.write([
    "Cloudexify Linux Node Agent " + AGENT_VERSION,
    "",
    "Commands:",
    "  node agent.mjs enroll",
    "  node agent.mjs run",
    "",
    "Enrollment environment:",
    "  CLOUDEXIFY_CONTROL_PLANE_URL  Required; HTTPS endpoint (localhost HTTP allowed for tests)",
    "  CLOUDEXIFY_ENROLLMENT_TOKEN   One-time token from Cloudexify admin",
    "  CLOUDEXIFY_NODE_NAME          Human-readable node name",
    "  CLOUDEXIFY_AGENT_STATE_DIR    Optional; defaults to ~/.local/share/cloudexify-agent",
    "",
    "Runtime environment:",
    "  CLOUDEXIFY_HEARTBEAT_SECONDS  Optional; 3–300, default 3",
    "  CLOUDEXIFY_POLL_SECONDS       Optional; 3–120, default 5",
    "",
    "Optional outbound mTLS tunnel (Linux only; configure all four):",
    "  CLOUDEXIFY_TUNNEL_URL         HTTPS gateway origin",
    "  CLOUDEXIFY_TUNNEL_CA          Gateway CA certificate path",
    "  CLOUDEXIFY_TUNNEL_CERT        Per-node client certificate path",
    "  CLOUDEXIFY_TUNNEL_KEY         Per-node private key path (0600)"
  ].join("\n") + "\n");
}

async function main() {
  const command = process.argv[2];
  if (command === "--help" || command === "-h" || !command) return usage();
  if (command === "enroll") {
    const result = await enrollNode({
      controlPlaneUrl: process.env.CLOUDEXIFY_CONTROL_PLANE_URL,
      enrollmentToken: process.env.CLOUDEXIFY_ENROLLMENT_TOKEN,
      nodeName: process.env.CLOUDEXIFY_NODE_NAME
    });
    log("info", "Node enrolled; approval is still required before jobs can be assigned", { node_id: result.node.id, node_name: result.node.name, state_directory: result.stateDirectory });
    return;
  }
  if (command === "run") {
    const controller = new AbortController();
    const stop = () => controller.abort();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    try {
      await runAgent({
        heartbeatSeconds: Number(process.env.CLOUDEXIFY_HEARTBEAT_SECONDS || DEFAULT_HEARTBEAT_SECONDS),
        pollSeconds: Number(process.env.CLOUDEXIFY_POLL_SECONDS || DEFAULT_POLL_SECONDS),
        signal: controller.signal
      });
    } finally {
      process.removeListener("SIGINT", stop);
      process.removeListener("SIGTERM", stop);
    }
    return;
  }
  usage();
  process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    log("error", "Agent stopped", { error: error.message });
    process.exitCode = 1;
  });
}
