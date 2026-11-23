import test from "node:test";
import assert from "node:assert/strict";

if (process.platform === "win32") {
  process.env.CLOUDEXIFY_TEST_PLATFORM = "linux";
  process.env.CLOUDEXIFY_TEST_ARCH = "x64";
}
import { mkdtemp, mkdir, chmod, lstat, symlink, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getLinuxIdentity, getCapabilities, detectPodmanRuntime, detectCosignVerifier, validateControlPlaneUrl, readLinuxMetrics } from "../src/agent/linux.mjs";
import { loadAgentState, saveAgentState } from "../src/agent/state.mjs";
import { executeDiagnostic, executeWorkloadJob, enrollNode, runAgent, getNodeCapabilities } from "../agent.mjs";

const validState = {
  node_id: "30000000-0000-4000-8000-000000000001",
  credential: "A".repeat(48),
  control_plane_url: "https://control.example.test",
  node_name: "linux-test-node"
};

test("Linux identity accepts only supported 64-bit architectures", () => {
  assert.deepEqual(getLinuxIdentity("linux", "x64"), { platform: "linux", architecture: "x86_64", environment: "linux" });
  assert.deepEqual(getLinuxIdentity("linux", "arm64"), { platform: "linux", architecture: "aarch64", environment: "linux" });
  assert.deepEqual(getLinuxIdentity("linux", "arm64", { TERMUX_VERSION: "0.118" }), { platform: "android", architecture: "aarch64", environment: "termux" });
  assert.deepEqual(getLinuxIdentity("linux", "arm64", { PREFIX: "/data/data/com.termux/files/usr" }), { platform: "android", architecture: "aarch64", environment: "termux" });
  assert.deepEqual(getLinuxIdentity("android", "arm64", { TERMUX_VERSION: "0.118" }), { platform: "android", architecture: "aarch64", environment: "termux" });
  assert.deepEqual(getLinuxIdentity("android", "arm64", { PREFIX: "/data/data/com.termux/files/usr" }), { platform: "android", architecture: "aarch64", environment: "termux" });
  assert.throws(() => getLinuxIdentity("android", "arm64", {}), /Linux or Android running Termux/);
  assert.throws(() => getLinuxIdentity("win32", "x64"), /Linux or Android running Termux/);
  assert.throws(() => getLinuxIdentity("linux", "ia32"), /Unsupported Linux\/Android architecture/);
});

test("agent dispatches typed deploy, stop and restart jobs to the workload runtime", async () => {
  const calls = [];
  const runtime = {
    async deploy(payload) { calls.push(["deploy", payload]); return { result_code: "started" }; },
    async stop(id) { calls.push(["stop", id]); return { result_code: "stopped" }; },
    async restart(id, options) { calls.push(["restart", id, options]); return { result_code: "restarted" }; }
  };
  const deploymentId = "40000000-0000-4000-8000-000000000001";
  const deployPayload = { deployment_id: deploymentId, image: "immutable" };
  const restartPayload = { deployment_id: deploymentId, container_port: 8080, health_check_path: "/healthz", health_check_timeout_seconds: 30 };
  assert.equal((await executeWorkloadJob({ job_type: "deploy", payload: deployPayload }, { runtime })).result_code, "started");
  assert.equal((await executeWorkloadJob({ job_type: "stop", payload: { deployment_id: deploymentId } }, { runtime })).result_code, "stopped");
  assert.equal((await executeWorkloadJob({ job_type: "restart", payload: restartPayload }, { runtime })).result_code, "restarted");
  assert.deepEqual(calls, [["deploy", deployPayload], ["stop", deploymentId], ["restart", deploymentId, restartPayload]]);
});

test("agent rejects malformed workload jobs and never accepts arbitrary command payloads", async () => {
  const runtime = { async deploy() { throw new Error("must not execute"); }, async stop() {}, async restart() {} };
  await assert.rejects(executeWorkloadJob({ job_type: "exec", payload: { command: "id" } }, { runtime }), /Unsupported or malformed/);
  await assert.rejects(executeWorkloadJob({ job_type: "stop", payload: { deployment_id: "id", command: "id" } }, { runtime }), /payload is malformed/);
  await assert.rejects(executeWorkloadJob({ job_type: "deploy", payload: {} }), /runtime is not configured/);
});

test("control-plane URL requires HTTPS except loopback development", () => {
  assert.equal(validateControlPlaneUrl("https://control.example.test/"), "https://control.example.test");
  assert.equal(validateControlPlaneUrl("http://127.0.0.1:4173"), "http://127.0.0.1:4173");
  assert.throws(() => validateControlPlaneUrl("http://control.example.test"), /must use HTTPS/);
  assert.throws(() => validateControlPlaneUrl("https://user:pass@control.example.test"), /must not contain credentials/);
});

test("agent state is atomically stored with owner-only permissions", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  const info = await lstat(path.join(directory, "node.json"));
  if (process.platform !== "win32") assert.equal(info.mode & 0o777, 0o600);
  assert.deepEqual(await loadAgentState(directory), validState);
});

test("agent refuses a credential file with group or world permissions", { skip: process.platform === "win32" }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  await chmod(path.join(directory, "node.json"), 0o644);
  await assert.rejects(loadAgentState(directory), /permissions are too open/);
});

test("agent refuses symlinked credential files", { skip: process.platform === "win32" }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, "elsewhere"), JSON.stringify(validState));
  await symlink(path.join(directory, "elsewhere"), path.join(directory, "node.json"));
  await assert.rejects(loadAgentState(directory), /symlink/);
});

test("agent refuses a symlinked state directory", { skip: process.platform === "win32" }, async (t) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const actual = path.join(parent, "actual");
  const link = path.join(parent, "link");
  await mkdir(actual);
  await symlink(actual, link);
  await assert.rejects(saveAgentState(link, validState), /symlink/);
});

test("Linux metrics return only finite non-negative allowlisted values", async () => {
  const metrics = await readLinuxMetrics();
  assert.ok(Number.isFinite(metrics.uptime_seconds) && metrics.uptime_seconds >= 0);
  for (const [key, value] of Object.entries(metrics)) {
    assert.ok(["uptime_seconds", "cpu_cores", "cpu_frequency_mhz", "memory_total_bytes", "memory_used_bytes", "memory_available_bytes", "disk_total_bytes", "disk_used_bytes", "disk_available_bytes", "android_shared_storage_total_bytes", "android_shared_storage_used_bytes", "android_shared_storage_available_bytes", "load_1m", "cpu_percent", "battery_percent", "temperature_c"].includes(key));
    assert.ok(Number.isFinite(value) && value >= 0, key);
  }
  if (metrics.cpu_percent !== undefined) assert.ok(metrics.cpu_percent <= 100);
  assert.ok(Number.isInteger(metrics.cpu_cores) && metrics.cpu_cores >= 1 && metrics.cpu_cores <= 256);
  if (metrics.memory_total_bytes !== undefined) { assert.ok(metrics.memory_used_bytes <= metrics.memory_total_bytes); assert.ok(metrics.memory_available_bytes <= metrics.memory_total_bytes); assert.equal(metrics.memory_used_bytes + metrics.memory_available_bytes, metrics.memory_total_bytes); }
  if (metrics.disk_total_bytes !== undefined) { assert.ok(metrics.disk_used_bytes <= metrics.disk_total_bytes); assert.ok(metrics.disk_available_bytes <= metrics.disk_total_bytes); }
});

test("probe diagnostic calls only the control-plane health endpoint", async () => {
  const calls = [];
  const result = await executeDiagnostic({ job_type: "probe", payload: {} }, {
    controlPlaneUrl: "https://control.example.test",
    fetchImpl: async (url) => {
      calls.push(url);
      return new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  assert.deepEqual(calls, ["https://control.example.test/api/health"]);
  assert.equal(result.result_code, "control_plane_reachable");
});

test("diagnostic handler rejects arbitrary command-like payloads", async () => {
  await assert.rejects(executeDiagnostic({ job_type: "probe", payload: { command: "id" } }), /Unsupported or malformed/);
  await assert.rejects(executeDiagnostic({ job_type: "shell", payload: { command: "id" } }), /Unsupported or malformed/);
});

test("enrollment stores the credential only after a successful control-plane response", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const calls = [];
  const result = await enrollNode({
    controlPlaneUrl: "https://control.example.test",
    enrollmentToken: "one-time-enrollment-token",
    nodeName: "ci-linux-node",
    stateDirectory: directory,
    getIdentity: () => ({ platform: "linux", architecture: "x86_64", environment: "linux" }),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({
        node: { id: validState.node_id, name: "ci-linux-node", status: "pending" },
        credential: { secret: validState.credential }
      }), { status: 201, headers: { "content-type": "application/json" } });
    }
  });
  assert.equal(result.node.status, "pending");
  assert.equal(calls[0].url, "https://control.example.test/api/v1/nodes/enroll");
  assert.equal(JSON.parse(calls[0].options.body).platform, "linux");
  assert.deepEqual(await loadAgentState(directory), { ...validState, node_name: "ci-linux-node", enrolled_at: (await loadAgentState(directory)).enrolled_at });
});

test("agent sends heartbeat and polls its own node queue", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  const controller = new AbortController();
  const calls = [];
  const logs = [];
  await runAgent({
    stateDirectory: directory, signal: controller.signal, heartbeatSeconds: 15, pollSeconds: 5,
    onLog: (level, message, fields) => logs.push({ level, message, fields }),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/jobs/claim")) controller.abort();
      const payload = url.endsWith("/heartbeat") ? { node: { status: "pending" } } : { jobs: [] };
      return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  assert.ok(calls.some((call) => call.url.endsWith("/heartbeat")));
  assert.ok(calls.some((call) => call.url.endsWith("/runtime/reconcile")));
  const heartbeatCall = calls.find((call) => call.url.endsWith("/heartbeat"));
  const heartbeatBody = JSON.parse(heartbeatCall.options.body);
  assert.equal(heartbeatBody.capabilities.workload_execution, false);
  assert.deepEqual(heartbeatBody.capabilities.diagnostics, ["probe", "collect_metrics"]);
  assert.equal(typeof heartbeatBody.capabilities.runtime_probe.podman.ready, "boolean");
  assert.ok(calls.some((call) => call.url.endsWith("/jobs/claim")));
  for (const call of calls) assert.equal(call.options.headers.authorization, "Bearer " + validState.credential);
  assert.equal(JSON.stringify(logs).includes(validState.credential), false);
});

test("agent executes claimed diagnostic jobs and acknowledges each lease through terminal success", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  const controller = new AbortController();
  const claimedJobs = [
    {
      job_id: "60000000-0000-4000-8000-000000000011",
      job_type: "probe",
      payload: {},
      attempt_id: "70000000-0000-4000-8000-000000000011",
      lease_token: "80000000-0000-4000-8000-000000000011"
    },
    {
      job_id: "60000000-0000-4000-8000-000000000012",
      job_type: "collect_metrics",
      payload: {},
      attempt_id: "70000000-0000-4000-8000-000000000012",
      lease_token: "80000000-0000-4000-8000-000000000012"
    }
  ];
  const acknowledgements = [];
  const logs = [];
  let claimCount = 0;
  await runAgent({
    stateDirectory: directory,
    signal: controller.signal,
    heartbeatSeconds: 15,
    pollSeconds: 5,
    onLog: (_level, message, fields) => {
      logs.push({ message, fields });
      if (message === "Diagnostic job completed" &&
          logs.filter((entry) => entry.message === "Diagnostic job completed").length === 2) {
        controller.abort();
      }
    },
    fetchImpl: async (url, options) => {
      if (url.endsWith("/runtime/reconcile")) return new Response(JSON.stringify({ reconciled_jobs: 0 }), { status: 200 });
      if (url.endsWith("/heartbeat")) return new Response(JSON.stringify({ node: { status: "online" } }), { status: 200 });
      if (url.endsWith("/jobs/claim")) {
        claimCount += 1;
        return new Response(JSON.stringify({ jobs: claimCount === 1 ? claimedJobs : [] }), { status: 200 });
      }
      if (url.endsWith("/api/health")) {
        return new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url.endsWith("/ack")) {
        const body = JSON.parse(options.body);
        acknowledgements.push({ jobId: url.split("/jobs/")[1].split("/")[0], ...body });
        return new Response(JSON.stringify({ job: { status: body.status } }), { status: 200 });
      }
      throw new Error("Unexpected agent request: " + url);
    }
  });

  for (const job of claimedJobs) {
    const attempts = acknowledgements.filter((entry) => entry.attempt_id === job.attempt_id);
    assert.deepEqual(attempts.map((entry) => entry.status), ["accepted", "running", "succeeded"]);
    for (const attempt of attempts) {
      assert.equal(attempt.jobId, job.job_id);
      assert.equal(attempt.lease_token, job.lease_token);
    }
  }
  const successResults = acknowledgements.filter((entry) => entry.status === "succeeded");
  assert.equal(successResults[0].result_code, "control_plane_reachable");
  assert.equal(successResults[1].result_code, "metrics_collected");
  assert.ok(JSON.parse(successResults[1].result_summary).cpu_cores >= 1);
  assert.equal(logs.filter((entry) => entry.message === "Diagnostic job completed").length, 2);
});

test("agent terminally rejects workload jobs on nodes without qualified Podman", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  const controller = new AbortController();
  const acknowledgements = [];
  const job = {
    job_id: "60000000-0000-4000-8000-000000000001",
    job_type: "deploy",
    payload: {
      deployment_id: "40000000-0000-4000-8000-000000000001",
      image: "registry.example.com/cloudexify/demo@sha256:" + "a".repeat(64),
      container_port: 8080,
      resources: { cpu_millicores: 500, memory_bytes: 268435456, disk_bytes: 1073741824 }
    },
    attempt_id: "70000000-0000-4000-8000-000000000001",
    lease_token: "80000000-0000-4000-8000-000000000001"
  };
  await runAgent({
    stateDirectory: directory,
    signal: controller.signal,
    heartbeatSeconds: 15,
    pollSeconds: 5,
    runtimeProbe: async () => ({ ready: false, rootless: false, cgroup_version: "v1", cgroup_v2_available: false }),
    onLog: (_level, message) => { if (message === "Diagnostic job failed") controller.abort(); },
    fetchImpl: async (url, options) => {
      if (url.endsWith("/runtime/reconcile")) return new Response(JSON.stringify({ reconciled_jobs: 0 }), { status: 200 });
      if (url.endsWith("/heartbeat")) return new Response(JSON.stringify({ node: { status: "online" } }), { status: 200 });
      if (url.endsWith("/jobs/claim")) return new Response(JSON.stringify({ jobs: [job] }), { status: 200 });
      if (url.endsWith("/ack")) {
        const body = JSON.parse(options.body);
        acknowledgements.push(body.status);
        return new Response(JSON.stringify({ job: { status: body.status } }), { status: 200 });
      }
      throw new Error("Unexpected agent request");
    }
  });
  assert.deepEqual(acknowledgements, ["accepted", "running", "rejected"]);
});

test("agent stops when the control plane rejects its node credential", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cloudexify-agent-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await saveAgentState(directory, validState);
  await assert.rejects(runAgent({
    stateDirectory: directory, onLog: () => {},
    fetchImpl: async () => new Response(JSON.stringify({ error: { message: "Node credential is invalid, expired or revoked." } }),
      { status: 401, headers: { "content-type": "application/json" } })
  }), /invalid, expired or revoked/);
});

test("Podman runtime probe requires rootless mode and cgroup v2", async () => {
  const runtime = await detectPodmanRuntime({
    runCommand: async (command, args, options) => {
      assert.equal(command, "podman");
      assert.deepEqual(args, ["info", "--format", "json"]);
      assert.equal(options.timeout, 3000);
      return { stdout: JSON.stringify({
        host: { security: { rootless: true }, cgroupVersion: "v2" },
        store: { graphDriverName: "overlay", graphRoot: "/var/lib/containers/storage" },
        version: { Version: "5.0.1" }
      }) };
    },
    readCgroupControllers: async () => "cpu memory pids",
    env: { CLOUDEXIFY_STORAGE_QUOTA_READY: "true" },
    readStorageMetrics: async () => ({ blocks: 100, bsize: 4096, bavail: 50 })
  });
  assert.deepEqual(runtime, {
    available: true, ready: true, version: "5.0.1", rootless: true,
    cgroup_version: "v2", cgroup_v2_available: true, graph_driver: "overlay",
    storage_quota: { available: true, ready: true, enforcement: "podman-overlay-size", total_bytes: 409600, available_bytes: 204800, reason: null }, reason: null
  });
});

test("Podman storage quota capability requires overlay and explicit operator attestation", async () => {
  const base = { host: { security: { rootless: true }, cgroupVersion: "v2" }, store: { graphDriverName: "overlay", graphRoot: "/var/lib/containers/storage" }, version: { Version: "5.0.1" } };
  const ready = await detectPodmanRuntime({
    runCommand: async () => ({ stdout: JSON.stringify(base) }),
    readCgroupControllers: async () => "cpu memory pids",
    env: { CLOUDEXIFY_STORAGE_QUOTA_READY: "true" },
    readStorageMetrics: async () => ({ blocks: 100, bsize: 4096, bavail: 50 })
  });
  assert.equal(ready.storage_quota.ready, true);
  const unconfigured = await detectPodmanRuntime({
    runCommand: async () => ({ stdout: JSON.stringify(base) }),
    readCgroupControllers: async () => "cpu memory pids",
    env: {}
  });
  assert.equal(unconfigured.storage_quota.ready, false);
  const unsupported = await detectPodmanRuntime({
    runCommand: async () => ({ stdout: JSON.stringify({ ...base, store: { graphDriverName: "vfs" } }) }),
    readCgroupControllers: async () => "cpu memory pids",
    env: { CLOUDEXIFY_STORAGE_QUOTA_READY: "true" },
    readStorageMetrics: async () => ({ blocks: 100, bsize: 4096, bavail: 50 })
  });
  assert.equal(unsupported.storage_quota.ready, false);
});

test("Podman runtime probe fails closed when rootless or cgroup v2 requirements are missing", async () => {
  const notRootless = await detectPodmanRuntime({
    runCommand: async () => ({ stdout: JSON.stringify({
      host: { security: { rootless: false }, cgroupVersion: "v2" },
      version: { Version: "5.0.1" }
    }) }),
    readCgroupControllers: async () => "cpu memory"
  });
  assert.equal(notRootless.ready, false);
  assert.equal(notRootless.reason, "podman_not_rootless");

  const noCgroupV2 = await detectPodmanRuntime({
    runCommand: async () => ({ stdout: JSON.stringify({
      host: { security: { rootless: true }, cgroupVersion: "v1" },
      version: { Version: "5.0.1" }
    }) }),
    readCgroupControllers: async () => { throw new Error("not mounted"); }
  });
  assert.equal(noCgroupV2.ready, false);
  assert.equal(noCgroupV2.reason, "cgroup_v2_unavailable");
});

test("Podman runtime probe handles missing binary and malformed output without throwing", async () => {
  const missing = await detectPodmanRuntime({ runCommand: async () => { throw new Error("ENOENT"); } });
  assert.equal(missing.available, false);
  assert.equal(missing.ready, false);
  const malformed = await detectPodmanRuntime({ runCommand: async () => ({ stdout: "not-json" }) });
  assert.equal(malformed.available, false);
  assert.equal(malformed.ready, false);
});

test("Cosign verifier requires the binary and the configured trusted public key", async () => {
  let accessed = null;
  const ready = await detectCosignVerifier({
    runCommand: async (command, args, options) => {
      assert.equal(command, "cosign");
      assert.deepEqual(args, ["version"]);
      assert.equal(options.timeout, 3000);
      return { stdout: "cosign version" };
    },
    trustKeyPath: "/etc/cloudexify/trust.pub",
    accessFile: async (file) => { accessed = file; }
  });
  assert.deepEqual(ready, { available: true, ready: true, trust_key_configured: true });
  assert.equal(accessed, "/etc/cloudexify/trust.pub");

  const missing = await detectCosignVerifier({
    runCommand: async () => { throw new Error("cosign missing"); },
    accessFile: async () => { throw new Error("must not access key"); }
  });
  assert.equal(missing.ready, false);
  assert.equal(missing.trust_key_configured, false);
});

test("agent advertises diagnostics and detected runtime without claiming workload execution", async () => {
  const capabilities = await getCapabilities(
    getLinuxIdentity("linux", "x64"),
    { podmanProbe: async () => ({ available: true, ready: true, version: "5.0.1", rootless: true, cgroup_version: "v2", cgroup_v2_available: true, reason: null }) }
  );
  assert.deepEqual(capabilities.diagnostics, ["probe", "collect_metrics"]);
  assert.equal(capabilities.container_runtime, "podman-rootless");
  assert.equal(capabilities.runtime_probe.podman.ready, true);
  assert.equal(capabilities.runtime_probe.podman.storage_quota.ready, false);
  assert.equal(capabilities.workload_execution, false);
  assert.ok(capabilities.service_manager === null || capabilities.service_manager === "systemd");
});

test("Termux never probes or advertises a container runtime", async () => {
  let probed = false;
  const capabilities = await getCapabilities(
    getLinuxIdentity("linux", "arm64", { TERMUX_VERSION: "0.118" }),
    { podmanProbe: async () => { probed = true; return { available: true, ready: true }; } }
  );
  assert.equal(probed, false);
  assert.equal(capabilities.container_runtime, null);
  assert.equal(capabilities.workload_execution, false);
});

test("agent advertises ingress capabilities only with complete Linux tunnel and grant-key configuration", async () => {
  const loader = async () => ({ agent_protocol: 1, diagnostics: ["probe"] });
  const linux = { platform: "linux", architecture: "x86_64", environment: "linux" };
  const termux = { platform: "android", architecture: "aarch64", environment: "termux" };
  const enabled = await getNodeCapabilities(linux, { CLOUDEXIFY_ROUTE_GRANT_PUBLIC_KEY: "public-pem" }, true, loader);
  assert.equal(enabled.ingress_tunnel, true);
  assert.equal(enabled.loopback_forwarder, true);
  const missingKey = await getNodeCapabilities(linux, {}, true, loader);
  assert.equal(missingKey.ingress_tunnel, false);
  assert.equal(missingKey.loopback_forwarder, false);
  const noTunnel = await getNodeCapabilities(linux, { CLOUDEXIFY_ROUTE_GRANT_PUBLIC_KEY: "public-pem" }, false, loader);
  assert.equal(noTunnel.ingress_tunnel, false);
  const android = await getNodeCapabilities(termux, { CLOUDEXIFY_ROUTE_GRANT_PUBLIC_KEY: "public-pem" }, true, loader);
  assert.equal(android.ingress_tunnel, false);
  assert.equal(android.loopback_forwarder, false);
});
