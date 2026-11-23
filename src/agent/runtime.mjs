import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IMAGE_DIGEST = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/;
const MIN_MEMORY_BYTES = 16 * 1024 * 1024;
const MAX_MEMORY_BYTES = 1024 * 1024 * 1024 * 1024;
const MIN_DISK_BYTES = 16 * 1024 * 1024;
const MAX_DISK_BYTES = 1024 * 1024 * 1024 * 1024;

function validateDeploymentPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Deployment payload must be an object.");
  const allowed = ["deployment_id", "image", "container_port", "resources", "health_check_path", "health_check_timeout_seconds", "volumes"];
  if (Object.keys(payload).some((key) => !allowed.includes(key))) throw new Error("Deployment payload contains unsupported fields.");
  if (!UUID.test(payload.deployment_id || "")) throw new Error("Deployment ID is invalid.");
  if (typeof payload.image !== "string" || !IMAGE_DIGEST.test(payload.image)) throw new Error("Deployment image must be a fully qualified, immutable OCI SHA-256 digest.");
  if (!Number.isInteger(payload.container_port) || payload.container_port < 1 || payload.container_port > 65535) throw new Error("Container port must be an integer from 1 to 65535.");
  const resources = payload.resources;
  if (!resources || typeof resources !== "object" || Array.isArray(resources) ||
      Object.keys(resources).some((key) => !["cpu_millicores", "memory_bytes", "disk_bytes"].includes(key)) ||
      !Number.isInteger(resources.cpu_millicores) || resources.cpu_millicores < 50 || resources.cpu_millicores > 64000 ||
      !Number.isSafeInteger(resources.memory_bytes) || resources.memory_bytes < MIN_MEMORY_BYTES || resources.memory_bytes > MAX_MEMORY_BYTES ||
      !Number.isSafeInteger(resources.disk_bytes) || resources.disk_bytes < MIN_DISK_BYTES || resources.disk_bytes > MAX_DISK_BYTES) {
    throw new Error("Deployment CPU, memory and disk requests are invalid or outside supported bounds.");
  }
  const healthCheckPath = payload.health_check_path == null ? "/" : payload.health_check_path;
  const healthCheckTimeout = payload.health_check_timeout_seconds == null ? 30 : payload.health_check_timeout_seconds;
  if (typeof healthCheckPath !== "string" || healthCheckPath.length < 1 || healthCheckPath.length > 256 || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]*$/.test(healthCheckPath) || healthCheckPath.startsWith("//") || healthCheckPath.split("/").includes("..")) throw new Error("Health-check path must be a safe absolute path of at most 256 characters.");
  if (!Number.isInteger(healthCheckTimeout) || healthCheckTimeout < 5 || healthCheckTimeout > 120) throw new Error("Health-check timeout must be an integer from 5 to 120 seconds.");
  const volumes = [];
  if (payload.volumes != null) {
    if (!Array.isArray(payload.volumes)) throw new Error("volumes must be an array.");
    for (const v of payload.volumes) {
      if (!v || typeof v !== "object") throw new Error("volume entry must be an object.");
      if (typeof v.host_path !== "string" || !v.host_path.startsWith("/var/lib/cloudexify/volumes/") || v.host_path.includes("..")) {
        throw new Error("volume host_path must be an absolute path under /var/lib/cloudexify/volumes/.");
      }
      if (typeof v.mount_path !== "string" || !v.mount_path.startsWith("/") || v.mount_path.includes("..")) {
        throw new Error("volume mount_path must be an absolute container path.");
      }
      const topSegment = v.mount_path.split("/")[1];
      if (["proc", "sys", "etc", "dev", "bin", "sbin", "lib", "lib64", "root"].includes(topSegment)) {
        throw new Error("volume mount_path cannot target system container directories.");
      }
      volumes.push({
        host_path: v.host_path,
        mount_path: v.mount_path,
        read_only: Boolean(v.read_only)
      });
    }
  }
  return { ...payload, volumes, health_check_path: healthCheckPath, health_check_timeout_seconds: healthCheckTimeout, container_name: "cloudexify-" + payload.deployment_id.toLowerCase() };
}

export class PodmanWorkloadRuntime {
  constructor({ runCommand = execFileAsync, runtimeProbe, timeoutMs = 30000, cosignBinary = "cosign", trustKeyPath = "/etc/cloudexify/trust.pub", fetchImpl = fetch, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), now = () => Date.now() } = {}) {
    this.runCommand = runCommand;
    this.runtimeProbe = runtimeProbe;
    this.timeoutMs = timeoutMs;
    this.cosignBinary = cosignBinary;
    this.trustKeyPath = trustKeyPath;
    this.fetchImpl = fetchImpl;
    this.sleep = sleep;
    this.now = now;
  }

  async verifyImage(image) {
    try {
      await this.runCommand(this.cosignBinary, ["verify", "--key", this.trustKeyPath, image], {
        timeout: 30000,
        maxBuffer: 256 * 1024,
        windowsHide: true
      });
    } catch (error) {
      const detail = String(error?.stderr || error?.message || "signature verification failed").replace(/[\\r\\n]+/g, " ").slice(0, 500);
      throw new Error("OCI image signature verification failed: " + detail);
    }
  }

  async command(args, timeout = this.timeoutMs) {
    try {
      return await this.runCommand("podman", args, { timeout, maxBuffer: 256 * 1024, windowsHide: true });
    } catch (error) {
      const detail = String(error?.stderr || error?.message || "Podman command failed").replace(/[\r\n]+/g, " ").slice(0, 500);
      throw new Error("Podman workload operation failed: " + detail);
    }
  }

  async assertReady({ requireStorageQuota = false } = {}) {
    if (!this.runtimeProbe) throw new Error("Podman runtime qualification is required before workload execution.");
    const probe = await this.runtimeProbe();
    if (!probe?.ready || probe.rootless !== true || probe.cgroup_version !== "v2" || probe.cgroup_v2_available !== true) {
      throw new Error("Node is not qualified for rootless Podman workload execution.");
    }
    if (requireStorageQuota && probe.storage_quota?.ready !== true) {
      throw new Error("Node is not qualified for enforced per-container storage quotas.");
    }
  }

  async inspect(containerName) {
    const result = await this.command(["inspect", containerName]);
    let value;
    try { value = JSON.parse(result.stdout); } catch { throw new Error("Podman returned invalid container inspection data."); }
    if (!Array.isArray(value) || !value[0]) return null;
    return value[0];
  }

  async waitForHealth(localPort, payload) {
    if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
      throw new Error("Container has no valid loopback health-check port mapping.");
    }
    const url = "http://127.0.0.1:" + localPort + payload.health_check_path;
    const deadline = this.now() + payload.health_check_timeout_seconds * 1000;
    let lastError = "health endpoint did not return HTTP 2xx";
    while (this.now() < deadline) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      try {
        const response = await this.fetchImpl(url, { method: "GET", redirect: "error", signal: controller.signal, headers: { accept: "application/json, text/plain, */*" } });
        if (response.status >= 200 && response.status < 300) return { checked_at: new Date().toISOString(), status_code: response.status };
        lastError = "health endpoint returned HTTP " + response.status;
      } catch (error) {
        lastError = String(error?.message || "health request failed").replace(/[\\r\\n]+/g, " ").slice(0, 240);
      } finally {
        clearTimeout(timer);
      }
      await this.sleep(Math.min(1000, Math.max(0, deadline - this.now())));
    }
    throw new Error("Application health check failed after " + payload.health_check_timeout_seconds + " seconds: " + lastError);
  }

  async removeUnhealthyContainer(containerName) {
    try { await this.command(["stop", "--time", "5", containerName], 10000); } catch { /* best-effort cleanup */ }
    try { await this.command(["rm", "--force", containerName], 15000); } catch { /* best-effort cleanup */ }
  }

  async deploy(rawPayload) {
    const payload = validateDeploymentPayload(rawPayload);
    await this.assertReady({ requireStorageQuota: true });
    const existing = await this.inspect(payload.container_name).catch((error) => {
      if (/no such object|not found/i.test(error.message)) return null;
      throw error;
    });
    let inspection = existing;
    if (existing?.State?.Running) {
      const localPort = this.getHostPort(existing, payload.container_port);
      try {
        const health = await this.waitForHealth(localPort, payload);
        return { result_code: "workload_healthy", result_summary: "Existing deployment container passed its application health check.", container_name: payload.container_name, local_port: localPort, result_metadata: { local_port: localPort, container_name: payload.container_name }, health };
      } catch (error) {
        await this.removeUnhealthyContainer(payload.container_name);
        throw error;
      }
    }
    if (existing) await this.command(["rm", "--force", payload.container_name]);

    await this.verifyImage(payload.image);
    await this.command(["pull", "--quiet", payload.image], 300000);
    const volumeArgs = (payload.volumes || []).map((v) => {
      const flags = (v.read_only ? "ro" : "rw") + ",noexec,nosuid,nodev,z";
      return "--volume=" + v.host_path + ":" + v.mount_path + ":" + flags;
    });
    const args = [
      "run", "--detach",
      "--name", payload.container_name,
      "--label", "io.cloudexify.managed=true",
      "--label", "io.cloudexify.deployment=" + payload.deployment_id,
      "--pull=never",
      "--network=slirp4netns",
      "--publish", "127.0.0.1::" + payload.container_port + "/tcp",
      "--cpus=" + String(payload.resources.cpu_millicores / 1000),
      "--memory=" + String(payload.resources.memory_bytes),
      "--storage-opt=size=" + String(payload.resources.disk_bytes),
      "--pids-limit=128",
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--user=10001:10001",
      "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=" + String(Math.floor(Math.min(64 * 1024 * 1024, payload.resources.disk_bytes) / (1024 * 1024))) + "m",
      ...volumeArgs,
      payload.image
    ];
    try {
      await this.command(args, 120000);
      inspection = await this.inspect(payload.container_name);
      if (!inspection?.State?.Running) throw new Error("Container did not enter the running state.");
      const localPort = this.getHostPort(inspection, payload.container_port);
      const health = await this.waitForHealth(localPort, payload);
      return {
        result_code: "workload_healthy",
        result_summary: "Rootless OCI container started and passed its application HTTP health check.",
        container_name: payload.container_name,
        local_port: localPort,
        result_metadata: { local_port: localPort, container_name: payload.container_name },
        health
      };
    } catch (error) {
      await this.removeUnhealthyContainer(payload.container_name);
      throw error;
    }
  }

  getHostPort(inspection, containerPort) {
    const mappings = inspection?.NetworkSettings?.Ports?.[containerPort + "/tcp"];
    const mapping = Array.isArray(mappings) ? mappings.find((item) => item?.HostIp === "127.0.0.1" && /^\d+$/.test(item?.HostPort || "")) : null;
    return mapping ? Number(mapping.HostPort) : null;
  }

  async stop(deploymentId) {
    if (!UUID.test(deploymentId || "")) throw new Error("Deployment ID is invalid.");
    await this.assertReady();
    const name = "cloudexify-" + deploymentId.toLowerCase();
    const existing = await this.inspect(name).catch((error) => {
      if (/no such object|not found/i.test(error.message)) return null;
      throw error;
    });
    if (!existing || !existing.State?.Running) return { result_code: "workload_already_stopped", result_summary: "Deployment container is absent or already stopped." };
    await this.command(["stop", "--time", "10", name], 20000);
    const after = await this.inspect(name);
    if (after?.State?.Running) throw new Error("Container remained running after stop request.");
    return { result_code: "workload_stopped", result_summary: "Container stop was confirmed by Podman." };
  }

  async restart(deploymentId, options = {}) {
    if (!UUID.test(deploymentId || "")) throw new Error("Deployment ID is invalid.");
    const containerPort = options.container_port;
    const healthCheckPath = options.health_check_path == null ? "/" : options.health_check_path;
    const healthCheckTimeout = options.health_check_timeout_seconds == null ? 30 : options.health_check_timeout_seconds;
    if (!Number.isInteger(containerPort) || containerPort < 1 || containerPort > 65535) throw new Error("Restart container port is invalid.");
    if (typeof healthCheckPath !== "string" || healthCheckPath.length < 1 || healthCheckPath.length > 256 || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]*$/.test(healthCheckPath) || healthCheckPath.startsWith("//") || healthCheckPath.split("/").includes("..")) throw new Error("Restart health-check path is invalid.");
    if (!Number.isInteger(healthCheckTimeout) || healthCheckTimeout < 5 || healthCheckTimeout > 120) throw new Error("Restart health-check timeout is invalid.");
    await this.assertReady();
    const name = "cloudexify-" + deploymentId.toLowerCase();
    const existing = await this.inspect(name);
    if (!existing) throw new Error("Deployment container does not exist on this node.");
    await this.command(["restart", "--time", "10", name], 30000);
    const after = await this.inspect(name);
    if (!after?.State?.Running) throw new Error("Container restart was not confirmed.");
    const localPort = this.getHostPort(after, containerPort);
    try {
      const health = await this.waitForHealth(localPort, { health_check_path: healthCheckPath, health_check_timeout_seconds: healthCheckTimeout });
      return { result_code: "workload_healthy", result_summary: "Container restarted and passed its application HTTP health check.", container_name: name, local_port: localPort, result_metadata: { local_port: localPort, container_name: name }, health };
    } catch (error) {
      await this.removeUnhealthyContainer(name);
      throw error;
    }
  }
}

export { validateDeploymentPayload };
