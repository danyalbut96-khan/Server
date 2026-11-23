import os from "node:os";
import { existsSync } from "node:fs";
import { access, readFile, statfs } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const ARCHITECTURES = new Map([["x64", "x86_64"], ["arm64", "aarch64"]]);

export function getLinuxIdentity(platform = process.env.CLOUDEXIFY_TEST_PLATFORM || process.platform, architecture = process.env.CLOUDEXIFY_TEST_ARCH || process.arch, env = process.env) {
  // Termux Node.js builds may report process.platform as "android" rather
  // than "linux". Accept that platform only when the Termux environment is
  // positively identified; never infer Termux from ARM architecture alone.
  const isTermux = Boolean(env.TERMUX_VERSION || env.PREFIX?.startsWith("/data/data/com.termux/files/usr"));
  if (platform !== "linux" && !(platform === "android" && isTermux)) {
    throw new Error("Cloudexify node agent requires Linux or Android running Termux.");
  }
  const normalized = ARCHITECTURES.get(architecture);
  if (!normalized) throw new Error("Unsupported Linux/Android architecture: " + architecture + ". Supported: x86_64 and aarch64.");
  return { platform: isTermux ? "android" : "linux", architecture: normalized, environment: isTermux ? "termux" : "linux" };
}

const execFileAsync = promisify(execFile);

export async function detectPodmanRuntime({
  runCommand = execFileAsync,
  readCgroupControllers = () => readFile("/sys/fs/cgroup/cgroup.controllers", "utf8"),
  env = process.env,
  readStorageMetrics = (targetPath) => statfs(targetPath)
} = {}) {
  let info;
  try {
    const result = await runCommand("podman", ["info", "--format", "json"], {
      timeout: 3000,
      maxBuffer: 64 * 1024,
      windowsHide: true
    });
    const output = typeof result?.stdout === "string" ? result.stdout : "";
    info = JSON.parse(output);
  } catch {
    return { available: false, ready: false, reason: "podman_unavailable_or_unresponsive" };
  }

  const rootless = info?.host?.security?.rootless === true;
  const cgroupVersion = String(info?.host?.cgroupVersion || info?.host?.cgroupManagerVersion || "").toLowerCase();
  const version = String(info?.version?.Version || info?.version?.version || "").slice(0, 40) || null;
  const graphDriver = String(info?.store?.graphDriverName || "").toLowerCase();
  const storageQuotaConfigured = env.CLOUDEXIFY_STORAGE_QUOTA_READY === "true";
  const graphRoot = typeof info?.store?.graphRoot === "string" ? info.store.graphRoot : null;
  let storageMetrics = null;
  if (graphRoot) {
    try {
      const fs = await readStorageMetrics(graphRoot);
      const totalBytes = Number(fs.blocks) * Number(fs.bsize);
      const availableBytes = Number(fs.bavail) * Number(fs.bsize);
      if (Number.isSafeInteger(totalBytes) && totalBytes > 0 && Number.isSafeInteger(availableBytes) && availableBytes >= 0 && availableBytes <= totalBytes) {
        storageMetrics = { total_bytes: totalBytes, available_bytes: availableBytes };
      }
    } catch { /* Podman storage capacity must be readable before placement */ }
  }
  const storageQuotaReady = graphDriver === "overlay" && storageQuotaConfigured && storageMetrics?.available_bytes > 0;
  let cgroupV2Available = false;
  try {
    const controllers = await readCgroupControllers();
    cgroupV2Available = typeof controllers === "string" && controllers.trim().length > 0;
  } catch { /* cgroup v2 is a required capability, not an assumption */ }

  const ready = rootless && cgroupVersion === "v2" && cgroupV2Available;
  return {
    available: true,
    ready,
    version,
    rootless,
    cgroup_version: cgroupVersion || null,
    cgroup_v2_available: cgroupV2Available,
    graph_driver: graphDriver || null,
    storage_quota: {
      available: graphDriver === "overlay",
      ready: storageQuotaReady,
      enforcement: graphDriver === "overlay" ? "podman-overlay-size" : null,
      total_bytes: storageMetrics?.total_bytes ?? null,
      available_bytes: storageMetrics?.available_bytes ?? null,
      reason: storageQuotaReady ? null : graphDriver !== "overlay" ? "overlay-storage-driver-required" : !storageMetrics ? "podman-storage-filesystem-unavailable" : "operator-storage-quota-attestation-required"
    },
    reason: ready ? null : !rootless ? "podman_not_rootless" : "cgroup_v2_unavailable"
  };
}

export async function detectCosignVerifier({
  runCommand = execFileAsync,
  trustKeyPath = "/etc/cloudexify/trust.pub",
  accessFile = access
} = {}) {
  try {
    await runCommand("cosign", ["version"], { timeout: 3000, maxBuffer: 16 * 1024, windowsHide: true });
    await accessFile(trustKeyPath);
    return { available: true, ready: true, trust_key_configured: true };
  } catch {
    return { available: false, ready: false, trust_key_configured: false, reason: "cosign_or_trust_key_unavailable" };
  }
}

export async function getCapabilities(identity = getLinuxIdentity(), { podmanProbe = detectPodmanRuntime, cosignProbe = detectCosignVerifier } = {}) {
  const podmanResult = identity.platform === "linux"
    ? await podmanProbe()
    : { available: false, ready: false, reason: "platform_not_qualified" };
  const podman = {
    ...podmanResult,
    storage_quota: podmanResult.storage_quota || {
      available: false, ready: false, enforcement: null, reason: "storage_quota_not_detected"
    }
  };
  const cosign = identity.platform === "linux"
    ? await cosignProbe()
    : { available: false, ready: false, trust_key_configured: false, reason: "platform_not_qualified" };
  return {
    agent_protocol: 1,
    diagnostics: ["probe", "collect_metrics"],
    service_manager: identity.platform === "linux" && existsSync("/run/systemd/system") ? "systemd" : null,
    environment: identity.environment,
    container_runtime: podman.ready ? "podman-rootless" : null,
    runtime_probe: { podman, cosign },
    workload_execution: false
  };
}

async function readCpuCounters(procRoot) {
  const contents = await readFile(path.join(procRoot, "stat"), "utf8");
  const line = contents.split("\n").find((item) => item.startsWith("cpu "));
  if (!line) throw new Error("CPU counters are unavailable.");
  const values = line.trim().split(/\s+/).slice(1).map(Number);
  if (values.length < 4 || values.some((value) => !Number.isFinite(value) || value < 0)) throw new Error("CPU counters are invalid.");
  const idle = values[3] + (values[4] || 0);
  const total = values.slice(0, 8).reduce((sum, value) => sum + value, 0);
  return { idle, total };
}

export async function readCpuPercent({ procRoot = "/proc", delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  const before = await readCpuCounters(procRoot);
  await delay(120);
  const after = await readCpuCounters(procRoot);
  const total = after.total - before.total;
  const idle = after.idle - before.idle;
  if (total <= 0 || idle < 0 || idle > total) return null;
  return Math.round(Math.max(0, Math.min(100, (1 - idle / total) * 100)) * 10) / 10;
}

async function readFilesystemMetrics(targetPath) {
  const disk = await statfs(targetPath);
  const total = Number(disk.blocks) * Number(disk.bsize);
  const free = Number(disk.bfree) * Number(disk.bsize);
  const available = Number(disk.bavail) * Number(disk.bsize);
  if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(free) || free < 0 || free > total ||
      !Number.isFinite(available) || available < 0 || available > total) return null;
  return { total, used: total - free, available };
}

async function readCpuFrequencyMhz() {
  for (const file of [
    "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
    "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
    "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"
  ]) {
    try {
      const khz = Number((await readFile(file, "utf8")).trim());
      if (Number.isFinite(khz) && khz > 0 && khz <= 10000000) return Math.round(khz / 100) / 10;
    } catch { /* frequency sysfs is optional and often restricted on Android */ }
  }
  return null;
}

export async function readLinuxMetrics({
  procRoot = "/proc",
  diskPath = process.env.PREFIX || "/",
  androidSharedStoragePath = "/storage/emulated/0",
  isAndroid = Boolean(process.env.TERMUX_VERSION || process.env.PREFIX?.startsWith("/data/data/com.termux/files/usr"))
} = {}) {
  const parallelism = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  const metrics = { uptime_seconds: Math.max(0, Math.floor(os.uptime())), cpu_cores: Math.max(1, Math.min(256, Math.floor(parallelism))) };
  try {
    const meminfo = await readFile(path.join(procRoot, "meminfo"), "utf8");
    const values = Object.fromEntries(meminfo.split("\n").map((line) => {
      const match = line.match(/^([A-Za-z_()]+):\s+(\d+)\s+kB$/);
      return match ? [match[1], Number(match[2]) * 1024] : null;
    }).filter(Boolean));
    if (Number.isFinite(values.MemTotal) && values.MemTotal > 0) {
      const available = Number.isFinite(values.MemAvailable) ? values.MemAvailable : values.MemFree;
      if (Number.isFinite(available) && available >= 0 && available <= values.MemTotal) {
        metrics.memory_total_bytes = values.MemTotal;
        metrics.memory_available_bytes = available;
        metrics.memory_used_bytes = values.MemTotal - available;
      }
    }
  } catch { /* unavailable metrics are omitted, never fabricated */ }
  try {
    const disk = await readFilesystemMetrics(diskPath);
    if (disk) {
      metrics.disk_total_bytes = disk.total;
      metrics.disk_used_bytes = disk.used;
      metrics.disk_available_bytes = disk.available;
    }
  } catch { /* unavailable metrics are omitted */ }
  if (isAndroid) {
    try {
      const shared = await readFilesystemMetrics(androidSharedStoragePath);
      if (shared) {
        metrics.android_shared_storage_total_bytes = shared.total;
        metrics.android_shared_storage_used_bytes = shared.used;
        metrics.android_shared_storage_available_bytes = shared.available;
      }
    } catch { /* Android shared storage requires user-granted storage access */ }
  }
  const frequency = await readCpuFrequencyMhz();
  if (frequency !== null) metrics.cpu_frequency_mhz = frequency;
  const load = os.loadavg()[0];
  if (Number.isFinite(load) && load >= 0) metrics.load_1m = Math.round(load * 100) / 100;
  try {
    const cpu = await readCpuPercent({ procRoot });
    if (cpu !== null) metrics.cpu_percent = cpu;
  } catch { /* CPU counters may be unavailable in restricted containers */ }
  // Android exposes battery readings through the Linux power_supply sysfs API
  // on many devices. Omit them when Termux/device permissions do not allow it.
  try {
    const battery = Number((await readFile("/sys/class/power_supply/battery/capacity", "utf8")).trim());
    if (Number.isFinite(battery) && battery >= 0 && battery <= 100) metrics.battery_percent = battery;
  } catch { /* battery sysfs may be unavailable on some Android devices */ }
  try {
    const rawTemperature = Number((await readFile("/sys/class/thermal/thermal_zone0/temp", "utf8")).trim());
    const temperature = rawTemperature > 1000 ? rawTemperature / 1000 : rawTemperature;
    if (Number.isFinite(temperature) && temperature >= 0 && temperature <= 150) metrics.temperature_c = Math.round(temperature * 10) / 10;
  } catch { /* thermal sysfs may be unavailable or permission restricted */ }
  return metrics;
}

export function validateControlPlaneUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error("CLOUDEXIFY_CONTROL_PLANE_URL must be a valid absolute URL."); }
  const localHost = ["127.0.0.1", "::1", "localhost"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && localHost)) {
    throw new Error("Control-plane URL must use HTTPS (HTTP is allowed only for localhost testing).");
  }
  if (url.username || url.password || url.search || url.hash) throw new Error("Control-plane URL must not contain credentials, query parameters or fragments.");
  return url.toString().replace(/\/$/, "");
}
