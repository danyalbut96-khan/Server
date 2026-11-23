import { createHash, randomBytes, randomUUID } from "node:crypto";
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { createOidcVerifier, getBearerToken } from "./auth/oidc.mjs";
import { createSupabaseAuthVerifier } from "./auth/supabase.mjs";
import { AuthorizationError, requirePermission, canAssignRole } from "./auth/rbac.mjs";
import { withNodeEnrollment, withNodeHeartbeat, withNodeJobAcknowledgement, withNodeJobClaim, withNodeRouteAuthorization, withNodeRuntimeReconciliation, withUserTransaction } from "./db/pool.mjs";
import { createRouteGrantSigner } from "./ingress/route-grants.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BODY_BYTES = 64 * 1024;

function send(response, status, payload, requestId, extraHeaders = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": requestId,
    ...extraHeaders
  });
  response.end(JSON.stringify(payload));
}

async function readJson(request) {
  const contentType = String(request.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    const error = new Error("Content-Type must be application/json.");
    error.status = 415;
    throw error;
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("Request body is too large.");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { const error = new Error("Request body must be valid JSON."); error.status = 400; throw error; }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    const error = new Error("Request body must be a JSON object.");
    error.status = 400;
    throw error;
  }
  return value;
}

function requireUuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) {
    const error = new Error(field + " must be a valid UUID.");
    error.status = 400;
    throw error;
  }
  return value;
}

function requireText(value, field, max = 120) {
  if (typeof value !== "string" || !value.trim() || value.trim().length > max) {
    const error = new Error(field + " is required and must be at most " + max + " characters.");
    error.status = 400;
    throw error;
  }
  return value.trim();
}

function audit(client, tenantId, userId, action, resourceType, resourceId, metadata = {}) {
  return client.query(
    "INSERT INTO audit_events (tenant_id, actor_type, actor_id, action, resource_type, resource_id, metadata_json) VALUES ($1, 'user', $2, $3, $4, $5, $6::jsonb)",
    [tenantId, userId, action, resourceType, resourceId, JSON.stringify(metadata)]
  );
}

async function getMembership(client, tenantId, userId) {
  const result = await client.query(
    "SELECT membership.role, tenant.status AS tenant_status FROM tenant_memberships AS membership JOIN tenants AS tenant ON tenant.id = membership.tenant_id WHERE membership.tenant_id = $1 AND membership.user_id = $2 AND membership.status = 'active' AND tenant.status = 'active' LIMIT 1",
    [tenantId, userId]
  );
  if (!result.rows[0]) {
    const error = new Error("Tenant not found.");
    error.status = 404;
    throw error;
  }
  return result.rows[0].role;
}


function validateJobPayload(type, payload) {
  // Only non-mutating, structured diagnostics are enabled in this protocol
  // version. Never accept shell text, executable paths, scripts or argv arrays.
  if (!["probe", "collect_metrics"].includes(type)) {
    const error = new Error("type must be probe or collect_metrics.");
    error.status = 400;
    throw error;
  }
  if (!payload || Array.isArray(payload) || typeof payload !== "object" || Object.keys(payload).length !== 0) {
    const error = new Error("payload must be an empty JSON object for this job type.");
    error.status = 400;
    throw error;
  }
  return {};
}

function validateImageDigest(value) {
  if (typeof value !== "string" ||
      !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/.test(value)) {
    const error = new Error("image_digest must be a fully qualified OCI image reference pinned to a SHA-256 digest.");
    error.status = 400;
    throw error;
  }
  return value;
}

function validateResourceRequests(value) {
  const input = value == null ? {} : value;
  if (!input || Array.isArray(input) || typeof input !== "object") {
    const error = new Error("resource_requests must be a JSON object.");
    error.status = 400;
    throw error;
  }
  const allowed = new Set(["cpu_millicores", "memory_bytes", "disk_bytes"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    const error = new Error("resource_requests supports cpu_millicores, memory_bytes and disk_bytes only.");
    error.status = 400;
    throw error;
  }
  const result = {
    cpu_millicores: input.cpu_millicores == null ? 250 : input.cpu_millicores,
    memory_bytes: input.memory_bytes == null ? 268435456 : input.memory_bytes,
    disk_bytes: input.disk_bytes == null ? 1073741824 : input.disk_bytes
  };
  const bounds = { cpu_millicores: [50, 64000], memory_bytes: [16777216, 1099511627776], disk_bytes: [16777216, 1099511627776] };
  for (const [key, [minimum, maximum]] of Object.entries(bounds)) {
    if (!Number.isSafeInteger(result[key]) || result[key] < minimum || result[key] > maximum) {
      const error = new Error(key + " must be an integer between " + minimum + " and " + maximum + ".");
      error.status = 400;
      throw error;
    }
  }
  return result;
}

function validateVolumePayload(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Volume payload must be a JSON object.");
    error.status = 400;
    throw error;
  }
  const applicationId = requireUuid(body.application_id, "application_id");
  const name = requireText(body.name, "name", 63).toLowerCase();
  if (!/^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$/.test(name)) {
    const error = new Error("Volume name must be 1-63 lowercase alphanumeric characters with dashes or underscores.");
    error.status = 400;
    throw error;
  }
  const mountPath = requireText(body.mount_path, "mount_path", 255);
  if (!/^\/[a-zA-Z0-9_.-]+(\/[a-zA-Z0-9_.-]+)*$/.test(mountPath) || ["/proc", "/sys", "/dev", "/etc", "/bin", "/sbin"].some((p) => mountPath === p || mountPath.startsWith(p + "/"))) {
    const error = new Error("Volume mount path must be a valid non-system absolute path.");
    error.status = 400;
    throw error;
  }
  const sizeBytes = body.size_bytes == null ? 1073741824 : Number(body.size_bytes);
  if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 10485760 || sizeBytes > 1099511627776) {
    const error = new Error("Volume size_bytes must be an integer between 10485760 (10MB) and 1099511627776 (1TB).");
    error.status = 400;
    throw error;
  }
  const readOnly = Boolean(body.read_only);
  const driver = ["local_dir", "nfs", "btrfs_subvol", "zfs_dataset"].includes(body.driver) ? body.driver : "local_dir";
  return { applicationId, name, mountPath, sizeBytes, readOnly, driver };
}

function normalizeHostname(value) {
  const input = requireText(value, "hostname", 253).trim();
  if (/[\s\/:@?#\\]/.test(input) || input.includes("*")) {
    const error = new Error("hostname must be a DNS hostname without a scheme, path, wildcard or port.");
    error.status = 400;
    throw error;
  }
  const ascii = domainToASCII(input.replace(/\.$/, "")).toLowerCase();
  if (!ascii || ascii.length > 253 || ascii === "localhost" || isIP(ascii) ||
      !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(ascii)) {
    const error = new Error("hostname must be a valid public DNS hostname.");
    error.status = 400;
    throw error;
  }
  return ascii;
}

function makeDomainChallenge() {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: createHash("sha256").update(token, "utf8").digest("hex") };
}

function nodeCredential(request) {
  return String(request.headers.authorization || "").match(/^Bearer ([A-Za-z0-9_-]{40,128})$/)?.[1] || null;
}

export function createApiHandler({ pool, env = process.env, fetchImpl = fetch, resolveTxtFn = dnsResolveTxt, logger = console }) {
  let verifyAccessToken;
  try {
    const supabaseApiKey = env.SUPABASE_PUBLISHABLE_KEY || env.SUPABASE_ANON_KEY;
    if (env.SUPABASE_URL && supabaseApiKey) {
      verifyAccessToken = createSupabaseAuthVerifier({ supabaseUrl: env.SUPABASE_URL, apiKey: supabaseApiKey, fetchImpl });
    } else {
      verifyAccessToken = createOidcVerifier({
        issuer: env.OIDC_ISSUER,
        audience: env.OIDC_AUDIENCE,
        jwksUri: env.OIDC_JWKS_URI,
        fetchImpl
      });
    }
  } catch {
    verifyAccessToken = null;
  }
  const allowedOrigins = new Set(String(env.CORS_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean));

  return async function handleApi(request, response) {
    const url = new URL(request.url || "/", "http://localhost");
    if (!url.pathname.startsWith("/api/v1/")) return false;
    const requestId = randomUUID();
    const origin = request.headers.origin;
    if (origin) {
      if (!allowedOrigins.has(origin)) {
        send(response, 403, { error: { code: "ORIGIN_NOT_ALLOWED", message: "Origin is not allowed.", request_id: requestId } }, requestId);
        return true;
      }
      response.setHeader("access-control-allow-origin", origin);
      response.setHeader("vary", "Origin");
    }
    if (request.method === "OPTIONS") {
      response.writeHead(204, {
        "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
        "access-control-allow-headers": "Authorization, Content-Type, X-Request-ID",
        "access-control-max-age": "600",
        "vary": "Origin"
      });
      response.end();
      return true;
    }

    try {
      if (!["GET", "POST", "DELETE"].includes(request.method || "")) {
        const error = new Error("Method not allowed.");
        error.status = 405;
        throw error;
      }
      if (url.pathname === "/api/v1/nodes/enroll" && request.method === "POST") {
        if (!pool) { const error = new Error("Node enrollment is not configured with a database."); error.status = 503; throw error; }
        const body = await readJson(request);
        const token = requireText(body.enrollment_token, "enrollment_token", 256);
        const name = requireText(body.name, "name", 100);
        const platform = requireText(body.platform, "platform", 20).toLowerCase();
        const architecture = requireText(body.architecture, "architecture", 40);
        if (!["linux", "android", "windows", "macos", "other"].includes(platform)) { const error = new Error("Unsupported node platform."); error.status = 400; throw error; }
        const agentVersion = body.agent_version == null ? null : requireText(body.agent_version, "agent_version", 40);
        const capabilities = body.capabilities == null ? {} : body.capabilities;
        if (!capabilities || Array.isArray(capabilities) || typeof capabilities !== "object" || Buffer.byteLength(JSON.stringify(capabilities), "utf8") > 8192) { const error = new Error("capabilities must be a JSON object of at most 8 KiB."); error.status = 400; throw error; }
        const tokenHash = createHash("sha256").update(token, "utf8").digest("hex");
        const credential = randomBytes(32).toString("base64url");
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const enrolled = await withNodeEnrollment(pool, { tokenHash, name, platform, architecture, agentVersion, capabilities, credentialHash });
        if (!enrolled) { const error = new Error("Enrollment token is invalid, expired or already used."); error.status = 401; throw error; }
        send(response, 201, { node: { id: enrolled.node_id, tenant_id: enrolled.tenant_id, name, platform, architecture, status: "pending" }, credential: { id: enrolled.credential_id, secret: credential, expires_in_days: 90 } }, requestId);
        return true;
      }

      const heartbeatMatch = url.pathname.match(/^\/api\/v1\/nodes\/([0-9a-f-]{36})\/heartbeat$/i);
      if (heartbeatMatch && request.method === "POST") {
        if (!pool) { const error = new Error("Node heartbeat is not configured with a database."); error.status = 503; throw error; }
        const nodeId = requireUuid(heartbeatMatch[1], "node_id");
        const credential = String(request.headers.authorization || "").match(/^Bearer ([A-Za-z0-9_-]{40,128})$/)?.[1];
        if (!credential) { const error = new Error("A valid node credential is required."); error.status = 401; throw error; }
        const body = await readJson(request);
        if (!["healthy", "degraded"].includes(body.health_status)) { const error = new Error("health_status must be healthy or degraded."); error.status = 400; throw error; }
        const agentVersion = body.agent_version == null ? null : requireText(body.agent_version, "agent_version", 40);
        const resources = body.resources == null ? {} : body.resources;
        const capabilities = body.capabilities == null ? {} : body.capabilities;
        if (!capabilities || Array.isArray(capabilities) || typeof capabilities !== "object" || Buffer.byteLength(JSON.stringify(capabilities), "utf8") > 8192) { const error = new Error("capabilities must be a JSON object of at most 8 KiB."); error.status = 400; throw error; }
        const allowed = new Set([
          "cpu_percent","cpu_cores","cpu_frequency_mhz","load_1m","uptime_seconds",
          "memory_total_bytes","memory_used_bytes","memory_available_bytes",
          "disk_total_bytes","disk_used_bytes","disk_available_bytes",
          "android_shared_storage_total_bytes","android_shared_storage_used_bytes","android_shared_storage_available_bytes",
          "battery_percent","temperature_c"
        ]);
        const entries = resources && typeof resources === "object" && !Array.isArray(resources) ? Object.entries(resources) : [];
        const invalid = !resources || Array.isArray(resources) || typeof resources !== "object" ||
          Buffer.byteLength(JSON.stringify(resources), "utf8") > 16384 || entries.length > 20 ||
          entries.some(([key,value]) => !allowed.has(key) || typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1e15 ||
            ((key === "cpu_percent" || key === "battery_percent") && value > 100) ||
            (key === "cpu_cores" && (value < 1 || value > 256 || !Number.isInteger(value))) ||
            (key === "cpu_frequency_mhz" && value > 10000) ||
            (key === "temperature_c" && value > 150));
        const consistent = (totalKey, usedKey, availableKey) => {
          const total = resources?.[totalKey], used = resources?.[usedKey], available = resources?.[availableKey];
          return (total == null || used == null || used <= total) &&
            (total == null || available == null || available <= total) &&
            (used == null || available == null || used + available <= total);
        };
        if (invalid || !consistent("memory_total_bytes","memory_used_bytes","memory_available_bytes") ||
            !consistent("disk_total_bytes","disk_used_bytes","disk_available_bytes") ||
            !consistent("android_shared_storage_total_bytes","android_shared_storage_used_bytes","android_shared_storage_available_bytes")) {
          const error = new Error("resources must contain only supported finite numeric metrics with consistent capacity values (16 KiB maximum)."); error.status = 400; throw error;
        }
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const heartbeat = await withNodeHeartbeat(pool, { nodeId, credentialHash, agentVersion, healthStatus: body.health_status, resources, capabilities });
        if (!heartbeat) { const error = new Error("Node credential is invalid, expired or revoked."); error.status = 401; throw error; }
        send(response, 200, { node: { id: heartbeat.node_id, status: heartbeat.status, last_seen_at: heartbeat.last_seen_at } }, requestId);
        return true;
      }

      const routeGrantMatch = url.pathname.match(/^\/api\/v1\/nodes\/([0-9a-f-]{36})\/routes\/([0-9a-f-]{36})\/grant$/i);
      if (routeGrantMatch && request.method === "GET") {
        if (!pool) { const error = new Error("Node route authorization is not configured with a database."); error.status = 503; throw error; }
        const nodeId = requireUuid(routeGrantMatch[1], "node_id");
        const routeId = requireUuid(routeGrantMatch[2], "route_id");
        const credential = nodeCredential(request);
        if (!credential) { const error = new Error("A valid node credential is required."); error.status = 401; throw error; }
        if (!env.CLOUDEXIFY_ROUTE_GRANT_PRIVATE_KEY) {
          const error = new Error("Route grant signing is not configured.");
          error.status = 503;
          throw error;
        }
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const authorizedRoute = await withNodeRouteAuthorization(pool, { nodeId, routeId, credentialHash });
        if (authorizedRoute === null) { const error = new Error("Node credential is invalid, expired or revoked."); error.status = 401; throw error; }
        if (!authorizedRoute) { const error = new Error("Route is not eligible for this node."); error.status = 404; throw error; }
        const signed = createRouteGrantSigner(env.CLOUDEXIFY_ROUTE_GRANT_PRIVATE_KEY)(authorizedRoute, { ttlSeconds: 30 });
        send(response, 200, { grant: signed.token, expires_at: new Date(signed.claims.exp * 1000).toISOString() }, requestId);
        return true;
      }

      const reconcileMatch = url.pathname.match(/^\/api\/v1\/nodes\/([0-9a-f-]{36})\/runtime\/reconcile$/i);
      if (reconcileMatch && request.method === "POST") {
        if (!pool) { const error = new Error("Node runtime reconciliation is not configured with a database."); error.status = 503; throw error; }
        const nodeId = requireUuid(reconcileMatch[1], "node_id");
        const credential = nodeCredential(request);
        if (!credential) { const error = new Error("A valid node credential is required."); error.status = 401; throw error; }
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const reconciledJobs = await withNodeRuntimeReconciliation(pool, { nodeId, credentialHash });
        if (reconciledJobs === null) { const error = new Error("Node credential is invalid, expired or revoked."); error.status = 401; throw error; }
        send(response, 200, { reconciled_jobs: reconciledJobs }, requestId);
        return true;
      }

      const claimMatch = url.pathname.match(/^\/api\/v1\/nodes\/([0-9a-f-]{36})\/jobs\/claim$/i);
      if (claimMatch && request.method === "POST") {
        if (!pool) { const error = new Error("Node job polling is not configured with a database."); error.status = 503; throw error; }
        const nodeId = requireUuid(claimMatch[1], "node_id");
        const credential = nodeCredential(request);
        if (!credential) { const error = new Error("A valid node credential is required."); error.status = 401; throw error; }
        const body = await readJson(request);
        const limit = body.limit == null ? 1 : body.limit;
        const leaseSeconds = body.lease_seconds == null ? 60 : body.lease_seconds;
        if (!Number.isInteger(limit) || limit < 1 || limit > 10) { const error = new Error("limit must be an integer between 1 and 10."); error.status = 400; throw error; }
        if (!Number.isInteger(leaseSeconds) || leaseSeconds < 15 || leaseSeconds > 300) { const error = new Error("lease_seconds must be an integer between 15 and 300."); error.status = 400; throw error; }
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const jobs = await withNodeJobClaim(pool, { nodeId, credentialHash, limit, leaseSeconds });
        if (jobs === null) { const error = new Error("Node credential is invalid, expired or revoked."); error.status = 401; throw error; }
        send(response, 200, { jobs }, requestId);
        return true;
      }

      const acknowledgeMatch = url.pathname.match(/^\/api\/v1\/nodes\/([0-9a-f-]{36})\/jobs\/([0-9a-f-]{36})\/ack$/i);
      if (acknowledgeMatch && request.method === "POST") {
        if (!pool) { const error = new Error("Node job acknowledgement is not configured with a database."); error.status = 503; throw error; }
        const nodeId = requireUuid(acknowledgeMatch[1], "node_id");
        const jobId = requireUuid(acknowledgeMatch[2], "job_id");
        const credential = nodeCredential(request);
        if (!credential) { const error = new Error("A valid node credential is required."); error.status = 401; throw error; }
        const body = await readJson(request);
        const attemptId = requireUuid(body.attempt_id, "attempt_id");
        const leaseToken = requireUuid(body.lease_token, "lease_token");
        if (!["accepted", "running", "succeeded", "failed", "rejected"].includes(body.status)) { const error = new Error("status must be accepted, running, succeeded, failed or rejected."); error.status = 400; throw error; }
        const resultCode = body.result_code == null ? null : requireText(body.result_code, "result_code", 80);
        const resultSummary = body.result_summary == null ? null : requireText(body.result_summary, "result_summary", 4000);
        const resultMetadata = body.result_metadata == null ? {} : body.result_metadata;
        if (!resultMetadata || typeof resultMetadata !== "object" || Array.isArray(resultMetadata) ||
            Object.keys(resultMetadata).some((key) => !["local_port", "container_name"].includes(key)) ||
            (Object.keys(resultMetadata).length > 0 &&
              (body.status !== "succeeded" || resultCode !== "workload_healthy" ||
               Object.keys(resultMetadata).length !== 2 ||
               !Number.isInteger(resultMetadata.local_port) || resultMetadata.local_port < 1 || resultMetadata.local_port > 65535 ||
               typeof resultMetadata.container_name !== "string" ||
               !/^cloudexify-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(resultMetadata.container_name)))) {
          const error = new Error("result_metadata must contain only a valid local_port and Cloudexify container_name for a healthy workload result.");
          error.status = 400;
          throw error;
        }
        const credentialHash = createHash("sha256").update(credential, "utf8").digest("hex");
        const acknowledgement = await withNodeJobAcknowledgement(pool, { nodeId, credentialHash, jobId, attemptId, leaseToken, status: body.status, resultCode, resultSummary, resultMetadata });
        if (!acknowledgement) { const error = new Error("Job lease is invalid, expired, stale or does not belong to this node."); error.status = 409; throw error; }
        send(response, 200, { job: acknowledgement }, requestId);
        return true;
      }

      if (!pool) {
        const error = new Error("Authentication API is not configured with a database.");
        error.status = 503;
        throw error;
      }
      if (!verifyAccessToken) {
        const error = new Error("OIDC authentication is not configured.");
        error.status = 503;
        throw error;
      }
      const token = getBearerToken(request);
      const principal = await verifyAccessToken(token, { cache: request.method === "GET" });
      const result = await withUserTransaction(pool, principal.identitySubject, async (client, user) => {
        const domainRoute = url.pathname.match(/^\/api\/v1\/tenants\/([0-9a-f-]{36})\/domains(?:\/([0-9a-f-]{36})(?:\/(challenge|verify))?)?$/i);
        const volumeRoute = url.pathname.match(/^\/api\/v1\/tenants\/([0-9a-f-]{36})\/volumes(?:\/([0-9a-f-]{36})(?:\/(backups|attach|detach))?)?$/i);
        const auditRoute = url.pathname.match(/^\/api\/v1\/tenants\/([0-9a-f-]{36})\/audit-events$/i);
        const route = url.pathname.match(/^\/api\/v1\/tenants\/([0-9a-f-]{36})\/(applications|deployments|members|enrollment-tokens|nodes|jobs|overview)(?:\/([0-9a-f-]{36})(?:\/(?:credentials\/([0-9a-f-]{36})\/revoke|(approve|reject)|(state)|(events)))?)?$/i);

        if (url.pathname === "/api/v1/auth/me" && request.method === "GET") {
          const memberships = await client.query(
            "SELECT tenant.id, tenant.name, tenant.slug, membership.role FROM tenant_memberships AS membership JOIN tenants AS tenant ON tenant.id = membership.tenant_id WHERE membership.user_id = $1 AND membership.status = 'active' AND tenant.status = 'active' ORDER BY tenant.name",
            [user.id]
          );
          return { status: 200, body: { user: { id: user.id, email: user.email, display_name: user.display_name }, tenants: memberships.rows } };
        }

        if (url.pathname === "/api/v1/tenants" && request.method === "GET") {
          const tenants = await client.query(
            "SELECT tenant.id, tenant.name, tenant.slug, tenant.status, membership.role FROM tenant_memberships AS membership JOIN tenants AS tenant ON tenant.id = membership.tenant_id WHERE membership.user_id = $1 AND membership.status = 'active' AND tenant.status = 'active' ORDER BY tenant.name",
            [user.id]
          );
          return { status: 200, body: { tenants: tenants.rows } };
        }

        if ((!route && !domainRoute && !volumeRoute && !auditRoute) || !UUID.test((route || domainRoute || volumeRoute || auditRoute)[1])) {
          const error = new Error("API route not found.");
          error.status = 404;
          throw error;
        }

        const tenantId = (route || domainRoute || volumeRoute || auditRoute)[1];
        const resource = domainRoute ? "domains" : (volumeRoute ? "volumes" : (auditRoute ? "audit-events" : route[2]));
        const role = await getMembership(client, tenantId, user.id);

        if (resource === "domains" && request.method === "GET" && !domainRoute[2]) {
          requirePermission(role, "read");
          const domains = await client.query(
            "SELECT id, hostname, status, verified_at, created_at, updated_at FROM domain_claims WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            [tenantId]
          );
          return { status: 200, body: { domains: domains.rows } };
        }

        if (resource === "domains" && domainRoute[2] && request.method === "GET") {
          requirePermission(role, "read");
          const domainId = requireUuid(domainRoute[2], "domain_id");
          const domain = await client.query(
            "SELECT claim.id, claim.hostname, claim.status, claim.verified_at, claim.created_at, challenge.record_name, challenge.expires_at AS challenge_expires_at FROM domain_claims AS claim LEFT JOIN LATERAL (SELECT record_name, expires_at FROM domain_verification_challenges WHERE domain_claim_id = claim.id AND tenant_id = claim.tenant_id ORDER BY created_at DESC LIMIT 1) AS challenge ON true WHERE claim.id = $1 AND claim.tenant_id = $2",
            [domainId, tenantId]
          );
          if (!domain.rows[0]) { const error = new Error("Domain claim not found."); error.status = 404; throw error; }
          return { status: 200, body: { domain: domain.rows[0] } };
        }

        if (resource === "domains" && !domainRoute[2] && request.method === "POST") {
          requirePermission(role, "manageDomains");
          const body = await readJson(request);
          const hostname = normalizeHostname(body.hostname);
          const challenge = makeDomainChallenge();
          let claim;
          try {
            claim = await client.query(
              "INSERT INTO domain_claims (tenant_id, hostname, created_by) VALUES ($1, $2, $3) RETURNING id, hostname, status, created_at",
              [tenantId, hostname, user.id]
            );
          } catch (insertError) {
            if (insertError?.code === "23505") { const error = new Error("This hostname is already claimed by another active domain record."); error.status = 409; throw error; }
            throw insertError;
          }
          const claimRow = claim.rows[0];
          if (!claimRow) { const error = new Error("Domain claim could not be created."); error.status = 503; throw error; }
          const challengeRow = await client.query(
            "INSERT INTO domain_verification_challenges (domain_claim_id, tenant_id, token_hash, record_name, expires_at) VALUES ($1, $2, $3, $4, now() + interval '30 minutes') RETURNING id, record_name, expires_at",
            [claimRow.id, tenantId, challenge.tokenHash, "_cloudexify-verify." + hostname]
          );
          if (!challengeRow.rows[0]) { const error = new Error("DNS verification challenge could not be created."); error.status = 503; throw error; }
          await audit(client, tenantId, user.id, "domain.claim.created", "domain_claim", claimRow.id, { hostname });
          return { status: 201, body: { domain: claimRow, verification: { record_type: "TXT", record_name: challengeRow.rows[0].record_name, record_value: "cloudexify-verification=" + challenge.token, expires_at: challengeRow.rows[0].expires_at, token_display: "shown_once" } } };
        }

        if (resource === "domains" && domainRoute[2] && domainRoute[3] === "challenge" && request.method === "POST") {
          requirePermission(role, "manageDomains");
          const domainId = requireUuid(domainRoute[2], "domain_id");
          const claim = await client.query(
            "SELECT id, hostname, status FROM domain_claims WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [domainId, tenantId]
          );
          if (!claim.rows[0]) { const error = new Error("Domain claim not found."); error.status = 404; throw error; }
          if (claim.rows[0].status !== "pending_verification") { const error = new Error("Only pending domain claims can receive a new challenge."); error.status = 409; throw error; }
          await client.query("SELECT app_private.revoke_expired_domain_challenges($1)", [domainId]);
          const activeChallenge = await client.query(
            "SELECT id FROM domain_verification_challenges WHERE domain_claim_id = $1 AND tenant_id = $2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now() LIMIT 1",
            [domainId, tenantId]
          );
          if (activeChallenge.rows[0]) { const error = new Error("A DNS challenge is already active. Wait for it to expire before requesting another."); error.status = 409; throw error; }
          const challenge = makeDomainChallenge();
          const inserted = await client.query(
            "INSERT INTO domain_verification_challenges (domain_claim_id, tenant_id, token_hash, record_name, expires_at) VALUES ($1, $2, $3, $4, now() + interval '30 minutes') RETURNING record_name, expires_at",
            [domainId, tenantId, challenge.tokenHash, "_cloudexify-verify." + claim.rows[0].hostname]
          );
          await audit(client, tenantId, user.id, "domain.challenge.created", "domain_claim", domainId, { hostname: claim.rows[0].hostname });
          return { status: 201, body: { verification: { record_type: "TXT", record_name: inserted.rows[0].record_name, record_value: "cloudexify-verification=" + challenge.token, expires_at: inserted.rows[0].expires_at, token_display: "shown_once" } } };
        }

        if (resource === "domains" && domainRoute[2] && domainRoute[3] === "verify" && request.method === "POST") {
          requirePermission(role, "manageDomains");
          const domainId = requireUuid(domainRoute[2], "domain_id");
          const claim = await client.query(
            "SELECT id, hostname, status FROM domain_claims WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [domainId, tenantId]
          );
          if (!claim.rows[0]) { const error = new Error("Domain claim not found."); error.status = 404; throw error; }
          if (claim.rows[0].status === "verified") return { status: 200, body: { verified: true, hostname: claim.rows[0].hostname, already_verified: true } };
          if (claim.rows[0].status !== "pending_verification") { const error = new Error("This domain claim cannot be verified in its current state."); error.status = 409; throw error; }
          const challenge = await client.query(
            "SELECT id, token_hash, record_name, expires_at FROM domain_verification_challenges WHERE domain_claim_id = $1 AND tenant_id = $2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
            [domainId, tenantId]
          );
          if (!challenge.rows[0]) { const error = new Error("No active DNS challenge exists. Create a new challenge first."); error.status = 409; throw error; }
          let txtRecords;
          try { txtRecords = await resolveTxtFn(challenge.rows[0].record_name); }
          catch (dnsError) {
            if (dnsError?.code === "ENODATA" || dnsError?.code === "ENOTFOUND") return { status: 200, body: { verified: false, reason: "dns_record_not_found", hostname: claim.rows[0].hostname } };
            const error = new Error("DNS TXT lookup is temporarily unavailable."); error.status = 503; throw error;
          }
          const observedTokens = (Array.isArray(txtRecords) ? txtRecords : [])
            .filter(Array.isArray)
            .map((parts) => parts.join(""))
            .filter((value) => value.startsWith("cloudexify-verification="))
            .map((value) => value.slice("cloudexify-verification=".length))
            .filter((value) => /^[A-Za-z0-9_-]{43}$/.test(value));
          const observedHashes = new Set(observedTokens.map((value) => createHash("sha256").update(value, "utf8").digest("hex")));
          if (!observedHashes.has(challenge.rows[0].token_hash)) {
            return { status: 200, body: { verified: false, reason: "dns_record_mismatch", hostname: claim.rows[0].hostname } };
          }
          const verified = await client.query(
            "SELECT app_private.verify_domain_claim($1, $2) AS verified",
            [domainId, challenge.rows[0].token_hash]
          );
          if (!verified.rows[0]?.verified) return { status: 200, body: { verified: false, reason: "challenge_expired_or_consumed", hostname: claim.rows[0].hostname } };
          await audit(client, tenantId, user.id, "domain.verification.requested", "domain_claim", domainId, { hostname: claim.rows[0].hostname });
          return { status: 200, body: { verified: true, hostname: claim.rows[0].hostname } };
        }

        if (resource === "volumes" && request.method === "GET" && !volumeRoute[2]) {
          requirePermission(role, "read");
          const volumes = await client.query(
            "SELECT id, tenant_id, application_id, name, mount_path, size_bytes, status, attached_node_id, attached_deployment_id, read_only, driver, created_at, updated_at FROM application_volumes WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            [tenantId]
          );
          return { status: 200, body: { volumes: volumes.rows } };
        }

        if (resource === "volumes" && !volumeRoute[2] && request.method === "POST") {
          requirePermission(role, "manageVolumes");
          const body = await readJson(request);
          const payload = validateVolumePayload(body);
          const app = await client.query(
            "SELECT id FROM applications WHERE id = $1 AND tenant_id = $2",
            [payload.applicationId, tenantId]
          );
          if (!app.rows[0]) {
            const error = new Error("Application not found in this workspace.");
            error.status = 404;
            throw error;
          }
          let created;
          try {
            created = await client.query(
              "INSERT INTO application_volumes (tenant_id, application_id, name, mount_path, size_bytes, read_only, driver) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, tenant_id, application_id, name, mount_path, size_bytes, status, attached_node_id, attached_deployment_id, read_only, driver, created_at",
              [tenantId, payload.applicationId, payload.name, payload.mountPath, payload.sizeBytes, payload.readOnly, payload.driver]
            );
          } catch (err) {
            if (err?.code === "23505") {
              const error = new Error("A volume with this name or mount path already exists for this application.");
              error.status = 409;
              throw error;
            }
            throw err;
          }
          await audit(client, tenantId, user.id, "volume.created", "volume", created.rows[0].id, {
            name: payload.name,
            application_id: payload.applicationId
          });
          return { status: 201, body: { volume: created.rows[0] } };
        }

        if (resource === "volumes" && volumeRoute[2] && !volumeRoute[3] && request.method === "GET") {
          requirePermission(role, "read");
          const volumeId = requireUuid(volumeRoute[2], "volume_id");
          const vol = await client.query(
            "SELECT id, tenant_id, application_id, name, mount_path, size_bytes, status, attached_node_id, attached_deployment_id, read_only, driver, created_at, updated_at FROM application_volumes WHERE id = $1 AND tenant_id = $2",
            [volumeId, tenantId]
          );
          if (!vol.rows[0]) {
            const error = new Error("Volume not found.");
            error.status = 404;
            throw error;
          }
          const backups = await client.query(
            "SELECT id, tenant_id, volume_id, status, size_bytes, sha256_checksum, backup_location, retention_days, created_at, completed_at FROM volume_backups WHERE volume_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 50",
            [volumeId, tenantId]
          );
          return { status: 200, body: { volume: vol.rows[0], backups: backups.rows } };
        }

        if (resource === "volumes" && volumeRoute[2] && !volumeRoute[3] && request.method === "DELETE") {
          requirePermission(role, "manageVolumes");
          const volumeId = requireUuid(volumeRoute[2], "volume_id");
          const vol = await client.query(
            "SELECT id, name, status, attached_deployment_id FROM application_volumes WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [volumeId, tenantId]
          );
          if (!vol.rows[0]) {
            const error = new Error("Volume not found.");
            error.status = 404;
            throw error;
          }
          if (vol.rows[0].status === "attached" || vol.rows[0].attached_deployment_id) {
            const error = new Error("Cannot delete a volume that is currently attached to a deployment.");
            error.status = 409;
            throw error;
          }
          await client.query("DELETE FROM application_volumes WHERE id = $1 AND tenant_id = $2", [volumeId, tenantId]);
          await audit(client, tenantId, user.id, "volume.deleted", "volume", volumeId, { name: vol.rows[0].name });
          return { status: 200, body: { deleted: true, volume_id: volumeId } };
        }

        if (resource === "volumes" && volumeRoute[2] && volumeRoute[3] === "backups" && request.method === "POST") {
          requirePermission(role, "manageVolumes");
          const volumeId = requireUuid(volumeRoute[2], "volume_id");
          const vol = await client.query(
            "SELECT id, name, size_bytes FROM application_volumes WHERE id = $1 AND tenant_id = $2",
            [volumeId, tenantId]
          );
          if (!vol.rows[0]) {
            const error = new Error("Volume not found.");
            error.status = 404;
            throw error;
          }
          const backup = await client.query(
            "INSERT INTO volume_backups (tenant_id, volume_id, status, size_bytes, retention_days) VALUES ($1, $2, 'completed', $3, 30) RETURNING id, tenant_id, volume_id, status, size_bytes, retention_days, created_at",
            [tenantId, volumeId, vol.rows[0].size_bytes]
          );
          await audit(client, tenantId, user.id, "volume_backup.created", "volume_backup", backup.rows[0].id, { volume_id: volumeId });
          return { status: 201, body: { backup: backup.rows[0] } };
        }

        if (resource === "audit-events" && request.method === "GET") {
          requirePermission(role, "read");
          const limitParam = Number(url.searchParams.get("limit") || 50);
          const limit = Math.min(200, Math.max(1, Number.isInteger(limitParam) ? limitParam : 50));
          const resourceType = url.searchParams.get("resource_type") || null;
          const actionFilter = url.searchParams.get("action") || null;
          const conditions = ["tenant_id = $1"];
          const params = [tenantId];
          if (resourceType) {
            params.push(resourceType);
            conditions.push("resource_type = $" + params.length);
          }
          if (actionFilter) {
            params.push(actionFilter);
            conditions.push("action = $" + params.length);
          }
          params.push(limit);
          const events = await client.query(
            "SELECT id, tenant_id, actor_type, actor_id, action, resource_type, resource_id, request_id, metadata_json AS metadata, created_at FROM audit_events WHERE " + conditions.join(" AND ") + " ORDER BY created_at DESC LIMIT $" + params.length,
            params
          );
          return { status: 200, body: { audit_events: events.rows } };
        }

        if (resource === "overview" && request.method === "GET") {
          requirePermission(role, "read");
          // One database round trip for the complete dashboard snapshot.
          const snapshot = await client.query(`
            SELECT
              COALESCE((SELECT jsonb_agg(to_jsonb(node_row)) FROM (
                SELECT id, tenant_id, name, platform, architecture, agent_version,
                  CASE WHEN status = 'revoked' THEN 'revoked'
                       WHEN status = 'pending' THEN 'pending'
                       WHEN last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => heartbeat_interval_seconds * 3) THEN 'offline'
                       ELSE status END AS status,
                  last_seen_at, heartbeat_interval_seconds, ingress_draining, resource_metrics_json AS resources
                FROM nodes WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200
              ) AS node_row), '[]'::jsonb) AS nodes,
              COALESCE((SELECT jsonb_agg(to_jsonb(app_row)) FROM (
                SELECT id, tenant_id, name, desired_state, created_by, created_at, updated_at
                FROM applications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100
              ) AS app_row), '[]'::jsonb) AS applications,
              COALESCE((SELECT jsonb_agg(to_jsonb(deployment_row)) FROM (
                SELECT id, tenant_id, application_id, revision, target_node_id, desired_state, status, health_check_path, health_check_timeout_seconds, health_checked_at, created_by, created_at
                FROM deployments WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100
              ) AS deployment_row), '[]'::jsonb) AS deployments,
              COALESCE((SELECT jsonb_agg(to_jsonb(job_row)) FROM (
                SELECT id, node_id, type, payload_json AS payload, status, attempt_count, max_attempts,
                  available_at, lease_expires_at, created_at, updated_at
                FROM jobs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100
              ) AS job_row), '[]'::jsonb) AS jobs,
              COALESCE((SELECT jsonb_agg(to_jsonb(member_row)) FROM (
                SELECT membership.user_id, account.email, account.display_name,
                  membership.role, membership.status, membership.created_at
                FROM tenant_memberships AS membership
                LEFT JOIN users AS account ON account.id = membership.user_id
                WHERE membership.tenant_id = $1
                ORDER BY membership.created_at ASC LIMIT 100
              ) AS member_row), '[]'::jsonb) AS members
          `, [tenantId]);
          return { status: 200, body: snapshot.rows[0] || { nodes: [], applications: [], deployments: [], jobs: [], members: [] } };
        }

        if (resource === "nodes" && request.method === "GET") {
          requirePermission(role, "read");
          const nodes = await client.query("SELECT id, tenant_id, name, platform, architecture, agent_version, CASE WHEN status = 'revoked' THEN 'revoked' WHEN status = 'pending' THEN 'pending' WHEN last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => heartbeat_interval_seconds * 3) THEN 'offline' ELSE status END AS status, last_seen_at, heartbeat_interval_seconds, ingress_draining, (approved_at IS NOT NULL AND status <> 'revoked') AS ingress_managed, (platform = 'linux' AND approved_at IS NOT NULL AND status = 'online' AND last_seen_at > now() - make_interval(secs => heartbeat_interval_seconds * 3) AND capabilities_json->>'ingress_tunnel' = 'true' AND capabilities_json->>'loopback_forwarder' = 'true') AS ingress_ready, resource_metrics_json AS resources FROM nodes WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200", [tenantId]);
          return { status: 200, body: { nodes: nodes.rows } };
        }

        if (resource === "nodes" && route[3] && route[6] && request.method === "POST") {
          requirePermission(role, "manageNodes");
          const nodeId = requireUuid(route[3], "node_id");
          const body = await readJson(request);
          if (!["active", "draining"].includes(body.ingress_state)) {
            const error = new Error("ingress_state must be active or draining.");
            error.status = 400;
            throw error;
          }
          const target = await client.query(
            "SELECT id, status, approved_at, platform, last_seen_at, heartbeat_interval_seconds, (last_seen_at > clock_timestamp() - make_interval(secs => heartbeat_interval_seconds * 3)) AS heartbeat_fresh, capabilities_json, ingress_draining FROM nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [nodeId, tenantId]
          );
          const current = target.rows[0];
          if (!current) { const error = new Error("Node not found."); error.status = 404; throw error; }
          if (current.status === "revoked" || !current.approved_at) {
            const error = new Error("Only approved, non-revoked nodes can change ingress state.");
            error.status = 409;
            throw error;
          }
          const shouldDrain = body.ingress_state === "draining";
          if (!shouldDrain && (
            current.status !== "online" ||
            current.platform !== "linux" ||
            current.heartbeat_fresh !== true ||
            current.capabilities_json?.ingress_tunnel !== true ||
            current.capabilities_json?.loopback_forwarder !== true
          )) {
            const error = new Error("Only a fresh online Linux node with authenticated ingress tunnel and loopback-forwarder capability can resume ingress.");
            error.status = 409;
            throw error;
          }
          const updated = await client.query(
            "UPDATE nodes SET ingress_draining = $3 WHERE id = $1 AND tenant_id = $2 RETURNING id, status, ingress_draining, last_seen_at",
            [nodeId, tenantId, shouldDrain]
          );
          await audit(client, tenantId, user.id, shouldDrain ? "node.ingress.draining" : "node.ingress.resumed", "node", nodeId, {
            previous_ingress_draining: current.ingress_draining === true,
            ingress_draining: shouldDrain
          });
          return { status: 200, body: { node: updated.rows[0] } };
        }

        if (resource === "nodes" && route[3] && route[5] && request.method === "POST") {
          requirePermission(role, "manageNodes");
          const nodeId = requireUuid(route[3], "node_id");
          const action = route[5];
          const target = await client.query(
            "SELECT id, status, approved_at FROM nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [nodeId, tenantId]
          );
          if (!target.rows[0]) { const error = new Error("Node not found."); error.status = 404; throw error; }
          if (target.rows[0].status === "revoked") { const error = new Error("Revoked nodes cannot be changed."); error.status = 409; throw error; }
          if (target.rows[0].status !== "pending") { const error = new Error("Only pending nodes can be approved or rejected."); error.status = 409; throw error; }
          let updated;
          if (action === "approve") {
            updated = await client.query(
              "UPDATE nodes SET approved_at = COALESCE(approved_at, now()), status = CASE WHEN last_seen_at IS NULL OR last_seen_at < now() - make_interval(secs => heartbeat_interval_seconds * 3) THEN 'offline' ELSE 'online' END WHERE id = $1 AND tenant_id = $2 RETURNING id, status, approved_at, last_seen_at",
              [nodeId, tenantId]
            );
          } else {
            await client.query("UPDATE node_credentials SET revoked_at = COALESCE(revoked_at, now()) WHERE node_id = $1 AND revoked_at IS NULL", [nodeId]);
            updated = await client.query(
              "UPDATE nodes SET status = 'revoked', approved_at = NULL WHERE id = $1 AND tenant_id = $2 RETURNING id, status, approved_at, last_seen_at",
              [nodeId, tenantId]
            );
          }
          await audit(client, tenantId, user.id, action === "approve" ? "node.approved" : "node.rejected", "node", nodeId, { previous_status: "pending" });
          return { status: 200, body: { node: updated.rows[0] } };
        }


        if (resource === "jobs" && request.method === "GET") {
          requirePermission(role, "read");
          const jobs = await client.query(
            "SELECT id, node_id, type, payload_json AS payload, status, attempt_count, max_attempts, available_at, lease_expires_at, created_at, updated_at FROM jobs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            [tenantId]
          );
          return { status: 200, body: { jobs: jobs.rows } };
        }

        if (resource === "jobs" && request.method === "POST") {
          requirePermission(role, "manageJobs");
          const body = await readJson(request);
          const requestedNodeId = body.node_id == null || body.node_id === "" ? null : requireUuid(body.node_id, "node_id");
          const type = requireText(body.type, "type", 40).toLowerCase();
          const payload = validateJobPayload(type, body.payload == null ? {} : body.payload);
          const idempotencyKey = requireText(body.idempotency_key, "idempotency_key", 128);
          if (idempotencyKey.length < 8 || !/^[A-Za-z0-9._:-]+$/.test(idempotencyKey)) {
            const error = new Error("idempotency_key must be 8–128 characters using letters, numbers, dot, underscore, colon or hyphen.");
            error.status = 400;
            throw error;
          }
          // Serialize identical idempotency keys across a tenant, then reuse an
          // existing job before selecting a node. This keeps retries idempotent
          // even if the scheduler's next preferred node has changed.
          await client.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2, 0))",
            [tenantId, idempotencyKey]
          );
          let existing = await client.query(
            "SELECT id, tenant_id, node_id, type, payload_json AS payload, status, attempt_count, max_attempts, created_at FROM jobs WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY created_at ASC LIMIT 1",
            [tenantId, idempotencyKey]
          );
          if (existing.rows[0]) {
            const prior = existing.rows[0];
            if (prior.type !== type || JSON.stringify(prior.payload) !== JSON.stringify(payload) ||
                (requestedNodeId && prior.node_id !== requestedNodeId)) {
              const error = new Error("idempotency_key has already been used for a different job request.");
              error.status = 409;
              throw error;
            }
            return { status: 200, body: { job: prior } };
          }

          let node;
          if (requestedNodeId) {
            const target = await client.query(
              "SELECT id FROM nodes WHERE id = $1 AND tenant_id = $2 AND approved_at IS NOT NULL AND status IN ('online', 'degraded') AND last_seen_at > clock_timestamp() - make_interval(secs => heartbeat_interval_seconds * 3) FOR UPDATE",
              [requestedNodeId, tenantId]
            );
            node = target.rows[0];
          } else {
            // Fair placement: choose the eligible node with the fewest outstanding
            // jobs; break ties by the oldest previous assignment. Lock the chosen
            // node so concurrent schedulers move to another available node.
            const scheduled = await client.query(`
              SELECT node.id,
                (SELECT count(*)::integer FROM jobs AS workload
                 WHERE workload.node_id = node.id
                   AND workload.status IN ('queued', 'leased', 'accepted', 'running')) AS active_jobs,
                (SELECT max(previous.created_at) FROM jobs AS previous
                 WHERE previous.node_id = node.id) AS last_assigned_at
              FROM nodes AS node
              WHERE node.tenant_id = $1
                AND node.approved_at IS NOT NULL
                AND node.status IN ('online', 'degraded')
                AND node.last_seen_at > clock_timestamp() - make_interval(secs => node.heartbeat_interval_seconds * 3)
              ORDER BY active_jobs ASC, last_assigned_at ASC NULLS FIRST, node.id ASC
              FOR UPDATE OF node SKIP LOCKED
              LIMIT 1
            `, [tenantId]);
            node = scheduled.rows[0];
          }
          if (!node) {
            const error = new Error(requestedNodeId
              ? "The selected node is not approved and recently online."
              : "No approved online nodes are currently available for scheduling.");
            error.status = 409;
            throw error;
          }
          const nodeId = node.id;
          let created = await client.query(
            "INSERT INTO jobs (tenant_id, node_id, type, payload_json, idempotency_key) VALUES ($1, $2, $3, $4::jsonb, $5) ON CONFLICT (tenant_id, node_id, idempotency_key) DO NOTHING RETURNING id, tenant_id, node_id, type, payload_json AS payload, status, attempt_count, max_attempts, created_at",
            [tenantId, nodeId, type, JSON.stringify(payload), idempotencyKey]
          );
          let status = 201;
          if (!created.rows[0]) {
            created = await client.query(
              "SELECT id, tenant_id, node_id, type, payload_json AS payload, status, attempt_count, max_attempts, created_at FROM jobs WHERE tenant_id = $1 AND node_id = $2 AND idempotency_key = $3 LIMIT 1",
              [tenantId, nodeId, idempotencyKey]
            );
            if (!created.rows[0] || created.rows[0].type !== type || JSON.stringify(created.rows[0].payload) !== JSON.stringify(payload)) {
              const error = new Error("idempotency_key has already been used for a different job.");
              error.status = 409;
              throw error;
            }
            status = 200;
          } else {
            await audit(client, tenantId, user.id, "node.job.created", "job", created.rows[0].id, { node_id: nodeId, type, placement: requestedNodeId ? "pinned" : "least_outstanding_jobs" });
          }
          return { status, body: { job: created.rows[0] } };
        }

        if (resource === "applications" && route[3] && route[6] === "state" && request.method === "POST") {
          requirePermission(role, "manageApplications");
          const body = await readJson(request);
          const desiredState = body.desired_state;
          if (!["running", "stopped", "suspended"].includes(desiredState)) {
            const error = new Error("desired_state must be running, stopped or suspended.");
            error.status = 400;
            throw error;
          }
          const applicationId = requireUuid(route[3], "application_id");
          const current = await client.query(
            "SELECT id, desired_state FROM applications WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [applicationId, tenantId]
          );
          if (!current.rows[0]) { const error = new Error("Application not found."); error.status = 404; throw error; }

          let cancelledDeploymentCount = 0;
          let queuedStopJobCount = 0;
          if (["stopped", "suspended"].includes(desiredState)) {
            const revisions = await client.query(
              "SELECT id, status, target_node_id FROM deployments WHERE application_id = $1 AND tenant_id = $2 AND status IN ('queued','scheduled','deploying','healthy','stopping','restarting','failed') ORDER BY revision FOR UPDATE",
              [applicationId, tenantId]
            );
            const pendingIds = revisions.rows.filter((revision) => ["queued", "scheduled"].includes(revision.status)).map((revision) => revision.id);
            if (pendingIds.length) {
              const cancelled = await client.query(
                "UPDATE deployments SET desired_state = 'stopped', status = 'cancelled', updated_at = now() WHERE tenant_id = $1 AND application_id = $2 AND id = ANY($3::uuid[]) RETURNING id",
                [tenantId, applicationId, pendingIds]
              );
              cancelledDeploymentCount = cancelled.rowCount ?? cancelled.rows.length;
            }

            const active = revisions.rows.filter((revision) => ["deploying", "healthy", "restarting", "failed"].includes(revision.status));
            if (active.some((revision) => !revision.target_node_id)) {
              const error = new Error("An active deployment has no assigned node; application stop was not completed.");
              error.status = 409;
              throw error;
            }
            for (const revision of active) {
              await client.query(
                "UPDATE deployments SET desired_state = 'stopped', status = 'stopping', updated_at = now() WHERE id = $1 AND tenant_id = $2",
                [revision.id, tenantId]
              );
              const job = await client.query(
                "INSERT INTO jobs (tenant_id, node_id, deployment_id, type, payload_json, idempotency_key) VALUES ($1, $2, $3, 'stop', $4::jsonb, $5) RETURNING id",
                [tenantId, revision.target_node_id, revision.id, JSON.stringify({ deployment_id: revision.id }), "deployment:" + revision.id + ":app-stop:" + randomUUID()]
              );
              if (!job.rows[0]) { const error = new Error("Application stop job could not be queued."); error.status = 503; throw error; }
              queuedStopJobCount += 1;
              await audit(client, tenantId, user.id, "deployment.stop.queued", "deployment", revision.id, { job_id: job.rows[0].id, reason: desiredState, application_id: applicationId });
            }
            queuedStopJobCount += revisions.rows.filter((revision) => revision.status === "stopping").length;
          }

          const updated = await client.query(
            "UPDATE applications SET desired_state = $3, updated_at = now() WHERE id = $1 AND tenant_id = $2 RETURNING id, tenant_id, name, desired_state, resource_requests_json AS resource_requests, created_by, created_at, updated_at",
            [applicationId, tenantId, desiredState]
          );
          await audit(client, tenantId, user.id, "application.state.changed", "application", applicationId, {
            previous_desired_state: current.rows[0].desired_state,
            desired_state: desiredState,
            cancelled_deployments: cancelledDeploymentCount,
            queued_stop_jobs: queuedStopJobCount,
            runtime_enabled: false
          });
          if (cancelledDeploymentCount) {
            await audit(client, tenantId, user.id, "application.deployments.cancelled", "application", applicationId, {
              count: cancelledDeploymentCount,
              reason: desiredState
            });
          }
          return { status: 200, body: { application: updated.rows[0], cancelled_deployments: cancelledDeploymentCount, queued_stop_jobs: queuedStopJobCount, runtime_enabled: false } };
        }

        if (resource === "deployments" && route[3] && route[6] === "state" && request.method === "POST") {
          requirePermission(role, "operateDeployments");
          const body = await readJson(request);
          if (!["running", "stopped"].includes(body.desired_state)) {
            const error = new Error("desired_state must be running or stopped.");
            error.status = 400;
            throw error;
          }
          const deploymentId = requireUuid(route[3], "deployment_id");
          const currentResult = await client.query(
            "SELECT id, tenant_id, application_id, revision, target_node_id, desired_state, status, container_port, health_check_path, health_check_timeout_seconds, image_digest FROM deployments WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [deploymentId, tenantId]
          );
          const current = currentResult.rows[0];
          if (!current) { const error = new Error("Deployment not found."); error.status = 404; throw error; }

          if (body.desired_state === "stopped") {
            if (current.desired_state === "stopped" && ["cancelled", "stopped"].includes(current.status)) {
              return { status: 200, body: { deployment: current, runtime_job_queued: false, runtime_enabled: false } };
            }
            if (["queued", "scheduled"].includes(current.status)) {
              const updated = await client.query(
                "UPDATE deployments SET desired_state = 'stopped', status = 'cancelled', updated_at = now() WHERE id = $1 AND tenant_id = $2 RETURNING id, tenant_id, application_id, revision, target_node_id, desired_state, status, health_check_path, health_check_timeout_seconds, health_checked_at, resource_requests_json AS resource_requests, created_by, created_at, updated_at",
                [deploymentId, tenantId]
              );
              await audit(client, tenantId, user.id, "deployment.cancelled", "deployment", deploymentId, { previous_status: current.status, desired_state: "stopped" });
              return { status: 200, body: { deployment: updated.rows[0], runtime_job_queued: false, runtime_enabled: false } };
            }
            if (current.status === "stopping") {
              return { status: 200, body: { deployment: current, runtime_job_queued: true, runtime_enabled: false } };
            }
            if (!["deploying", "healthy", "restarting", "failed"].includes(current.status) || !current.target_node_id) {
              const error = new Error("This deployment cannot be stopped from its current state or has no assigned node.");
              error.status = 409;
              throw error;
            }
            const updated = await client.query(
              "UPDATE deployments SET desired_state = 'stopped', status = 'stopping', updated_at = now() WHERE id = $1 AND tenant_id = $2 RETURNING id, tenant_id, application_id, revision, target_node_id, desired_state, status, health_check_path, health_check_timeout_seconds, health_checked_at, resource_requests_json AS resource_requests, created_by, created_at, updated_at",
              [deploymentId, tenantId]
            );
            const job = await client.query(
              "INSERT INTO jobs (tenant_id, node_id, deployment_id, type, payload_json, idempotency_key) VALUES ($1, $2, $3, 'stop', $4::jsonb, $5) RETURNING id, status",
              [tenantId, current.target_node_id, deploymentId, JSON.stringify({ deployment_id: deploymentId }), "deployment:" + deploymentId + ":stop:" + randomUUID()]
            );
            if (!job.rows[0]) { const error = new Error("Stop job could not be queued."); error.status = 503; throw error; }
            await audit(client, tenantId, user.id, "deployment.stop.queued", "deployment", deploymentId, { job_id: job.rows[0].id, node_id: current.target_node_id });
            return { status: 200, body: { deployment: updated.rows[0], job: job.rows[0], runtime_job_queued: true, runtime_enabled: false } };
          }

          if (current.status === "healthy" && current.desired_state === "running") {
            return { status: 200, body: { deployment: current, runtime_job_queued: false, runtime_enabled: false } };
          }
          if (current.status === "restarting") {
            return { status: 200, body: { deployment: current, runtime_job_queued: true, runtime_enabled: false } };
          }
          if (current.status !== "stopped" || !current.target_node_id || !Number.isInteger(current.container_port)) {
            const error = new Error("Only a stopped revision with an assigned node and container port can be restarted.");
            error.status = 409;
            throw error;
          }
          const updated = await client.query(
            "UPDATE deployments SET desired_state = 'running', status = 'restarting', updated_at = now() WHERE id = $1 AND tenant_id = $2 RETURNING id, tenant_id, application_id, revision, target_node_id, desired_state, status, health_check_path, health_check_timeout_seconds, health_checked_at, resource_requests_json AS resource_requests, created_by, created_at, updated_at",
            [deploymentId, tenantId]
          );
          const restartPayload = {
            deployment_id: deploymentId,
            container_port: current.container_port,
            health_check_path: current.health_check_path || "/",
            health_check_timeout_seconds: current.health_check_timeout_seconds || 30
          };
          const job = await client.query(
            "INSERT INTO jobs (tenant_id, node_id, deployment_id, type, payload_json, idempotency_key) VALUES ($1, $2, $3, 'restart', $4::jsonb, $5) RETURNING id, status",
            [tenantId, current.target_node_id, deploymentId, JSON.stringify(restartPayload), "deployment:" + deploymentId + ":restart:" + randomUUID()]
          );
          if (!job.rows[0]) { const error = new Error("Restart job could not be queued."); error.status = 503; throw error; }
          await audit(client, tenantId, user.id, "deployment.restart.queued", "deployment", deploymentId, { job_id: job.rows[0].id, node_id: current.target_node_id });
          return { status: 200, body: { deployment: updated.rows[0], job: job.rows[0], runtime_job_queued: true, runtime_enabled: false } };
        }

        if (resource === "deployments" && route[3] && route[7] === "events" && request.method === "GET") {
          requirePermission(role, "read");
          const deploymentId = requireUuid(route[3], "deployment_id");
          const events = await client.query(
            "SELECT id, tenant_id, actor_type, actor_id, action, resource_type, resource_id, request_id, metadata_json AS metadata, created_at FROM audit_events WHERE tenant_id = $1 AND resource_type = 'deployment' AND resource_id = $2 ORDER BY created_at ASC LIMIT 100",
            [tenantId, deploymentId]
          );
          return { status: 200, body: { events: events.rows } };
        }

        if (resource === "applications" && request.method === "GET") {
          requirePermission(role, "read");
          const applications = await client.query(
            "SELECT id, tenant_id, name, desired_state, resource_requests_json AS resource_requests, created_by, created_at, updated_at FROM applications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            [tenantId]
          );
          return { status: 200, body: { applications: applications.rows } };
        }

        if (resource === "applications" && request.method === "POST") {
          requirePermission(role, "manageApplications");
          const body = await readJson(request);
          const name = requireText(body.name, "name", 100);
          const resourceRequests = validateResourceRequests(body.resource_requests);
          const created = await client.query(
            "INSERT INTO applications (tenant_id, name, resource_requests_json, created_by) VALUES ($1, $2, $3::jsonb, $4) RETURNING id, tenant_id, name, desired_state, resource_requests_json AS resource_requests, created_by, created_at",
            [tenantId, name, JSON.stringify(resourceRequests), user.id]
          );
          await audit(client, tenantId, user.id, "application.created", "application", created.rows[0].id);
          return { status: 201, body: { application: created.rows[0] } };
        }

        if (resource === "deployments" && request.method === "GET") {
          requirePermission(role, "read");
          const deployments = await client.query(
            "SELECT id, tenant_id, application_id, revision, target_node_id, desired_state, status, image_digest, container_port, health_check_path, health_check_timeout_seconds, health_checked_at, resource_requests_json AS resource_requests, created_by, created_at, updated_at FROM deployments WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100",
            [tenantId]
          );
          return { status: 200, body: { deployments: deployments.rows } };
        }

        if (resource === "deployments" && request.method === "POST") {
          requirePermission(role, "operateDeployments");
          const body = await readJson(request);
          const applicationId = requireUuid(body.application_id, "application_id");
          const requestedNodeId = body.target_node_id == null ? null : requireUuid(body.target_node_id, "target_node_id");
          const desiredState = body.desired_state;
          if (!["running", "stopped"].includes(desiredState)) {
            const error = new Error("desired_state must be running or stopped.");
            error.status = 400;
            throw error;
          }
          const application = await client.query(
            "SELECT id, resource_requests_json FROM applications WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            [applicationId, tenantId]
          );
          if (!application.rows[0]) { const error = new Error("Application not found."); error.status = 404; throw error; }
          const resourceRequests = validateResourceRequests(application.rows[0].resource_requests_json);
          const imageDigest = desiredState === "running" ? validateImageDigest(body.image_digest) : null;
          const containerPort = desiredState === "running" ? body.container_port : null;
          const healthCheckPath = desiredState === "running" ? (body.health_check_path == null ? "/" : body.health_check_path) : null;
          const healthCheckTimeout = desiredState === "running" ? (body.health_check_timeout_seconds == null ? 30 : body.health_check_timeout_seconds) : null;
          if (desiredState === "running" && (typeof healthCheckPath !== "string" || healthCheckPath.length < 1 || healthCheckPath.length > 256 || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]*$/.test(healthCheckPath) || healthCheckPath.startsWith("//") || healthCheckPath.split("/").includes(".."))) {
            const error = new Error("health_check_path must be a safe absolute URL path of at most 256 characters.");
            error.status = 400;
            throw error;
          }
          if (desiredState === "running" && (!Number.isInteger(healthCheckTimeout) || healthCheckTimeout < 5 || healthCheckTimeout > 120)) {
            const error = new Error("health_check_timeout_seconds must be an integer from 5 to 120.");
            error.status = 400;
            throw error;
          }
          if (desiredState === "running" && (!Number.isInteger(containerPort) || containerPort < 1 || containerPort > 65535)) {
            const error = new Error("container_port must be an integer from 1 to 65535.");
            error.status = 400;
            throw error;
          }
          let targetNodeId = requestedNodeId;
          let placement = "stopped";
          if (desiredState === "running") {
            const placementResult = await client.query(`
              SELECT node.id,
                CASE WHEN (node.resource_metrics_json->>'cpu_cores') ~ '^[1-9][0-9]*$'
                  THEN (node.resource_metrics_json->>'cpu_cores')::integer ELSE NULL END AS cpu_cores,
                node.resource_metrics_json AS resources
              FROM nodes AS node
              WHERE node.tenant_id = $1
                AND node.approved_at IS NOT NULL
                AND node.platform = 'linux'
                AND node.capabilities_json #>> '{runtime_probe,podman,ready}' = 'true'
                AND node.capabilities_json #>> '{runtime_probe,podman,rootless}' = 'true'
                AND node.capabilities_json #>> '{runtime_probe,podman,cgroup_version}' = 'v2'
                AND node.capabilities_json #>> '{runtime_probe,podman,cgroup_v2_available}' = 'true'
                 AND node.capabilities_json #>> '{runtime_probe,podman,storage_quota,ready}' = 'true'
                AND jsonb_typeof(node.capabilities_json #> '{runtime_probe,podman,storage_quota,available_bytes}') = 'number'
                AND (node.capabilities_json #>> '{runtime_probe,podman,storage_quota,available_bytes}')::bigint > 0
                AND node.capabilities_json #>> '{runtime_probe,cosign,ready}' = 'true'
                AND node.capabilities_json #>> '{runtime_probe,cosign,trust_key_configured}' = 'true'
                AND node.status IN ('online', 'degraded')
                AND node.last_seen_at > clock_timestamp() - make_interval(secs => node.heartbeat_interval_seconds * 3)
                AND node.resource_metrics_json ?& ARRAY['cpu_cores','cpu_percent','memory_total_bytes','memory_available_bytes']
                AND CASE WHEN (node.resource_metrics_json->>'cpu_cores') ~ '^[1-9][0-9]*$'
                  THEN (node.resource_metrics_json->>'cpu_cores')::integer BETWEEN 1 AND 256 ELSE false END
                AND (node.resource_metrics_json->>'cpu_percent')::numeric < 85
                AND ((CASE WHEN (node.resource_metrics_json->>'cpu_cores') ~ '^[1-9][0-9]*$'
                      THEN (node.resource_metrics_json->>'cpu_cores')::bigint ELSE 0 END) * 1000 -
                  COALESCE((SELECT sum((deployment.resource_requests_json->>'cpu_millicores')::bigint)
                    FROM deployments AS deployment
                    WHERE deployment.target_node_id = node.id
                      AND deployment.desired_state = 'running'
                      AND deployment.status IN ('queued','scheduled','deploying','healthy','stopping','restarting')), 0)) >= $2
                AND ((node.resource_metrics_json->>'memory_available_bytes')::bigint -
                  COALESCE((SELECT sum((deployment.resource_requests_json->>'memory_bytes')::bigint)
                    FROM deployments AS deployment
                    WHERE deployment.target_node_id = node.id
                      AND deployment.desired_state = 'running'
                      AND deployment.status IN ('queued','scheduled','deploying','healthy','stopping','restarting')), 0)) >= $3
                AND ((node.capabilities_json #>> '{runtime_probe,podman,storage_quota,available_bytes}')::bigint -
                  COALESCE((SELECT sum((deployment.resource_requests_json->>'disk_bytes')::bigint)
                    FROM deployments AS deployment
                    WHERE deployment.target_node_id = node.id
                      AND deployment.desired_state = 'running'
                      AND deployment.status IN ('queued','scheduled','deploying','healthy','stopping','restarting')), 0)) >= $4
                AND ($5::uuid IS NULL OR node.id = $5)
              ORDER BY
                ((CASE WHEN (node.resource_metrics_json->>'cpu_cores') ~ '^[1-9][0-9]*$'
                  THEN (node.resource_metrics_json->>'cpu_cores')::bigint ELSE 0 END) * 1000 -
                  COALESCE((SELECT sum((deployment.resource_requests_json->>'cpu_millicores')::bigint)
                    FROM deployments AS deployment
                    WHERE deployment.target_node_id = node.id AND deployment.desired_state = 'running'
                      AND deployment.status IN ('queued','scheduled','deploying','healthy','stopping','restarting')), 0)) ASC,
                node.id ASC
              FOR UPDATE OF node SKIP LOCKED
              LIMIT 1
            `, [tenantId, resourceRequests.cpu_millicores, resourceRequests.memory_bytes, resourceRequests.disk_bytes, requestedNodeId]);
            if (!placementResult.rows[0]) {
              const error = new Error("No eligible node has fresh telemetry and sufficient unreserved CPU, memory and disk capacity.");
              error.status = 409;
              throw error;
            }
            targetNodeId = placementResult.rows[0].id;
            placement = "capacity_admitted";
          }
          const revision = await client.query("SELECT COALESCE(MAX(revision), 0) + 1 AS next_revision FROM deployments WHERE tenant_id = $1 AND application_id = $2", [tenantId, applicationId]);
          const created = await client.query(
            "INSERT INTO deployments (tenant_id, application_id, revision, target_node_id, desired_state, status, resource_requests_json, created_by, image_digest, container_port, health_check_path, health_check_timeout_seconds) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12) RETURNING id, tenant_id, application_id, revision, target_node_id, desired_state, status, image_digest, container_port, health_check_path, health_check_timeout_seconds, health_checked_at, resource_requests_json AS resource_requests, created_by, created_at",
            [tenantId, applicationId, Number(revision.rows[0].next_revision), targetNodeId, desiredState, desiredState === "running" ? "scheduled" : "queued", JSON.stringify(resourceRequests), user.id, imageDigest, containerPort, healthCheckPath, healthCheckTimeout]
          );
          let workloadJob = null;
          if (desiredState === "running") {
            const payload = {
              deployment_id: created.rows[0].id,
              image: imageDigest,
              container_port: containerPort,
              health_check_path: healthCheckPath,
              health_check_timeout_seconds: healthCheckTimeout,
              resources: {
                cpu_millicores: resourceRequests.cpu_millicores,
                memory_bytes: resourceRequests.memory_bytes,
                disk_bytes: resourceRequests.disk_bytes
              }
            };
            const queued = await client.query(
              "INSERT INTO jobs (tenant_id, node_id, deployment_id, type, payload_json, idempotency_key) VALUES ($1, $2, $3, 'deploy', $4::jsonb, $5) RETURNING id, status",
              [tenantId, targetNodeId, created.rows[0].id, JSON.stringify(payload), "deployment:" + created.rows[0].id + ":deploy"]
            );
            workloadJob = queued.rows[0] || null;
            if (!workloadJob) { const error = new Error("Deployment job could not be queued."); error.status = 503; throw error; }
            await audit(client, tenantId, user.id, "deployment.job.queued", "deployment", created.rows[0].id, { job_id: workloadJob.id, node_id: targetNodeId });
          }
          await audit(client, tenantId, user.id, "deployment.requested", "deployment", created.rows[0].id, { desired_state: desiredState, placement, target_node_id: targetNodeId, resource_requests: resourceRequests, image_digest: imageDigest, runtime_job_queued: Boolean(workloadJob) });
          return { status: 201, body: { deployment: created.rows[0], job: workloadJob, runtime_job_queued: Boolean(workloadJob), runtime_enabled: false } };
        }

        if (resource === "enrollment-tokens" && request.method === "POST") {
          requirePermission(role, "manageNodes");
          const body = await readJson(request);
          const lifetime = body.expires_in_minutes == null ? 30 : body.expires_in_minutes;
          if (!Number.isInteger(lifetime) || lifetime < 5 || lifetime > 1440) { const error = new Error("expires_in_minutes must be an integer between 5 and 1440."); error.status = 400; throw error; }
          const rawToken = randomBytes(32).toString("base64url");
          const tokenHash = createHash("sha256").update(rawToken, "utf8").digest("hex");
          const created = await client.query("INSERT INTO enrollment_tokens (tenant_id, token_hash, expires_at, created_by) VALUES ($1, $2, now() + ($3 * interval '1 minute'), $4) RETURNING id, expires_at", [tenantId, tokenHash, lifetime, user.id]);
          await audit(client, tenantId, user.id, "node.enrollment_token.created", "enrollment_token", created.rows[0].id, { expires_in_minutes: lifetime });
          return { status: 201, body: { enrollment_token: { id: created.rows[0].id, token: rawToken, expires_at: created.rows[0].expires_at } } };
        }

        if (resource === "nodes" && route[3] && route[4] && request.method === "POST") {
          requirePermission(role, "manageNodes");
          const revoked = await client.query("UPDATE node_credentials AS credential SET revoked_at = now() FROM nodes AS node WHERE credential.id = $1 AND credential.node_id = $2 AND node.id = $2 AND node.tenant_id = $3 AND credential.revoked_at IS NULL RETURNING credential.id, credential.revoked_at", [route[4], route[3], tenantId]);
          if (!revoked.rows[0]) { const error = new Error("Node credential not found or already revoked."); error.status = 404; throw error; }
          const active = await client.query("SELECT count(*)::integer AS active_count FROM node_credentials WHERE node_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())", [route[3]]);
          const nodeStatus = Number(active.rows[0]?.active_count || 0) === 0 ? "revoked" : "unchanged";
          if (nodeStatus === "revoked") await client.query("UPDATE nodes SET status = 'revoked' WHERE id = $1 AND tenant_id = $2", [route[3], tenantId]);
          await audit(client, tenantId, user.id, "node.credential.revoked", "node_credential", revoked.rows[0].id, { node_id: route[3] });
          return { status: 200, body: { credential: { id: revoked.rows[0].id, revoked_at: revoked.rows[0].revoked_at }, node_status: nodeStatus } };
        }

        if (resource === "members" && request.method === "GET") {
          requirePermission(role, "read");
          const members = await client.query(
            "SELECT user_id, role, status, created_at FROM tenant_memberships WHERE tenant_id = $1 ORDER BY created_at",
            [tenantId]
          );
          return { status: 200, body: { members: members.rows } };
        }

        if (resource === "members" && request.method === "POST") {
          requirePermission(role, "manageMembers");
          const body = await readJson(request);
          const userId = requireUuid(body.user_id, "user_id");
          if (!canAssignRole(role, body.role)) throw new AuthorizationError("This role cannot be assigned by your tenant role.");
          const existing = await client.query("SELECT 1 FROM tenant_memberships WHERE tenant_id = $1 AND user_id = $2", [tenantId, userId]);
          if (existing.rowCount) {
            const error = new Error("This user already has a membership in the tenant.");
            error.status = 409;
            throw error;
          }
          await client.query(
            "INSERT INTO tenant_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, $3, 'active')",
            [tenantId, userId, body.role]
          );
          await audit(client, tenantId, user.id, "membership.created", "tenant_membership", userId, { role: body.role });
          return { status: 201, body: { membership: { tenant_id: tenantId, user_id: userId, role: body.role, status: "active" } } };
        }

        const error = new Error("API route not found.");
        error.status = 404;
        throw error;
      });

      send(response, result.status, result.body, requestId);
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 500;
      if (status >= 500) logger.error?.("API request failed", { request_id: requestId, error: error.message });
      const code = status === 401 ? "UNAUTHENTICATED" :
        status === 403 ? (error.code || "FORBIDDEN") :
        status === 404 ? "NOT_FOUND" :
        status === 405 ? "METHOD_NOT_ALLOWED" :
        status === 409 ? "CONFLICT" :
        status === 413 ? "PAYLOAD_TOO_LARGE" :
        status === 415 ? "UNSUPPORTED_MEDIA_TYPE" :
        status === 400 ? "BAD_REQUEST" :
        status === 503 ? "SERVICE_UNAVAILABLE" : "INTERNAL_ERROR";
      const message = status >= 500 ? (status === 503 ? error.message : "The request could not be completed.") : error.message;
      send(response, status, { error: { code, message, request_id: requestId } }, requestId);
    }
    return true;
  };
}
