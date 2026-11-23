const $ = (selector) => document.querySelector(selector);
const AUTH_STORAGE_KEY = "cloudexify.server.auth.v1";
const THEME_STORAGE_KEY = "cloudexify.server.theme.v1";
const REFRESH_INTERVAL_MS = 3000;
const SESSION_REFRESH_MARGIN_SECONDS = 300;
let refreshInFlight = null;

const state = {
  selectedNodeId: null,
  config: null,
  session: null,
  user: null,
  tenants: [],
  tenantId: null,
  page: "overview",
  data: {
    nodes: [],
    applications: [],
    deployments: [],
    jobs: [],
    members: [],
    domains: [],
    volumes: []
  },
  timer: null,
  loading: false,
  refreshFailures: 0, nextRefreshAt: 0
};

export const pageMeta = {
  overview: ["Overview", "Infrastructure overview", "Live status from your registered infrastructure."],
  nodes: ["Compute nodes", "Compute nodes", "Devices enrolled with your control plane."],
  applications: ["Applications", "Hosted applications", "Applications registered in this workspace."],
  deployments: ["Deployments", "Deployment history", "Deployment records stored in your database."],
  jobs: ["Jobs", "Node jobs", "Diagnostic jobs and their current execution state."],
  domains: ["Domains & Ingress", "Ingress & routing", "Custom domain claims, TLS certificates and loopback route grants."],
  storage: ["Storage & Volumes", "Persistent storage", "Durable application volumes and snapshot backup records."],
  members: ["Workspace members", "Access management", "People and roles assigned to this workspace."],
  settings: ["Settings", "Session and workspace settings", "Authentication status, session continuity and control-plane configuration."]
};

export const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
}[char]));

const formatDate = (value) => value ? new Date(value).toLocaleString() : "—";

const formatBytes = (value) => {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return "—";
  if (number < 1024 ** 2) return (number / 1024).toFixed(0) + " KB";
  if (number < 1024 ** 3) return (number / 1024 ** 2).toFixed(0) + " MB";
  return (number / 1024 ** 3).toFixed(1) + " GB";
};

function message(text, error = false) {
  const element = $("#auth-message");
  if (element) {
    element.textContent = text;
    element.classList.toggle("error", error);
  }
}

function dashboardMessage(text, error = false) {
  const element = $("#dashboard-message");
  if (!element) return;
  element.hidden = !text;
  element.textContent = text || "";
  element.classList.toggle("error-notice", error);
}

function showToast(text, duration = 3500) {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = text;
  toast.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove("show"), duration);
}

function readSession() {
  try {
    return JSON.parse(localStorage.getItem(AUTH_STORAGE_KEY) || "null");
  } catch {
    return null;
  }
}

function saveSession(session) {
  state.session = session;
  if (session) localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
  else localStorage.removeItem(AUTH_STORAGE_KEY);
}

function applyTheme(theme) {
  const chosen = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", chosen);
  localStorage.setItem(THEME_STORAGE_KEY, chosen);
}

function initTheme() {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved) {
    applyTheme(saved);
  } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    applyTheme("light");
  } else {
    applyTheme("dark");
  }
}

async function authRequest(path, body, accessToken = null) {
  const response = await fetch(state.config.supabaseUrl.replace(/\/$/, "") + "/auth/v1/" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: state.config.supabasePublishableKey,
      ...(accessToken ? { authorization: "Bearer " + accessToken } : {})
    },
    body: JSON.stringify(body)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(result.msg || result.message || result.error_description || "Authentication request failed.");
    error.status = response.status;
    error.code = result.error || result.error_code || null;
    throw error;
  }
  return result;
}

async function signIn(email, password) {
  const result = await authRequest("token?grant_type=password", { email, password });
  if (!result.access_token || !result.refresh_token || !result.user?.id) {
    throw new Error("Supabase Auth returned an incomplete session.");
  }
  saveSession({
    access_token: result.access_token,
    refresh_token: result.refresh_token,
    expires_at: Math.floor(Date.now() / 1000) + Number(result.expires_in || 3600),
    user: result.user
  });
  return result.user;
}

async function ensureFreshSession({ force = false } = {}) {
  if (!state.session?.access_token || !state.session?.refresh_token) throw new Error("Please sign in again.");
  const expiresAt = Number(state.session.expires_at || 0);
  if (!force && expiresAt > Math.floor(Date.now() / 1000) + SESSION_REFRESH_MARGIN_SECONDS) {
    return state.session;
  }
  if (!refreshInFlight) {
    const refreshToken = state.session.refresh_token;
    refreshInFlight = authRequest("token?grant_type=refresh_token", { refresh_token: refreshToken })
      .then((result) => {
        if (!result.access_token || !result.refresh_token) {
          throw new Error("Supabase Auth returned an incomplete refreshed session.");
        }
        saveSession({
          access_token: result.access_token,
          refresh_token: result.refresh_token,
          expires_at: Math.floor(Date.now() / 1000) + Number(result.expires_in || 3600),
          user: result.user || state.session?.user
        });
        return state.session;
      }).catch((error) => {
        // Preserve a valid refresh token during transient Auth/network failures.
        // Clear it only when Supabase explicitly rejects the refresh grant.
        if ([400, 401, 403].includes(error.status)) saveSession(null);
        throw error;
      }).finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

async function api(path, options = {}) {
  await ensureFreshSession();
  const request = async () => {
    try {
      return await fetch(path, {
        ...options,
        headers: {
          ...(options.headers || {}),
          authorization: "Bearer " + state.session.access_token,
          ...(options.body ? { "content-type": "application/json" } : {})
        },
        cache: "no-store"
      });
    } catch (error) {
      const networkError = new Error("Control plane network request failed. The last successful dashboard data is being kept; automatic retry is active.");
      networkError.cause = error;
      throw networkError;
    }
  };
  let response = await request();
  if (response.status === 401) {
    await ensureFreshSession({ force: true });
    response = await request();
  }
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    saveSession(null);
    throw new Error("Your session expired. Please sign in again.");
  }
  if (!response.ok) throw new Error(payload.error?.message || "Request failed (" + response.status + ").");
  return payload;
}

async function signOut() {
  try {
    if (state.session?.access_token) await authRequest("logout", {}, state.session.access_token);
  } catch {
    /* Local sign-out still clears this browser session. */
  }
  if (state.timer) clearInterval(state.timer);
  saveSession(null);
  state.user = null;
  state.tenants = [];
  state.tenantId = null;
  $("#app-view").hidden = true;
  $("#auth-view").hidden = false;
  message("You have been signed out.");
}

function renderLogin() {
  $("#app-view").hidden = true;
  $("#auth-view").hidden = false;
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("#login-button");
    button.disabled = true;
    message("Signing in…");
    try {
      const user = await signIn($("#login-email").value.trim(), $("#login-password").value);
      state.user = user;
      await openDashboard();
    } catch (error) {
      // A dashboard/API outage after successful sign-in must not erase a valid refresh token.
      $("#app-view").hidden = true;
      $("#auth-view").hidden = false;
      message(error.message || "Unable to sign in.", true);
    } finally {
      button.disabled = false;
    }
  });
}

function loadTenants(tenants = []) {
  state.tenants = Array.isArray(tenants) ? tenants : [];
  if (!state.tenants.some((tenant) => tenant.id === state.tenantId)) {
    state.tenantId = state.tenants[0]?.id || null;
  }
  const select = $("#tenant-select");
  select.innerHTML = state.tenants.map((tenant) => '<option value="' + escapeHtml(tenant.id) + '">' + escapeHtml(tenant.name) + " · " + escapeHtml(tenant.role) + "</option>").join("");
  select.disabled = state.tenants.length < 2;
  if (state.tenantId) select.value = state.tenantId;
  $("#workspace-name").textContent = state.tenants.find((tenant) => tenant.id === state.tenantId)?.name || "No workspace";
}

async function loadData() {
  if (!state.tenantId) {
    state.data = { nodes: [], applications: [], deployments: [], jobs: [], members: [], domains: [], volumes: [] };
    renderPage();
    dashboardMessage("Your account is authenticated, but it has no active Cloudexify workspace membership. Ask an Owner to provision your user and tenant membership.");
    return;
  }
  const base = "/api/v1/tenants/" + encodeURIComponent(state.tenantId);
  const snapshot = await api(base + "/overview");
  state.data = {
    nodes: Array.isArray(snapshot.nodes) ? snapshot.nodes : [],
    applications: Array.isArray(snapshot.applications) ? snapshot.applications : [],
    deployments: Array.isArray(snapshot.deployments) ? snapshot.deployments : [],
    jobs: Array.isArray(snapshot.jobs) ? snapshot.jobs : [],
    members: Array.isArray(snapshot.members) ? snapshot.members : [],
    domains: Array.isArray(snapshot.domains) ? snapshot.domains : [],
    volumes: Array.isArray(snapshot.volumes) ? snapshot.volumes : []
  };

  // Update navigation badge counters
  const nodesBadge = $("#nodes-count-badge");
  if (nodesBadge) nodesBadge.textContent = state.data.nodes.length;
  const appsBadge = $("#apps-count-badge");
  if (appsBadge) appsBadge.textContent = state.data.applications.length;
  const depBadge = $("#deployments-count-badge");
  if (depBadge) depBadge.textContent = state.data.deployments.length;

  dashboardMessage("");
  $("#last-updated").textContent = "Updated " + new Date().toLocaleTimeString();
  renderPage();
}

function metric(label, value, foot) {
  return '<article class="metric-card"><div class="metric-top"><span>' + escapeHtml(label) + '</span><span class="status online">Live</span></div><div class="metric-value">' + escapeHtml(value) + '</div><div class="metric-foot">' + escapeHtml(foot) + "</div></article>";
}

function status(value) {
  const safe = String(value || "unknown").toLowerCase();
  const healthy = ["online", "running", "healthy", "succeeded", "completed", "active", "verified"].includes(safe);
  return '<span class="status ' + (healthy ? "online" : "offline") + '" data-status="' + escapeHtml(safe) + '">' + escapeHtml(value || "Unknown") + "</span>";
}

function table(headers, rows, empty) {
  if (!rows.length) return '<div class="empty-state">' + escapeHtml(empty) + "</div>";
  return "<table><thead><tr>" + headers.map((header) => "<th>" + escapeHtml(header) + "</th>").join("") + "</tr></thead><tbody>" + rows.join("") + "</tbody></table>";
}

function nodeRows(nodes) {
  const role = state.tenants.find((tenant) => tenant.id === state.tenantId)?.role;
  const canManage = ["owner", "admin"].includes(role);
  return nodes.map((node) => {
    const resources = node.resources || {};
    const cpu = resources.cpu_percent == null ? "—" : Number(resources.cpu_percent).toFixed(1) + "% CPU";
    const memory = resources.memory_total_bytes == null ? "—" : formatBytes(resources.memory_used_bytes) + " / " + formatBytes(resources.memory_total_bytes);
    const battery = resources.battery_percent == null ? "" : " · " + Number(resources.battery_percent).toFixed(0) + "% battery";
    const temperature = resources.temperature_c == null ? "" : " · " + Number(resources.temperature_c).toFixed(1) + "°C";
    const approvalActions = canManage && node.status === "pending"
      ? '<button type="button" class="small-action" data-node-action="approve" data-node-id="' + escapeHtml(node.id) + '">Approve</button><button type="button" class="small-action" data-node-action="reject" data-node-id="' + escapeHtml(node.id) + '">Reject</button>'
      : "";
    const ingressAction = canManage && node.ingress_managed
      ? node.ingress_draining
        ? (node.ingress_ready ? '<button type="button" class="small-action" data-node-ingress-state="active" data-node-id="' + escapeHtml(node.id) + '">Resume ingress</button>' : '<small class="subcell">Ingress draining · node not ready to resume</small>')
        : '<button type="button" class="small-action" data-node-ingress-state="draining" data-node-id="' + escapeHtml(node.id) + '">Drain ingress</button>'
      : "";
    const actions = approvalActions || ingressAction
      ? '<div class="node-actions">' + approvalActions + ingressAction + '</div>'
      : "";
    return '<tr class="node-row" tabindex="0" data-node-open="' + escapeHtml(node.id) + '"><td><div class="node-name"><span>' + escapeHtml(node.name) + '</span><small class="subcell">' + escapeHtml(node.id) + "</small></div></td><td>" + escapeHtml(node.platform) + " · " + escapeHtml(node.architecture) + "</td><td>" + cpu + " · " + memory + battery + temperature + "</td><td>" + status(node.status) + '</td><td>' + escapeHtml(formatDate(node.last_seen_at)) + actions + "</td></tr>";
  });
}

function applicationRows(apps, canManage) {
  return apps.map((app) => {
    const nextState = app.desired_state === "running" ? "stopped" : "running";
    const action = canManage
      ? '<button type="button" class="small-action" data-application-state="' + nextState + '" data-application-id="' + escapeHtml(app.id) + '">' + (nextState === "running" ? "Set running" : "Set stopped") + '</button>'
      : "";
    return "<tr><td><strong>" + escapeHtml(app.name) + '</strong><small class="subcell">' + escapeHtml(app.id) + "</small></td><td>" + status(app.desired_state) + "</td><td>" + escapeHtml(formatDate(app.updated_at || app.created_at)) + action + "</td></tr>";
  });
}

function deploymentRows(items, canOperate) {
  return items.map((item) => {
    const canCancel = canOperate && item.desired_state === "running" && ["queued", "scheduled"].includes(item.status);
    const canStop = canOperate && item.desired_state === "running" && ["deploying", "healthy", "restarting", "failed"].includes(item.status);
    const canRestart = canOperate && item.desired_state === "stopped" && item.status === "stopped";
    const action = canCancel
      ? '<button type="button" class="small-action" data-deployment-cancel="' + escapeHtml(item.id) + '">Cancel queued</button>'
      : canStop
        ? '<button type="button" class="small-action" data-deployment-action="stopped" data-deployment-id="' + escapeHtml(item.id) + '">Stop</button>'
        : canRestart
          ? '<button type="button" class="small-action" data-deployment-action="running" data-deployment-id="' + escapeHtml(item.id) + '">Restart</button>'
          : "";
    const health = item.status === "healthy"
      ? '<small class="subcell">HTTP 2xx verified · ' + escapeHtml(formatDate(item.health_checked_at)) + '</small>'
      : item.desired_state === "running" ? '<small class="subcell">Health not verified</small>' : "";
    return "<tr><td><code>" + escapeHtml(item.revision) + "</code></td><td><code>" + escapeHtml(item.application_id) + "</code></td><td>" + escapeHtml(item.desired_state) + "</td><td>" + status(item.status) + health + "</td><td>" + escapeHtml(formatDate(item.created_at)) + action + "</td></tr>";
  });
}

function jobRows(items) {
  return items.map((item) => "<tr><td><code>" + escapeHtml(item.type) + "</code></td><td><code>" + escapeHtml(item.node_id) + "</code></td><td>" + status(item.status) + "</td><td>" + escapeHtml(item.attempt_count) + "</td><td>" + escapeHtml(formatDate(item.updated_at || item.created_at)) + "</td></tr>");
}

function memberRows(items) {
  return items.map((item) => "<tr><td><strong>" + escapeHtml(item.display_name || item.email || item.user_id) + '</strong><small class="subcell">' + escapeHtml(item.email || item.user_id) + "</small></td><td><code>" + escapeHtml(item.role) + "</code></td><td>" + status(item.status === "active" ? "Active" : item.status) + "</td><td>" + escapeHtml(formatDate(item.created_at)) + "</td></tr>");
}

function domainRows(items) {
  return items.map((item) => {
    return "<tr><td><strong>" + escapeHtml(item.hostname) + '</strong><small class="subcell">Tenant ID: ' + escapeHtml(item.tenant_id) + "</small></td><td>" + status(item.status) + '</td><td><span class="status offline">Transport Gated</span></td><td>' + escapeHtml(formatDate(item.created_at)) + "</td></tr>";
  });
}

function volumeRows(items) {
  return items.map((item) => {
    return "<tr><td><strong>" + escapeHtml(item.name) + '</strong><small class="subcell">' + escapeHtml(item.id) + "</small></td><td><code>" + escapeHtml(item.mount_path) + "</code></td><td>" + formatBytes(item.size_bytes) + "</td><td>" + status(item.status) + "</td><td>" + escapeHtml(formatDate(item.created_at)) + "</td></tr>";
  });
}

function showResourceDialog({ title, description, fields, submitLabel, onSubmit }) {
  const dialog = document.createElement("dialog");
  dialog.className = "token-dialog resource-dialog";
  const fieldMarkup = fields.map((field) => {
    const control = field.type === "select"
      ? '<select name="' + escapeHtml(field.name) + '"' + (field.required ? " required" : "") + '>' + field.options.map((option) => '<option value="' + escapeHtml(option.value) + '"' + (option.selected ? " selected" : "") + '>' + escapeHtml(option.label) + "</option>").join("") + "</select>"
      : '<input name="' + escapeHtml(field.name) + '" type="' + escapeHtml(field.type || "text") + '" maxlength="' + escapeHtml(field.maxLength || 120) + '" placeholder="' + escapeHtml(field.placeholder || "") + '"' + (field.required ? " required" : "") + ">";
    return "<label>" + escapeHtml(field.label) + control + "</label>";
  }).join("");
  dialog.innerHTML = "<form><h2>" + escapeHtml(title) + "</h2><p>" + escapeHtml(description) + "</p>" + fieldMarkup + '<p class="dialog-error" role="alert" hidden></p><div><button type="button" class="secondary-btn" data-cancel>Cancel</button><button type="submit" class="primary-btn">' + escapeHtml(submitLabel) + "</button></div></form>";
  document.body.append(dialog);
  const form = dialog.querySelector("form");
  const submit = form.querySelector('[type="submit"]');
  const errorBox = form.querySelector(".dialog-error");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    errorBox.hidden = true;
    try {
      await onSubmit(new FormData(form));
      dialog.close();
      await refreshData();
    } catch (error) {
      errorBox.textContent = error.message || "The request could not be completed.";
      errorBox.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });
  form.querySelector("[data-cancel]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => dialog.remove(), { once: true });
  dialog.showModal();
}

function renderNodeDetails(nodeId) {
  const node = state.data.nodes.find((item) => item.id === nodeId);
  if (!node) return;
  const r = node.resources || {};
  const items = [
    ["CPU cores", r.cpu_cores == null ? "Not reported" : String(r.cpu_cores) + " logical cores"],
    ["CPU usage", r.cpu_percent == null ? "Not reported" : Number(r.cpu_percent).toFixed(1) + "%"],
    ["CPU frequency", r.cpu_frequency_mhz == null ? "Not reported" : Number(r.cpu_frequency_mhz).toFixed(0) + " MHz"],
    ["RAM used", r.memory_used_bytes == null ? "Not reported" : formatBytes(r.memory_used_bytes)],
    ["RAM available", r.memory_available_bytes == null ? "Not reported" : formatBytes(r.memory_available_bytes)],
    ["RAM total", r.memory_total_bytes == null ? "Not reported" : formatBytes(r.memory_total_bytes)],
    ["Agent filesystem used", r.disk_used_bytes == null ? "Not reported" : formatBytes(r.disk_used_bytes)],
    ["Agent filesystem available", r.disk_available_bytes == null ? "Not reported" : formatBytes(r.disk_available_bytes)],
    ["Agent filesystem total", r.disk_total_bytes == null ? "Not reported" : formatBytes(r.disk_total_bytes)],
    ["Android shared storage used", r.android_shared_storage_used_bytes == null ? "Not reported" : formatBytes(r.android_shared_storage_used_bytes)],
    ["Android shared storage available", r.android_shared_storage_available_bytes == null ? "Not reported" : formatBytes(r.android_shared_storage_available_bytes)],
    ["Android shared storage total", r.android_shared_storage_total_bytes == null ? "Not reported" : formatBytes(r.android_shared_storage_total_bytes)],
    ["Load average", r.load_1m == null ? "Not reported" : Number(r.load_1m).toFixed(2)],
    ["Uptime", r.uptime_seconds == null ? "Not reported" : Math.floor(r.uptime_seconds / 3600) + " hours"],
    ["Battery", r.battery_percent == null ? "Not reported" : Number(r.battery_percent).toFixed(0) + "%"],
    ["Temperature", r.temperature_c == null ? "Not reported" : Number(r.temperature_c).toFixed(1) + " °C"]
  ];
  let panel = $("#node-details");
  if (!panel) {
    panel = document.createElement("section");
    panel.id = "node-details";
    panel.className = "panel node-details";
    $("#table-content").after(panel);
  }
  panel.hidden = false;
  panel.innerHTML = '<div class="panel-heading"><div><h2>' + escapeHtml(node.name) + "</h2><p>Node ID: " + escapeHtml(node.id) + '</p></div><button class="secondary-btn" id="close-node-details" type="button">Close</button></div><div class="node-detail-grid"><div><span>STATUS</span><b>' + escapeHtml(node.status) + '</b></div><div><span>PLATFORM</span><b>' + escapeHtml(node.platform) + " · " + escapeHtml(node.architecture) + '</b></div><div><span>AGENT VERSION</span><b>' + escapeHtml(node.agent_version || "—") + '</b></div><div><span>LAST HEARTBEAT</span><b>' + escapeHtml(formatDate(node.last_seen_at)) + "</b></div>" + items.map(([label, value]) => "<div><span>" + escapeHtml(label) + "</span><b>" + escapeHtml(value) + "</b></div>").join("") + "</div>";
  $("#close-node-details").addEventListener("click", () => {
    panel.hidden = true;
    state.selectedNodeId = null;
  });
}

function renderPage() {
  const [navTitle, title, subtitle] = pageMeta[state.page] || pageMeta.overview;
  $("#breadcrumb-page").textContent = navTitle;
  $("#page-eyebrow").textContent = navTitle.toUpperCase();
  $("#page-title").textContent = title;
  $("#page-subtitle").textContent = subtitle;
  document.querySelectorAll("[data-page]").forEach((link) => link.classList.toggle("active", link.dataset.page === state.page));

  const { nodes, applications, deployments, jobs, members, domains, volumes } = state.data;
  const currentRole = state.tenants.find((tenant) => tenant.id === state.tenantId)?.role;
  const enrollmentButton = $("#create-enrollment-button");
  if (enrollmentButton) enrollmentButton.hidden = !(state.page === "nodes" && ["owner", "admin"].includes(currentRole));

  const online = nodes.filter((node) => node.status === "online").length;
  const running = applications.filter((app) => app.desired_state === "running").length;

  // Overview metrics answering 7 infrastructure operational questions
  const metrics = state.page === "overview"
    ? metric("Online nodes", online + " / " + nodes.length, "Based on server-side heartbeat status") +
      metric("Applications", applications.length, running + " configured to run") +
      metric("Deployments", deployments.length, "Stored deployment revisions") +
      metric("Jobs", jobs.length, "Queued and historical node jobs")
    : "";
  $("#metric-grid").innerHTML = metrics;

  const overviewExtras = $("#overview-extras");
  if (overviewExtras) {
    overviewExtras.hidden = state.page !== "overview";
    overviewExtras.innerHTML = state.page === "overview"
      ? '<div class="overview-grid">' +
        '<section class="panel"><div class="panel-heading"><div><h2>Recent jobs</h2><p>Latest diagnostic activity across this workspace</p></div></div>' +
        table(["TASK", "NODE", "STATUS"], jobs.slice(0, 5).map((job) => "<tr><td><code>" + escapeHtml(job.type) + "</code></td><td><code>" + escapeHtml(String(job.node_id || "").slice(0, 8)) + "</code></td><td>" + status(job.status) + "</td></tr>"), "No jobs have been queued yet.") +
        '</section>' +
        '<section class="panel"><div class="panel-heading"><div><h2>Applications</h2><p>Registered application records</p></div></div>' +
        (applications.length
          ? '<div class="overview-app-list">' + applications.slice(0, 5).map((app) => '<div class="overview-app-item"><span class="overview-app-icon">A</span><div><b>' + escapeHtml(app.name) + "</b><small>" + escapeHtml(app.desired_state || "stopped") + "</small></div>" + status(app.desired_state || "stopped") + "</div>").join("") + "</div>"
          : '<div class="empty-state">No applications registered yet.</div>') +
        '</section>' +
        '</div>'
      : "";
  }

  const config = {
    overview: ["Compute nodes", "Latest node heartbeat and resource reports", table(["NODE", "PLATFORM", "RESOURCES", "STATUS", "LAST SEEN"], nodeRows(nodes.slice(0, 8)), "No nodes registered in this workspace.")],
    nodes: ["Compute nodes", "All registered compute nodes", table(["NODE", "PLATFORM", "RESOURCES", "STATUS", "LAST SEEN"], nodeRows(nodes), "No nodes registered in this workspace.")],
    applications: ["Applications", "Stopping queues node jobs for active revisions; starting requires a new deployment revision.", table(["APPLICATION", "DESIRED STATE", "UPDATED / ACTION"], applicationRows(applications, ["owner", "admin"].includes(currentRole)), "No applications registered in this workspace.")],
    deployments: ["Deployments", "Stop or restart a revision on its assigned node. A revision becomes healthy only after its HTTP endpoint returns 2xx.", table(["REVISION", "APPLICATION ID", "DESIRED STATE", "STATUS", "CREATED / ACTION"], deploymentRows(deployments, ["owner", "admin", "operator"].includes(currentRole)), "No deployments recorded in this workspace.")],
    jobs: ["Node jobs", "Diagnostic job queue and execution state", table(["TYPE", "NODE ID", "STATUS", "ATTEMPTS", "UPDATED"], jobRows(jobs), "No jobs recorded in this workspace.")],
    domains: ["Domains & Ingress", "Custom domain claims, DNS verification challenges and route registry status", table(["HOSTNAME", "STATUS", "GATEWAY TRANSPORT", "CREATED"], domainRows(domains), "No domain claims recorded in this workspace.")],
    storage: ["Persistent application volumes", "Durable volumes and snapshot backup records with tenant isolation", table(["VOLUME NAME", "MOUNT PATH", "CAPACITY", "STATUS", "CREATED"], volumeRows(volumes), "No persistent volumes provisioned in this workspace.")],
    members: ["Workspace members", "Members with access to this tenant", table(["MEMBER", "ROLE", "STATUS", "JOINED"], memberRows(members), "No workspace members found.")],
    settings: ["Session and workspace settings", "Authentication, session continuity and service configuration", '<div class="settings-grid"><article class="settings-card"><span>AUTHENTICATION</span><h3>Supabase Auth</h3><p>Browser session persistence with automatic token refresh and stale-token recovery.</p><b class="setting-state">Automatic refresh enabled</b></article><article class="settings-card"><span>ACCESS TOKEN</span><h3>' + escapeHtml(state.session?.expires_at ? formatDate(new Date(Number(state.session.expires_at) * 1000)) : "Not available") + '</h3><p>Current access-token expiry. The browser refreshes it before expiry; this is not the overall session end time.</p></article><article class="settings-card"><span>WORKSPACE</span><h3>' + escapeHtml(state.tenants.find((tenant) => tenant.id === state.tenantId)?.name || "No workspace") + '</h3><p>Current role: ' + escapeHtml(currentRole || "Unknown") + '</p></article><article class="settings-card"><span>DATA REFRESH</span><h3>Every 3 seconds</h3><p>Single combined snapshot while this dashboard is active, with bounded retry backoff after network failures.</p></article><article class="settings-card"><span>API PROTECTION</span><h3>600 requests / minute</h3><p>Vercel edge rate limit per source IP for the authenticated control-plane API.</p></article><article class="settings-card"><span>WORKLOAD RUNTIME</span><h3>Rootless Podman qualified</h3><p>Workload isolation with Cosign verification and fail-closed ingress transport gate active.</p></article></div>']
  }[state.page] || null;

  if (config) {
    $("#table-title").textContent = config[0];
    $("#table-subtitle").textContent = config[1];
    $("#table-content").innerHTML = config[2];
  }

  $("#table-content").querySelectorAll("[data-application-state]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const id = button.dataset.applicationId;
        const desiredState = button.dataset.applicationState;
        const result = await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/applications/" + encodeURIComponent(id) + "/state", {
          method: "POST",
          body: JSON.stringify({ desired_state: desiredState })
        });
        dashboardMessage("Application desired state updated to " + desiredState + "; " + Number(result.cancelled_deployments || 0) + " queued deployment(s) cancelled and " + Number(result.queued_stop_jobs || 0) + " active revision stop job(s) queued. Starting requires a new deployment revision.");
        await refreshData({ force: true });
      } catch (error) {
        dashboardMessage(error.message || "Unable to update application state.", true);
        button.disabled = false;
      }
    });
  });

  $("#table-content").querySelectorAll("[data-deployment-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const id = button.dataset.deploymentId;
        const desiredState = button.dataset.deploymentAction;
        const result = await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/deployments/" + encodeURIComponent(id) + "/state", {
          method: "POST",
          body: JSON.stringify({ desired_state: desiredState })
        });
        dashboardMessage(desiredState === "stopped"
          ? (result.runtime_job_queued ? "Stop job queued. The revision will be marked stopped only after the node confirms it." : "Deployment is already stopped.")
          : (result.runtime_job_queued ? "Restart job queued. The revision will be marked healthy only after its HTTP health check passes." : "Deployment is already healthy."));
        await refreshData({ force: true });
      } catch (error) {
        dashboardMessage(error.message || "Unable to change deployment state.", true);
        button.disabled = false;
      }
    });
  });

  $("#table-content").querySelectorAll("[data-deployment-cancel]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const id = button.dataset.deploymentCancel;
        await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/deployments/" + encodeURIComponent(id) + "/state", {
          method: "POST",
          body: JSON.stringify({ desired_state: "stopped" })
        });
        dashboardMessage("Queued deployment revision cancelled.");
        await refreshData({ force: true });
      } catch (error) {
        dashboardMessage(error.message || "Unable to cancel deployment revision.", true);
        button.disabled = false;
      }
    });
  });

  const applicationButton = $("#create-application-button");
  if (applicationButton) applicationButton.hidden = !(state.page === "applications" && ["owner", "admin"].includes(currentRole));
  const deploymentButton = $("#create-deployment-button");
  if (deploymentButton) deploymentButton.hidden = !(state.page === "deployments" && ["owner", "admin", "operator"].includes(currentRole) && applications.length > 0);
  const memberButton = $("#create-member-button");
  if (memberButton) memberButton.hidden = !(state.page === "members" && ["owner", "admin"].includes(currentRole));
  const diagnosticButton = $("#create-diagnostic-job");
  if (diagnosticButton) diagnosticButton.hidden = !(state.page === "jobs" && ["owner", "admin", "operator"].includes(currentRole) && nodes.some((node) => ["online", "degraded"].includes(node.status)));
  if (state.page === "nodes" && state.selectedNodeId) renderNodeDetails(state.selectedNodeId);
}

async function refreshData({ force = false } = {}) {
  if (state.loading || !state.session || (!force && Date.now() < state.nextRefreshAt)) return;
  state.loading = true;
  const refreshButton = $("#refresh-button");
  if (refreshButton) refreshButton.disabled = true;
  try {
    await loadData();
    state.refreshFailures = 0;
    state.nextRefreshAt = 0;
  } catch (error) {
    state.refreshFailures += 1;
    const delay = Math.min(30000, REFRESH_INTERVAL_MS * (2 ** Math.min(state.refreshFailures - 1, 4)));
    state.nextRefreshAt = Date.now() + delay;
    dashboardMessage((error.message || "Unable to load workspace data.") + " Retrying in " + Math.ceil(delay / 1000) + " seconds.", true);
  } finally {
    state.loading = false;
    if (refreshButton) refreshButton.disabled = false;
  }
}

async function openDashboard() {
  const user = await api("/api/v1/auth/me");
  state.user = user.user || state.session.user;
  $("#profile-name").textContent = state.user.display_name || state.user.email || "Account";
  $("#profile-email").textContent = state.user.email || "";
  $("#profile-avatar").textContent = (state.user.display_name || state.user.email || "C").slice(0, 1).toUpperCase();
  loadTenants(user.tenants);
  await loadData();
  $("#auth-view").hidden = true;
  $("#app-view").hidden = false;
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(refreshData, REFRESH_INTERVAL_MS);
}

async function init() {
  initTheme();
  const configResponse = await fetch("/api/config", { cache: "no-store" });
  state.config = await configResponse.json();
  if (!state.config.authConfigured) {
    message("Supabase Auth is not configured. Add SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in Vercel.");
    $("#login-button").disabled = true;
    renderLogin();
    return;
  }
  renderLogin();
  state.session = readSession();
  if (state.session?.access_token && state.session?.refresh_token) {
    try {
      await ensureFreshSession();
      await openDashboard();
    } catch (error) {
      $("#app-view").hidden = true;
      $("#auth-view").hidden = false;
      message(error.message || "Unable to restore the session. Retry when the connection is available.", true);
    }
  }

  // Event handlers
  $("#theme-toggle")?.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");
  });

  $("#signout-button").addEventListener("click", signOut);
  $("#refresh-button").addEventListener("click", () => refreshData({ force: true }));

  $("#create-enrollment-button").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    if (button.disabled || !state.tenantId) return;
    button.disabled = true;
    try {
      const result = await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/enrollment-tokens", {
        method: "POST",
        body: JSON.stringify({ expires_in_minutes: 30 })
      });
      const token = result.enrollment_token?.token;
      if (!token) throw new Error("The API did not return an enrollment token.");
      const dialog = document.createElement("dialog");
      dialog.className = "token-dialog";
      dialog.innerHTML = "<h2>Enrollment token created</h2><p>Copy this one-time token now. It expires at " + escapeHtml(new Date(result.enrollment_token.expires_at).toLocaleString()) + '.</p><textarea readonly rows="3"></textarea><div><button type="button" class="secondary-btn" data-copy-token>Copy token</button><button type="button" class="primary-btn" data-close-token>Done</button></div>';
      dialog.querySelector("textarea").value = token;
      document.body.append(dialog);
      dialog.showModal();
      dialog.querySelector("[data-copy-token]").addEventListener("click", async () => {
        await navigator.clipboard.writeText(token);
        dialog.querySelector("[data-copy-token]").textContent = "Copied";
      });
      dialog.querySelector("[data-close-token]").addEventListener("click", () => dialog.close());
      dialog.addEventListener("close", () => dialog.remove(), { once: true });
      dashboardMessage("A one-time enrollment token was created. Use it on the Android/Termux device within 30 minutes.");
    } catch (error) {
      dashboardMessage(error.message || "Unable to create enrollment token.", true);
    } finally {
      button.disabled = false;
    }
  });

  $("#table-content").addEventListener("click", async (event) => {
    const row = event.target.closest("[data-node-open]");
    if (row && !event.target.closest("[data-node-action], [data-node-ingress-state]")) {
      state.selectedNodeId = row.dataset.nodeOpen;
      renderNodeDetails(state.selectedNodeId);
      return;
    }
    const button = event.target.closest("[data-node-action], [data-node-ingress-state]");
    if (!button || button.disabled) return;
    const action = button.dataset.nodeAction;
    const ingressState = button.dataset.nodeIngressState;
    const nodeId = button.dataset.nodeId;
    if (!nodeId) return;
    if (ingressState && !["active", "draining"].includes(ingressState)) return;
    if (!ingressState && !["approve", "reject"].includes(action)) return;
    if (action === "reject" && !window.confirm("Reject this node? Its current credentials will be revoked and it cannot reconnect.")) return;
    if (ingressState === "draining" && !window.confirm("Stop accepting new customer requests on this node and drain existing ingress connections?")) return;
    button.disabled = true;
    try {
      if (ingressState) {
        await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/nodes/" + encodeURIComponent(nodeId) + "/state", {
          method: "POST",
          body: JSON.stringify({ ingress_state: ingressState })
        });
        dashboardMessage(ingressState === "draining" ? "Node ingress is draining; new requests are blocked." : "Node ingress resumed.");
      } else {
        await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/nodes/" + encodeURIComponent(nodeId) + "/" + action, {
          method: "POST"
        });
        dashboardMessage(action === "approve" ? "Node approved." : "Node rejected and its credentials revoked.");
      }
      await refreshData();
    } catch (error) {
      dashboardMessage(error.message || "Unable to update node state.", true);
      button.disabled = false;
    }
  });

  $("#create-diagnostic-job").addEventListener("click", () => {
    const onlineNodes = state.data.nodes.filter((item) => ["online", "degraded"].includes(item.status));
    if (!onlineNodes.length) {
      dashboardMessage("No approved online node is available for diagnostics.", true);
      return;
    }
    showResourceDialog({
      title: "Run node diagnostics",
      description: "Automatic placement balances work across the approved online node pool. You can optionally pin a task to one node.",
      fields: [
        {
          name: "node_id",
          label: "Placement",
          type: "select",
          required: false,
          options: [{ value: "", label: "Automatic · balance across node pool", selected: true }, ...onlineNodes.map((node) => ({ value: node.id, label: "Specific node · " + node.name + " · " + node.platform }))]
        },
        {
          name: "type",
          label: "Diagnostic task",
          type: "select",
          required: true,
          options: [{ value: "collect_metrics", label: "Collect resource metrics", selected: true }, { value: "probe", label: "Connectivity probe" }]
        }
      ],
      submitLabel: "Queue diagnostic",
      onSubmit: async (form) => {
        const selectedNodeId = form.get("node_id") || null;
        const result = await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/jobs", {
          method: "POST",
          body: JSON.stringify({ ...(selectedNodeId ? { node_id: selectedNodeId } : {}), type: form.get("type"), payload: {}, idempotency_key: "dashboard-" + crypto.randomUUID() })
        });
        const assignedNode = onlineNodes.find((item) => item.id === result.job?.node_id);
        dashboardMessage(form.get("type") + " job queued on " + (assignedNode?.name || "the selected node") + (selectedNodeId ? "." : " by automatic pool scheduling."));
      }
    });
  });

  $("#create-application-button").addEventListener("click", () => showResourceDialog({
    title: "Create application",
    description: "Register an application in this workspace. This creates a control-plane record; it does not deploy or run code yet.",
    fields: [{ name: "name", label: "Application name", required: true, maxLength: 100, placeholder: "e.g. customer-portal" }],
    submitLabel: "Create application",
    onSubmit: async (form) => {
      await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/applications", {
        method: "POST",
        body: JSON.stringify({ name: String(form.get("name") || "").trim() })
      });
      dashboardMessage("Application record created.");
    }
  }));

  $("#create-deployment-button").addEventListener("click", () => {
    if (!state.data.applications.length) {
      dashboardMessage("Create an application before requesting a deployment.", true);
      return;
    }
    const apps = state.data.applications;
    const nodes = state.data.nodes.filter((node) => ["online", "degraded"].includes(node.status));
    showResourceDialog({
      title: "Request deployment",
      description: "Queue a deployment job on a qualified Linux node. The node waits for the application health endpoint before reporting the revision healthy. Public ingress is still pending.",
      fields: [
        { name: "application_id", label: "Application", type: "select", required: true, options: apps.map((app, index) => ({ value: app.id, label: app.name, selected: index === 0 })) },
        { name: "image_digest", label: "Immutable OCI image digest (required for running)", required: false, maxLength: 300, placeholder: "registry.example.com/team/app@sha256:<64 hex>" },
        { name: "container_port", label: "Container TCP port (required for running)", type: "number", required: false, maxLength: 5, placeholder: "8080" },
        { name: "health_check_path", label: "HTTP health-check path", required: false, maxLength: 256, placeholder: "/healthz" },
        { name: "health_check_timeout_seconds", label: "Health-check timeout (5–120 seconds)", type: "number", required: false, maxLength: 3, placeholder: "30" },
        { name: "target_node_id", label: "Target node (optional)", type: "select", required: false, options: [{ value: "", label: "Automatic capacity-based placement" }, ...nodes.map((node) => ({ value: node.id, label: node.name + " · " + node.platform }))] },
        { name: "desired_state", label: "Desired state", type: "select", required: true, options: [{ value: "running", label: "Running", selected: true }, { value: "stopped", label: "Stopped" }] }
      ],
      submitLabel: "Create deployment request",
      onSubmit: async (form) => {
        const desiredState = String(form.get("desired_state"));
        const body = {
          application_id: form.get("application_id"),
          target_node_id: form.get("target_node_id") || null,
          desired_state: desiredState
        };
        if (desiredState === "running") {
          body.image_digest = String(form.get("image_digest") || "").trim();
          body.container_port = Number(form.get("container_port"));
          body.health_check_path = String(form.get("health_check_path") || "/").trim();
          body.health_check_timeout_seconds = Number(form.get("health_check_timeout_seconds") || 30);
        }
        const result = await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/deployments", {
          method: "POST",
          body: JSON.stringify(body)
        });
        dashboardMessage(result.runtime_job_queued ? "Deployment job queued on node " + result.deployment.target_node_id + ". Process startup and application health will be reported separately." : "Stopped deployment revision recorded.");
      }
    });
  });

  $("#create-member-button").addEventListener("click", () => {
    const role = state.tenants.find((tenant) => tenant.id === state.tenantId)?.role;
    const roles = role === "owner" ? ["admin", "operator", "viewer"] : ["operator", "viewer"];
    showResourceDialog({
      title: "Add workspace member",
      description: "Enter the UUID of an already-provisioned Cloudexify user and assign a tenant role.",
      fields: [
        { name: "user_id", label: "User ID (UUID)", required: true, maxLength: 36, placeholder: "00000000-0000-4000-8000-000000000000" },
        { name: "role", label: "Workspace role", type: "select", required: true, options: roles.map((value, index) => ({ value, label: value[0].toUpperCase() + value.slice(1), selected: index === 0 })) }
      ],
      submitLabel: "Add member",
      onSubmit: async (form) => {
        await api("/api/v1/tenants/" + encodeURIComponent(state.tenantId) + "/members", {
          method: "POST",
          body: JSON.stringify({ user_id: String(form.get("user_id") || "").trim(), role: form.get("role") })
        });
        dashboardMessage("Workspace membership created.");
      }
    });
  });

  $("#tenant-select").addEventListener("change", async (event) => {
    state.tenantId = event.target.value;
    $("#workspace-name").textContent = state.tenants.find((tenant) => tenant.id === state.tenantId)?.name || "Workspace";
    await refreshData();
  });

  document.querySelectorAll("[data-page]").forEach((link) => link.addEventListener("click", (event) => {
    event.preventDefault();
    state.page = link.dataset.page;
    renderPage();
    if (window.innerWidth < 900) {
      $("#sidebar")?.classList.remove("open");
    }
  }));

  $("#menu-btn")?.addEventListener("click", () => $("#sidebar")?.classList.toggle("open"));
  $("#mobile-sidebar-close")?.addEventListener("click", () => $("#sidebar")?.classList.remove("open"));
  $("#sidebar-backdrop")?.addEventListener("click", () => $("#sidebar")?.classList.remove("open"));

  document.addEventListener("visibilitychange", () => {
    if (document.hidden || !state.session) return;
    if ($("#app-view").hidden) {
      void openDashboard().catch((error) => message(error.message || "Unable to restore the dashboard. Your session is still saved.", true));
    } else {
      void refreshData({ force: true });
    }
  });
}

init().catch((error) => {
  message(error.message || "Dashboard initialization failed.", true);
});
