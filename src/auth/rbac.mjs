export const TENANT_ROLES = Object.freeze(["owner", "admin", "operator", "viewer"]);

export const PERMISSIONS = Object.freeze({
  read: TENANT_ROLES,
  manageApplications: ["owner", "admin"],
  manageMembers: ["owner", "admin"],
  manageNodes: ["owner", "admin"],
  manageDomains: ["owner", "admin"],
  manageVolumes: ["owner", "admin"],
  operateDeployments: ["owner", "admin", "operator"],
  manageJobs: ["owner", "admin", "operator"]
});

export class AuthorizationError extends Error {
  constructor(message = "You do not have permission to perform this action.", status = 403) {
    super(message);
    this.name = "AuthorizationError";
    this.status = status;
  }
}

export function isTenantRole(role) {
  return TENANT_ROLES.includes(role);
}

export function requirePermission(role, permission) {
  const allowed = PERMISSIONS[permission];
  if (!allowed) throw new Error("Unknown authorization permission: " + permission);
  if (!allowed.includes(role)) throw new AuthorizationError();
  return true;
}

export function canAssignRole(actorRole, requestedRole) {
  if (!isTenantRole(requestedRole) || requestedRole === "owner") return false;
  if (actorRole === "owner") return true;
  return actorRole === "admin" && ["operator", "viewer"].includes(requestedRole);
}
