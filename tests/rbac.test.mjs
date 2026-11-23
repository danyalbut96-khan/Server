import test from "node:test";
import assert from "node:assert/strict";
import { canAssignRole, isTenantRole, requirePermission, AuthorizationError } from "../src/auth/rbac.mjs";

test("recognizes only the four tenant roles", () => {
  for (const role of ["owner", "admin", "operator", "viewer"]) assert.equal(isTenantRole(role), true);
  assert.equal(isTenantRole("platform_admin"), false);
});

test("read permission is available to every tenant role", () => {
  for (const role of ["owner", "admin", "operator", "viewer"]) assert.equal(requirePermission(role, "read"), true);
});

test("application and member management is restricted to owner/admin", () => {
  for (const role of ["owner", "admin"]) {
    assert.equal(requirePermission(role, "manageApplications"), true);
    assert.equal(requirePermission(role, "manageMembers"), true);
  }
  for (const role of ["operator", "viewer"]) {
    assert.throws(() => requirePermission(role, "manageApplications"), AuthorizationError);
    assert.throws(() => requirePermission(role, "manageMembers"), AuthorizationError);
  }
});

test("domain management is restricted to tenant owners and admins", () => {
  for (const role of ["owner", "admin"]) assert.equal(requirePermission(role, "manageDomains"), true);
  for (const role of ["operator", "viewer"]) assert.throws(() => requirePermission(role, "manageDomains"), AuthorizationError);
});

test("volume management is restricted to tenant owners and admins", () => {
  for (const role of ["owner", "admin"]) assert.equal(requirePermission(role, "manageVolumes"), true);
  for (const role of ["operator", "viewer"]) assert.throws(() => requirePermission(role, "manageVolumes"), AuthorizationError);
});

test("deployment operations allow operator but not viewer", () => {
  for (const role of ["owner", "admin", "operator"]) assert.equal(requirePermission(role, "operateDeployments"), true);
  assert.throws(() => requirePermission("viewer", "operateDeployments"), AuthorizationError);
});

test("role assignment cannot create another owner or escalate an admin", () => {
  assert.equal(canAssignRole("owner", "admin"), true);
  assert.equal(canAssignRole("owner", "viewer"), true);
  assert.equal(canAssignRole("owner", "owner"), false);
  assert.equal(canAssignRole("admin", "operator"), true);
  assert.equal(canAssignRole("admin", "viewer"), true);
  assert.equal(canAssignRole("admin", "admin"), false);
  assert.equal(canAssignRole("operator", "viewer"), false);
});
