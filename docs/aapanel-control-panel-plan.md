# Cloudexify aaPanel-style control panel implementation plan

**Reference:** https://www.aapanel.com/  
**Target:** A first-party Cloudexify managed-hosting control panel. This is a workflow and capability reference, not a dependency on aaPanel.

## Engineering rules

- Keep all work on the `working` branch and open a pull request to `main`; do not commit directly to `main`.
- Preserve the existing control-plane identity, tenant isolation, RBAC, audit trail, node enrollment and typed job protocol.
- Do not introduce arbitrary shell execution, arbitrary filesystem paths, arbitrary upstream URLs, public container ports, or browser-visible infrastructure secrets.
- All node mutations must be typed, schema-validated, tenant-authorized, audited, idempotent where practical, and acknowledged by the target node.
- Use additive database migrations. Do not ask the operator to apply a migration until its SQL and rollback implications have been reviewed and CI has passed.
- Do not claim production readiness until physical Linux qualification, failure testing, restore drills and security review pass.
- Do not enable public ingress by default.

## Milestone A — dashboard audit and aaPanel-style redesign

- [ ] Document current dashboard pages, controls, API dependencies, role gates and empty/error/loading states.
- [ ] Refactor the monolithic dashboard entry into maintainable page, component, API-client and state modules without breaking authentication/session refresh.
- [ ] Introduce a consistent aaPanel-inspired navigation hierarchy: Overview, Websites, Applications, Deployments, Databases, Files, Domains, SSL, Nodes, Security, Logs, Backups, Monitoring, Members, Settings.
- [ ] Implement responsive desktop/tablet/mobile layouts, accessible keyboard navigation, clear status semantics and dark/light themes.
- [ ] Ensure every visible action is connected to a real API operation or explicitly disabled with an explanation.

## Milestone B — server overview and live telemetry

- [ ] Provide fleet and per-node CPU, memory, filesystem, network, runtime, uptime, heartbeat freshness and workload summaries.
- [ ] Display metric freshness and distinguish unavailable/stale values from zero.
- [ ] Add bounded history/aggregation APIs and dashboard charts; avoid excessive polling.
- [ ] Verify reported values against qualified Linux host measurements and test stale/offline transitions.

## Milestone C — websites, applications and deployments

- [ ] Add website inventory, create/configure/archive workflows and supported runtime templates.
- [ ] Support Git/image-based deployments with immutable image digests, build/deploy logs, health gates, restart/stop and rollback.
- [ ] Add environment-variable and secret management with write-only secret handling and audit events.
- [ ] Add deployment progress/events, per-app resource usage, domain binding and safe node placement.
- [ ] Keep Termux diagnostic-only; workload execution requires a qualified Linux node.

## Milestone D — file manager and database management

- [ ] Design tenant/application-scoped file access with path canonicalization, symlink containment, quotas, bounded uploads/downloads and audit logging.
- [ ] Implement typed node file operations; never expose arbitrary shell or unrestricted host filesystem access.
- [ ] Design managed database provisioning, lifecycle, credentials, network isolation, backups and restore.
- [ ] Store credentials in a dedicated secret mechanism; show secrets only once and never return them in list/detail APIs.
- [ ] Add database usage, health, connection and backup status views.

## Milestone E — domains, SSL and reverse proxy

- [ ] Complete domain lifecycle UI, DNS instructions and verification states.
- [ ] Implement ACME certificate issuance/renewal/revocation and secure private-key storage.
- [ ] Complete ingress route activation, reverse-proxy operations, SNI/Host validation, limits and audit events.
- [ ] Add multi-node route switching only after health verification and failure tests.
- [ ] Keep public ingress opt-in until production qualification passes.

## Milestone F — security, logs, backups and monitoring

- [ ] Add security posture dashboard, firewall/SSH posture reporting and policy-controlled actions.
- [ ] Add structured application, node, deployment, ingress and audit log views with redaction and retention.
- [ ] Add metrics, alerts, notification routing and incident history.
- [ ] Add scheduled backups, retention policies, restore workflows and verified recovery drills.
- [ ] Add per-user rate limits, login abuse monitoring, credential rotation and secrets review.

## Milestone G — multi-server and access management

- [ ] Add fleet inventory, node groups/labels, capability qualification, capacity-aware scheduling and placement controls.
- [ ] Add safe drain/maintenance workflows, node upgrade/agent version management and credential rotation.
- [ ] Complete tenant Owner/Admin/Operator/Viewer permission matrix for all new resources.
- [ ] Add resource-level authorization tests and cross-tenant isolation tests.
- [ ] Qualify multi-node deployment, ingress failover, node loss and recovery behavior.

## Acceptance gates

- [ ] Unit and API tests for every new workflow.
- [ ] PostgreSQL integration tests for migrations, constraints, RLS, RBAC and concurrent operations.
- [ ] Browser visual/functional QA on mobile and desktop.
- [ ] Physical Debian/Linux node qualification; Android/Termux remains diagnostic-only.
- [ ] Security review covering path traversal, symlinks, SSRF, secret exposure, tenant isolation, request limits and unsafe command execution.
- [ ] Backup restore and node/gateway failure drills.
- [ ] Production deployment and health checks verified against the exact merged commit.
