# Vexa Arc Product Tiers — Release Documentation

**Status:** Product direction, not a pricing commitment.  
**As of:** 27 October 2026.  
**Upcoming release:** Community only, after the Community release gates pass. Team and Enterprise features below are planned options, not current product capabilities or commitments.

## Tier matrix

| Capability | Community — upcoming release | Team — planned, not shipping | Enterprise — future, not shipping |
|---|---|---|---|
| Intended customer | One developer on one workstation | A small engineering team coordinating shared project controls | Organizations needing centrally managed governance and support |
| Core engine | Local Rust CLI/library and selected policy checks | Same core engine; no separate weaker security engine | Same engine plus separately validated management and integration services |
| Host integrations | Selected Claude Code and Cursor hook events; explicit coverage limitations | Shared, versioned team configuration for supported adapters; broader coverage only after host-specific testing | Managed deployment/configuration and coverage reporting after fleet agent exists |
| MCP protection | Explicitly launched stdio broker; user-provided reviewed schema pin, or clearly labeled development-only TOFU | Git-reviewed team MCP allowlist and schema pin updates; CI checks for unexpected changes | Authenticated central pin distribution, key rotation/rollback, fleet policy enforcement; remote transports only after proxy is built and assessed |
| Taint and DLP | Heuristic classification and selected-path scanning; not universal interception or dataflow proof | Shared, reviewable policy and CI reporting for supported checks; enforcement only on validated paths | Fleet-wide policy administration and audit evidence after broader mediation and controls are independently validated |
| Package checks | Advisory name heuristic; optional exact-version OSV vulnerability query; no install interception | Reproducible CI advisory checks and team-configured thresholds may be explored; not an install firewall | Registry-backed, provenance-aware install controls and managed offline feeds only after they are implemented and tested |
| Policy distribution | Local files and explicit local configuration | Repository/Git-distributed policy with review and change history; no centralized remote trust service assumed | Signed organization policy bundles, managed trust keys, rollback protection, deployment inventory |
| CI/CD | CLI can be invoked by the user's pipeline; current checks remain advisory unless that pipeline explicitly fails on status | Team-owned CI templates, shared rules, machine-readable results/SARIF only after validated | Central policy gates, organization-wide reporting, deployment controls and integrations after delivery |
| Users, identity, and roles | Local OS user; no Arc-managed SSO/RBAC | Lightweight team ownership and reviewer roles are a candidate, not yet designed | SSO, RBAC, group mapping, administrator controls and audit trails, subject to a real service and security review |
| Audit and integrations | Local output/files; user controls retention | Repository-attached findings and CI artifacts may be supported | Managed audit events, SIEM/OpenTelemetry integrations, retention and privacy controls |
| Support and availability | Community support; no enterprise SLA implied | Paid support is a future packaging decision | Contracted support/SLA only after service operations and incident response are staffed |
| Price and limits | Free; no usage quota is specified here | Not priced or committed | Not priced or committed |

**Meaning of statuses:** “Upcoming” means intended for the next scoped Community release but still subject to the release checklist. “Planned” or “future” means a discovery/roadmap option only; there is no working implementation, availability date, or purchase entitlement.

## Packaging rules

Do not paywall the basic security primitives that make the local tool useful, or leave Community with a deliberately unsafe engine. Differentiation should come from shared administration, coordination, verified integrations, fleet operations, auditability, and support—not from weakening local decisions.

Keep Community useful without a Vexa-hosted service. The Team path should begin with a repository-controlled policy workflow and CI checks, because those can be reviewed and rolled back with familiar developer practices. Do not build a cloud control plane before teams demonstrate that Git-based coordination is insufficient.

Enterprise is not “Team plus a dashboard.” It requires a managed trust root, policy signing and revocation, safe rollback, identity and authorization, endpoint inventory, upgrade/rollback operations, audit retention, incident handling, and independent validation. Build those only against specific customer requirements and operational ownership.

## Release gates between tiers

**Community → Team:** demonstrate repeated demand from multiple real teams; define the shared policy format and compatibility rules; add policy review/ownership, deterministic CI output, supported-host test coverage, and false-positive/override measurement; validate migration and rollback. Do not call current CLI flags “team governance.”

**Team → Enterprise:** establish a threat model and service architecture; provide authenticated tenant identity and authorization; sign and revoke policy bundles; prevent replay/rollback; inventory endpoint versions and health; define audit, privacy, retention, incident response, availability, and support operations; run adversarial tests and an operational pilot. A remote service must fail safely without silently weakening local policy.

## Tier strategy

Make the progression from individual use to shared team workflow to organization-level governance understandable. Keep Vexa Arc focused on its local agent/MCP wedge, and add each tier's capabilities only after customer evidence, implementation, and validation support them.
