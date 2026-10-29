# Vexa Arc Community Core Scope and Release Maintenance

**Status date:** 2026-10-29
**Audience:** Individual developers evaluating Vexa Arc on their own workstation.

## Current availability

The **Community Core is currently available as free software under Apache-2.0**. This document defines its supported local-use boundary. Team capabilities are in **private Beta**, with access and enabled scope defined by cohort; Enterprise governance remains future direction. A Beta or roadmap label does not expand the Community Core's technical coverage.

The [current product-tier matrix](product-tiers.md) describes availability and packaging. Its Team Beta scope is cohort-specific; only the features explicitly enabled for a participating cohort should be treated as available.

## Intended use

Vexa Arc Community Core is a local defense-in-depth utility for an individual developer who explicitly installs supported hooks or launches an MCP server through the `arc protect stdio` broker. It is not a general endpoint firewall. The supported boundary is the event that the configured hook or broker actually receives; direct tools, direct network clients, unwrapped MCP transports, and unsupported host events remain outside Arc's control.

## What a Community Core user can use

- **Claude Code and Cursor:** selected native hook events, subject to the host's configuration and event model. Cursor ordinary editor file writes are not mediated. Windsurf and Cline have no native adapter in this repository; only an MCP server explicitly wrapped by Arc is in scope.
- **MCP stdio broker:** an explicitly launched local stdio server can be mediated. Supply a reviewed `--pin-schema <hash>` for a stable pin, or explicitly use `--allow-tofu` for a local development/bootstrap session. TOFU is not a trustworthy pin and must not be presented as equivalent protection. Starting the server outside this wrapper bypasses Arc.
- **Session taint and DLP:** the engine tracks source/sink labels on observed actions and checks supported patterns/secrets on selected paths. Source and sink classification is heuristic; this is not byte-accurate taint analysis, a full AST analyzer, or universal outbound DLP.
- **Package review:** `arc shield` is advisory. Name heuristics use local baselines and caller-supplied values; exact-version OSV queries check known advisories. Shield does not inspect live registry metadata, determine that a package is benign, or intercept package-manager installs.
- **Process lifecycle:** Windows Job Objects and Unix process lifecycle/resource controls are used by the explicit broker. They are not syscall, filesystem, container, or network sandboxes.

## Privacy and connectivity

Local source/prompt scanning is performed on the workstation. An exact-version OSV check may send package coordinates to the OSV service; the MCP server launched by the user may use its own network connections. Arc does not provide a packet-level egress policy. Users should review the selected MCP server's permissions and network behavior independently.

## Explicitly outside the Community Core scope

The Community Core does not promise enterprise fleet enrollment, remote policy management, centrally managed trust keys or sequence floors, SSO/RBAC, SIEM streaming, universal host coverage, full executable/publisher identity verification, package-install interception, an offline enterprise threat-intelligence service, endpoint sandboxing, or guaranteed prevention of arbitrary agent egress. These are separate future requirements and are not prerequisites for the documented local developer tool.

## Release maintenance for future artifacts

The following checks are maintainer practices for each future tagged artifact. This checklist does not mean the current Community Core release is conditional, and it is not evidence that a future artifact has passed; attach the actual CI/release evidence for each tag.

1. Run `cargo fmt --all -- --check`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and the repository's security/dependency checks on supported Windows, Linux, and macOS CI workers.
2. Exercise first-time hook install, status, uninstall/rollback, and a representative allow/deny event for each claimed host. Verify that malformed input or a missing executable does not corrupt user configuration or silently report protection as active.
3. Exercise the stdio broker with a pinned schema, an explicit TOFU session, a schema change, malformed JSON, child exit, and an unwrapped-server bypass. Label TOFU prominently as development-only.
4. Keep product, CLI, and release-note wording within this document's boundary. Do not claim complete Lethal Trifecta prevention, universal DLP, install-time package blocking, an OS sandbox, zero network egress, or a measured latency target without evidence.
5. Publish versioned artifacts with checksums, a release provenance/signing process, dependency inventory, upgrade/rollback steps, and a usable security disclosure channel.

## Decision rule

- **Community Core:** current free Apache-2.0 offer, within the exact scope above. A future tag's release status depends on its own attached validation evidence.
- **Team:** private Beta; cohort notice defines access, enabled capabilities, support, limits, and terms. No universal device cap, price, evaluation period, or SLA is published.
- **Enterprise:** future direction, not a generally available offer. Reassess after managed trust distribution, broader mediation, artifact identity, package enforcement/cache, containment, adversarial testing, and an operational pilot exist.
