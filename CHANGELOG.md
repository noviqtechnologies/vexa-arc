# Changelog

All notable changes to **Vexa Arc** are documented in this file.

## [1.3.0] - 2026-11-22

### Security & Correctness Fixes (P0)
- **Package Shield & MCP `check_package` OSV Parity (`arc-firewall`, `arc-cli`):** Fixed a `DepGraph` root-node collision in `OsvPackageScanner::scan_package` where the target package was set as `DepGraph::root_pkg` and filtered out by `DepGraph::get_all_pkgs()`, causing 0 OSV queries and false-clean `"permitted"` verdicts. Added a `scanned_packages_count == 0` fail-closed guard, unified JSON `"status": "blocked"` when OSV blocks, upgraded MCP `check_package` to use live registry + OSV checks matching `arc shield check`, added `advisory_source`/`queried_at`/`package_purl` fields, and wired OSV version checks into `arc shield run`.
- **Policy Precedence & Native Hook vs Direct CLI Parity (`arc-policy-engine`, `arc-cli`):** Fixed a policy-downgrade bug in `PolicyConfig::merge_lower_precedence` where `|=` allowed local `.arc/policy.json` (`require_approval_for_trifecta: true` from `arc init`) to downgrade an authoritative `SignedOrganization` `Enforce` policy (`require_approval_for_trifecta: false`) from `Verdict::Deny` into `Verdict::RequireApproval` (`permissionDecision: "ask"`). Updated `run_intercept_eval_with_opts` (`arc intercept eval/mcp/exec/read/prompt`) to load `PolicyConfig::try_load_with_precedence` instead of `PolicyEvaluator::default()`, ensuring native hooks and direct CLI evaluation always agree.
- **Verified SCA Remediation (`arc-firewall`, `arc-cli`):** `arc sca fix` now validates proposed target versions iteratively against OSV (advancing past still-vulnerable intermediate releases such as `lodash@4.18.0 -> 4.18.1`), regenerates lockfiles safely across Windows/macOS/Linux with `--ignore-scripts`, re-scans the patched dependency graph, exposes `verification_status` (`verified_clean` / `partial` / `unverified`), `lockfile_updated`, `remaining_findings_count`, and `remaining_advisories`, and refuses to open automated PRs when unresolved vulnerabilities remain.

### Operational & UX Improvements (P1)
- **Telemetry Visibility & Prompt Enforcement Flushing (`arc-telemetry`, `arc-cli`):** Reduced enforcement background-flush cooldown to 2 seconds so rapid native-hook and CLI enforcement events flush promptly to Vexa Console. Expanded `arc telemetry status` (text & `--json`) to report both Cloud Console sync state (`enrolled`, `queued_events`, `last_sync_at`, `spool_file`) and local UDP pilot collector state.
- **Causal Trace Auto-Discovery (`arc-cli`):** `arc trace latest` now auto-discovers the most recent session when `--session` is omitted (matching `arc session report`) instead of failing on a nonexistent `default-session`.
- **Host Adapter Parity (`arc-cli`, Docs):** Updated `arc host install|status|uninstall` help text, mediated/unmediated path reporting, and uninstall output to full parity across all 5 supported hosts (`claude-code`, `cursor`, `codex-cli`, `gemini-cli`, `windsurf`), and reconciled `COMPATIBILITY_MATRIX.md` and `docs/user-guide.md`.
- **Workstation Audit Clarity & `--output-bom` Fix (`arc-discover`, `arc-cli`):** Added `.codex`, `.gemini`, and `.cline` workstation roots; separated `not_installed_locations` (absent host directories) from `unscanned_locations` (budget/depth/permission skips); printed path breakdowns; and fixed `--workstation --output-bom` so CycloneDX 1.6 AI-BOM export is no longer skipped.
- **Explicit CI Gate Scope & `--fail-on-unpinned-mcp` (`arc-cli`, `action.yml`):** Added `--fail-on-unpinned-mcp` to `arc ci-report` and `fail-on-unpinned-mcp` to the GitHub Action, and added `checks_enforced` and `advisory_warnings` to JSON and Markdown reports.
- **Read-Only MCP Schema Pin Inspection (`arc-cli`):** Added `arc mcp inspect-schema --server <name> -- <cmd> [args...]` to compute canonical JCS SHA-256 schema pins without executing tools, and updated `SignedOrganization` missing-pin errors with the exact bootstrap command.

### Release Infrastructure (P2)
- Updated `.github/workflows/release.yml` to publish curated `CHANGELOG.md` notes on GitHub Releases.

## [1.2.5] - 2026-11-10
- MCP Safe Rollout (`observe` / `review` / `enforce`), fail-closed installers, GitHub Action input hardening, and initial signed-policy precedence checks.
