# Changelog

All notable changes to **Vexa Arc** are documented in this file.

## [1.4.1] - 2026-11-23

### Discovery Performance, Determinism & `arc init` UX
- **`.gitignore` / `.arcignore`-Aware Parallel Discovery (`arc-discover`):**
  - Upgraded `DiscoveryScanner` to use deterministic sorted `.gitignore` and `.arcignore` traversal (`ignore::WalkBuilder`) with cross-platform symlink and Windows NTFS reparse-point guards, OS-heavy directory exclusions, and multi-core file inspection via `std::thread::scope`.
  - Preserved security coverage for high-signal local files (`.env*`, IDE MCP configs, `.cursor/rules/*.mdc`, `CLAUDE.md`) even when listed in `.gitignore`, deduplicated and sorted deterministically.
  - Added `files_scanned` to `AuditReport` for transparent scan coverage reporting.
- **Deterministic & Idempotent `arc init` Baseline (`arc-cli`):**
  - Replaced flaky 5-second wall-clock quick-scan cutoffs with a deterministic sorted 5,000-file cap (and 30-second runaway safety guard) so repeated `arc init` runs report consistent finding counts.
  - Excluded Vexa Arc's own self-managed MCP entry (`vexa-arc`) and directive (`vexa-arc-security.mdc`) from the baseline `AI Assets` summary so first and subsequent `arc init` runs agree.
  - Formatted capped quick-scans unambiguously as `N+ finding(s)` with scanned file count, and added `files_scanned` to `arc init --json`.

## [1.4.0] - 2026-11-23

### Security & Runtime Fixes (P0)
- **Native Hook DLP Fail-Closed Enforcement (`arc-cli`):** Fixed a critical bypass in `run_intercept_hook` where `ARC-DLP-001` (`Verdict::Allow { obligations: [Obligation::Redact] }`) was skipped by `!verdict.is_allowed()`, silently allowing raw secrets in shell commands, MCP arguments, and prompts across all 5 host adapters. Native Pre-phase hooks now reliably fail closed (exit code 2 / deny) and emit `ARC-DLP-001` audit and cloud telemetry records.
- **Managed MCP Stdio Broker Reliability (`arc-hooks`):** Fixed two concurrency/lifecycle bugs in `McpStdioBroker::run_stdio`:
  - Added a `Condvar` synchronization barrier for in-flight `tools/list` exchanges so pipelined `tools/call` frames wait for trusted schema pin verification instead of racing into false `ARC-MCP-003` denials.
  - Fixed premature child termination on host stdin EOF: `run_stdio` now closes child stdin first and waits for the relay thread to drain all pending JSON-RPC responses (with a bounded 5s grace timeout) before terminating the child process tree, fixing silent empty exits under `--allow-tofu` and pipelined sessions across Windows, macOS, and Linux.

### Hardened Defaults & False-Positive Reduction (P1)
- **Standalone Sensitive Path (`ARC-FS-001`) & Destructive Command (`ARC-CMD-001`) Rules (`arc-policy-engine`, `arc-cli`):**
  - Added `protect_sensitive_paths` (`ARC-FS-001`) protecting `.env`, `.env.*`, `~/.ssh/*`, `~/.aws/*`, `*.pem`, `*.key`, and credential stores across Unix and Windows, and `protect_destructive_commands` (`ARC-CMD-001`, enabled by default) blocking `rm -rf`, `Remove-Item -Recurse -Force`, `rmdir /s /q`, `curl/wget/iwr | sh/bash/iex`, `git push --force`, `git reset --hard`, `git clean -fd`, `chmod 777`, and disk wipes.
  - Hardened `arc init` generated `.arc/policy.json` to enable `block_unapproved_mcp: true`, `protect_sensitive_paths: true`, `protect_destructive_commands: true`, and `require_approval_rules: ["ARC-MCP-001", "ARC-FS-001"]`, while including `vexa-arc` in `allowed_mcp_servers` and dynamically pinning `vexa-arc` in `.arc/mcp-pins.lock`.
- **`.env.example` & Benign File Taint Exclusion (`arc-policy-engine`):** Excluded environment template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults`, `.env.schema`) and public docs (`README.md`, `LICENSE`, `CHANGELOG.md`) from sensitive path classification and session taint, eliminating `ARC-LTT-001` false positives on example files.

### Consistency, Inventory & Cloud Telemetry Parity (P2)
- **Unified Secret Scanning & Zero-Allocation Prefilter (`arc-discover`, `arc-dlp`, `arc-cli`):**
  - Upgraded `DiscoveryScanner::inspect_file` to scan all non-binary repository files up to 2 MB so `arc audit`, `arc ci-report`, `arc scan-secrets`, and MCP `audit_ai_assets` / `scan_secrets` report identical secret findings.
  - Replaced per-file `to_ascii_lowercase()` heap allocations in `SecretScanEngine::scan` with a case-insensitive Aho-Corasick automaton.
  - Fixed `arc audit --json --output-bom` printing plain text to stdout before the JSON payload.
- **Claude Code `UserPromptSubmit` & Full 5-Host Inventory Parity (`arc-hooks`, `arc-cli`):**
  - Wired `UserPromptSubmit` installation, uninstallation, and decoding in `ClaudeCodeAdapter`.
  - Updated `arc mcp inventory` coverage contracts (`rollout.rs`) to accurately reflect `pre_and_post_hook` automatic installer parity for `windsurf`, `codex-cli`, and `gemini-cli`.
- **Heartbeat Policy Source Disambiguation (`arc-telemetry`, `arc-cli`):** Added `policy_source` and `signed_policy_synced` fields to `CloudArcHeartbeat` so Vexa Cloud Console can distinguish local `.arc/policy.json` enforcement at sequence 0 from synced signed organization policies.

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
