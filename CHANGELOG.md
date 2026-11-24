# Changelog

All notable changes to **Vexa Arc** are documented in this file.

## [1.7.1] - 2026-11-24

### Security Patching & Full Multi-Engine CI Scan
- **Dependency Security Fixes (`Cargo.lock`):**
  - Updated `url` (`2.5.8` → `2.5.9`, resolving `RUSTSEC-2026-0592` / `GHSA-hrj5-67jp-wqp9`) and `rustix` (`1.1.5` → `1.1.6`, resolving `RUSTSEC-2026-0486` / `GHSA-jh2m-fhpj-3vr7`).
  - Synced `npm/package-lock.json` root version alignment with `npm/package.json` (`1.7.1`).
- **CI Security Workflow (`.github/workflows/vexa-sca.yml`):**
  - Enabled `--sast` and `--secrets` in `Vexa SCA Security Scan` so Code Security (SAST) and Secrets engines execute instead of being skipped.

## [1.7.0] - 2026-11-24

### Multi-Engine PR Security Matrix, License Exposure & Policy Fixture Reporting
- **Multi-Engine PR Security Matrix (`arc-cli`, `action.yml`, `.github/actions/comment-pr.js`):**
  - Upgraded `arc ci-report` Markdown rendering to a 7-column severity matrix (`Status | Scan Engine | Critical | High | Medium | Low | Total`) covering **Secret Detection (DLP)**, **Agent Prompt / Unicode Integrity**, **MCP Supply Chain & Pinning**, **Open Source Security (SCA)** (all 4 severities + reachable count), **Licenses**, and **Policy Fixtures**, with collapsible `<details>` sections, Markdown/HTML injection escaping (`escape_md_cell`), and a shift-left local onboarding CTA.
  - Added `--policy-test` flag to `arc ci-report` (and wired it in `action.yml` when `run-policy-test: 'true'`) so deterministic policy fixture results are included directly in the PR report matrix.
  - Hardened `.github/actions/comment-pr.js` with a 65,000-character truncation guard (`clampCommentBody`) for GitHub's PR comment API limit.
- **License Summary Surfacing & `vexa-sca` v1.8.0 Upgrade (`arc-firewall`, `Cargo.toml`):**
  - Added `ScaLicenseSummary` to `ScaAuditResult` and populated it directly from `vexa_sca::scan_project`'s `license_audit` instead of discarding it.
  - Upgraded `vexa-sca` and `vexa-core` dependencies to `v1.8.0` and updated `.github/workflows/vexa-sca.yml`, `README.md`, and `docs/user-guide.md`.

## [1.6.0] - 2026-11-24

### Automatic Cloud AI-BOM Sync, Fair Workstation Discovery & CLI Ergonomics
- **Automatic Zero-Code AI-BOM Sync on `arc audit` & `arc setup` (`arc-cli`):**
  - `arc audit` (both repository and `--workstation` modes) now automatically uploads a zero-code AI-BOM inventory snapshot to `POST /arc/inventory` when authenticated and not in offline mode (`ARC_OFFLINE=1`), with `--no-upload` to opt out and `--api-url` override. Sync is best-effort and non-fatal, prints a concise `Cloud Sync:` status line in terminal mode, and preserves pure JSON stdout under `--json`.
  - `arc setup` now uploads the initial AI-BOM / MCP inventory snapshot immediately alongside the workstation heartbeat so **MCP & AI-BOM** and **AI-BOM Anomalies** populate right after onboarding, and keeps `arc setup --token ... --json` stdout strictly valid JSON.
  - Upgraded `build_arc_inventory_payload` (shared across `arc audit`, `arc setup`, and `arc ci-report --upload`) to report full deduplicated `mcp_servers` (including `transport`, `risk_band`, `risk_score`, `pinned`, `schema_hash`), `agent_skills`, `model_assets`, and anomaly counts with zero raw secret or home-path egress.
- **Fair Per-Root Workstation Discovery & Actionable Reporting (`arc-discover`, `arc-cli`):**
  - Replaced the single shared workstation scan budget with a fair per-root budget (`2,500` files / `3s` per host root, `20s` overall cap) so a single noisy host directory can never starve later roots (such as `.gemini` or `.cline`).
  - Excluded legacy `.sca-cache/`, ephemeral IDE/plugin cache directories (`.tmp`, `tmp`, `CachedData`, `Code Cache`, `GPUCache`, `DawnGPUCache`, `DawnGraphiteCache`, `Crashpad`, `logs`, `blob_storage`, `Session Storage`, `IndexedDB`, `Local Storage`), and generated report artifacts (`sbom-cyclonedx.json`, `sca-report.{html,json,sarif}`, `ai-bom.json`, `vexa-ai-bom.json`) from secret scanning across Windows, macOS, and Linux.
  - Added capped (top 25 per section) discovered MCP server, agent skill, AI model, and exposed secret summaries to `arc audit --workstation` terminal output.
- **`arc intercept eval` Ergonomics & Cross-OS Stack Hardening (`arc-cli`):**
  - Added `--tool` (alias for `--kind`, normalizing `Bash`/`pwsh`/`powershell`/`sh`/`exec` → `shell`, `Read` → `file_read`, `Write`/`Edit` → `file_write`) and `--cmd` (alias for `--target`) to `arc intercept eval`.
  - Added `crates/arc-cli/build.rs` setting an 8 MiB stack on Windows MSVC (`/STACK:8388608`), Windows GNU (`-Wl,--stack,8388608`), and Linux musl (`-Wl,-z,stack-size=8388608`), matching macOS/Linux glibc defaults.

## [1.5.1] - 2026-11-24

### Zero-Prerequisite Native Sigstore Verification in `@vexasec/arc`
- **Built-in Offline Sigstore Bundle Verification (`npm/bin/arc.js`, `npm/lib/sigstore-trusted-root.json`):**
  - Added native Node.js Sigstore verification (`@sigstore/verify@^3.1.1`) against the bundled Sigstore Public Good trusted root so `npx @vexasec/arc@latest` works out of the box on clean Windows, macOS, and Linux machines without requiring `cosign`, authenticated `gh`, or a manually configured Ed25519 public key.
  - Supports both Cosign `sign-blob --bundle` legacy JSON bundles and Sigstore v0.1/v0.2/v0.3 bundles while strictly pinning the exact GitHub Actions release workflow + tag identity (`@refs/tags/<TAG>`) and OIDC issuer (`https://token.actions.githubusercontent.com`), remaining fail-closed on any signature, digest, or identity mismatch.
  - Updated `gh` fallback so unauthenticated `gh` falls through to built-in native Sigstore verification automatically.
- **CI & Release Gate Updates (`.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/actions/comment-pr.test.js`):**
  - Added regression tests for native Sigstore bundle verification, malformed bundle rejection, unauthenticated `gh` fallback, and bundled trusted root validation.
  - Updated `verify-release` cross-OS smoke tests to execute `npm/bin/arc.js --version` cold without `GH_TOKEN` to verify end-user zero-prerequisite Sigstore verification before publishing to npm.

## [1.5.0] - 2026-11-23

### Cross-OS User Cache Directories & `vexa-sca` v1.7.0 Integration
- **Eliminated Repo-Local `.sca-cache/` (`arc-firewall`, `arc-cli`, `vexa-sca` v1.7.0):**
  - Migrated all advisory, CISA KEV, EPSS, and registry metadata caches to OS-standard user cache directories (`~/.cache/vexa` on Linux/Unix, `~/Library/Caches/vexa` on macOS, `%LOCALAPPDATA%\vexa\cache` on Windows, with temp-dir fallback for minimal containers).
  - Added global `--cache-dir <PATH>` CLI flag and `VEXA_CACHE_DIR` environment variable override, propagated across both `arc-firewall` and `vexa-sca`.
  - Upgraded `vexa-sca` and `vexa-core` dependencies from `v1.5.0` to `v1.7.0`, eliminating all transitive `.sca-cache/` writes during OSV/KEV/EPSS scans.
  - Updated documentation (`README.md`, `COMPATIBILITY_MATRIX.md`, `docs/developer-guide.md`, `docs/user-guide.md`).

## [1.4.3] - 2026-11-23

### Installer Hardening, Release Verification & Hook Clarity
- **npm Launcher Rollback & Cache Integrity (`npm/bin/arc.js`):**
  - Wired `checkVersionRollback` into `ensureBinary()` using persisted highest-installed version state (`installed-version.txt` + cache scan) across Windows, macOS, and Linux; silent downgrades fail closed unless `ARC_ALLOW_DOWNGRADE=1`.
  - Added cached-binary SHA-256 sidecar verification (`<bin>.sha256`) re-checked on every cache hit; missing or tampered cache digests fail closed.
  - Updated `gh attestation verify` fallback so unauthenticated `gh` falls through to pinned Ed25519 verification when configured, while genuine attestation mismatches still fail closed immediately.
- **Cross-OS Release Smoke-Test Gate (`.github/workflows/release.yml`):**
  - Added `verify-release` (`ubuntu-latest`, `macos-latest`, `windows-latest`) running `npm/bin/arc.js --version` cold and cached against the live published GitHub Release before `publish-npm` executes, preventing npm/GitHub version drift.
- **Explicit Hook Lifecycle Allowlists (`arc-hooks`):**
  - Added explicit `IGNORED_LIFECYCLE_EVENTS` allowlists to `ClaudeCodeAdapter` and `CursorAdapter`, emitting a stderr diagnostic for unrecognized non-mediated event names while keeping malformed mediated payloads fail-closed.
- **macOS HTTP Proxy Rate-Limit Fix (`arc-hooks`):**
  - Fixed BSD `ECONNRESET` race when reading `429 Too Many Requests` status lines on macOS.
- **Documentation Sync (`README.md`, `npm/README.md`, `docs/user-guide.md`, `install.sh`, `install.ps1`):**
  - Documented mandatory fail-closed verifier prerequisites (`cosign`, authenticated `gh`, or pinned Ed25519 key), cached-binary integrity checks, and rollback override behavior consistently across all installers and guides.

## [1.4.2] - 2026-11-23

### Security & Trust-Plane Hardening (P0/P1)
- **Hardened HTTP MCP Proxy (`arc-hooks`, `arc-cli`):**
  - Enforced loopback-only binding by default (`127.0.0.0/8`, `::1`); hard-rejects `0.0.0.0`, `::`, LAN/public, and IPv4-mapped IPv6 addresses before socket bind unless `--allow-non-loopback`, `--auth-token` (`>= 16` chars, constant-time verified), and native `rustls` TLS (`--tls-cert` + `--tls-key`) are all configured.
  - Added `Host` and `Origin` validation (DNS rebinding / CSRF defense), header count/size bounds, configurable body/connection/rate limits, read/TLS/upstream timeouts, redacted error responses, and default `Strip` credential forwarding.
- **Anchored Policy Trust Root, Key Rotation & Revocation (`arc-policy-engine`, `arc-cli`):**
  - Removed server-supplied `trusted_key` trust substitution in `run_policy_sync`.
  - Added integrity-protected `PolicyTrustStore` (`state_sha256`, monotonic `min_sequence` and `rotation_sequence`, permanent `revoked_key_ids`, symlink-rejecting atomic writes) and domain-separated `KeyRotationEnvelope` (`VEXA-ARC-KEY-ROTATION-V1\0`).
  - Added `arc policy trust-init --root-key <id:hex>`, `arc policy rotate-key --envelope <file>`, and `arc setup --root-key <id:hex>` for one-command anchored workstation onboarding.
- **Mandatory Installer Verification & Immutable Releases (`install.sh`, `install.ps1`, `npm/bin/arc.js`, `release.yml`):**
  - Made publisher authenticity mandatory and fail-closed via tag-pinned Cosign (`@refs/tags/<TAG>`), `gh attestation verify`, or zero-dependency native Ed25519 verification (`ARC_RELEASE_PUBLIC_KEY_PEM`/`FILE`), with cross-OS POSIX `awk` / PowerShell / Node rollback protection.
  - Removed `overwrite: true` from `release.yml` for immutable releases.
- **Enriched Audit Telemetry & Metadata Cleanup (`arc-telemetry`, `SECURITY.md`, `COMPATIBILITY_MATRIX.md`, `docs/`):**
  - Added `actor`, `arc_version`, `policy_revision`, `policy_source`, `execution_status`, and `correlation_id` to runtime/cloud audit events and `policy_health` to workstation heartbeats.
  - Updated `SECURITY.md` supported versions (`1.4.x` / `1.3.x`), standardized reporting email to `contact@vexasec.io`, narrowed compatibility claims accurately, synced `docs/product-tiers.md`, and added cross-OS live-host verification harnesses (`scripts/verify-live-hosts.{ps1,sh}`).

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
