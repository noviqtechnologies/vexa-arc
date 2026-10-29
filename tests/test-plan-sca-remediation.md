# Test Plan: Pillar 4 — Consensual, Disposable-Worktree SCA Remediation (arc sca)

**Document Version:** 1.0.0  
**Target Release:** Community Tier (Local-First Developer Security)  
**Primary Modules Under Test:**
- [`crates/arc-firewall/src/remediation.rs`](file:///c:/vexa-arc/crates/arc-firewall/src/remediation.rs)
- [`crates/arc-cli/src/main.rs`](file:///c:/vexa-arc/crates/arc-cli/src/main.rs)
- [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs)

---

## 1. Executive Summary & Objective

The objective of **Pillar 4: Consensual, Disposable-Worktree SCA Remediation** is to provide enterprise-grade Software Composition Analysis (SCA) auditing and patch remediation that never contaminates active developer working trees, leaks confidential source snippets into SARIF reports, or causes Git branch collisions.

### Key Capabilities & Remediation Architecture
1. **Scoped SCA Audit with SARIF (`arc sca audit`):**
   - High-level project scanning powered by `vexa_sca::scan_project`.
   - Generates standard OASIS SARIF v2.1.0 reports via `vexa_sca::reporters::sarif::format_sarif_report`.
   - Supports confidential source-file pseudonymization via `--sanitize-locations` (SHA-256 URI scrub and code snippet omission).
   - Enforces policy gating via `--fail-on <severity>` (critical, high, medium, low).
2. **Dry-Run Scratch Diff (`arc sca fix --dry-run`):**
   - Creates an isolated scratch copy in OS temporary storage.
   - Copies manifest and lockfile context (including Cargo workspace skeletons).
   - Runs `vexa_sca::patcher::apply_fixes` in the scratch directory with `dry_run = false`.
   - Computes a non-destructive unified diff proposal without modifying a single byte in the working tree.
3. **Isolated Disposable Git Worktree (`arc sca fix --open-pr`):**
   - Distinguishes Git refs (`refs/remotes/origin/<base>`) from GitHub PR base branch names (`<base>`).
   - Fetches and validates remote refs.
   - Fails closed on divergence between local HEAD and remote origin unless explicitly overridden with `--force-remote-base`.
   - Spawns a detached worktree (`git worktree add --detach`) marked with `.arc-worktree-marker.json`.
   - Delegates branch creation, commit, push, and PR opening to `vexa_sca::patcher::PrCreator::create_and_open_pr`, eliminating duplicate branch creation errors.
   - Enforces best-effort RAII `Drop` cleanup and 5-point stale worktree safety pruning.
   - Executes opt-in build and test suites (`--run-tests`) inside the isolated worktree before pushing.

---

## 2. Invariants Under Test

| Invariant | Description | Verification Method |
| :--- | :--- | :--- |
| **INV-SCA-01: Scoped SCA Audit & Policy Gating** | `arc sca audit` runs manifest-specific scanning, detects vulnerabilities, and returns an exit code of 1 if the highest severity meets or exceeds `--fail-on <severity>`. | Integration test `TC-SCA-01` / `TC-SCA-02` |
| **INV-SCA-02: Confidentiality & SARIF Location Pseudonymization** | When `--sanitize-locations` is passed, SARIF report physical locations are stripped of call-site snippets, line numbers, and absolute file system paths. URIs are pseudonymized as `file:///arc-scrubbed-<sha256>`. | Integration test `TC-SCA-01` & Unit test `test_sarif_location_sanitization` |
| **INV-SCA-03: Working Tree Cleanliness on Dry-Run** | `arc sca fix --dry-run` performs scratch copy isolation in OS temp. The active developer working tree remains byte-for-byte unmodified with unchanged mtime. Scratch directories are guaranteed cleaned up. | Integration test `TC-SCA-03` |
| **INV-SCA-04: Remote Base Validation & Divergence Fail-Closed** | `arc sca fix --open-pr` checks divergence against `refs/remotes/origin/<base>`. If local unpushed commits exist, the tool fails closed with an actionable error. Passing `--force-remote-base` overrides local divergence. | Integration test `TC-SCA-04` |
| **INV-SCA-05: Disposable Detached Worktree & RAII Lifecycle** | The disposable worktree is spawned in detached HEAD mode with `.arc-worktree-marker.json` recording PID and target ref. On `Drop` or command completion, `git worktree remove --force` and directory deletion run immediately. | Integration test `TC-SCA-05` |
| **INV-SCA-06: 5-Point Stale Worktree Safety Pruning Contract** | Stale worktrees are only deleted if they satisfy all 5 checks: (1) Canonical containment in OS temp, (2) strict `arc-remediation-<uuid>` basename, (3) presence of `.git` and `.arc-worktree-marker.json`, (4) filesystem user ownership, and (5) PID liveness check proving creator process is dead. | Integration test `TC-SCA-06` & Unit test `test_stale_worktree_safety_pruning_contract` |

---

## 3. Acceptance Test Matrix

This matrix is executed automatically in [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs) (`test_phase4_disposable_worktree_sca_remediation_matrix`):

### TC-SCA-01: Scoped SCA Audit with SARIF and Location Sanitization
- **Preconditions:** A valid project directory with manifest (`Cargo.toml`) and OASIS SARIF v2.1.0 output containing file paths and source code snippets.
- **Action:** Run `run_sca_audit` with `sarif_out` and invoke `sanitize_sarif_locations`.
- **Expected Outcome:**
  - Scanned project generates valid SARIF report.
  - All usernames, internal repository paths, and source code snippets (`region.snippet`) are eliminated.
  - File locations are replaced with `file:///arc-scrubbed-<sha256>`.

### TC-SCA-02: Policy Failure Gating (`--fail-on`)
- **Preconditions:** Scanned project evaluated against threshold levels (critical, high, medium, low).
- **Action:** Run audit with `--fail-on high`.
- **Expected Outcome:**
  - If vulnerabilities meeting or exceeding the threshold exist, `should_fail == true` and non-zero exit code is produced.
  - If 0 vulnerabilities or vulnerabilities below threshold exist, `should_fail == false` and exit code is 0.

### TC-SCA-03: Dry-Run Scratch Diff Invariant (Working Tree Cleanliness)
- **Preconditions:** Active working tree with manifest file.
- **Action:** Record file contents and timestamps, then invoke `run_scratch_diff`.
- **Expected Outcome:**
  - Unified diff proposal is generated from isolated temporary copy.
  - Active working tree manifest remains 100% byte-identical with unchanged mtime.
  - Scratch folder in OS temp is cleanly deleted.

### TC-SCA-04: Remote Base Validation & Divergence Policy
- **Preconditions:** Git repository with a bare remote origin (`refs/remotes/origin/main`).
- **Action:**
  1. Synchronized state: Evaluate `check_remote_base_divergence(&repo, "main", false)`.
  2. Diverged state: Commit local change without pushing; re-evaluate.
  3. Forced state: Re-evaluate with `force_remote_base = true`.
- **Expected Outcome:**
  - Synchronized state returns `Ok(DivergenceCheckResult)` with `ahead_count == 0` and `behind_count == 0`.
  - Diverged state returns `Err(ScaRemediationError::DivergedFromRemote { base: "main", ahead: 1, behind: 0 })`.
  - Forced state returns `Ok(DivergenceCheckResult)` with `ahead_count == 1` and `forced_override == true`.

### TC-SCA-05: Detached Worktree Creation, Marker Metadata, and RAII Cleanup
- **Preconditions:** Git repository with remote tracking branch.
- **Action:**
  1. Spawn worktree via `DisposableWorktree::create(&repo, "refs/remotes/origin/main")`.
  2. Inspect worktree path, `.arc-worktree-marker.json`, and git status.
  3. Drop `DisposableWorktree` instance.
- **Expected Outcome:**
  - Worktree directory resides under `std::env::temp_dir()`.
  - `.arc-worktree-marker.json` contains current PID and canonical repo root hash.
  - Git status reports detached HEAD (no branch conflict with `PrCreator`).
  - Dropping the struct triggers automatic removal of the worktree directory and Git worktree metadata.

### TC-SCA-06: 5-Point Stale Worktree Safety Pruning Contract
- **Preconditions:** Stale worktree directory in OS temp with dead PID (`4999999`) and an invalid directory failing formatting criteria.
- **Action:** Invoke `prune_stale_remediation_worktrees(Some(&repo), 0)`.
- **Expected Outcome:**
  - Stale worktree satisfying all 5 safety rules is pruned (`pruned_directories >= 1`).
  - Directories failing naming format (`arc-remediation-invalid-uuid-format`) or missing markers remain completely untouched.

---

## 4. Test Execution Instructions

### Running the Phase 4 Integration Matrix
```bash
cargo test --test integration_tests test_phase4_disposable_worktree_sca_remediation_matrix
```

### Running Unit Tests in `arc-firewall`
```bash
cargo test -p arc-firewall test_
```

### Running the Full Workspace Suite
```bash
cargo test --workspace --locked
```
