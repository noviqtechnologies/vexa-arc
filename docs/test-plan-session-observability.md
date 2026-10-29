# Test Plan: Pillar 2 — Local Observability & Exact Session Storage Resolution (`arc session`)

**Document Version:** 1.0.0  
**Target Release:** Community Tier (Local-First Developer Security)  
**Primary Modules Under Test:**
- [`crates/arc-policy-engine/src/taint_dag.rs`](file:///c:/vexa-arc/crates/arc-policy-engine/src/taint_dag.rs)
- [`crates/arc-policy-engine/src/lib.rs`](file:///c:/vexa-arc/crates/arc-policy-engine/src/lib.rs)
- [`crates/arc-cli/src/main.rs`](file:///c:/vexa-arc/crates/arc-cli/src/main.rs)
- [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs)

---

## 1. Executive Summary & Objective

The objective of **Pillar 2: Local Observability & Exact Session Storage Resolution** is to establish deterministic, transparent, and auditable local session storage and provenance tracking for autonomous AI agent sessions mediated by Arc.

Prior to this phase, session storage resolution and audit trail observability presented four operational challenges:
1. **Ambiguous Storage Paths:** Session storage location differed between temporary runs and project roots without an explicit resolution hierarchy or diagnostic tooling.
2. **Missing Operational Audit Logging:** Runtime policy decisions (`Allow`, `Deny`, `RequireApproval`), redaction obligation counts, and lethal trifecta risk indicators lacked a queryable, append-only local audit log.
3. **No CLI Session Surface:** Developers had no top-level CLI command to inspect session DAG nodes, review verdicts, audit trails, or query active storage paths.
4. **Unpruned Stale Sessions:** Expired session DAGs and associated audit records could accumulate on disk indefinitely if `expires_at_ms` TTL checks didn't account for user-requested maximum age thresholds.

This test plan defines the automated validation matrix ensuring that `arc session storage`, `arc session dag`, `arc session report`, and `arc session clean` strictly satisfy all security and observability invariants across **Windows**, **macOS**, and **Linux**.

---

## 2. Invariants Under Test

| Invariant | Description | Verification Method |
| :--- | :--- | :--- |
| **INV-SESS-01: Deterministic Storage Hierarchy** | Storage resolution strictly follows the 5-tier precedence order: CLI flag > `ARC_SESSION_DIR` > Project-Local flag (`.arc/sessions`) > Active CWD continuity (`.arc/sessions`) > OS User Data Dir (`%LOCALAPPDATA%\vexa-arc\sessions` on Windows, `$XDG_DATA_HOME/vexa-arc/sessions` or `~/Library/Application Support/vexa-arc/sessions` on macOS, `~/.local/share/vexa-arc/sessions` on Linux) > Temp fallback. | Integration test `TC-SESS-01` (`test_phase2_session_observability_and_storage_resolution_matrix`) |
| **INV-SESS-02: Cross-Platform File Sanitization** | Session identifiers containing dangerous characters (`:`, `/`, `\`, `*`, `?`, `"`, `<`, `>`, `|`) must be sanitized into safe disk filenames via `SessionTaintDag::safe_file_name`. | Unit tests in `taint_dag::tests` |
| **INV-SESS-03: Append-Only Operational Audit Log** | Every mediated runtime action (`intercept hook`, `intercept eval`, `protect stdio`) appends a single-line JSON record (`SessionAuditRecord`) to `<storage_dir>/<safe_session_id>.audit.jsonl` containing timestamp, event ID, action summary, verdict, lethal trifecta flag, and redaction count. | Integration test `TC-SESS-02` |
| **INV-SESS-04: Causal Provenance & DAG Integrity** | Causal DAG nodes (`CausalNode`) correctly track parent node IDs, event UUIDs, and introduced taint flags (`UntrustedInput`, `SensitiveData`, `ExfiltrationChannel`). | Integration test `TC-SESS-03` |
| **INV-SESS-05: Aggregate Session Reporting** | `arc session report` accurately computes aggregate statistics: total actions, allow/deny/approval counts, lethal trifecta triggers, redacted secrets, and unique sessions. | Integration test `TC-SESS-04` |
| **INV-SESS-06: Atomic Cleanup & Dual-Condition Pruning** | `arc session clean` and `cleanup_expired_sessions` prune both `.json` DAGs and associated `.audit.jsonl` files when either TTL is expired (`now > expires_at_ms`) OR elapsed age exceeds `max_age_ms`. | Integration test `TC-SESS-05` & Unit test `test_session_audit_record_lifecycle_and_pruning` |
| **INV-SESS-07: Fail-Closed Denial Semantics** | In `arc intercept eval`, when a security policy evaluates to `Deny` (e.g. Lethal Trifecta trigger), the CLI exits with non-zero exit code (1), writes the verdict JSON to stdout, and logs the denial in the session audit trail. | Integration test `TC-SESS-02` |

---

## 3. Phase 2 Acceptance Test Matrix

This matrix is executed automatically in [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs) (`test_phase2_session_observability_and_storage_resolution_matrix`):

### TC-SESS-01: Storage Resolution Precedence Verification
- **Preconditions:** Clean temporary workspace with and without `.arc/sessions` directories and `ARC_SESSION_DIR` environment variables.
- **Action:** Execute `arc session storage` under combinations of:
  1. Default mode in clean directory (resolves to OS user data directory).
  2. `--project-local` flag (resolves to `.arc/sessions` in workspace root).
  3. Pre-existing `.arc/sessions` directory in current working directory without flags (resolves via CWD continuity).
  4. Explicit `ARC_SESSION_DIR` environment variable override.
  5. Explicit `--session-dir` CLI override (highest priority).
- **Expected Outcome:**
  - `storage_dir` matches expected tier with exact resolution reason recorded.
  - `--json` output returns structured JSON matching `SessionStorageResolution`.

### TC-SESS-02: Runtime Action Audit Logging
- **Preconditions:** Active session initialized with `--session-id test-obs-sess-1` and `--session-dir <temp_dir>`.
- **Action:**
  1. Intercept `PreToolUse` bash command via `arc intercept hook`.
  2. Intercept safe file read via `arc intercept eval`.
  3. Intercept unsafe exfiltration command triggering Lethal Trifecta denial via `arc intercept eval`.
- **Expected Outcome:**
  - Audit log file `<temp_dir>/test-obs-sess-1.audit.jsonl` is created.
  - Exactly 3 valid JSON lines are recorded.
  - Line 1 records `Allow` verdict for hook execution.
  - Line 2 records `Allow` verdict for file read.
  - Line 3 records `Deny` verdict with `lethal_trifecta: true`.
  - Process exit code for denial evaluation is `1` (fail-closed).

### TC-SESS-03: Causal DAG Inspection (`arc session dag`)
- **Preconditions:** Recorded session with causal nodes and taint flow.
- **Action:** Run `arc session dag test-obs-sess-1 --session-dir <temp_dir>` and with `--json`.
- **Expected Outcome:**
  - Standard output prints session ID, active taint mask, and formatted causal history table.
  - `--json` outputs complete `SessionTaintDag` JSON with all causal nodes, timestamps, and taint transitions.

### TC-SESS-04: Session Operational Report (`arc session report`)
- **Preconditions:** Completed session with mixed verdicts and audit logs.
- **Action:** Run `arc session report test-obs-sess-1 --session-dir <temp_dir>` and `arc session report --all --session-dir <temp_dir> --json`.
- **Expected Outcome:**
  - Total actions equals 3.
  - Allowed actions equals 2.
  - Denied actions equals 1.
  - Lethal trifecta events equals 1.
  - JSON format outputs valid `SessionAuditSummary`.

### TC-SESS-05: Session Pruning & Audit Log Cleanup (`arc session clean`)
- **Preconditions:** Active session file and audit log with timestamp older than 0 hours.
- **Action:** Run `arc session clean --max-age-hours 0 --session-dir <temp_dir> --json`.
- **Expected Outcome:**
  - Both `test-obs-sess-1.json` and `test-obs-sess-1.audit.jsonl` are pruned from `<temp_dir>`.
  - JSON summary returns `{"removed_sessions": 1, ...}`.
  - Re-querying `arc session dag` confirms session no longer exists.

---

## 4. Execution Commands

### Unit Tests
```bash
cargo test -p arc-policy-engine taint_dag::tests
```

### Integration Test
```bash
cargo test --test integration_tests test_phase2_session_observability_and_storage_resolution_matrix
```

### Full Workspace Validation
```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```
