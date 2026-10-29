# Test Plan: Pillar 3 — Threat-Modeled Human Approval (Host Delegation & OS Modals)

**Document Version:** 1.0.0  
**Target Release:** Community Tier (Local-First Developer Security)  
**Primary Modules Under Test:**
- [`crates/arc-policy-engine/src/approval.rs`](file:///c:/vexa-arc/crates/arc-policy-engine/src/approval.rs)
- [`crates/arc-policy-engine/src/evaluator.rs`](file:///c:/vexa-arc/crates/arc-policy-engine/src/evaluator.rs)
- [`crates/arc-hooks/src/broker.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/broker.rs)
- [`crates/arc-hooks/src/claude_code.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/claude_code.rs)
- [`crates/arc-hooks/src/cursor.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/cursor.rs)
- [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs)

---

## 1. Executive Summary & Objective

The objective of **Pillar 3: Threat-Modeled Human Approval** is to provide rigorous, threat-modeled human authorization mechanisms for high-risk actions (such as potential Lethal Trifecta triggers or unapproved MCP tool servers).

### Threat Model & Boundaries
- **The Threat:** Checking for a TTY (`atty::is(Stream::Stdin)`) does **not** prove a human is present. Autonomous agents execute commands inside integrated terminal sessions and pseudo-terminals (PTYs). An agent with bash execution privileges can parse error messages, simulate TTY input, and invoke same-user CLI overrides.
- **In-Scope Threat:** Text-based and tool-calling agents interacting through standard chat, subprocess command execution, and stdin/stdout tool calls.
- **Host Approval Reliance (External Assumption):** Mapping `Verdict::RequireApproval` to host "ask" responses delegates enforcement to the host IDE's input dialog (Claude Code and Cursor). Under the assumption that the host IDE isolates its modal approval prompts from agent tool execution streams, the agent cannot self-approve.
- **Out-of-Scope Threat:** Computer-use agents or local processes possessing desktop screenshot capabilities, accessibility tree inspection (e.g. Windows UI Automation / `WM_GETTEXT`), mouse automation, or keyboard event injection.

---

## 2. Invariants Under Test

| Invariant | Description | Verification Method |
| :--- | :--- | :--- |
| **INV-APPR-01: Canonical Action Binding** | Approval grants are cryptographically bound to `SHA256(canonical_action_bytes || session_id || rule_id)`. `canonical_action_bytes` is computed using RFC 8785 JSON Canonicalization Scheme (JCS), ensuring key-order independence. | Integration test `TC-APPR-01` & Unit test `test_jcs_canonical_bytes_and_grant_key` |
| **INV-APPR-02: Atomic Single-Use Consumption** | Approval grants are stored in memory and consumed atomically on first match. Once consumed, the grant is removed immediately to strictly prevent replay attacks. | Integration test `TC-APPR-02` & Unit test `test_single_use_atomic_grant_consumption` |
| **INV-APPR-03: Host IDE Delegation (Primary Mechanism)** | When an action requires approval, host adapters encode `Verdict::RequireApproval` into the host's native interactive confirmation structure (`permissionDecision: "ask"` for Claude Code, `permission: "ask"` for Cursor) with exit code 0. | Integration test `TC-APPR-03` |
| **INV-APPR-04: Headless Preflight Fail-Closed** | For stdio / standalone broker sessions, if no interactive desktop session is available (e.g. CI, Docker, remote headless SSH) and no webhook is configured, Arc **fails closed immediately** with `Verdict::Deny` (`ARC-AUTH-HEADLESS-UNSUPPORTED`). | Integration test `TC-APPR-04` & Unit test `test_headless_environment_fails_closed` |
| **INV-APPR-05: CSPRNG 6-Digit PIN OS Modal** | For interactive desktop sessions, Arc spawns an isolated OS GUI modal detached from stdin/stderr with a 6-digit numeric PIN sampled via CSPRNG (~20 bits entropy). A matching PIN converts the verdict to `Allow` and forwards the action. | Integration test `TC-APPR-05` & Unit test `test_approval_manager_mock_valid_pin_flow` |
| **INV-APPR-06: 3-Attempt Rate Lockout** | If an incorrect PIN is entered 3 consecutive times, the action is denied with `ARC-AUTH-PIN-EXHAUSTED` and an active **15-minute rate-lockout** is instituted. Subsequent attempts within 15 minutes are denied immediately with `ARC-AUTH-LOCKED-OUT`. | Integration test `TC-APPR-06` & Unit test `test_rate_lockout_after_pin_exhaustion` |
| **INV-APPR-07: Rolling Rate-Limiting** | Prompts are throttled to at most 3 requests per rolling 60-second window. A 4th request within 60 seconds is immediately denied with `ARC-AUTH-RATE-LIMITED`. | Integration test `TC-APPR-07` & Unit test `test_rate_limiting_enforces_3_requests_per_minute` |

---

## 3. Acceptance Test Matrix

This matrix is executed automatically in [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs) (`test_phase3_threat_modeled_human_approval_matrix`):

### TC-APPR-01: Canonical Action Binding & RFC 8785 JCS Integrity
- **Preconditions:** JSON tool arguments with different key orderings (`{"b": 2, "a": 1}` vs `{"a": 1, "b": 2}`).
- **Action:** Compute canonical bytes, action hash, and grant key for both variations.
- **Expected Outcome:**
  - JCS canonical bytes are byte-for-byte identical.
  - Action hashes match.
  - Grant keys match.
  - Modifying `session_id` or `rule_id` produces strictly disjoint grant keys.

### TC-APPR-02: Single-Use Atomic Consumption Invariant
- **Preconditions:** An approval grant is issued for `(canonical_bytes, session_id, rule_id)`.
- **Action:**
  1. Call `check_and_consume_grant` on first evaluation.
  2. Call `check_and_consume_grant` on second evaluation with the identical parameters.
- **Expected Outcome:**
  - First call returns `true` (consumed).
  - Second call returns `false` (grant was deleted on first consumption).

### TC-APPR-03: Primary Mechanism (Host Delegation)
- **Preconditions:** `Verdict::RequireApproval` with rule `ARC-LTT-001`.
- **Action:** Encode verdict via `ClaudeCodeAdapter` and `CursorAdapter`.
- **Expected Outcome:**
  - Claude Code: `exit_code == 0`, stdout JSON contains `hookEventName: "PreToolUse"` and `permissionDecision: "ask"`.
  - Cursor: `exit_code == 0`, stdout JSON contains `permission: "ask"`, `user_message`, and `agent_message`.

### TC-APPR-04: Headless Preflight Fail-Closed
- **Preconditions:** Headless environment (`mock_interactive = false` or `ARC_HEADLESS=1`).
- **Action:** Broker receives unapproved tool call requiring authorization.
- **Expected Outcome:**
  - Broker responds locally with `ClientMessageOutcome::RespondLocally`.
  - Error JSON contains `ARC-AUTH-HEADLESS-UNSUPPORTED`.
  - Message is **never** forwarded to child process.

### TC-APPR-05: Out-of-Band OS Modal Approval with CSPRNG PIN
- **Preconditions:** Interactive desktop session with valid PIN entered in OS dialog.
- **Action:** Broker receives tool call requiring authorization.
- **Expected Outcome:**
  - `ApprovalManager` prompts OS modal.
  - Correct PIN validates successfully.
  - Action is converted to `Verdict::Allow` with `Obligation::ExceptionGranted`.
  - Broker forwards request to child process (`ClientMessageOutcome::Forward`).

### TC-APPR-06: 3-Attempt Rate Lockout
- **Preconditions:** Human enters wrong PIN 3 consecutive times.
- **Action:**
  1. Attempt approval with wrong PIN.
  2. Immediately re-attempt identical tool call.
- **Expected Outcome:**
  - First attempt fails with `ARC-AUTH-PIN-EXHAUSTED`.
  - Second attempt fails immediately with `ARC-AUTH-LOCKED-OUT` without spawning new dialogs.

### TC-APPR-07: Rolling Rate-Limiting (3/min)
- **Preconditions:** 3 approval prompts recorded within 15 seconds.
- **Action:** Submit 4th approval prompt within 20 seconds.
- **Expected Outcome:**
  - Check returns `Err(Verdict::Deny)` with rule `ARC-AUTH-RATE-LIMITED`.

---

## 4. Execution Commands

### Unit Tests
```bash
cargo test -p arc-policy-engine approval::tests
cargo test -p arc-hooks broker_human_approval
```

### Full Integration Matrix
```bash
cargo test --test integration_tests test_phase3_threat_modeled_human_approval_matrix
```

### Full Workspace Validation
```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```
