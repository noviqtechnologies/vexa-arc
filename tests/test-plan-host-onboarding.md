# Test Plan: Pillar 1 — Hardened Host Onboarding (`arc host install`)

**Document Version:** 1.0.0  
**Target Release:** Community Tier (Local-First Developer Security)  
**Primary Modules Under Test:**
- [`crates/arc-hooks/src/host_config.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/host_config.rs)
- [`crates/arc-hooks/src/claude_code.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/claude_code.rs)
- [`crates/arc-hooks/src/cursor.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/cursor.rs)
- [`crates/arc-hooks/src/lib.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/lib.rs)
- [`crates/arc-cli/src/main.rs`](file:///c:/vexa-arc/crates/arc-cli/src/main.rs)
- [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs)

---

## 1. Executive Summary & Objective

The objective of **Pillar 1: Hardened Host Onboarding** is to provide a deterministic, cross-platform, fail-closed mechanism for instrumenting developer AI host environments (Claude Code and Cursor IDE).

Prior to this hardening, host onboarding faced four operational vulnerabilities:
1. Subprocess command invocation failed when binary paths contained spaces or Windows extended-length UNC prefixes (`\\?\`).
2. Installation silently proceeded even if the binary was missing or lacked executable permissions.
3. Existing host configurations were modified without a byte-for-byte non-clobbering backup.
4. Malformed JSON (specifically a non-object `hooks` key) could cause undefined behavior or overwrite user settings.

This test plan defines the automated validation matrix ensuring that `arc host install`, `arc host status`, and `arc host uninstall` strictly satisfy all security invariants across **Windows**, **macOS**, and **Linux**.

---

## 2. Invariants Under Test

| Invariant | Description | Verification Method |
| :--- | :--- | :--- |
| **INV-HOST-01: Canonical Binary Resolution** | The installed command must use an absolute canonical path. On Windows, `\\?\` UNC prefixes must be stripped so IDE shell invocation does not fail. | Unit tests in `host_config::tests` + Integration matrix |
| **INV-HOST-02: Safe Shell Token Quoting** | Any path containing spaces (e.g. `/Users/jane doe/.cargo/bin/arc` or `C:\Program Files\Vexa\arc.exe`) or special characters must be enclosed in double quotes. | Unit test `test_host_install_path_with_spaces_and_special_chars` |
| **INV-HOST-03: Preflight Permission & File Verification** | The target executable must exist. On POSIX systems, `mode & 0o111 != 0` is required. If running from volatile/temp paths (`target/debug`), a visible warning is logged. | Unit tests `test_preflight_checks` |
| **INV-HOST-04: Non-Clobbering Byte Backup** | Before modifying any configuration, a pristine `<config>.arc.bak` file is written. If `<config>.arc.bak` already exists, it is **never** overwritten on subsequent installs. | Integration test `TC-HOST-03` |
| **INV-HOST-05: Structural Preservation** | All non-Arc keys, custom user hooks, and environment configurations must be preserved unaltered. | Integration test `TC-HOST-02` |
| **INV-HOST-06: Malformed Config Fail-Closed** | If a configuration has `"hooks": "string"` or `"hooks": []`, install must abort with `io::ErrorKind::InvalidData` and never corrupt the file. | Unit test `test_validate_hooks_object` + Integration test `TC-HOST-04` |
| **INV-HOST-07: Substring Independence** | Status checking (`is_arc_command`) must match the exact executable token rather than a naive substring, properly recognizing bare names, Windows `.exe`, and quoted paths. | Unit test `test_is_arc_command_quoted_and_spaces` |

---

## 3. Phase 1 Acceptance Test Matrix

This matrix is executed automatically in [`tests/integration_tests.rs`](file:///c:/vexa-arc/tests/integration_tests.rs#L1590) (`test_phase1_host_onboarding_hardening_matrix`):

### TC-HOST-01: Clean Installation & Path Normalization
- **Preconditions:** Clean temporary workspace without existing `.claude` or `.cursor` configuration directories.
- **Action:** Run `claude.install_integration(&dir)` and `cursor.install_integration(&dir)`.
- **Expected Outcome:**
  - Both `.claude/settings.json` and `.cursor/hooks.json` are created.
  - The hook commands resolve to the running executable path.
  - Windows extended UNC prefix (`\\?\`) is absent.
  - `adapter.status()` returns `is_installed: true`, `bypass_risk: None`.

### TC-HOST-02: Structural Preservation & Foreign Keys
- **Preconditions:** Pre-seed configuration files containing foreign properties:
  - Claude: `{"custom_user_setting": "preserve_me", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo foreign"}]}]}}`
  - Cursor: `{"foreign_editor_key": true, "version": 1, "hooks": {"beforeShellExecution": [{"command": "echo cursor foreign"}]}}`
- **Action:** Run `install_integration(&dir)` on both adapters.
- **Expected Outcome:**
  - `custom_user_setting` and `foreign_editor_key` remain present with original values.
  - Pre-existing foreign hooks remain intact alongside newly registered Arc hooks.

### TC-HOST-03: Configuration Backup & Invariance
- **Preconditions:** Host configuration files exist on disk with pre-install content.
- **Action:**
  1. Run `install_integration(&dir)`. Verify `.claude/settings.json.arc.bak` and `.cursor/hooks.json.arc.bak` exist and match pre-install contents byte-for-byte.
  2. Mutate active settings file.
  3. Run `install_integration(&dir)` a second time.
- **Expected Outcome:**
  - Backup files are **not** overwritten on the second run; they retain the initial pre-install configuration.

### TC-HOST-04: Malformed Configuration Rejection (Fail-Closed)
- **Preconditions:** Host configurations containing invalid `hooks` types:
  - Claude: `{"hooks": "invalid_string_instead_of_object"}`
  - Cursor: `{"version": 1, "hooks": ["invalid_array"]}`
- **Action:** Call `install_integration(&dir)`.
- **Expected Outcome:**
  - Both calls fail immediately with `std::io::ErrorKind::InvalidData`.
  - The malformed configuration files are untouched (not deleted or truncated).

### TC-HOST-05: Status & Clean Uninstallation
- **Preconditions:** Workspaces with installed Arc hooks.
- **Action:**
  1. Query `adapter.status()`.
  2. Call `adapter.uninstall(&dir)`.
  3. Query `adapter.status()` again.
- **Expected Outcome:**
  - Initial status: `is_installed: true`, `bypass_risk: None`.
  - After uninstall: `is_installed: false`. Foreign keys and foreign hooks remain intact.

---

## 4. Cross-Platform Unit Test Coverage

Located in [`crates/arc-hooks/src/host_config.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/host_config.rs):

| Unit Test | Target Verification |
| :--- | :--- |
| `test_clean_canonical_path_windows_prefix` | Strips `\\?\C:\path` and preserves POSIX `/path` |
| `test_format_hook_command` | Safely encloses paths with spaces in double quotes; passes plain paths cleanly |
| `test_is_arc_command_quoted_and_spaces` | Correctly identifies Arc commands with spaces (`"C:\Program Files\Vexa\arc.exe" intercept hook`) and bare commands |
| `test_validate_hooks_object` | Rejects string/array `hooks`, accepts valid object and absent `hooks` |
| `test_backup_existing_config` | Copies file to `.arc.bak` byte-for-byte; preserves existing backup on retry |
| `test_host_install_path_with_spaces_and_special_chars` | Simulates mock binary named `my arc tool v1.0.exe` in path with spaces; verifies command output and subsequent status detection |

---

## 5. Execution & Verification Commands

To run the complete suite across platforms:

```bash
# 1. Run all host onboarding unit tests:
cargo test -p arc-hooks --lib

# 2. Run the Phase 1 Integration Matrix:
cargo test --test integration_tests test_phase1_host_onboarding_hardening_matrix

# 3. Run the entire workspace test suite:
cargo test --workspace --locked
```
