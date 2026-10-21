# Vexa Arc Validation Report

**Repository:** `https://github.com/noviqtechnologies/vexa-arc`

**Revision validated:** `2f09414` (`v1.0.0`, `main`)

**Environment:** Windows desktop, `C:\vexa-arc`

**Validation date:** 2026-10-21

## Executive verdict

The core library behavior is promising and the existing positive-path test suite is green, but I would **not** call the product release-ready as a CI security gate yet. The main security flow works when given the expected URL/issue-shaped input, while several documented exit-code guarantees are false. The most important defect is that secret findings, invalid scan paths, and failed BOM writes return exit code `0`, which can silently pass CI.

No tracked source files were changed during validation.

## What passed

- The prebuilt Windows release binary `target/release/arc.exe` exists and runs.
- The newest compiled test artifacts report exactly **46 tests**, matching the README breakdown.
- The compiled integration suite ran **9/9 passing**.
- CLI help and `arc version` work.
- `arc shield check 'npm install reactt' --json` blocks the suspected typosquat and returns exit code `1`.
- `arc shield check react` permits the known package.
- Stdin secret detection and redaction work functionally: an AWS key was detected and replaced with `<ARC_VAULT_SECRET_01>`.
- BOM generation to a valid output path works and produces `CycloneDX`, spec version `1.6`, version `1`, with a UUID serial number.
- The documented lethal-trifecta sequence works when the prompt contains a recognizable external URL:
  1. read `.env`;
  2. ingest `https://github.com/...` prompt content;
  3. attempt `slack_post_message`.

  The final action returned `ARC-LTT-001` and exit code `1`.
- Dynamic schema rug-pull and unapproved-MCP behavior pass their existing integration tests.
- Formatting, Clippy, fresh compilation, and Cargo test commands could **not** be executed in this Windows session because neither `cargo` nor `rustc` was available on `PATH`. Existing compiled artifacts were used for runtime and test-binary validation instead.

## Blocking defects

### 1. Secret findings do not fail CI

**Severity: Critical for the documented CI use case**

The README promises:

- exit `0`: permitted / no policy violations;
- exit `1`: hard block, slopsquatting, or leaked secrets.

However, `run_scan_secrets` prints findings and returns normally. The observed command:

```powershell
'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' | .\target\release\arc.exe scan-secrets --redact
```

printed one detected secret but returned exit code `0`.

The same issue applies to file and directory scans: findings are reported, but the process does not call `exit(1)`.

**Fix:** make the command return a status (or call `std::process::exit(1)`) when `total_findings > 0`. Also return a nonzero status for read failures and missing paths. Add CLI integration tests that assert both output and exit status for stdin, file, and directory scans.

### 2. Invalid audit paths silently pass

**Severity: High**

This command returned exit code `0` and a low-risk empty report:

```powershell
.\target\release\arc.exe audit --path does-not-exist-dir --json
```

The scanner appears to convert an unreadable/nonexistent target into an empty report. That is dangerous in CI because a typo in the path can look like a clean audit.

**Fix:** validate the target path before scanning, emit a clear error, and return exit code `1` when it does not exist or cannot be read. Add tests for nonexistent files, nonexistent directories, and permission/read errors.

### 3. BOM export errors also return success

**Severity: High**

Both commands printed an error for an unwritable parent directory but returned `0`:

```powershell
.\target\release\arc.exe bom --out qa-no-such-dir\bom.json
.\target\release\arc.exe audit --output-bom qa-no-such-dir\bom.json --json
```

**Fix:** propagate file-write and serialization failures to the process exit status. Do not print a successful-looking report after a requested artifact export failed. Add tests for invalid parent directories and read-only destinations.

## Important security/design issues

### 4. Prompt tainting is overly heuristic and silently misses generic untrusted content

A prompt such as:

```text
content from an untrusted GitHub issue
```

did not add `UNTRUSTED_CONTENT`, so the subsequent Slack post was allowed. A URL-bearing prompt did add the taint and was blocked as expected.

This is internally consistent with the current classifier, which looks for `issue #`, `http://`, or `https://`, but it is weaker than the product wording (“ingests untrusted prompt or issue text”). A caller can pass externally sourced issue text without a URL and evade the intended flow control.

**Fix:** distinguish trusted local prompts from explicitly untrusted ingress at the event/API boundary. For MCP results, classify based on the server/tool and transport metadata rather than requiring magic substrings in content. For the CLI, provide an explicit `--untrusted`/source option or make `intercept prompt` conservatively taint by default, with a separate local/trusted command if needed.

### 5. Schema fingerprints are global to a `PolicyEvaluator`, not scoped to a session

`known_schemas` is a `HashMap<String, [u8; 32]>` keyed only by MCP server name. The documented behavior is “mid-session” rug-pull detection, but the implementation can compare a schema in one session against a prior schema observed in another session using the same server name.

This can produce false quarantines across independent sessions and makes session reset semantics incomplete.

**Fix:** key fingerprints by `(session_id, server_name)` or persist an explicit approved baseline with clear lifecycle semantics. Add a test proving that two independent sessions can establish different initial baselines without cross-contamination.

### 6. CLI intercept path cannot exercise schema rug-pull detection

The CLI’s `run_intercept_eval` constructs `ServerIdentity` with `schema_root: None` for MCP calls. Therefore, the CLI path advertised for runtime interception cannot supply a schema fingerprint and cannot trigger `ARC-RUG-001`; that capability is currently only reachable through library/API callers and tests.

**Fix:** accept a schema hash or canonical schema input in the hook/CLI protocol, or document that rug-pull protection is only available through the JSON-RPC adapter and ensure that adapter is actually wired into the executable integration path.

### 7. Runtime session files are stored relative to the current working directory

The CLI writes `.arc\sessions\<session>.json` under the process working directory. This is convenient for a project-local flow, but agent hooks often run from changing directories. A session can therefore be split across locations, or sensitive taint history can be written into an unintended project directory.

**Fix:** define and document the storage root explicitly. Prefer a caller-provided session directory or an OS-appropriate user data directory, with an opt-in project-local mode. Add tests invoking the binary from different working directories.

## Documentation and packaging feedback

- The README links to `LICENSE`, but no root `LICENSE` file was present in the checked-out workspace. Add the Apache-2.0 license file or remove the broken link before release.
- The README says “all 7 workspace crates,” but the test breakdown includes `arc-cli` plus six library crates, which is fine; the wording should be made precise because the root workspace has seven members and the integration test is attached to `arc-cli`.
- The “zero network egress” and performance claims are not established by this validation. The positive tests check one local scan duration, not a robust p99 benchmark or network-connection prohibition. Treat those as unverified claims until benchmark and egress tests exist.
- The current test suite is heavily positive-path oriented. It validates that expected detections work, but not that invalid inputs fail closed or that CI status codes are correct—the exact gap that allowed the defects above.

## Recommended implementation order

1. Fix exit-status propagation for secret findings, invalid paths, and failed exports.
2. Add CLI black-box tests that assert exit codes, not only output.
3. Add explicit untrusted-ingress semantics and broaden/replace substring-based prompt tainting.
4. Scope schema baselines correctly and expose schema metadata through the runtime hook path.
5. Define session storage semantics and test cross-working-directory behavior.
6. Add the missing `LICENSE` file and revise claims that are not backed by automated benchmarks.

## Final assessment

**Core engine:** good prototype quality; the taint-DAG, DLP, firewall, BOM, and JSON-RPC components have coherent positive-path behavior.

**CLI/CI product:** not safe to advertise as a fail-closed quality gate until the exit-code defects are fixed. A pipeline can currently pass while secrets were found or a requested audit/BOM path was invalid.

**Release recommendation:** hold the release for the blocking defects above. The fixes are localized and testable, but they should be implemented before relying on Vexa Arc to enforce security policy in CI or agent hooks.
