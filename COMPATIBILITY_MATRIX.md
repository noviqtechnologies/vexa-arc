# Vexa Arc — Compatibility & Enforcement Matrix (v1.4.0)

This matrix reflects the verified capabilities in `crates/` for **Vexa Arc v1.4.0** across **Windows**, **macOS**, and **Linux**.

> [!IMPORTANT]
> **Enforcement Boundary:** Vexa Arc is **not** endpoint detection and response (EDR) or an OS-wide network firewall. Runtime enforcement applies **only** to configured host hooks and explicitly brokered MCP paths (`arc protect`). Unmanaged processes, direct editor writes outside hooks, and unbrokered network requests are not intercepted.

---

## 1. Capability Matrix by Mode

| Capability | Command / Module | Supported Targets | OS Support | Status | Notes & Boundaries |
| --- | --- | --- | --- | --- | --- |
| **Workstation & Repo Audit / AI-BOM** | `arc audit [--workstation] [--output-bom ai-bom.json]` (`arc-discover`) | Local agent & MCP configs (`.claude`, `.cursor`, `.vscode`, `.windsurf`, `.codex`, `.gemini`, `.cline`) + all non-binary repo files (<=2 MB) | Linux, macOS, Windows | **GA** | Unified secret scanning matches `arc ci-report`, `arc scan-secrets`, and MCP `audit_ai_assets`/`scan_secrets`. Separates `not_installed_locations` from `unscanned_locations`; `--json --output-bom` emits pure JSON on stdout. |
| **Local MCP Inventory & Schema Inspect** | `arc mcp inventory`, `arc mcp inspect-schema --server <name> -- <cmd>` | Local MCP configs & stdio servers | Linux, macOS, Windows | **GA** | Read-only `initialize` + `tools/list` JCS SHA-256 fingerprint extraction. `arc init` dynamically pins `vexa-arc` in `.arc/mcp-pins.lock`. Coverage contracts reflect all 5 native host installers. |
| **MCP Safe Rollout Report & Staged Transition** | `arc mcp rollout [--stage observe\|review\|enforce] [--json]` (`rollout.rs`) | Mediated MCP sessions | Linux, macOS, Windows | **GA** | Summarizes `would_allow` / `would_deny` / `would_require_approval`, schema drift, and explicit `observe -> review -> enforce` transitions. |
| **Native IDE & CLI Hooks (Auto-Install + Decode)** | `arc init`, `arc host install\|status\|uninstall`, `arc intercept hook` | **Claude Code**, **Cursor**, **Codex CLI**, **Gemini CLI**, **Windsurf** | Linux, macOS, Windows | **GA** | All 5 adapters enforce fail-closed `ARC-DLP-001` secret blocking, `ARC-FS-001` sensitive path protection (excluding `.env.example`-style templates), `ARC-CMD-001` destructive command blocking, and `ARC-MCP-001` unapproved MCP checks under `arc init` defaults. **Cursor note:** ordinary editor file writes have no pre-write hook (`bypass_risk: true`). |
| **Mediated MCP Broker (Stdio & HTTP/SSE)** | `arc protect stdio [--observe]`, `arc protect http` (`broker.rs`, `http_proxy.rs`) | Explicitly wrapped MCP servers | Linux, macOS, Windows | **GA** | Supports `--observe`, `--pin-schema` (with `tools/list` synchronization barrier for pipelined clients), graceful EOF response draining, and `--allow-tofu` (rejected under `SignedOrganization`). |
| **Policy Engine & Precedence** | `arc intercept hook`, `arc intercept eval\|mcp\|exec\|read\|prompt` | `SignedOrganization` > `ProjectLocal` > `UserGlobal` | Linux, macOS, Windows | **GA** | Enforces `ARC-FS-001`, `ARC-CMD-001`, `ARC-DLP-001`, `ARC-MCP-001/003`, `ARC-LTT-001` (with `.env.example` template exclusion), `ARC-AST-001`, and `ARC-PKG-001`. `SignedOrganization` cannot be weakened by local policy. |
| **Package Shield & MCP `check_package`** | `arc shield check <pkg>`, `arc shield run <cmd>`, MCP `check_package` | npm, PyPI, Cargo, Go | Linux, macOS, Windows | **GA (Advisory / Lookup)** | Unified live registry + OSV/EPSS check matching `arc sca audit`. `arc shield run` is advisory-only (does not execute package managers). |
| **SCA Audit & Verified Remediation** | `arc sca audit`, `arc sca fix [--dry-run\|--open-pr]` | npm, yarn, pnpm, Cargo, Python | Linux, macOS, Windows | **GA** | `arc sca fix` refines target versions against OSV, regenerates lockfiles safely (`--ignore-scripts`), re-scans the patched graph, and blocks `--open-pr` if vulnerabilities remain. |
| **CI Security Gate** | `arc ci-report [--sca] [--fail-on <sev>] [--fail-on-unpinned-mcp]` | GitHub Actions (`action.yml`) & local CI | Linux, macOS, Windows | **GA** | Reports explicit `checks_enforced` and `advisory_warnings` alongside `passed`. Supports strict `--fail-on-unpinned-mcp` gating. |
| **Secret Scan & Vault Redaction** | `arc scan-secrets [--redact]` (`arc-dlp`) | Stdin, files, directories | Linux, macOS, Windows | **GA** | Local regex/entropy scan and `<ARC_VAULT_SECRET_XX>` pseudonymization. |
| **Causal Trace & Session Audit** | `arc trace latest`, `arc session report [--all]` | Local session storage | Linux, macOS, Windows | **GA** | `arc trace latest` auto-discovers the most recent session when `--session` is omitted. |
| **Vexa Console Sync & Telemetry Status** | `arc setup`, `arc policy sync`, `arc telemetry status\|flush` | `api.vexasec.io/sca/v1` | Linux, macOS, Windows | **Optional** | Heartbeats include `policy_source` and `signed_policy_synced` to distinguish local `.arc/policy.json` from synced signed org policies. `arc telemetry status` reports both Cloud Console spool and local UDP collector. |

---

## 2. Host Hook Coverage Summary

| Host | Mediated Surfaces | Known Unmediated / Bypass Surfaces |
| --- | --- | --- |
| **Claude Code** | `PreToolUse` (Bash, Read/Write/Edit, WebFetch, `mcp__*`), `PostToolUse` (WebFetch, WebSearch, `mcp__*`), `UserPromptSubmit` | Direct editor writes outside agent tools, unwrapped MCP servers, external terminal / direct network egress |
| **Cursor** | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `afterMCPExecution` | **Ordinary Cursor editor file writes (no pre-write hook)**, unwrapped MCP servers, external terminal / direct network egress |
| **Codex CLI** | `PreToolUse` (Bash, file read/write, MCP), `PostToolUse` | Unwrapped MCP servers, external terminal / direct network egress |
| **Gemini CLI** | `BeforeTool` (shell, file read/write, web fetch, MCP), `AfterTool` | Unwrapped MCP servers, external terminal / direct network egress |
| **Windsurf** | `pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use`, `post_mcp_tool_use` | Direct editor writes outside Cascade hooks, unwrapped MCP servers, external terminal / direct network egress |

---

## 3. Network & Offline Behavior

* **Default local commands (`audit`, `bom`, `mcp inventory`, `mcp rollout`, `policy test`, `policy simulate`, `scan-secrets`, `intercept`, `test`):** No cloud upload.
* **Package/advisory lookups (`arc shield`, `arc sca`, MCP `check_package`):** Query public OSV/EPSS (`api.osv.dev`) and package registries with a 24-hour `.sca-cache` fallback and explicit provenance reporting (`live`, `cache`, `heuristic_fallback`). Set `ARC_OFFLINE=1` or `VEXA_FIREWALL_OFFLINE=1` to disable live network lookups.
* **Cloud sync (`arc setup`, `arc policy sync`, `arc telemetry flush`, `arc ci-report --upload`):** Opt-in only; sends secret-redacted posture/event metadata to the configured Vexa Console API.
