# Vexa Arc — Compatibility & Enforcement Matrix (v1.2.3)

This matrix reflects the verified capabilities in `crates/` for **Vexa Arc v1.2.3** across **Windows**, **macOS**, and **Linux**.

> [!IMPORTANT]
> **Enforcement Boundary:** Vexa Arc is **not** endpoint detection and response (EDR) or an OS-wide network firewall. Runtime enforcement applies **only** to configured host hooks and explicitly brokered MCP paths (`arc protect`). Unmanaged processes, direct shell/editor writes outside hooks, and unbrokered network requests are not intercepted.

---

## 1. Capability Matrix by Mode

| Capability | Command / Module | Supported Targets | OS Support | Status | Notes & Boundaries |
| --- | --- | --- | --- | --- | --- |
| **Workstation & Repo Audit / AI-BOM** | `arc audit [--workstation] [--output-bom ai-bom.json]` (`arc-discover`) | Local agent & MCP configs | Linux, macOS, Windows | **GA** | Read-only inventory & CycloneDX v1.6 AI-BOM export. Does **not** prove runtime enforcement. |
| **Native IDE Hooks (Auto-Install + Decode)** | `arc init`, `arc host install`, `arc intercept hook` (`claude_code.rs`, `cursor.rs`) | Claude Code, Cursor | Linux, macOS, Windows | **GA** | Installs `arc intercept hook --host <host>` into host config with backup & parse-error protection. |
| **Hook Payload Decoders (Decode-Only)** | `HostAdapter::decode` (`windsurf.rs`, `codex_cli.rs`, `gemini_cli.rs`) | Windsurf, Codex CLI, Gemini CLI | Linux, macOS, Windows | **Preview** | Payload decoders exist in `arc-hooks`; automatic `DEFAULT_HOOK_CMD` host install is not yet at parity with Claude Code / Cursor. |
| **Mediated MCP Broker (Stdio & HTTP/SSE)** | `arc protect stdio`, `arc protect http` (`broker.rs`, `http_proxy.rs`) | Explicitly wrapped MCP servers | Linux, macOS, Windows | **GA** | Computes RFC 8785 JCS `tools/list` schema pins (`--pin-schema` or signed org pin; `--allow-tofu` is dev/bootstrap only). |
| **Package Risk Lookup (`arc shield`)** | `arc shield check <pkg>` (`arc-firewall`) | npm, PyPI, Cargo, Go | Linux, macOS, Windows | **GA (Lookup Only)** | **Advisory check only** — does **not** intercept or execute package-manager installs. Use `vexa-sca` wrappers for pre-install blocking. |
| **Secret Scan & Vault Redaction** | `arc scan-secrets [--redact]` (`arc-dlp`) | Stdin, files, directories | Linux, macOS, Windows | **GA** | Local regex/entropy scan and `<ARC_VAULT_SECRET_XX>` pseudonymization. |
| **Adversarial Verification Suite** | `arc test [--json]` (`arc-cli`) | Built-in fixtures | Linux, macOS, Windows | **GA** | Runs 6 checks including `ClaudeCodeAdapter -> PolicyEvaluator` and pinned-schema `McpStdioBroker` quarantine. |
| **Vexa Console Sync** | `arc setup`, `arc policy sync`, `arc ci-report --upload` | `api.vexasec.io/sca/v1` | Linux, macOS, Windows | **Optional** | Off by default. Local CLI telemetry (`ARC_PILOT_TELEMETRY=local`) is disabled by default and restricted to loopback `127.0.0.1:39741`. |

---

## 2. Network & Offline Behavior

* **Default local commands (`audit`, `bom`, `scan-secrets`, `intercept`, `test`):** No cloud upload.
* **Package/advisory lookups (`arc shield`, `osv_scanner.rs`, `registry.rs`):** Query public OSV/EPSS and registry metadata APIs with a 24-hour `.sca-cache` fallback. Set `ARC_OFFLINE=1` or `VEXA_FIREWALL_OFFLINE=1` to disable live network lookups.
* **Cloud sync (`arc setup`, `arc policy sync`, `arc ci-report --upload`):** Opt-in only; sends secret-redacted posture/event metadata to the configured Vexa Console API.
