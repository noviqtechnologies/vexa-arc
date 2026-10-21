# Vexa Arc Developer Guide

Welcome to the **Vexa Arc (Agentic Runtime Control)** Developer Guide. This document provides technical architecture details, domain contracts, development workflows, and extension guidelines for engineers contributing to Vexa Arc.

---

## Table of Contents

1. [Architecture Principles & System Blueprint](#1-architecture-principles--system-blueprint)
2. [Workspace & Crate Hierarchy](#2-workspace--crate-hierarchy)
3. [Core Rust Contracts](#3-core-rust-contracts)
   - [Normalized Action Event (`arc-core::event`)](#normalized-action-event-arc-coreevent)
   - [Decision Verdicts & Explanations (`arc-core::verdict`)](#decision-verdicts--explanations-arc-coreverdict)
   - [Monotonic Taint Labels & Sinks (`arc-core::taint`)](#monotonic-taint-labels--sinks-arc-coretaint)
   - [3D MCP Risk Profiling & JCS Hashing (`arc-core::mcp_profile`)](#3d-mcp-risk-profiling--jcs-hashing-arc-coremcp_profile)
4. [DLP & Context Sanitization Engine (`arc-dlp`)](#4-dlp--context-sanitization-engine-arc-dlp)
   - [Multi-Stage Secret Detector](#multi-stage-secret-detector)
   - [Inbound Prompt Injection Sanitization & Nonce Delimitation](#inbound-prompt-injection-sanitization--nonce-delimitation)
   - [Local Pseudonymization Vault](#local-pseudonymization-vault)
5. [Stateful Session Taint DAG & Policy Engine (`arc-policy-engine`)](#5-stateful-session-taint-dag--policy-engine-arc-policy-engine)
6. [Asset Discovery & CycloneDX v1.6 AI-BOM (`arc-discover`)](#6-asset-discovery--cyclonedx-v16-ai-bom-arc-discover)
7. [Dependency Firewall & Compound Anti-Slopsquatting (`arc-firewall`)](#7-dependency-firewall--compound-anti-slopsquatting-arc-firewall)
8. [Host Adapters & MCP JSON-RPC Interceptors (`arc-hooks`)](#8-host-adapters--mcp-json-rpc-interceptors-arc-hooks)
9. [CLI Binary (`arc-cli`)](#9-cli-binary-arc-cli)
10. [Development, Testing & Extension Points](#10-development-testing--extension-points)
    - [Adding a New Secret Detector](#adding-a-new-secret-detector)
    - [Adding a New Package Ecosystem](#adding-a-new-package-ecosystem)
    - [Adding a New Host Adapter](#adding-a-new-host-adapter)
    - [Running Tests & Benchmarks](#running-tests--benchmarks)

---

## 1. Architecture Principles & System Blueprint

Vexa Arc operates under three core engineering invariants:
1. **The Pre-Execution Inversion:** Security enforcement must occur *pre-execution* on the developer endpoint and in CI, before malicious shell scripts or indirect prompt injections reach disk or execute.
2. **Sub-Millisecond Latency Budget:** All in-memory evaluations, regex prefiltering, and taint checking must meet $p_{99} < 3.5\text{ ms}$ budgets to guarantee zero perceived developer friction.
3. **Zero Network Egress Invariant:** All discovery, parsing, DLP pattern matching, and taint tracking occur entirely in-process without network transmissions.

```mermaid
flowchart TB
    HOST["Agent / IDE (Claude Code, Cursor, Windsurf)"] -->|"Hook / JSON-RPC"| HOOKS["arc-hooks"]
    HOOKS -->|"Normalized ActionEvent"| ENGINE["arc-policy-engine"]
    
    subgraph ENGINE_SUBSYSTEMS["Core Security Subsystems"]
        DAG["Stateful Taint DAG FSM"]
        DLP["arc-dlp (Secret & Injection Scan)"]
        FW["arc-firewall (Anti-Slopsquatting)"]
    end
    
    ENGINE --> DAG
    ENGINE --> DLP
    ENGINE --> FW
    
    ENGINE -->|"Verdict (Allow / Deny / Quarantine)"| HOOKS
    HOOKS -->|"JSON-RPC isError: true with self-explaining options"| HOST
```

---

## 2. Workspace & Crate Hierarchy

Vexa Arc follows strict downward dependency layering:

```mermaid
flowchart BT
    CORE["arc-core"]
    DLP["arc-dlp"]
    POLICY["arc-policy-engine"]
    DISCOVER["arc-discover"]
    FIREWALL["arc-firewall"]
    HOOKS["arc-hooks"]
    CLI["arc-cli"]

    DLP --> CORE
    POLICY --> CORE
    POLICY --> DLP
    DISCOVER --> CORE
    DISCOVER --> DLP
    FIREWALL --> CORE
    HOOKS --> CORE
    HOOKS --> POLICY
    CLI --> CORE
    CLI --> DLP
    CLI --> POLICY
    CLI --> DISCOVER
    CLI --> FIREWALL
    CLI --> HOOKS
```

* **`#![forbid(unsafe_code)]`** is enforced across domain logic crates.
* Libraries use **`thiserror`**; the CLI binary handles user-facing errors cleanly.

---

## 3. Core Rust Contracts

### Normalized Action Event (`arc-core::event`)

All host-specific payloads are normalized into a unified `ActionEvent`:

```rust
pub struct ActionEvent {
    pub event_id: Uuid,                // UUIDv7, time-ordered
    pub observed_at_unix_ms: u64,
    pub host: AgentHost,               // ClaudeCode, Cursor, Windsurf, etc.
    pub host_session_id: String,
    pub os_principal: OsPrincipal,     // Uid(u32) or Sid(String)
    pub phase: Phase,                  // Pre or Post
    pub action: Action,
}
```

Supported `Action` variants:
- `McpToolCall { server: ServerIdentity, tool: String, arguments: Value }`
- `McpToolResult { server: ServerIdentity, tool: String, content: String, is_error: bool }`
- `McpToolsList { server: ServerIdentity, tools_json: String }`
- `Shell { command: String, cwd: PathBuf }`
- `FileRead { path: PathBuf }`
- `FileWrite { path: PathBuf, new_content: Option<String> }`
- `PackageInstall { ecosystem: Ecosystem, name: String, version: Option<String> }`
- `PromptSubmit { text: String }`

### Decision Verdicts & Explanations (`arc-core::verdict`)

When an action is evaluated, Arc returns a `Verdict`:

```rust
pub enum Verdict {
    Allow { obligations: Vec<Obligation> },
    Deny { rule: RuleId, explanation: Explanation },
    RequireApproval { rule: RuleId, explanation: Explanation, timeout_secs: u32, on_timeout: TimeoutAction },
    Quarantine { rule: RuleId, explanation: Explanation },
}
```

An `Explanation` includes a one-sentence summary, 1 to 3 self-service options, and an optional policy URL:

```rust
pub struct Explanation {
    pub summary: String,
    pub options: Vec<String>,
    pub policy_url: Option<String>,
}
```

### Monotonic Taint Labels & Sinks (`arc-core::taint`)

In accordance with ADR-004, session taints are **strictly monotonic** and never cleared during an active session:

```rust
bitflags::bitflags! {
    pub struct Taint: u16 {
        const PRIVATE_DATA      = 1 << 0;
        const UNTRUSTED_CONTENT = 1 << 1;
        const SECRET_MATERIAL   = 1 << 2;
        const PRIVILEGED_DATA   = 1 << 3;
    }

    pub struct SinkClass: u16 {
        const EXTERNAL_EGRESS = 1 << 0;
        const PUBLISH         = 1 << 1;
        const DESTRUCTIVE     = 1 << 2;
        const CODE_EXECUTION  = 1 << 3;
    }
}
```

### 3D MCP Risk Profiling & JCS Hashing (`arc-core::mcp_profile`)

Quantifies the "Lethal Trifecta" dimensions ($0\text{--}1000$):
* `private_data_exposure`: local filesystem, database, or credentials access.
* `untrusted_content_ingest`: web crawl, issue/PR comment ingestion.
* `destructive_capabilities`: outbound network, file deletion, shell execution.
* `canonical_schema_hash`: RFC 8785 JSON Canonicalization Scheme (JCS) SHA-256 hash calculated over tool definitions to detect rug-pulls across restarts.

---

## 4. DLP & Context Sanitization Engine (`arc-dlp`)

### Multi-Stage Secret Detector

The detection engine combines:
1. **Aho-Corasick Multi-Pattern Prefilter:** Quickly identifies candidate keywords in linear time ($< 0.1\text{ ms}$):
   - AWS Access Key IDs (`AKIA`) and Session Keys (`ASIA`)
   - GitHub Personal Access Tokens (`ghp_`, `github_pat_`)
   - Anthropic API Keys (`sk-ant-api`) and OpenAI Keys (`sk-proj-`)
   - Slack Bot Tokens (`xoxb-`)
   - Cryptographic Private Keys (`-----BEGIN RSA/EC/OPENSSH/DSA PRIVATE KEY-----`)
   - JSON Web Tokens (`eyJ`)
   - Stripe Live Secret and Restricted Keys (`sk_live_`, `rk_live_`)
   - Google Cloud API Keys (`AIza`)
   - PyPI API Tokens (`pypi-`) and npm Access Tokens (`npm_`)
   - Database Connection Strings (`postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `redis://`)
2. **Linear-Time Anchored Regex:** Confirms structural token boundaries and format validation.
3. **Shannon & Normalized Entropy:** Ensures false-positive resistance ($H(X) \ge 4.2$, normalized entropy $H_{\text{norm}} \ge 0.85$).

### Inbound Prompt Injection Sanitization & Nonce Delimitation

* **Unicode Stripping:** Eliminates invisible Unicode tags (`U+E0000`..`U+E007F`), zero-width joiners/spaces (`U+200B`, `U+200C`, `U+200D`, `U+2060`, `U+FEFF`), Trojan Source bidi overrides (`U+202A`..`U+202E`, `U+2066`..`U+2069`), and variation selectors (`U+FE00`..`U+FE0F`, `U+E0100`..`U+E01EF`).
* **Cryptographic Spotlighting:** Encloses external content inside random 128-bit hex nonce boundaries (`<<<ARC_UNTRUSTED_CONTENT_<nonce> source="<source>">>>`), escaping nested occurrences.

### Local Pseudonymization Vault

Provides the `LocalPseudonymizationVault`:
* `redact_and_vault(session_id, raw_bytes, findings) -> (redacted_bytes, tokens)`
* Stores mappings in volatile memory (`<ARC_VAULT_SECRET_XX> -> raw_bytes`).
* `rehydrate(session_id, token, target_tool) -> Option<raw_bytes>` allows rehydration exclusively for explicitly authorized tools.

---

## 5. Stateful Session Taint DAG & Policy Engine (`arc-policy-engine`)

The policy engine tracks chronological agent interactions as a **Directed Acyclic Graph (DAG)** maintained in `SessionTaintDag` instances indexed by `session_id`.

### Policy Configuration & Custom Allow-Lists (`PolicyConfig`)

Projects can customize runtime governance by placing `.arc/policy.json` or `.arc.json` in their repository root:
```json
{
  "allowed_mcp_servers": ["github", "local-filesystem", "git", "sqlite"],
  "block_unapproved_mcp": false,
  "enforce_taint_dag": true,
  "redact_secrets": true
}
```
`PolicyConfig::load_from_dir(&Path)` automatically resolves project-level configurations, falling back to defaults if omitted.

### Why a Directed Acyclic Graph (DAG)?

* **Causality & Flow Modeling:** An agent's workflow consists of sequential context-building steps (e.g. `FileRead(.env)` $\to$ `IngestPrompt(web_url)` $\to$ `McpCall(slack)`). Modeling this as a directed graph ensures that policy enforcement preserves causal ancestry—Arc knows *which* prior events contributed to the current action request.
* **Strict Acyclicity:** Session time and state progression move monotonically forward. Because actions cannot alter past history, the graph is acyclic by design, preventing infinite traversal loops and guaranteeing deterministic, linear-time evaluation ($O(1)$ bitmask checks).
* **Monotonic Accumulation:** Taint labels are accumulated additively into a bitmask (`u16`). Once `PRIVATE_DATA` or `UNTRUSTED_CONTENT` is introduced into a session, the taint persists until the session is explicitly reset (`arc intercept session <id> --reset`).
* **Cross-OS Path Normalization:** Paths in `Action::FileRead` are normalized across backslashes (`\`) and forward slashes (`/`), ensuring secrets (`.env`, `.ssh/id_ed25519`, `.aws`) trigger `PRIVATE_DATA | SECRET_MATERIAL` identically across Windows, macOS, and Linux.

**Lethal Trifecta Condition:**
$$\text{SessionTaints} \supseteq (\text{PRIVATE\_DATA} \cup \text{UNTRUSTED\_CONTENT}) \quad \land \quad \text{SinkClass} \supseteq \text{EXTERNAL\_EGRESS}$$

When this invariant is triggered, `evaluator.evaluate()` immediately emits `RuleId("ARC-LTT-001")`.

---

## 6. Asset Discovery & CycloneDX v1.6 AI-BOM (`arc-discover`)

- `DiscoveryScanner::audit_directory(&Path) -> AuditReport`: Walks directory structures, parses `.cursor/mcp.json`, `.claude.json`, Claude Desktop configs, Windsurf configs, agent skills (`CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `.cursor/rules/*.mdc`, `.prompt.md`), and model checkpoints (`.gguf`, `.safetensors`, `.onnx`, `.pt`, `.bin`).
- `generate_cyclonedx_1_6_bom(&AuditReport) -> CycloneDxBom`: Serializes to official CycloneDX v1.6 specification with `machine-learning-model` components, `data` components for skills, and `services` for MCP servers.

---

## 7. Dependency Firewall & Compound Anti-Slopsquatting (`arc-firewall`)

The 4-gate compound scoring engine (`CompoundAntiSlopsquatEngine`):
1. **Dangerous Lifecycle Gate:** Blocks newly registered packages attempting execution in `preinstall`/`postinstall`/`setup.py`.
2. **Phantom Watchlist Gate:** Blocks packages on hallucination / recent 404 watchlists.
3. **Typosquat Gate:** Blocks packages with Levenshtein $\le 2$ or Jaro-Winkler $\ge 0.92$ against top popular packages.
4. **Provenance Gate:** Blocks packages lacking active repository history ($0$ stars, $0$ commits).

Package command interceptors (`PackageFirewall::parse_command`) support:
- `npm install`, `npm i`, `npm add`
- `pnpm add`, `pnpm install`
- `yarn add`
- `pip install`, `uv add`, `uv pip install`
- `python -m pip install`, `python3 -m pip install`
- `cargo add`
- `go get`

---

## 8. Host Adapters & MCP JSON-RPC Interceptors (`arc-hooks`)

- `ClaudeCodeAdapter`: Decodes Claude Code CLI hook inputs and formats exit code + stderr remediation narratives.
- `CursorAdapter`: Decodes Cursor PreToolUse shell and MCP events.
- `McpJsonRpcInterceptor`: Converts intercepted MCP requests into `ActionEvent` and formats denials as standard JSON-RPC 2.0 `isError: true` responses.

---

## 9. CLI Binary (`arc-cli`)

The root binary tying the subsystems together with `clap`.

### Command Invocations Across Operating Systems

| Command | Windows (PowerShell) | Linux / macOS (Bash/Zsh) |
| :--- | :--- | :--- |
| **Audit Workstation** | `PS C:\vexa-arc\target\release> .\arc.exe audit` | `arc audit` (or `./target/release/arc audit`) |
| **Export CycloneDX BOM** | `PS C:\vexa-arc\target\release> .\arc.exe bom --path . --out bom.json` | `arc bom --path . --out bom.json` |
| **Scan Directory Secrets** | `PS C:\vexa-arc\target\release> .\arc.exe scan-secrets --path .\src` | `arc scan-secrets --path ./src` |
| **Scan Piped Stdin** | `Get-Content log.txt \| .\arc.exe scan-secrets --redact` | `cat log.txt \| arc scan-secrets --redact` |
| **Shield Firewall** | `PS C:\vexa-arc\target\release> .\arc.exe shield reactt` | `arc shield reactt` |
| **Intercept Eval** | `PS C:\vexa-arc\target\release> .\arc.exe intercept eval .env --session s1` | `arc intercept eval .env --session s1` |
| **Inspect Session** | `PS C:\vexa-arc\target\release> .\arc.exe intercept session s1` | `arc intercept session s1` |

### Core CLI Capabilities:
* `arc audit`: Runs discovery of MCP servers, skills, and model checkpoints with optional CycloneDX v1.6 BOM export.
* `arc bom`: Exports CycloneDX v1.6 AI-BOM capturing all AI dependencies.
* `arc scan-secrets`: Runs deep DLP pattern and Shannon entropy analysis on target files, directory trees, or standard input streams:
  - **Directory Recursion:** Automatically traverses directory hierarchies (up to depth 10) and scans all contained files, filtering out build directories (`.git`, `target`, `node_modules`, `.venv`, `venv`).
  - **Single File & Stdin:** Reads from an explicit file path or pipes from standard input.
  - **Pseudonymization Vaulting:** Optional `--redact` flag replaces detected secrets with `<ARC_VAULT_SECRET_XX>` tokens and registers entries in the `LocalPseudonymizationVault`.
* `arc shield check`: Evaluates packages against compound 4-gate anti-slopsquatting rules with contextual remediation guidance, `--json` serialization for machine workflows, and standard exit status codes (`0` for pass, `1` for block).
* `arc intercept eval`: Evaluates actions through the monotonic Stateful Session Taint DAG.

---

## 10. Development, Testing & Extension Points

### Adding a New Secret Detector

1. Add target pattern keywords to `SecretScanEngine::new()` in [`crates/arc-dlp/src/detector.rs`](file:///c:/vexa-arc/crates/arc-dlp/src/detector.rs).
2. Define the linear-time regular expression and minimum entropy threshold.
3. Add a unit test covering happy path and edge cases.

### Adding a New Package Ecosystem

1. Add the ecosystem variant to `Ecosystem` in [`crates/arc-core/src/event.rs`](file:///c:/vexa-arc/crates/arc-core/src/event.rs).
2. Extend CLI command parsing in `PackageFirewall::parse_command()` in [`crates/arc-firewall/src/proxy.rs`](file:///c:/vexa-arc/crates/arc-firewall/src/proxy.rs).

### Adding a New Host Adapter

1. Implement the `HostAdapter` trait in [`crates/arc-hooks/src/adapter.rs`](file:///c:/vexa-arc/crates/arc-hooks/src/adapter.rs).
2. Define host-specific `decode()` and `encode()` methods.

### Building & Running Tests Across Operating Systems

#### Windows (PowerShell)
```powershell
# Build workspace in release mode
PS C:\vexa-arc> cargo build --release
PS C:\vexa-arc\target\release> .\arc.exe --version

# Run all unit tests across the 7 crates
PS C:\vexa-arc> cargo test --workspace

# Run integration tests specifically
PS C:\vexa-arc> cargo test --test integration_tests
```

#### Linux & macOS (Bash / Zsh)
```bash
# Build workspace in release mode
cargo build --release
./target/release/arc --version

# Run all unit tests across the 7 crates
cargo test --workspace

# Run integration tests specifically
cargo test --test integration_tests
```
