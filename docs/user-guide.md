# Vexa Arc User Guide

Welcome to the **Vexa Arc (Agentic Runtime Control)** User Guide. This document provides step-by-step instructions for configuring, operating, and integrating Vexa Arc on developer workstations and in CI/CD environments.

---

## Table of Contents

1. [Overview & Key Concepts](#1-overview--key-concepts)
   - [Key Concepts & Acronym Glossary](#key-concepts--acronym-glossary)
2. [Installation & Setup](#2-installation--setup)
   - [Windows (x64 / ARM64)](#windows-x64--arm64)
   - [macOS (Apple Silicon & Intel)](#macos-apple-silicon--intel)
   - [Linux (x64 & ARM64)](#linux-x64--arm64)
3. [CLI Reference & Workflows](#3-cli-reference--workflows)
   - [`arc audit`: Zero-Touch AI & MCP Asset Discovery](#arc-audit-zero-touch-ai--mcp-asset-discovery)
   - [`arc bom`: CycloneDX v1.6 AI-BOM Generation](#arc-bom-cyclonedx-v16-ai-bom-generation)
   - [`arc scan-secrets`: Secret Detection & Pseudonymization Vault](#arc-scan-secrets-secret-detection--pseudonymization-vault)
   - [`arc shield`: Advisory Package Risk Checks](#arc-shield-advisory-package-risk-checks)
   - [`arc intercept eval`: Runtime Action & Taint Tracking (DAG)](#arc-intercept-eval-runtime-action--taint-tracking-dag)
   - [`arc session`: Local Observability & Exact Storage Resolution (Pillar 2)](#arc-session-local-observability--exact-storage-resolution-pillar-2)
   - [`arc sca`: Consensual, Disposable-Worktree SCA Remediation (Pillar 4)](#arc-sca-consensual-disposable-worktree-sca-remediation-pillar-4)
4. [Host Agent & IDE Integration](#4-host-agent--ide-integration)
   - [Claude Code Integration](#claude-code-integration)
   - [Cursor IDE Integration](#cursor-ide-integration)
   - [Generic Model Context Protocol (MCP) JSON-RPC](#generic-model-context-protocol-mcp-json-rpc)
5. [Threat-Modeled Human Approval (Pillar 3)](#5-threat-modeled-human-approval-pillar-3)
   - [Dual-Path Approval Architecture](#dual-path-approval-architecture)
   - [Desktop Preflight & Headless Fail-Closed Invariant](#desktop-preflight--headless-fail-closed-invariant)
   - [CSPRNG 6-Digit PIN & Anti-Fatigue Controls](#csprng-6-digit-pin--anti-fatigue-controls)
   - [RFC 8785 Canonical Binding & Single-Use Grants](#rfc-8785-canonical-binding--single-use-grants)
6. [Local Pilot Telemetry](#6-local-pilot-telemetry)
7. [Understanding Security Violations & Remediation](#7-understanding-security-violations--remediation)
   - [The "Lethal Trifecta" Invariant (`ARC-LTT-001`)](#the-lethal-trifecta-invariant-arc-ltt-001)
   - [Dynamic Schema Rug-Pull Quarantine (`ARC-RUG-001`)](#dynamic-schema-rug-pull-quarantine-arc-rug-001)
   - [Self-Explaining Error Contracts](#self-explaining-error-contracts)
8. [Local Pseudonymization Vault Lifecycle](#8-local-pseudonymization-vault-lifecycle)
9. [Frequently Asked Questions (FAQ)](#9-frequently-asked-questions-faq)

---

## 1. Overview & Key Concepts

**Vexa Arc** is an open-source Rust policy engine with selected Claude Code/Cursor hooks and an explicitly invoked MCP stdio broker. It evaluates configured actions before execution on those mediated paths; it does not govern all code, dependency, shell, or editor activity on the workstation:

* **Arc Intercept:** Evaluates agent tool calls in real time against a monotonic **Stateful Session Taint DAG** (Directed Acyclic Graph).
* **Arc Veil:** Provides targeted secret detection, DLP/redaction obligations on supported mediated paths, prompt-injection sanitization, and local vaulting (`<ARC_VAULT_SECRET_XX>`). Latency varies by input and host; no end-to-end sub-millisecond performance claim is validated here.
* **Arc Shield:** Evaluates package names and install commands against anti-slopsquatting compound heuristics and queries OSV for exact version coordinates.
* **Arc Atlas:** Discovers shadow MCP (Model Context Protocol) servers, agent instruction files, and model checkpoints, producing standardized CycloneDX v1.6 AI-BOM (AI Bill of Materials) artifacts.

> [!IMPORTANT]
> **Architectural Boundary:** Vexa Arc is an application-level pre-execution firewall at the agent host hook and MCP stdio boundary. It does not hook operating system system calls (it is not a kernel EDR), does not inspect network packets at the NIC layer (it is not a network egress firewall), and is not a centralized SaaS fleet management platform.

### Key Concepts & Acronym Glossary

To ensure clarity across security, DevOps, and AI development teams, the table below defines the core acronyms and domain concepts used throughout this documentation:

| Term / Acronym | Full Form | Meaning & Purpose in Vexa Arc |
| :--- | :--- | :--- |
| **DAG** | **D**irected **A**cyclic **G**raph | A mathematical graph that flows strictly forward in one direction with no circular loops. Arc uses a DAG to trace the chronological cause-and-effect chain of agent actions (e.g., Reading a File $\to$ Ingesting Untrusted Web Context $\to$ Invoking an External API) to detect dangerous action combinations. |
| **Taint Tracking** | Dynamic Taint Analysis | A security approach where sensitive data (e.g. `.env` files) or untrusted input (e.g. web pages, public pull request comments) tags the agent's active session with a persistent label ("taint"). Taints accumulate monotonically throughout the session to prevent confidential data from flowing into untrusted sinks. |
| **Lethal Trifecta** | — | A compound security state where an agent simultaneously has: (1) **Private Data Access** (e.g. `.env`, source code), (2) **Untrusted Context Ingestion** (e.g. prompt injection via web links or issue trackers), and (3) **External Egress / Destructive Capabilities** (e.g. sending outbound messages via Slack or executing arbitrary shell commands). When all three conditions align, prompt injection can lead to direct data exfiltration. |
| **MCP** | **M**odel **C**ontext **P**rotocol | An open standard created by Anthropic that standardizes how AI agents call external tools, read resources, and interface with developer tools via JSON-RPC. |
| **AI-BOM / SBOM** | (AI) **S**oftware **B**ill **o**f **M**aterials | An inventory manifest listing all components in a project. Arc generates official CycloneDX v1.6 AI-BOMs documenting AI models (`.gguf`, `.safetensors`), agent skill/rule files (`CLAUDE.md`, `.cursorrules`), and configured MCP tool servers. |
| **DLP** | **D**ata **L**oss **P**revention | Automated detection, redaction, and pseudonymization of confidential credentials (API keys, passwords, private keys) before they leave the developer endpoint or enter LLM prompts. |
| **Slopsquatting** | AI Hallucination Squatting | A supply-chain vulnerability where attackers register package names that generative AI models frequently hallucinate (or typosquat from real libraries) on registries like npm and PyPI, embedding malicious post-install lifecycle scripts. |
| **Dynamic Schema Rug-Pull** | — | A vulnerability where an MCP server or tool dynamically modifies its declared schemas, parameters, or descriptions after initial authorization to escalate privileges or bypass safety boundaries. |
| **JCS** | **J**SON **C**anonicalization **S**cheme (RFC 8785) | A deterministic serialization standard for JSON payloads. Arc calculates SHA-256 hashes of canonicalized tool schemas to verify tools have not mutated between sessions. |
| **Pre-Execution Firewall** | — | A host-level policy control that evaluates agent requests before process spawn or disk write, blocking policy violations and feeding structured error feedback back to the agent model for self-correction. |

---

## 2. Installation & Setup

### Prerequisites

* Rust 1.85+ toolchain installed via [rustup.rs](https://rustup.rs/) (if building from source).

### Windows (x64 / ARM64)

#### Option 1: Download Pre-Compiled Binary (GitHub Releases)
1. Download `arc-windows-x64.zip` from [GitHub Releases](https://github.com/noviqtechnologies/vexa-arc/releases).
2. Extract the archive into your target folder (e.g., `C:\vexa-arc\target\release` or `C:\tools\arc`).
3. Open PowerShell and run:

```powershell
PS C:\vexa-arc\target\release> .\arc.exe --version

# (Optional) Add to user PATH permanently:
[System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\vexa-arc\target\release", "User")

# Or add to current PowerShell session PATH:
$env:Path += ";C:\vexa-arc\target\release"

# Once in PATH, run directly from anywhere:
PS C:\> arc --version
```

#### Option 2: Build from Source
In PowerShell:

```powershell
git clone https://github.com/noviqtechnologies/vexa-arc.git
cd vexa-arc
cargo build --release

# Run the compiled binary:
PS C:\vexa-arc\target\release> .\arc.exe --version
```

### macOS (Apple Silicon & Intel)

#### Option 1: Download Pre-Compiled Binary (GitHub Releases)
In Terminal:

```bash
# Download Apple Silicon (arm64) or Intel (x64) release archive
curl -LO https://github.com/noviqtechnologies/vexa-arc/releases/latest/download/arc-macos-arm64.tar.gz
tar -xzf arc-macos-arm64.tar.gz
chmod +x arc
./arc --version

# (Optional) Install to system PATH
sudo mv arc /usr/local/bin/
arc --version
```

#### Option 2: Build from Source
```bash
git clone https://github.com/noviqtechnologies/vexa-arc.git
cd vexa-arc
cargo build --release

# Symlink to /usr/local/bin or ~/.cargo/bin
sudo cp target/release/arc /usr/local/bin/
arc --version
```

### Linux (x64 & ARM64)

#### Option 1: Download Pre-Compiled Binary (GitHub Releases)
```bash
curl -LO https://github.com/noviqtechnologies/vexa-arc/releases/latest/download/arc-linux-x64.tar.gz
tar -xzf arc-linux-x64.tar.gz
chmod +x arc
./arc --version

# (Optional) Install to system PATH
sudo mv arc /usr/local/bin/
arc --version
```

#### Option 2: Build from Source
```bash
git clone https://github.com/noviqtechnologies/vexa-arc.git
cd vexa-arc
cargo build --release

sudo cp target/release/arc /usr/local/bin/
arc --version
```

---

## 3. CLI Reference & Workflows

### `arc audit`: Zero-Touch AI & MCP Asset Discovery

Scans developer workstations and codebases in $< 1.2\text{ seconds}$ without modifying disk or transmitting data over the network:

**Windows (PowerShell):**
```powershell
# Audit the current repository and display a terminal summary
PS C:\vexa-arc\target\release> .\arc.exe audit

# Audit a specific directory path
PS C:\vexa-arc\target\release> .\arc.exe audit --path C:\projects\my-project

# Output machine-readable JSON for automated ingestion
PS C:\vexa-arc\target\release> .\arc.exe audit --json

# Run discovery and automatically export a CycloneDX v1.6 AI-BOM
PS C:\vexa-arc\target\release> .\arc.exe audit --output-bom cyclonedx-bom.json
```

**Linux / macOS (or when `arc` is in PATH):**
```bash
# Audit the current repository and display a terminal summary
arc audit

# Audit a specific directory path
arc audit --path /path/to/my-project

# Output machine-readable JSON for automated ingestion
arc audit --json

# Run discovery and automatically export a CycloneDX v1.6 AI-BOM
arc audit --output-bom cyclonedx-bom.json
```

**Example Output:**
```text
=======================================================
             VEXA ARC ZERO-TOUCH AUDIT REPORT           
=======================================================
Scanned Target:     C:\projects\core-service
Scan Duration:      34 ms (< 1200 ms latency target)
Total AI Assets:    5
Overall Risk Band:  Medium
-------------------------------------------------------

[1] Discovered MCP Servers (2):
  • github           [transport: stdio    risk: low      score: 180 ] (from: .cursor/mcp.json)
  • custom-db-tool   [transport: stdio    risk: high     score: 640 ] (from: .cursor/mcp.json)

[2] Agent Skills & Instruction Directives (2):
  • CLAUDE.md                (42 lines, sha256: 8a7f1e2b...)
  • .cursorrules             (98 lines, sha256: e419ca03...)

[3] AI Models & Local Checkpoints (1):
  • mistral-7b-q4.gguf       [format: gguf] (4369982464 bytes)

[4] Exposed Credentials & Secret Findings (0):
  (No exposed production credentials detected)
=======================================================
```

---

### `arc bom`: CycloneDX v1.6 AI-BOM Generation

Exports a valid CycloneDX v1.6 Bill of Materials capturing models, MCP services, and agent skills:

**Windows (PowerShell):**
```powershell
# Print CycloneDX v1.6 JSON to stdout
PS C:\vexa-arc\target\release> .\arc.exe bom

# Save directly to a file
PS C:\vexa-arc\target\release> .\arc.exe bom --path . --out sbom\cyclonedx-ai-bom.json
```

**Linux / macOS:**
```bash
# Print CycloneDX v1.6 JSON to stdout
arc bom

# Save directly to a file
arc bom --path . --out sbom/cyclonedx-ai-bom.json
```

---

### `arc scan-secrets`: Secret Detection & Pseudonymization Vault

Performs deep Data Loss Prevention (DLP) secret detection across entire directories, individual files, or piped standard input streams using 13 high-precision detectors and Shannon entropy verification:

**Windows (PowerShell):**
```powershell
# Recursively scan an entire directory or repository
PS C:\vexa-arc\target\release> .\arc.exe scan-secrets --path C:\projects\my-service
PS C:\vexa-arc\target\release> .\arc.exe scan-secrets --path .\src

# Scan an individual file
PS C:\vexa-arc\target\release> .\arc.exe scan-secrets --path .env.local

# Read from pipe/stdin and output redacted content with pseudonymization vault tokens
PS C:\vexa-arc\target\release> Get-Content server.log | .\arc.exe scan-secrets --redact
# Windows CMD: type server.log | .\arc.exe scan-secrets --redact

# Recursively scan a directory and register detected tokens in the pseudonymization vault
PS C:\vexa-arc\target\release> .\arc.exe scan-secrets --path .\config --redact
```

**Linux / macOS:**
```bash
# Recursively scan an entire directory or repository
arc scan-secrets --path ./src
arc scan-secrets --path /path/to/my-service

# Scan an individual file
arc scan-secrets --path .env.local

# Read from pipe/stdin and output redacted content with pseudonymization vault tokens
cat server.log | arc scan-secrets --redact

# Recursively scan a directory and register detected tokens in the pseudonymization vault
arc scan-secrets --path ./config --redact
```

> [!NOTE]
> **Directory Scanning Behavior:** When `--path` points to a directory, `arc scan-secrets` recursively traverses the directory tree (up to 10 levels deep) and scans every file, automatically skipping heavy source-control and build directories (`.git`, `target`, `node_modules`, `.venv`, `venv`).

**Example: Directory Scan Output:**
```text
• [SEC-AWS-001] in c:/projects/my-service\config\aws.yaml:124..144 Snippet: AKIA...MPLE
• [SEC-GTH-001] in c:/projects/my-service\scripts\deploy.sh:450..490 Snippet: ghp_...3456
• [SEC-PRV-001] in c:/projects/my-service\certs\server.key:0..87 Snippet: -----BEGIN PRIVATE KEY-----...
Scan complete: 3 secret(s) detected across 428 file(s)!
```

**Example: Single-File Scan with Redaction:**
```text
Scan complete: 1 secret(s) detected!
• Detector: SEC-AWS-001  Offset: 15..35 Snippet: AKIA...MPLE

--- Redacted Output (Vault tokens attached) ---
AWS_ACCESS_KEY_ID=<ARC_VAULT_SECRET_01>

Vault Tokens Registered (1):
  • Token: <ARC_VAULT_SECRET_01>    Detector: SEC-AWS-001
```

> [!TIP]
> **`arc scan-secrets` vs. `arc audit`:**
> * Use `arc audit` for fast (< 1.2s) high-level posture assessment across all AI assets (MCP servers, Agent skills/rules, Model checkpoints) and common configuration secret files.
> * Use `arc scan-secrets` when you need dedicated, exhaustive DLP inspection across every file in a directory tree or to pseudonymize streams with local vault tokens (`<ARC_VAULT_SECRET_XX>`).

---

### `arc shield`: Advisory Package Risk Checks (Not an Install Firewall)

Arc evaluates a package name or parsed package-manager command against a seeded popular-package heuristic. It does **not** intercept, execute, or prevent the install command. Age, download, and lifecycle-script values supplied as flags are simulation inputs, not live registry observations. An exact `name@version` passed to `arc shield check` may additionally be queried against OSV; that vulnerability query is not a malware verdict or proof that a package is safe. Treat these commands as advisory checks only and retain your existing registry, lockfile, and endpoint controls.

#### Windows (PowerShell):
```powershell
# Option 1: Bare package name (ecosystem auto-detected from project files or default npm)
PS C:\vexa-arc\target\release> .\arc.exe shield reactt

# Option 2: Scoped ecosystem prefix
PS C:\vexa-arc\target\release> .\arc.exe shield npm:reactt
PS C:\vexa-arc\target\release> .\arc.exe shield pypi:shadow-agent --dangerous-scripts
PS C:\vexa-arc\target\release> .\arc.exe shield go:github.com/gin-gonic/gin

# Option 3: Parse command text only; Arc does not run the install command
PS C:\vexa-arc\target\release> .\arc.exe shield npm install reactt
PS C:\vexa-arc\target\release> .\arc.exe shield pnpm add reactt
PS C:\vexa-arc\target\release> .\arc.exe shield pip install shadow-agent --dangerous-scripts
PS C:\vexa-arc\target\release> .\arc.exe shield python -m pip install shadow-agent
PS C:\vexa-arc\target\release> .\arc.exe shield cargo add tokio
PS C:\vexa-arc\target\release> .\arc.exe shield go get github.com/gin-gonic/gin

# Option 4: Explicit check subcommand (flags like --age-days and --downloads are optional)
PS C:\vexa-arc\target\release> .\arc.exe shield check reactt
PS C:\vexa-arc\target\release> .\arc.exe shield check reactt -e npm --json
```

#### Linux / macOS:
```bash
# Option 1: Bare package name (ecosystem auto-detected from project files or default npm)
arc shield reactt

# Option 2: Scoped ecosystem prefix
arc shield npm:reactt
arc shield pypi:shadow-agent --dangerous-scripts
arc shield go:github.com/gin-gonic/gin

# Option 3: Parse command text only; Arc does not run the install command
arc shield npm install reactt
arc shield pnpm add reactt
arc shield pip install shadow-agent --dangerous-scripts
arc shield python -m pip install shadow-agent
arc shield cargo add tokio
arc shield go get github.com/gin-gonic/gin

# Option 4: Explicit check subcommand (flags like --age-days and --downloads are optional)
arc shield check reactt
arc shield check reactt -e npm --json
```

The following are illustrative heuristic results, not live registry observations. Age/download values and lifecycle-script flags must be supplied by the caller; the CLI does not retrieve or verify them. A returned `PERMITTED` verdict is not a package safety attestation.

```bash
arc shield check reactt --ecosystem npm --age-days 2 --downloads 12
arc shield check pypi:shadow-agent --dangerous-scripts
```

**Illustrative Diagnostic Output (Typosquat / AI Hallucination):**
```text
┌────────────────────────────────────────────────────────┐
│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │
└────────────────────────────────────────────────────────┘
Package:            reactt (npm)
Simulation Inputs:  Age: 2 days | Monthly Downloads: 12
Dangerous Scripts:  false
----------------------------------------------------------
STATUS:             🛑 BLOCKED (HARD GATE REJECTION)
Triggered Gate:     CompoundTyposquatGate
Finding:            Package 'reactt' is a suspected hallucination/typosquat of 'react' (similarity: 0.97, edit_distance: 1, age: 2d, downloads: 12)

SUGGESTED ACTION:
  💡 Did you mean: 'react'? Run: npm install react
  ℹ️  If legitimate: verify package identity independently and use your approved dependency review process
──────────────────────────────────────────────────────────
```

**Diagnostic Output (Dangerous Lifecycle Scripts):**
```text
┌────────────────────────────────────────────────────────┐
│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │
└────────────────────────────────────────────────────────┘
Package:            shadow-agent (pypi)
Simulation Inputs:  Age: 1 days | Monthly Downloads: 0
Dangerous Scripts:  true
----------------------------------------------------------
STATUS:             🛑 BLOCKED (HARD GATE REJECTION)
Triggered Gate:     CompoundLifecycleGate
Finding:            New package 'shadow-agent' attempts arbitrary shell/network execution in install lifecycle scripts

SUGGESTED ACTION:
  ⚠️  Inspect package lifecycle scripts (preinstall/postinstall/setup.py). Run with --ignore-scripts if safe.
──────────────────────────────────────────────────────────
```

**Exit Codes:**
* `0`: The submitted advisory check returned a non-blocking verdict; this does not establish that the package is safe.
* `1`: The submitted check returned a blocking verdict (or, for a versioned OSV check, an incomplete/blocked scan). This exit code cannot stop a separate package-manager process unless your CI or wrapper explicitly enforces it.

#### OSV/EPSS Vulnerability Scanning (`ARC-SCA-001`) — FR-PKG-005 & FR-PKG-006

`arc shield check` can invoke the **vexa-sca** OSV scanner when given an exact package version. A bare package name or a command parsed by `arc shield run` is not an exact-version vulnerability scan. This query checks known vulnerability records; it does not establish that a package is benign or detect all malicious packages.

- Exact coordinates may be sent to the public OSV service; source code is not part of the query.
- A local `.sca-cache` is used, but the repository does not provide an enterprise-managed, pre-warmed air-gap cache process. An unavailable exact-version scan can be incomplete and may fail closed.
- EPSS, when returned by the SCA provider, is a prioritization signal for known vulnerabilities—not a typosquat or malware verdict.
- `--json` returns CLI JSON output; it is not a JSON-RPC agent remediation channel.

```bash
# Query OSV for an exact package version
arc shield check lodash@4.17.15 --ecosystem npm --json

# A name without a version is not an exact-version OSV scan
arc shield check lodash --ecosystem npm
```

> [!IMPORTANT]
> Exact-version OSV checks may return a blocked/incomplete result and exit non-zero. `arc shield` does not intercept installations; your CI must explicitly honor the result, and must define its own safe offline/cache policy.

---

### Code-Pattern Pre-Write Check (`ARC-AST-001`) — FR-CORE-006

For a `FileWrite` action that is actually submitted to `arc intercept eval` or another mediated pre-write hook, Arc runs `AstPatternEngine` before that mediated write proceeds. It uses Aho-Corasick prefiltering and targeted regexes; it does **not** parse an AST and only detects selected patterns. Cursor's configured hooks do not include a pre-file-write event, so direct Cursor editor writes and shell/script writes are not scanned by this hook. Do not treat this as a general file-write DLP control.

| Injection Category | Detection Pattern |
| :--- | :--- |
| Raw SQL interpolation | `SELECT/INSERT/UPDATE … ${user}` / Python f-string with table name |
| Direct eval/exec | `eval(…)` / `exec(…)` / `child_process.exec(req.param)` |
| Raw innerHTML | `element.innerHTML = untrustedVar` |
| Plaintext private keys | `-----BEGIN PRIVATE KEY-----` / `-----BEGIN RSA PRIVATE KEY-----` |

A blocked mediated write returns rule ID `ARC-AST-001` with a structured JSON-RPC error. Existing latency measurements apply to the scanner path only, not full editor-hook execution.

---

### Process Lifecycle Controls (`FR-HOOKS-003`)

When `arc protect stdio` launches an MCP server, it applies the listed process-lifecycle/resource controls before executing user code; these controls are not an OS sandbox:

| Platform | Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Windows** | `CreateProcess(CREATE_SUSPENDED)` + `AssignProcessToJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Eliminates launch race window; child and descendants terminate when Job handle closes. Supports `--max-memory-mb`. |
| **Linux** | `prctl(PR_SET_PDEATHSIG, SIGKILL)` in pre-exec + parent PID race verification + `setrlimit(RLIMIT_AS)` | Signals the direct child on parent death; process-group cleanup runs during supervisor teardown. Descendant survival after hard parent death is not guaranteed against. |
| **macOS/other Unix** | `setpgrp()` process-group isolation — `kill(-pgid, SIGKILL)` during supervisor teardown | Orderly teardown can kill the process group; hard-parent-crash, detached-child, and orphan behavior is not guaranteed. |

These mechanisms bound process lifecycle/resource use only. They do not sandbox syscalls, filesystem access, or network egress.

```bash
# Controlled enrollment only: independently verify the server artifact, then record the JCS hash printed to stderr
arc protect stdio --server github --allow-tofu -- npx @modelcontextprotocol/server-github

# Managed use: provision the reviewed hash under `mcp_schema_pins` in the verified
# `.arc/signed_policy.json`; the CLI pin may be omitted (if supplied, it must match)
arc protect stdio --server github --max-memory-mb 512 -- npx @modelcontextprotocol/server-github

# Standalone non-managed use: supply a reviewed pin directly
arc protect stdio --server github --pin-schema "$MCP_SCHEMA_SHA256" -- npx @modelcontextprotocol/server-github
```

---

### Field-Level & Path-Level Taint Isolation (`FR-TAINT-005`)

The Session Taint DAG tracks taint at **field granularity** and **path granularity**:

- Reading `.env.SECRET` taints that specific field, not the entire session.
- **Benign local commands** (`git status`, `git diff`, `git log`, `cargo test`, `npm test`, `pytest`) are whitelisted from blanket session taint and permitted in tainted sessions.
- **Compound command guard:** The benign exemption strictly requires atomic commands; command chaining, pipes, or shell redirection (`git status; curl ...`, `pytest | nc ...`) immediately void the exemption and are evaluated against full egress policy.
- The Lethal Trifecta check can target specific field/path combinations for surgical blocking.

```bash
# Benign command in a tainted session — permitted
arc intercept eval "git status" --session tainted-sess  # EXIT 0

# Outbound egress after .env read — blocked (Lethal Trifecta)
arc intercept eval slack/slack_post_message --session tainted-sess  # EXIT 1
```

---


### `arc intercept eval`: Runtime Action & Taint Tracking (DAG)

Simulates how Arc evaluates agent actions in the context of an ongoing session using monotonic on-disk persistence (`.arc/sessions/<session_id>.json`).

> [!NOTE]
> **What is a "Taint DAG"?**
> * **DAG (Directed Acyclic Graph):** An ordered graph that flows strictly forward in time without circular loops. Arc uses this graph model to trace causal dependencies between past actions (e.g., reading sensitive files or untrusted web pages) and requested actions (e.g., executing shell commands or sending network requests).
> * **Taint Propagation:** When an agent reads `.env`, Arc tags the session with `PRIVATE_DATA`. When it ingests external text from a website or pull request, Arc tags it with `UNTRUSTED_CONTENT`. If the agent subsequently attempts an outbound action (such as sending a Slack message), Arc recognizes that the session carries both sensitive data and untrusted instructions, automatically blocking the egress attempt under the **Lethal Trifecta** invariant (`ARC-LTT-001`).

**Windows (PowerShell):**
```powershell
# 1. Agent accesses a sensitive file (adds PRIVATE_DATA & SECRET_MATERIAL taints)
PS C:\vexa-arc\target\release> .\arc.exe intercept eval .env --session dev-sess
# Shorthand: .\arc.exe intercept read .env --session dev-sess
# Traditional: .\arc.exe intercept eval --session dev-sess --kind file_read --target .env

# 2. Agent ingests untrusted issue / web instructions (adds UNTRUSTED_CONTENT taint)
PS C:\vexa-arc\target\release> .\arc.exe intercept prompt "https://malicious.com/issue/42" --session dev-sess
# Traditional: .\arc.exe intercept eval --session dev-sess --kind prompt --target "https://malicious.com/issue/42"

# 3. Agent attempts outbound egress under Lethal Trifecta (Blocked with rule ARC-LTT-001)
PS C:\vexa-arc\target\release> .\arc.exe intercept eval slack/slack_post_message --session dev-sess
# Shorthand: .\arc.exe intercept mcp slack slack_post_message --session dev-sess
# Traditional: .\arc.exe intercept eval --session dev-sess --kind mcp_call --target slack_post_message --server slack

# Session Inspection & Management:
PS C:\vexa-arc\target\release> .\arc.exe intercept session dev-sess          # Inspect active taints & chronological history
PS C:\vexa-arc\target\release> .\arc.exe intercept session dev-sess --reset  # Reset session state
```

**Linux / macOS:**
```bash
# 1. Agent accesses a sensitive file (adds PRIVATE_DATA & SECRET_MATERIAL taints)
arc intercept eval .env --session dev-sess
# Shorthand: arc intercept read .env --session dev-sess
# Traditional: arc intercept eval --session dev-sess --kind file_read --target .env

# 2. Agent ingests untrusted issue / web instructions (adds UNTRUSTED_CONTENT taint)
arc intercept prompt "https://malicious.com/issue/42" --session dev-sess
# Traditional: arc intercept eval --session dev-sess --kind prompt --target "https://malicious.com/issue/42"

# 3. Agent attempts outbound egress under Lethal Trifecta (Blocked with rule ARC-LTT-001)
arc intercept eval slack/slack_post_message --session dev-sess
# Shorthand: arc intercept mcp slack slack_post_message --session dev-sess
# Traditional: arc intercept eval --session dev-sess --kind mcp_call --target slack_post_message --server slack

# Session Inspection & Management:
arc intercept session dev-sess          # Inspect active taints & chronological history
arc intercept session dev-sess --reset  # Reset session state
```

---

### `arc shield run`: Advisory Command Inspection (Not a Supervisor)

Parses package-manager command text and prints package verdicts. Arc does **not** launch or supervise a child process. `--show-recommendation` prints a proposed command variant (for example, with `--ignore-scripts` for selected npm-family cases); it does not execute or enforce that suggestion. `--fail-on-risk` returns a nonzero CI status for REVIEW or BLOCK, but still does not intercept or run an install. The result is heuristic and caller-supplied metadata is not registry-verified.

```bash
# Inspect command text only; this does not run npm:
arc shield run npm install express

# Print a proposed safer command only; this does not install the package:
arc shield run --show-recommendation -- npm install questionable-package

# Gate CI on review/block verdicts; this still only inspects the command:
arc shield run --fail-on-risk -- npm install questionable-package
```

---

### `arc audit --workstation`: Workstation AI-SPM Inventory (FR-DISC-002)

Discovers agent configurations, MCP configs, models, and rule files across workstation-level OS user roots:
- **Windows:** `%APPDATA%\Claude`, `%APPDATA%\Code\User`, `%USERPROFILE%\.cursor`, `%USERPROFILE%\.cline`
- **macOS:** `~/Library/Application Support/Claude`, `~/Library/Application Support/Cursor`, `~/.config`
- **Linux:** `~/.config/Claude`, `~/.config/Cursor`, `~/.cursor`, `~/.cline`

```bash
# Scan full workstation AI and MCP footprint:
arc audit --workstation

# Output structured JSON inventory:
arc audit --workstation --json
```

---

### `arc trace`: Causal Trace & Evidence Export (FR-CLI-004)

Inspects the causal data-flow ancestry of any event in the session Taint DAG and exports a tamper-evident redacted JSON evidence bundle:

```bash
# Inspect the most recent session event:
arc trace latest --session dev-sess

# Export redacted causal evidence to file:
arc trace latest --session dev-sess --export audit_evidence.json
```

---

### `arc doctor --metrics`: Diagnostics & Runtime Health (NFR-OPS-001)

Verifies toolchain installation, adapter availability, session storage permissions, host integrations, and reports cumulative policy decision metrics:

```bash
arc doctor --metrics
arc doctor --metrics --json
```

---

### `arc session`: Local Observability & Exact Storage Resolution (Pillar 2)

Vexa Arc provides local observability over agent causal data-flow DAGs, active taint states, and operational audit logs without transmitting sensitive telemetry off the developer machine.

#### Session Storage Resolution Hierarchy

Session state DAG files (`<session_id>.json`) and operational audit logs (`<session_id>.audit.jsonl`) are resolved using a deterministic hierarchy:

1. **CLI Argument Override:** `--session-dir <path>`
2. **Environment Variable Override:** `ARC_SESSION_DIR`
3. **Opt-in Project-Local Mode:** `--project-local` flag or `ARC_PROJECT_LOCAL=1` (resolves to `.arc/sessions` in CWD)
4. **Existing CWD Directory Continuity:** If `.arc/sessions` already exists in CWD and is writable, reuse it.
5. **OS User Data Directory (Default):**
   - **Windows:** `%LOCALAPPDATA%\vexa-arc\sessions` (fallback: `%USERPROFILE%\.arc\vexa-arc\sessions`)
   - **macOS:** `$XDG_DATA_HOME/vexa-arc/sessions` (if set) or `~/Library/Application Support/vexa-arc/sessions`
   - **Linux:** `$XDG_DATA_HOME/vexa-arc/sessions` (if set) or `~/.local/share/vexa-arc/sessions`
6. **System Temp Directory Fallback:** `%TEMP%\vexa-arc\sessions` or `/tmp/vexa-arc/sessions`

```bash
# Verify resolved storage directory, source rule, and write probe status:
arc session storage
arc session storage --json
```

#### Causal DAG Inspection (`arc session dag`)

Inspects causal graph ancestry, causal depth, tainted AST argument fields, file path taints, and pinned RFC 8785 JCS schemas directly from the resolved session store:

```bash
# Inspect the active DAG for the most recently modified session:
arc session dag --latest

# Inspect a specific session:
arc session dag my-session-id

# Output machine-readable JSON:
arc session dag my-session-id --json
```

#### Operational Audit Reporting (`arc session report`)

On each mediated agent tool execution or prompt ingestion, Arc appends a structured record to `<storage_dir>/<session_id>.audit.jsonl` recording event UUID, action/tool, verdict (`Allow`, `Deny`, `RequireApproval`, `Quarantine`), rule ID, and secret redaction count.

```bash
# Generate audit summary for the latest active session:
arc session report --latest

# Generate audit summary for a specific session:
arc session report my-session-id

# Aggregate audit metrics across all stored sessions in the directory:
arc session report --all
arc session report --all --json
```

#### Session & Audit Log Pruning (`arc session clean`)

Prunes session DAG files and associated `.audit.jsonl` logs older than the expiration threshold:

```bash
# Prune expired sessions older than 24 hours (default):
arc session clean

# Prune sessions older than custom threshold (e.g. 1 hour):
arc session clean --max-age-hours 1 --json
```

---

### `arc sca`: Consensual, Disposable-Worktree SCA Remediation (Pillar 4)

Vexa Arc provides consensual, non-contaminating Software Composition Analysis (SCA) auditing and patch remediation powered by `vexa-sca`. It scans dependencies across supported package managers (`Cargo.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `go.sum`, `pom.xml`) and generates isolated fixes without altering the developer's working tree.

#### Scoped SCA Audit with SARIF (`arc sca audit`)

Scan dependencies for known vulnerabilities and generate standard OASIS SARIF v2.1.0 reports:

```bash
# Audit project dependencies:
arc sca audit

# Generate SARIF report with location sanitization:
arc sca audit --sarif audit.sarif --sanitize-locations

# Enforce policy failure gating (returns exit code 1 if critical/high vulnerabilities exist):
arc sca audit --fail-on high
```

* **Confidentiality & Location Sanitization (`--sanitize-locations`):** Eliminates internal file paths, suppresses physical line/column numbers, strips vulnerable code snippets (`region.snippet`), and pseudonymizes physical URIs into deterministic SHA-256 hashes (`sanitized/<hash>.source`).
* **Policy Failure Gating (`--fail-on <severity>`):** Gates CI/CD and terminal workflows by exiting with status code 1 if the highest detected vulnerability meets or exceeds the threshold (`critical`, `high`, `medium`, `low`).

#### Dry-Run Scratch Diff Proposal (`arc sca fix --dry-run`)

Inspect proposed manifest updates non-destructively:

```bash
# Propose unified diff fixes in isolated OS temporary storage:
arc sca fix --dry-run
```

* **Working Tree Cleanliness Invariant:** Copies manifest and lockfile context into an isolated scratch directory inside OS temp storage (`%TEMP%` or `/tmp`), including Cargo workspace skeleton files.
* Applies candidate version upgrades within the scratch directory.
* Outputs a standard unified diff proposal to terminal stdout.
* Guarantees zero writes or file timestamp modifications in the active developer working directory.

#### Isolated Disposable Git Worktree (`arc sca fix --open-pr`)

Remediate vulnerabilities by creating a single-purpose Pull Request from a dedicated, detached Git worktree:

```bash
# Create automated PR against origin/main using an isolated worktree:
arc sca fix --open-pr --base main

# Enforce remote base ref when local branch has unpushed commits:
arc sca fix --open-pr --base main --force-remote-base

# Execute project test suites in the worktree prior to pushing:
arc sca fix --open-pr --base main --run-tests
```

* **Remote Base Validation & Divergence Policy:** Distinguishes Git tracking refs (`refs/remotes/origin/<base>`) from GitHub PR base branch names (`<base>`). Evaluates local HEAD divergence and fails closed by default if unpushed commits exist, preventing accidental leakage of unrelated work.
* **Detached Head Worktree:** Spawns a dedicated worktree (`git worktree add --detach`) in OS temp storage marked with `.arc-worktree-marker.json`.
* **Conflict-Free PR Creation:** Leaves branch creation, commit, push, and PR opening to `vexa_sca::patcher::PrCreator`, preventing duplicate branch creation errors.
* **5-Point Stale Worktree Safety Pruning:** Cleans up worktrees immediately via RAII `Drop`. Abandoned worktrees are only pruned if they pass a strict 5-point safety contract:
  1. *Canonical Temp Containment:* Path resides strictly within `temp_dir().canonicalize()`.
  2. *Strict Basename Format:* Folder name conforms to `arc-remediation-<valid-uuid>`.
  3. *Marker & Git Integrity:* Contains valid `.git` reference and `.arc-worktree-marker.json`.
  4. *Filesystem Ownership:* Folder is owned by the current user.
  5. *PID Liveness Check:* Creator process is verified dead (inactive) via platform process queries.

---

## 4. Host Agent & IDE Integration (FR-MCP-005)

Vexa Arc provides native host adapter integrations for **Claude Code** and **Cursor IDE** with automated installation, health verification, and bypass detection.

### Automated Host Installation

Instead of editing JSON configuration files manually, Arc automates installation and configuration via `arc host`:

```bash
# 1. Install Arc protection into Claude Code:
arc host install --host claude-code

# 2. Install Arc protection into Cursor IDE:
arc host install --host cursor

# 3. Target a specific workspace root:
arc host install --host claude-code --workspace /path/to/project
```

#### Hardened Host Onboarding Guarantees

When running `arc host install`, Arc enforces the following hardened safety invariants across Windows, macOS, and Linux:

1. **Canonical Binary Resolution & Safe Quoting:**
   - Arc automatically determines the exact absolute path to its own binary (`std::env::current_exe()?.canonicalize()`).
   - On Windows, extended-length UNC prefixes (`\\?\`) are stripped so shell and IDE subprocesses can execute without path syntax errors.
   - Paths containing spaces (e.g. `C:\Users\Jane Doe\.cargo\bin\arc.exe` or `/Users/jane doe/.cargo/bin/arc`) or special characters are safely escaped and wrapped in quotes in the resulting hook command strings.

2. **Preflight Environment Verification:**
   - **Existence & Permission Check:** Verifies that the resolved binary exists on disk and, on POSIX platforms, that the binary has executable permission bits (`mode & 0o111 != 0`).
   - **Volatile Directory Detection:** If `arc host install` is run from a temporary directory or an ephemeral build directory (e.g. `target/debug` or `target/release`), Arc emits a visible warning recommending that the binary be placed in a persistent `PATH` location (such as `~/.cargo/bin` or `%USERPROFILE%\.cargo\bin`).

3. **Automatic Byte-for-Byte Backup (`.arc.bak`):**
   - Before modifying any host configuration, Arc creates a byte-for-byte backup of the existing file:
     - Claude Code: `<workspace>/.claude/settings.json.arc.bak`
     - Cursor IDE: `<workspace>/.cursor/hooks.json.arc.bak`
   - If an `.arc.bak` backup file already exists from a previous installation, it is **never overwritten**, guaranteeing that the user's pristine, pre-Arc configuration is preserved indefinitely.

4. **Safe Structural JSON Merging & Preservation:**
   - Arc parses existing host configuration files and preserves all existing foreign settings (e.g. custom user hooks, env vars, permissions, MCP server registrations).
   - If a host configuration contains a `hooks` key that is not a JSON object (for example, a malformed string or array), Arc **fails closed** with an `InvalidData` error and refuses to clobber the configuration, outputting clear guidance on resolving the syntax issue.

#### Manual Configuration Recovery

If you ever need to restore your editor configuration to its pre-Arc state:

1. Verify the backup file exists (`.claude/settings.json.arc.bak` or `.cursor/hooks.json.arc.bak`).
2. Copy the `.arc.bak` file over the target configuration file:
   - **Linux / macOS:** `cp .claude/settings.json.arc.bak .claude/settings.json`
   - **Windows:** `Copy-Item .claude\settings.json.arc.bak -Destination .claude\settings.json -Force`
3. Alternatively, run `arc host uninstall --host <claude-code|cursor>` to safely remove Arc hook registrations while retaining all other settings.

### Bypass Detection & Status Verification

Arc verifies whether host configurations invoke the runtime proxy wrapper or if users/scripts have bypassed protection:

```bash
# Inspect integration health and bypass risk:
arc host status --host claude-code
arc host status --host cursor --json

# Run holistic platform diagnostics across all host adapters:
arc doctor --metrics
```

### Clean Host Uninstallation

To restore original host configurations cleanly:

```bash
arc host uninstall --host claude-code
arc host uninstall --host cursor
```

### Manual Configuration Reference
 
 If manual configuration is preferred:
 
- **Claude Code (`.claude/settings.json`):**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "arc intercept hook --host claude-code"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "arc intercept hook --host claude-code"
          }
        ]
      }
    ]
  }
}
```

- **Cursor IDE (`.cursor/hooks.json`):**
```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "arc intercept hook --host cursor",
        "failClosed": true
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "arc intercept hook --host cursor",
        "failClosed": true
      }
    ],
    "beforeReadFile": [
      {
        "command": "arc intercept hook --host cursor",
        "failClosed": true
      }
    ],
    "afterMCPExecution": [
      {
        "command": "arc intercept hook --host cursor"
      }
    ]
  }
}
```

> [!TIP]
> **Native Stdin Intercept Hook (`arc intercept hook`):**
> Claude Code and Cursor communicate directly with `arc intercept hook --host <claude-code|cursor>` over standard I/O using their native hook schemas. Any execution error or malformed payload exits with code `2`, safely failing closed to prevent unauthorized actions.

### Editors Without Native Hook APIs (Windsurf, Cline)

Some AI coding environments (e.g. Windsurf, Cline) do not currently provide documented pre-execution hook APIs for intercepting internal editor commands, file reads, or shell tasks before they execute.

In these environments:
- **MCP Brokering (`arc protect stdio`):** An explicitly launched stdio server can be wrapped via `arc protect stdio --server <NAME> -- <COMMAND>`. The CLI obtains managed pins from verified `.arc/signed_policy.json`; outside managed policy, supply `--pin-schema <HASH>`. `--allow-tofu` is development/bootstrap only and is rejected when signed organization policy is active. This wrapper does not stop users/agents from launching an unwrapped server or using another transport. It redacts supported secrets, ingests results into the taint tracker, and applies process-lifecycle/memory controls; these do not sandbox filesystem access or network egress.
- **Direct Editor Terminal / File Writes:** Cursor's installed hooks mediate selected shell, MCP, and read events, but there is no configured pre-file-write event; direct editor writes bypass ARC-AST-001 and file-write DLP. Writes through scripts/processes also exceed the scanner's mediated `FileWrite` path. Windsurf and Cline have no native adapters here; only MCP traffic explicitly wrapped by `arc protect stdio` is mediated.

### Generic Model Context Protocol (MCP) JSON-RPC

For custom MCP client setups, configure Arc as a loopback stdio proxy:

**Windows:**
```json
{
  "mcpServers": {
    "protected-github": {
      "command": "arc.exe",
      "args": ["protect", "stdio", "--server", "github", "--", "npx.cmd", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

**Linux / macOS:**
```json
{
  "mcpServers": {
    "protected-github": {
      "command": "arc",
      "args": ["intercept", "stdio", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

---

## 5. Threat-Modeled Human Approval (Pillar 3)

Vexa Arc implements a threat-modeled human authorization framework designed to handle high-risk agent operations—such as external egress under Lethal Trifecta taint combinations, execution of unvetted MCP tools, or destruction of local state—without introducing automation bypasses or authorization token leakage.

### Dual-Path Approval Architecture

Vexa Arc separates human authorization into two distinct operational paths based on the host runtime model:

```mermaid
flowchart TD
    ACTION["Agent Tool Call / Evaluated Action"] --> EVAL["PolicyEvaluator::evaluate()"]
    EVAL -->|"Verdict::RequireApproval"| DISPATCH{"Mediated Runtime Path?"}
    
    subgraph PRIMARY_PATH["Primary Path: Host IDE Delegation"]
        DISPATCH -->|"Claude Code Hook"| CC["Claude Code Native Ask Dialog"]
        DISPATCH -->|"Cursor Hook"| CURSOR["Cursor IDE Permission Prompt"]
        CC -->|"User Decides"| HOST_RESP["User Confirms / Rejects in IDE UI"]
        CURSOR -->|"User Decides"| HOST_RESP
    end
    
    subgraph SECONDARY_PATH["Secondary Path: Out-of-Band OS Modal"]
        DISPATCH -->|"arc protect stdio Broker"| PREFLIGHT{"Preflight Desktop Check"}
        PREFLIGHT -->|"Headless / CI / SSH"| FAIL_CLOSED["Fail Closed (ARC-AUTH-HEADLESS-UNSUPPORTED)"]
        PREFLIGHT -->|"Interactive Desktop"| RATE{"Rate Limit <= 3/60s?"}
        RATE -->|"Exceeded"| RATE_ERR["Reject (ARC-AUTH-RATE-LIMITED)"]
        RATE -->|"Permitted"| LOCK{"Locked Out?"}
        LOCK -->|"Yes (15m window)"| LOCK_ERR["Reject (ARC-AUTH-LOCKED-OUT)"]
        LOCK -->|"No"| CSPRNG["Generate 6-Digit CSPRNG PIN"]
        CSPRNG --> DETACHED["Spawn Detached Platform OS Modal"]
        DETACHED --> PIN_VALIDATE{"PIN Matched? (Max 3 Tries)"}
        PIN_VALIDATE -->|"3 Failed Tries"| EXHAUST["Lockout 15m (ARC-AUTH-PIN-EXHAUSTED)"]
        PIN_VALIDATE -->|"Correct PIN"| ISSUE_GRANT["Issue RFC 8785 Bound Single-Use Grant"]
    end
```

#### 1. Primary Mechanism: Host IDE Delegation
For native IDE integrations (Claude Code and Cursor), Arc returns a `Verdict::RequireApproval`. The native host adapters (`arc-hooks`) translate this directly into the host's supported approval channels:
* **Claude Code:** Returns `"ask"` in hook output JSON, prompting the developer within the terminal UI.
* **Cursor IDE:** Returns `permission: "ask"` in hook output JSON, triggering Cursor's native UI permission prompt.

#### 2. Secondary Mechanism: Out-of-Band OS Confirmation Modals
For standalone MCP proxy brokering (`arc protect stdio`), the child MCP server communicates over standard I/O streams (`stdin`/`stdout`). If an agent attempts an action requiring human approval, asking in the stdio stream would allow a compromised LLM to self-approve its own requests. Arc solves this by invoking an out-of-band OS confirmation dialog directly on the user's interactive desktop.

---

### Desktop Preflight & Headless Fail-Closed Invariant

Before attempting to render any GUI confirmation modal, Arc executes a strict platform preflight check (`DesktopSessionPreflight`) to ensure an active human desktop session exists:

| Operating System | Detection Mechanism | Failure Condition |
| :--- | :--- | :--- |
| **Windows** | Validates window station handle via `GetProcessWindowStation()` and checks for interactive flags (`WSF_VISIBLE`) via `GetUserObjectInformationW`. | Service accounts, SSH sessions, non-interactive Windows services. |
| **macOS** | Checks WindowServer process status and GUI session variables (`CGSessionCopyCurrentDictionary`). | Headless Terminal / SSH sessions without Quartz compositing. |
| **Linux / BSD** | Validates presence and non-emptiness of `$DISPLAY` or `$WAYLAND_DISPLAY` environment variables. | Headless servers, CI runners, SSH sessions without X11 forwarding. |

#### Fail-Closed Invariant (`ARC-AUTH-HEADLESS-UNSUPPORTED`)
If an approval request is triggered in a non-interactive desktop or headless environment without pre-configured webhooks, Arc **strictly fails closed**:
* The action is immediately **denied** with rule ID `ARC-AUTH-HEADLESS-UNSUPPORTED`.
* Arc never stalls, hangs, or blocks CI/CD pipelines indefinitely.
* Arc never falls back to unauthenticated stdio prompts that a compromised agent could automate.

---

### CSPRNG 6-Digit PIN & Anti-Fatigue Controls

To prevent automated accessibility-tree automation, clickjacking, or accidental user clicking:

1. **Cryptographic Rejection-Sampled PIN:**
   Arc generates a 6-digit numeric PIN (`100000`–`999999`) using `rand::rngs::OsRng` via unbiased rejection sampling. This provides $\approx 20\text{ bits}$ of cryptographic entropy, preventing brute-force guessing while remaining effortless for a human to type.

2. **3-Attempt Exhaustion & 15-Minute Lockout:**
   The human is given up to 3 attempts to enter the PIN matching the dialog prompt. If 3 consecutive incorrect PINs are submitted:
   - The session is immediately placed in an administrative **15-minute rate lockout**.
   - The request is aborted with error code `ARC-AUTH-PIN-EXHAUSTED`.
   - Any subsequent approval attempts during the lockout window fail immediately with `ARC-AUTH-LOCKED-OUT`.

3. **Rolling Rate-Limiting (Anti-Alert-Fatigue):**
   To mitigate denial-of-wallet attacks and developer approval fatigue, Arc enforces a rolling window of at most **3 approval requests per 60 seconds** per session. Exceeding this threshold aborts with `ARC-AUTH-RATE-LIMITED`.

---

### RFC 8785 Canonical Binding & Single-Use Grants

When an approval request is confirmed with the correct PIN:

1. **Deterministic Action Hashing (RFC 8785 JCS):**
   Arc normalizes the exact tool call or evaluated action into canonical JSON bytes using the RFC 8785 JSON Canonicalization Scheme (JCS) and computes its SHA-256 hash.

2. **Bound Grant Key:**
   The single-use grant is keyed cryptographically to the exact action, session, and rule:
   $$\text{GrantKey} = \text{SHA256}(\text{CanonicalActionBytes} \mathbin{\Vert} \text{SessionID} \mathbin{\Vert} \text{RuleID})$$

3. **Single-Use Atomic Consumption:**
   Approval grants are valid for 15 minutes (`TTL = 900s`). When the broker proceeds to evaluate the action:
   - The grant is retrieved and atomically removed from the `ApprovalStore`.
   - The exact action parameters must match bit-for-bit with the granted action.
   - An approved grant cannot be reused, replayed, or transferred to different tool parameters or different sessions.

---

## 6. Local Pilot Telemetry

Vexa Arc includes an opt-in, local-only telemetry collector for small-team pilot measurement. It is disabled by default and does not affect policy decisions. The collector receives redacted event metadata over loopback and writes a local NDJSON spool.

Start it in a separate terminal:

```powershell
# Windows PowerShell
arc telemetry run
$env:ARC_PILOT_TELEMETRY = "local"
```

```bash
# Linux/macOS
arc telemetry run
export ARC_PILOT_TELEMETRY=local
```

Inspect the collector and export an aggregate:

```text
arc telemetry status --json
arc telemetry export --out arc-pilot-telemetry.json
```

The event sink records coarse fields such as host, action class, decision, rule ID, taint labels, schema status, and latency. It does not record prompts, source code, file contents, raw commands, MCP arguments, package names, URLs, or secrets. If the collector is down, Arc continues its normal security behavior and records a telemetry drop when possible. Do not treat telemetry completeness as security coverage: direct tools, unsupported host events, ordinary Cursor editor writes, unwrapped MCP servers, and direct network clients remain outside Arc's control.

## 7. Understanding Security Violations & Remediation

### The "Lethal Trifecta" Invariant (`ARC-LTT-001`)

An autonomous agent becomes dangerous when three properties converge:
1. **Private Data Exposure:** Access to private files (`.env`, `id_rsa`, source code) or databases.
2. **Untrusted Context Ingestion:** External web pages, public GitHub issues, PR comments, or Slack messages.
3. **Outbound Capability:** Network egress (`curl`, `fetch`, `slack_post`) or shell execution.

Arc's monotonic **Taint DAG** tracks taints observed on mediated events and denies actions that its policy engine classifies as a matching outbound sink. This is not byte-level taint tracking or a network firewall: unrecognized shell syntax, custom binaries, direct network clients, unwrapped tools, and host events that bypass Arc can evade sink mediation. Do not assume every outbound or destructive command is blocked.

### Dynamic Schema Rug-Pull Quarantine (`ARC-RUG-001`)

MCP servers can silently alter their tool definitions across restarts or updates. Arc calculates the canonical **RFC 8785 JSON Canonicalization Scheme (JCS) SHA-256 hash** of every tool schema. If a tool signature changes unexpectedly mid-session, Arc quarantines the tool until reviewed.

### Self-Explaining Error Contracts

When Arc denies an action, it **never crashes the agent socket**. It returns a standard JSON-RPC 2.0 response with `isError: true` containing self-service guidance:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "isError": true,
    "content": [
      {
        "type": "text",
        "text": "• Arc Policy Violation [ARC-LTT-001]: Action blocked by your organization's security policy.\n\nReason: Lethal Trifecta detected. Session has accessed private context ('.env') and ingested untrusted external context ('read_github_issue'). Outbound network tool 'slack_post_message' was blocked to prevent data exfiltration.\n\nRemediation Alternatives:\n1. Run local verification commands instead ('cargo test', 'npm test').\n2. Clear active session context before querying external services.\n3. Request an explicit policy exception from your security administrator."
      }
    ]
  }
}
```

---

## 8. Local Pseudonymization Vault Lifecycle

Instead of terminating agent workflows when secrets are encountered, Arc can replace sensitive credentials with deterministic local placeholders:

1. **Detection:** Arc Veil detects an AWS Key (`AKIAIOSFODNN7EXAMPLE`) in a file read by the agent.
2. **Redaction:** The credential is replaced with `<ARC_VAULT_SECRET_01>` before the LLM receives the prompt context.
3. **Vault Registration:** The mapping `<ARC_VAULT_SECRET_01> -> AKIAIOSFODNN7EXAMPLE` is held only in workstation memory.
4. **Controlled Re-hydration:**
   - If the agent passes `<ARC_VAULT_SECRET_01>` to an **authorized local tool** (e.g. `aws_s3_sync`), Arc re-hydrates the secret pre-execution.
   - If the agent passes the token to an external web call or Slack post, re-hydration is rejected and the request is blocked.

---

## 9. Frequently Asked Questions (FAQ)

**Q: Does Arc transmit my source code or prompts to an external cloud?**  
A: The local engine does not upload source code or prompts as part of its local scans, taint evaluations, or DLP matching. Network behavior is not universally zero-egress: an exact-version `arc shield check` may send public package coordinates to OSV, and the MCP server you explicitly launch may access its own network destinations.

**Q: Does Arc slow down my developer terminal or IDE loops?**  
A: The repository contains performance targets, but end-to-end hook/broker latency and developer workflow impact have not been validated in this assessment. Benchmark on your supported hosts and run in shadow mode before enabling blocking policy.

**Q: Can I run `arc audit` in CI/CD pipelines?**  
A: Yes. `arc audit --json` or `arc bom --out bom.json` can run as a build step or pre-commit hook to continuously audit repositories.
