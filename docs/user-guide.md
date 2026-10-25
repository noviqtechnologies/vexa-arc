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
   - [`arc shield`: Install-Time Anti-Slopsquatting Firewall](#arc-shield-install-time-anti-slopsquatting-firewall)
   - [`arc intercept eval`: Runtime Action & Taint Tracking (DAG)](#arc-intercept-eval-runtime-action--taint-tracking-dag)
4. [Host Agent & IDE Integration](#4-host-agent--ide-integration)
   - [Claude Code Integration](#claude-code-integration)
   - [Cursor IDE Integration](#cursor-ide-integration)
   - [Generic Model Context Protocol (MCP) JSON-RPC](#generic-model-context-protocol-mcp-json-rpc)
5. [Understanding Security Violations & Remediation](#5-understanding-security-violations--remediation)
   - [The "Lethal Trifecta" Invariant (`ARC-LTT-001`)](#the-lethal-trifecta-invariant-arc-ltt-001)
   - [Dynamic Schema Rug-Pull Quarantine (`ARC-RUG-001`)](#dynamic-schema-rug-pull-quarantine-arc-rug-001)
   - [Self-Explaining Error Contracts](#self-explaining-error-contracts)
6. [Local Pseudonymization Vault Lifecycle](#6-local-pseudonymization-vault-lifecycle)
7. [Frequently Asked Questions (FAQ)](#7-frequently-asked-questions-faq)

---

## 1. Overview & Key Concepts

**Vexa Arc** is a zero-dependency, ultra-low-latency native Rust runtime firewall (Endpoint Detection and Response — EDR — for AI Agents). It inspects what coding agents see, use, and execute on developer endpoints:

* **Arc Intercept:** Evaluates agent tool calls in real time against a monotonic **Stateful Session Taint DAG** (Directed Acyclic Graph).
* **Arc Veil:** Performs linear-time secret detection and Data Loss Prevention (DLP) ($< 0.9\text{ ms}$), prompt injection sanitization, and deterministic local vaulting (`<ARC_VAULT_SECRET_XX>`).
* **Arc Shield:** Blocks hallucinated ("slopsquatted") and typosquatted dependencies before install lifecycle scripts (`postinstall.js`, `setup.py`) execute.
* **Arc Atlas:** Discovers shadow MCP (Model Context Protocol) servers, agent instruction files, and model checkpoints, producing standardized CycloneDX v1.6 AI-BOM (AI Bill of Materials) artifacts.

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
| **EDR** | **E**ndpoint **D**etection and **R**esponse | An endpoint security discipline focused on monitoring endpoint activities and responding to threats in real time. Arc acts as an agent-aware runtime firewall/EDR for coding agents. |

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

### `arc shield`: Install-Time Anti-Slopsquatting Firewall

Evaluates packages before running `npm install`, `pnpm add`, `pip install`, `python -m pip install`, `cargo add`, or `go get`. Arc prevents developers and AI coding agents from installing hallucinated, typosquatted, or malicious packages.

#### Windows (PowerShell):
```powershell
# Option 1: Bare package name (ecosystem auto-detected from project files or default npm)
PS C:\vexa-arc\target\release> .\arc.exe shield reactt

# Option 2: Scoped ecosystem prefix
PS C:\vexa-arc\target\release> .\arc.exe shield npm:reactt
PS C:\vexa-arc\target\release> .\arc.exe shield pypi:shadow-agent --dangerous-scripts
PS C:\vexa-arc\target\release> .\arc.exe shield go:github.com/gin-gonic/gin

# Option 3: Natural CLI command wrapper (paste your full install command!)
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

# Option 3: Natural CLI command wrapper (paste your full install command!)
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

**Diagnostic Output (Typosquat / AI Hallucination):**
```text
┌────────────────────────────────────────────────────────┐
│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │
└────────────────────────────────────────────────────────┘
Package:            reactt (npm)
Registry Metrics:   Age: 2 days | Monthly Downloads: 12
Dangerous Scripts:  false
----------------------------------------------------------
STATUS:             🛑 BLOCKED (HARD GATE REJECTION)
Triggered Gate:     CompoundTyposquatGate
Finding:            Package 'reactt' is a suspected hallucination/typosquat of 'react' (similarity: 0.97, edit_distance: 1, age: 2d, downloads: 12)

SUGGESTED ACTION:
  💡 Did you mean: 'react'? Run: npm install react
  ℹ️  If legitimate: arc shield allow reactt --ecosystem npm
──────────────────────────────────────────────────────────
```

**Diagnostic Output (Dangerous Lifecycle Scripts):**
```text
┌────────────────────────────────────────────────────────┐
│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │
└────────────────────────────────────────────────────────┘
Package:            shadow-agent (pypi)
Registry Metrics:   Age: 1 days | Monthly Downloads: 0
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
* `0`: Package evaluation permitted (passed all security gates).
* `1`: Package evaluation blocked (hard gate rejection, stopping CI/CD build or installation).

#### OSV/EPSS Vulnerability Scanning (`ARC-SCA-001`) — FR-PKG-005 & FR-PKG-006

`arc shield` integrates **vexa-sca** as a native Rust crate. Every package check now runs a live OSV batch-query + EPSS scoring after the slopsquat evaluation:

- **Air-gapped safe:** Only public package coordinates (name + ecosystem) leave the host. Source code never leaves localhost.
- **`.sca-cache` fallback:** 24-hour TTL local cache enables offline / air-gapped operation after the first successful query.
- **EPSS threshold:** Findings at ≥ 70th EPSS percentile are flagged as actively exploited.
- **JSON-RPC inline remediation:** Structured error payload `{"error": "Vulnerable package {name}@{version}; update constraint to >={safe}", "rule_id": "ARC-SCA-001"}` for agent self-healing (FR-PKG-006).

```bash
# Get JSON output with OSV findings and inline remediation
arc shield check lodash --ecosystem npm --json

# Terminal output shows OSV section after slopsquat evaluation
arc shield lodash
```

**Example terminal output with OSV findings:**
```text
┌────────────────────────────────────────────────────────┐
│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │
└────────────────────────────────────────────────────────┘
Package:            lodash (npm)
Registry Metrics:   Pre-install Gate (Automated package baseline & slopsquat check)
Dangerous Scripts:  false
----------------------------------------------------------
STATUS:             ✅ PERMITTED (PASS)
Reason:             Package 'lodash' is an established popular package.
----------------------------------------------------------
OSV VULNERABILITY SCAN  [ARC-SCA-001]
  🔴 GHSA-jf85-cpcp-j695 – HIGH (CVSS: 7.5)
     Vulnerable package lodash@4.17.15; update constraint to >=4.17.21
  JSON-RPC remediation: {"error":"Vulnerable package lodash@4.17.15; update constraint to >=4.17.21","rule_id":"ARC-SCA-001","severity":"HIGH"}
----------------------------------------------------------
```

> [!IMPORTANT]
> `arc shield` returns **exit code 1** (blocking) when either the slopsquat gate fires **or** an OSV finding with CRITICAL/HIGH severity or EPSS ≥ 70% is detected.

---

### AST Pattern Injection Hook (`ARC-AST-001`) — FR-CORE-006

Every `FileWrite` action evaluated by `arc intercept eval` triggers the **`AstPatternEngine`** before bytes reach disk. The check runs in **< 8ms** on files up to 256 KiB using Aho-Corasick prefiltering + regex matching:

| Injection Category | Detection Pattern |
| :--- | :--- |
| Raw SQL interpolation | `SELECT/INSERT/UPDATE … ${user}` / Python f-string with table name |
| Direct eval/exec | `eval(…)` / `exec(…)` / `child_process.exec(req.param)` |
| Raw innerHTML | `element.innerHTML = untrustedVar` |
| Plaintext private keys | `-----BEGIN PRIVATE KEY-----` / `-----BEGIN RSA PRIVATE KEY-----` |

A blocked write returns rule ID `ARC-AST-001` with a structured JSON-RPC error.

---

### OS-Level Process Containment (`FR-HOOKS-003`)

When `arc protect stdio` launches an MCP server, the child process is wrapped in OS-level containment before executing user code:

| Platform | Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Windows** | `CreateProcess(CREATE_SUSPENDED)` + `AssignProcessToJobObject` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Eliminates launch race window; child and descendants terminate when Job handle closes. Supports `--max-memory-mb`. |
| **Linux** | `prctl(PR_SET_PDEATHSIG, SIGKILL)` in pre-exec + parent PID race verification + `setrlimit(RLIMIT_AS)` | SIGKILL on broker parent death; enforces virtual address space bounds. |
| **macOS/Unix** | `setpgrp()` process group isolation — `kill(-pgid, SIGKILL)` on Drop | Reaps entire process subtree on supervisor shutdown or crash. |

```bash
# Supervise an MCP server with schema pinning and 512 MB memory boundary:
arc protect stdio --server github --pin-schema 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b --max-memory-mb 512 -- npx @modelcontextprotocol/server-github
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

### `arc shield run`: Supervised Package Containment Wrapper (FR-PKG-004)

Wraps package manager commands (`npm`, `pnpm`, `yarn`, `pip`, `cargo`, `go`) to inspect target dependencies before child processes spawn. When dangerous lifecycle scripts are detected, Arc can automatically inject `--ignore-scripts` to contain pre/post-install code execution:

```bash
# Evaluate and wrap install command:
arc shield run npm install express

# Automatically enforce containment:
arc shield run --enforce npm install questionable-package
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

### `arc intercept session --cleanup`: Session Pruning (NFR-PRIV-004)

Prunes expired session state files older than the retention threshold (default: 24 hours):

```bash
arc intercept session --cleanup --max-age-hours 24
```

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

## 5. Understanding Security Violations & Remediation

### The "Lethal Trifecta" Invariant (`ARC-LTT-001`)

An autonomous agent becomes dangerous when three properties converge:
1. **Private Data Exposure:** Access to private files (`.env`, `id_rsa`, source code) or databases.
2. **Untrusted Context Ingestion:** External web pages, public GitHub issues, PR comments, or Slack messages.
3. **Outbound Capability:** Network egress (`curl`, `fetch`, `slack_post`) or shell execution.

Arc's monotonic **Taint DAG** tracks this state. Once a session has ingested both Private Data and Untrusted Context, all outbound network and destructive commands are blocked deterministically.

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

## 6. Local Pseudonymization Vault Lifecycle

Instead of terminating agent workflows when secrets are encountered, Arc can replace sensitive credentials with deterministic local placeholders:

1. **Detection:** Arc Veil detects an AWS Key (`AKIAIOSFODNN7EXAMPLE`) in a file read by the agent.
2. **Redaction:** The credential is replaced with `<ARC_VAULT_SECRET_01>` before the LLM receives the prompt context.
3. **Vault Registration:** The mapping `<ARC_VAULT_SECRET_01> -> AKIAIOSFODNN7EXAMPLE` is held only in workstation memory.
4. **Controlled Re-hydration:**
   - If the agent passes `<ARC_VAULT_SECRET_01>` to an **authorized local tool** (e.g. `aws_s3_sync`), Arc re-hydrates the secret pre-execution.
   - If the agent passes the token to an external web call or Slack post, re-hydration is rejected and the request is blocked.

---

## 7. Frequently Asked Questions (FAQ)

**Q: Does Arc transmit my source code or prompts to an external cloud?**  
A: No. Arc's open-core engine operates with **zero network egress**. All scans, taint evaluations, and DLP pattern matches execute locally on your machine in native Rust.

**Q: Does Arc slow down my developer terminal or IDE loops?**  
A: No. In-daemon decision latency is designed for $p_{99} < 3.5\text{ ms}$ and secret scans complete in $< 0.9\text{ ms}$.

**Q: Can I run `arc audit` in CI/CD pipelines?**  
A: Yes. `arc audit --json` or `arc bom --out bom.json` can run as a build step or pre-commit hook to continuously audit repositories.
