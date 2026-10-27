# Vexa Arc Threat Model & Abuse Cases

**Document Version:** 1.0.0  
**Baseline Date:** 2026-10-23  
**Standard:** Meets NFR-SEC-002 (PRD v5.0)

---

## 1. System Overview & Trust Boundaries

Vexa Arc (`arc`) acts as a local, deterministic security control and pre-execution firewall for AI-assisted engineering workflows. It mediates interactions between:
1. **Agent Hosts** (e.g. Claude Code, Cursor, Windsurf, generic MCP clients)
2. **MCP Tool Servers** (e.g. filesystem, git, slack, bash execution)
3. **Local File System & Environment** (`.env`, `.ssh`, source code, shell interpreters)
4. **External Registries & APIs** (npm, PyPI, Cargo, web endpoints)

### Core Trust Boundaries

```
[ UNTRUSTED EXTERNAL CONTEXT ]
  (Web pages, PR comments, issue trackers, hallucinated packages)
             │
             ▼
  ┌────────────────────────┐
  │  AI Coding Agent Host  │ (Semi-trusted: subject to prompt injection)
  └──────────┬─────────────┘
             │ JSON-RPC (stdio)
  ═══════════╪══════════════════════════════════════════════════════════ [TRUST BOUNDARY: ARC ENFORCEMENT EDGE]
             ▼
  ┌────────────────────────┐
  │  Vexa Arc Stdio Broker │
  │  - Policy Evaluator    │ (Trusted Local Control: Deterministic Rust)
  │  - Causal Taint DAG    │
  │  - DLP & Secret Vault  │
  └──────────┬─────────────┘
             │ Evaluated & Sanitized JSON-RPC
  ═══════════╪══════════════════════════════════════════════════════════ [CONTROLLED BOUNDARY]
             ▼
  ┌────────────────────────┐
  │    MCP Tool Server     │ (Potentially Malicious / Vulnerable to Drift)
  └────────────────────────┘
```

---

## 2. Threat Catalog & Abuse Cases

### T-01: Lethal Trifecta (Indirect Prompt Injection $\to$ Context Exfiltration)
- **Threat:** An agent reads confidential local context (`.env`, AWS keys), ingests untrusted text containing indirect injection instructions from an external issue or web crawl, and attempts to execute an outbound egress or destructive action (`slack_post_message`, `curl evil.com`).
- **Mitigation:** Arc tracks session data-flow in a monotonic **Causal Taint Graph**. When `PRIVATE_DATA` + `UNTRUSTED_CONTENT` converge on a sensitive sink (`EXTERNAL_EGRESS`, `DESTRUCTIVE`), rule `ARC-LTT-001` blocks the action before execution.

### T-02: Dynamic Schema Rug-Pull (Post-Approval Tool Escalation)
- **Threat:** An MCP server declares benign tools during initial configuration (`tools/list`), but dynamically updates tool descriptions, arguments, or schemas mid-session to escalate capabilities.
- **Mitigation:** Arc captures runtime schemas from `tools/list` responses, computes an RFC 8785 JSON Canonicalization Scheme (JCS) SHA-256 fingerprint, and isolates baselines per session. Unexpected mutations mid-session trigger immediate quarantine (`ARC-RUG-001`).

### T-03: Provenance Spoofing
- **Threat:** An attacker or compromised agent passes arbitrary flags or metadata claiming an untrusted payload is `UserExplicit`.
- **Mitigation:** Arc models provenance through authenticated adapter contracts (`AuthenticatedProvenance`). Untrusted content ingested from remote origins cannot be cleared to `UserExplicit` without authenticated operator authorization.

### T-04: Credential & Secret Exfiltration Across Protected Boundaries
- **Threat:** Sensitive tokens (AWS, GitHub PATs, OpenAI keys, SSH private keys) are embedded in prompt submissions, tool arguments, or shell commands.
- **Mitigation / limitation:** The DLP engine scans and can redact supported payloads on mediated paths (notably the stdio MCP broker); native adapters deny when a required redaction obligation cannot be applied. This is not universal outbound DLP: direct shell/network traffic, direct editor file writes, unwrapped servers, and unsupported host paths remain outside guaranteed coverage.

### T-05: AI Slopsquatting & Dependency Hallucination
- **Threat:** Generative models hallucinate non-existent package names or slight typosquats (`reactt`, `collor`), which attackers pre-register with malicious `preinstall`/`postinstall` scripts.
- **Mitigation / limitation:** The current `arc shield` CLI is advisory only and does not intercept installs or fetch registry reputation/lifecycle data. Its library applies ecosystem-scoped name heuristics, blocks a caller-reported dangerous lifecycle signal, and can review caller-reported provenance/SLSA signals. Those values are not verified by the CLI; keep registry, lockfile, and endpoint controls in place.

### T-06: Local State & Policy Tampering
- **Threat:** Multiple concurrent agent processes race to corrupt session files, or an attacker attempts to downgrade policy settings.
- **Mitigation:**
  - Policy precedence is enforced: BuiltInDefault < ProjectLocal < UserGlobal < SignedOrganization < EmergencyDeny. Emergency deny rules cannot be overridden by project-local configuration.
  - Multi-process safety is guaranteed via cross-platform file locking (`SessionLock`).
  - File persistence is atomic (write to temporary UUID file + atomic rename).

### T-07: Telemetry & Payload Leakage
- **Threat:** Sensitive source code, developer prompts, or secrets are transmitted to external servers under the guise of telemetry.
- **Mitigation:** Arc operates under a **Zero Egress Invariant**. All discovery, audit, taint tracking, and DLP occurs locally in-process. Telemetry is disabled by default, and log messages redact all secret values.

---

## 3. Explicit Limitations, Non-Goals & Architectural Boundaries

To avoid ambiguity regarding deployment guarantees, Vexa Arc defines explicit operational boundaries:

1. **Not a Kernel-Level EDR or OS Syscall Sandbox:** Arc does not hook operating system system calls or inspect kernel event streams (e.g., eBPF, Windows ETW/minifilters). Malicious processes spawned independently of Arc or commands executing raw kernel bypasses fall outside Arc's control boundary. Arc functions strictly as an application-level, pre-execution policy firewall at the agent host hook and MCP JSON-RPC boundary.
2. **Not a Commercial Network Egress Firewall:** Arc inspects shell command tokens, interpreter flags, and tool arguments at the boundary of agent sessions. It does not inspect packet-level TCP/IP traffic or DNS queries at the network interface layer.
3. **Host Adapter Coverage Scope:** Full pre-execution interception (shell, filesystem read/write, MCP calls) requires the host editor to expose documented hook APIs. Arc currently provides native adapters for:
   - **Claude Code**: Structured hooks in `.claude/settings.json` (`PreToolUse`, `PostToolUse`).
   - **Cursor**: Structured hooks in `.cursor/hooks.json` (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `afterMCPExecution`). This adapter has no pre-file-write event; ordinary editor writes bypass ARC-AST-001 and file-write DLP.
   Hosts without documented native pre-execution adapters (e.g., Windsurf, Cline) can only be mediated at the MCP transport layer via the stdio broker (`arc protect stdio`); unmediated internal host actions in those editors are not intercepted.
4. **Dataflow Tracking Nature:** The Session Taint DAG accumulates taints monotonically across causal events. While it isolates benign commands (e.g., `git status`, local test runners) and tracks structured field/path access, it is a conservative session-level and path-level automaton, not a full byte-level taint tracking compiler engine.
5. **Package Firewall Scope:** `arc shield` evaluates slopsquatting risks using deterministic algorithmic distance metrics (Levenshtein, Jaro-Winkler) against seeded popular package baselines, script presence, and caller simulation flags. It is not an active online package registry crawler. OSV vulnerability scanning evaluates exact coordinates (`name@version`); requests without concrete versions are categorized as `not_scanned_no_version`, and unavailable advisory feeds fail closed (`incomplete`).
6. **Code Pattern Scanner Nature:** The pre-write injection engine uses linear-time Aho-Corasick prefiltering and targeted regular expressions evaluated per line. It does not construct an Abstract Syntax Tree (AST) or perform inter-procedural dataflow analysis across files.
7. **Process Containment Scope:** Windows Job Objects provide kill-on-job-close for assigned processes; Linux `PR_SET_PDEATHSIG` applies to the direct child and `RLIMIT_AS` is a per-process bound; Unix process groups are cleaned up during orderly supervisor teardown. Descendant survival after hard parent failure is not universally prevented. These are lifecycle/resource controls, not a syscall, filesystem, or network sandbox.
8. **Same-User Local Privilege Limit:** An attacker with equal or higher OS-level privileges (e.g., administrator/root) can modify local binaries, tamper with unencrypted files, or kill processes. Arc defends against untrusted external content and agent-mediated workflows executing under standard user privileges.
