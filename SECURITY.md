# Security Policy & Vulnerability Reporting

## Supported Versions

Vexa Arc follows semantic versioning and provides security updates for the following active releases:

| Version | Supported          | Security Maintenance Level |
| ------- | ------------------ | --------------------------- |
| 1.0.x   | :white_check_mark: | Active security updates     |
| < 1.0.0 | :x:                | Deprecated / Not maintained |

---

## Reporting a Security Vulnerability

The Vexa Arc team is committed to ensuring the safety of autonomous agent workflows and developer environments. If you believe you have discovered a vulnerability in Vexa Arc, please do not file a public GitHub issue.

### Reporting Channels

1. **Email Disclosure:** Send details to [contact@vexasec.io](mailto:security@vexasec.io)
2. **PGP Encryption:** If reporting sensitive details or reproduction exploits, request our PGP public key via the contact email.

### What to Include

Please provide:
- Description of the vulnerability and attack vector (e.g. broker bypass, secret leakage, parser exploit, state tampering).
- Minimal reproducible proof-of-concept (PoC) code or command sequence.
- Target component (`arc-cli`, `arc-hooks`, `arc-core`, `arc-policy-engine`, `arc-dlp`, `arc-firewall`, or `arc-discover`).
- Operating system platform and Rust toolchain version.

### Response Timelines & SLA

- **Initial Acknowledgment:** Within **24 business hours**.
- **Triage & Severity Assessment:** Within **48 business hours**.
- **Remediation & Patch Target:** Critical/High severity issues patched within **7 calendar days**; Medium/Low within **30 days**.
- **Coordinated Disclosure:** We adhere to a 90-day coordinated disclosure policy, allowing maintainers and users time to upgrade before public advisories are published.

---

## Scope & Non-Goals

Vexa Arc provides local pre-execution runtime controls for AI agent and MCP workflows:
- **In-Scope:** MCP stdio broker bypasses, secret detector circumvention, causal taint graph corruption, local policy tampering by untrusted context, package command parsing bypasses.
- **Out-of-Scope:** Host compromise where attacker already possesses root/administrator privileges, physical endpoint tampering, denial-of-service on developer workstations via excessive local resource allocation.
