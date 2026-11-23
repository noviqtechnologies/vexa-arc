# Vexa Arc Product Tiers — Current Packaging

**Status:** Current packaging & commercial terms (synced with Vexa Console).
**As of:** 23 November 2026.

## Current Availability

- **Community Core / Free Tier:** Available now under Apache-2.0 for local CLI use, plus **Vexa Arc Personal Cloud** (1 developer seat, up to 2 workstations, 1 private repo, 4 public repos, 500 Console CI scans/month, 14-day redacted telemetry retention, local `.arc/policy.json` guardrails).
- **Team (Early Access / Beta):** Available at **\$19 / active developer seat / month** (**\$15 / seat / month** billed annually at \$180/seat/yr; **3-seat minimum**; read-only Console viewers are free). Bundles both **Vexa Arc** and **Vexa SCA** across unlimited enrolled workstations, Ed25519-signed organization policy distribution (`arc policy sync`), key rotation & revocation, centralized MCP governance, Threat Radar, and **90-day** redacted event/posture retention.
- **Enterprise:** Future direction (SAML SSO/SCIM, 4-role RBAC + two-person HSM approval, SIEM streaming, regional data residency, 365-day retention, custom uptime/contractual SLAs). Not a standard GA offer yet.

## Tier Matrix

| Capability | Community Core / Free | Team (Early Access / Beta) | Enterprise (Future Direction) |
| --- | --- | --- | --- |
| **Pricing & Seat Minimum** | Free (Apache-2.0 local core + 1 Personal Cloud seat) | **\$19 / dev / mo** (**\$15 / dev / mo** annual) · **3-seat min** · free read-only viewers | Custom |
| **Enrolled Workstations** | Unlimited local CLI · up to **2** Cloud workstations | **Unlimited** team workstations | Unlimited |
| **Repositories & CI Scans** | 1 private repo · 4 public repos · 500 CI scans/mo | Unlimited repos & CI scans | Unlimited |
| **Policy & Trust Root** | Local `.arc/policy.json` & `.arc/mcp-pins.lock` | **Ed25519 signed org policies** anchored via `arc policy trust-init` / `arc setup --root-key`, signed key rotation & revocation | Custom KMS/HSM & two-person approval |
| **RBAC & Access** | Personal account + up to 5 scoped API tokens | **Admin** + **Member** + repo-scoped **CI Tokens** | SAML SSO / SCIM + 4-role RBAC |
| **Data Retention & Deletion** | Zero source-code / zero secret retention · **14-day** event/posture retention | Zero source-code / zero secret retention · **90-day** event/posture retention · **30-day** hard delete on org cancellation | Configurable (up to 365+ days) |
| **Host Coverage** | Claude Code & Cursor (Verified via hook fixtures & CLI probes); Codex CLI, Gemini CLI, Windsurf (Preview) | Same host matrix; Team graduation to GA requires live multi-OS authenticated Claude Code & Cursor evidence | Multi-OS enterprise validation |
| **Support & Availability** | Community GitHub issues | Business-hours (8x5) email/Slack support (1 business day target); local enforcement continues fail-closed offline | Dedicated SLA |

## Data Retention & Deletion Policy

- **Zero-Code Retention:** Vexa Arc and Vexa SCA cloud endpoints never store raw source code, prompts, file contents, MCP arguments, or raw secrets. Sensitive fields are redacted or hashed locally before egress.
- **Retention Windows:** Redacted runtime events, posture heartbeats, and AI-BOM/SCA snapshots are retained for **14 days** on Free and **90 days** on Team.
- **Deletion:** Organization admins can request immediate tenant deletion via `contact@vexasec.io` or Console billing settings; all tenant data and signing keys are hard-deleted within **30 calendar days** of cancellation.

## Beta-to-GA Graduation Criteria (Team)

Team transitions from **Early Access / Beta** to **General Availability (GA)** once all of the following are verified and published:
1. Unambiguous Console policy-state badges (`signed_organization` vs `project_local` vs `stale` / `expired` / `revoked`) and enriched audit logs verified in live two-endpoint tests.
2. End-to-end signed key rotation, policy rollback, and endpoint revocation verified between `vexa-arc` and `vexa-sca-cloud`.
3. Reproducible multi-OS GitHub Actions release gates (`ubuntu-latest`, `macos-latest`, `windows-latest`) and live authenticated Claude Code & Cursor session transcripts published per release tag.
