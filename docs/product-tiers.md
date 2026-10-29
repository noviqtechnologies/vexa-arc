# Vexa Arc Product Tiers — Current Packaging

**Status:** Current packaging guidance.
**As of:** 29 October 2026.

## Current availability

- **Community Core:** Currently available as free software under Apache-2.0 for individual local use, within the technical boundaries in the [Community Core scope](community-release-scope.md).
- **Team:** Private Beta. Access and enabled capabilities are cohort-specific; the applicable onboarding notice or written cohort terms define the scope. There is no universal public device cap, evaluation period, price, or SLA.
- **Enterprise:** Future direction, not a generally available or standard offer. No universal feature commitment, price, cap, or service level is published.

## Tier matrix

| Capability | Community Core — current/free | Team — private Beta | Enterprise — future direction |
|---|---|---|---|
| Intended use | One developer on one workstation | Participating beta teams under cohort-specific scope | Organizations with future centralized-governance requirements |
| Availability | Current Apache-2.0 local core | Access is granted by cohort; not general availability | Not a standard offer |
| Host and MCP coverage | Selected Claude Code/Cursor hook events and explicitly launched MCP stdio broker only | Use only the hosts and capabilities explicitly listed for the cohort; do not infer broader coverage | Future scope requires host-specific validation and a delivered service |
| Policy and coordination | Local files and explicit local configuration | Only beta capabilities explicitly enabled for the cohort; no general promise of shared policy distribution | Future option requiring design, implementation, and security review |
| Package checks | Advisory; no package-install interception | Cohort-specific only; no install-blocking promise | Future option only after implementation and validation |
| Identity, audit, and integrations | Local OS identity and user-controlled local output | Cohort-specific; no general SSO, central audit, or SIEM entitlement is implied | Future direction, subject to implemented and validated scope |
| Support | Community channels; no enterprise SLA implied | Support and response expectations are stated per cohort; no universal SLA | Not offered as a standard support plan |
| Price, limits, and duration | Free under Apache-2.0; no usage quota is specified here | No universal public price, device cap, or beta duration; follow the specific cohort terms | No standard price, cap, or availability commitment |

## How to interpret Team Beta

“Team Beta” confirms that a cohort-based beta exists; it does not mean every capability in the Enterprise column, or every roadmap concept elsewhere in the repository, is available. Only the features, supported hosts, entitlements, support expectations, and terms explicitly supplied to a participating cohort should be represented as enabled. Do not publish a universal numerical cap or preview period unless an approved common policy is adopted.

## Packaging principles

Keep Community useful without requiring a Vexa-hosted service. Do not weaken local security primitives to create a paid tier. Distinguish the current local core from beta-only coordination and future enterprise operations. Never describe a planned feature as shipped merely because it appears in an architecture document.

## Progression beyond beta

Team Beta may move to a broader offer only after supported-host coverage, shared policy behavior, CI output, ownership/review, migration, rollback, and support operations are validated. Enterprise requires a separate threat model and operational plan for identity, authorization, policy signing and revocation, rollback protection, endpoint inventory, audit/privacy/retention, incident response, availability, and support. These are readiness criteria, not current entitlements.

## Release maintenance

For each new tagged artifact, preserve evidence for formatting, locked tests, lint/security checks across supported platforms, host install/rollback smoke tests, broker failure cases, checksums/provenance, and security-disclosure availability. This maintenance checklist does not change the current Community Core availability and is not, by itself, proof that a particular future artifact passed validation.
