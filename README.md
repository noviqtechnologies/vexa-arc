# Vexa Arc (Agentic Runtime Control)

> **Vexa Arc** is an ultra-low-latency, zero-dependency native Rust runtime firewall and pre-execution endpoint security platform (EDR for AI Agents) governing autonomous AI coding workflows and Model Context Protocol (MCP) interactions before execution.

## Architectural Pillars

- **Arc Intercept:** Inline MCP/Agent runtime proxy with sub-millisecond decision latency ($p_{99} < 3.5\text{ ms}$) and Stateful Session Taint DAG tracking stopping the "Lethal Trifecta" (Private Data + Untrusted Context + Outbound Egress).
- **Arc Veil:** Bi-directional context DLP, SIMD secret redaction ($< 0.9\text{ ms}$), and local deterministic pseudonymization vault (`<ARC_VAULT_SECRET_XX>`).
- **Arc Shield:** Install-time dependency firewall (`npm`, `pnpm`, `pip`, `uv`, `cargo`) with compound multi-signal anti-slopsquatting protection against hallucinated packages.
- **Arc Atlas:** Fleet-wide AI-SPM, `arc audit` zero-touch diagnostic CLI, CycloneDX v1.6 AI-BOM export, and Ed25519-signed AWS Cedar policy enforcement.

## License

Apache-2.0
