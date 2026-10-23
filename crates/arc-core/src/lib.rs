pub mod capability;
pub mod error;
pub mod event;
pub mod mcp_profile;
pub mod taint;
pub mod verdict;

pub use capability::{Capability, CapabilityAssertion, CapabilityEvidenceSource, RiskClass};
pub use error::ArcError;
pub use event::{
    Action, ActionEvent, AgentHost, Artifact, AuthenticatedProvenance, Ecosystem, EventProvenance,
    OsPrincipal, Phase, ProvenanceConfidence, ProvenanceSourceType, ServerIdentity,
};
pub use mcp_profile::{compute_jcs_schema_hash, Mcp3DCapabilityProfile, RiskBand};
pub use taint::{SinkClass, Taint};
pub use verdict::{Explanation, Obligation, RuleId, TimeoutAction, Verdict};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_action_event_creation() {
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "sess-1234",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::Shell {
                command: "cargo check".to_string(),
                cwd: PathBuf::from("/workspace"),
            },
        );

        assert_eq!(event.host, AgentHost::ClaudeCode);
        assert_eq!(event.host_session_id, "sess-1234");
        assert!(event.observed_at_unix_ms > 0);
    }

    #[test]
    fn test_taint_bitflags() {
        let mut taints = Taint::empty();
        taints.insert(Taint::PRIVATE_DATA);
        taints.insert(Taint::UNTRUSTED_CONTENT);

        assert!(taints.contains(Taint::PRIVATE_DATA));
        assert!(taints.contains(Taint::UNTRUSTED_CONTENT));
        assert!(!taints.contains(Taint::SECRET_MATERIAL));

        let lethal_condition = Taint::PRIVATE_DATA | Taint::UNTRUSTED_CONTENT;
        assert!(taints.contains(lethal_condition));
    }

    #[test]
    fn test_jcs_canonical_hash_consistency() {
        // Different key ordering in JSON must produce the exact same canonical SHA-256
        let json_a = br#"{"tools":[{"name":"bash","description":"executes command"},{"name":"fetch","description":"gets url"}]}"#;
        let json_b = br#"{"tools":[{"description":"executes command","name":"bash"},{"description":"gets url","name":"fetch"}]}"#;

        let hash_a = compute_jcs_schema_hash(json_a).expect("hash_a failed");
        let hash_b = compute_jcs_schema_hash(json_b).expect("hash_b failed");

        assert_eq!(
            hash_a, hash_b,
            "JCS RFC 8785 canonical hashes must be identical regardless of key order"
        );
    }

    #[test]
    fn test_mcp_3d_profile_and_risk_band() {
        let hash = [0u8; 32];
        let low_profile = Mcp3DCapabilityProfile::calculate(100, 100, 100, hash);
        assert_eq!(low_profile.band, RiskBand::Low);

        let high_profile = Mcp3DCapabilityProfile::calculate(800, 700, 900, hash);
        assert_eq!(high_profile.band, RiskBand::Critical);
    }

    #[test]
    fn test_verdict_explanation_format() {
        let rule = RuleId("ARC-LTT-001".to_string());
        let expl = Explanation::new(
            "Lethal Trifecta detected.",
            vec![
                "Run local unit tests instead.".to_string(),
                "Strip secrets before calling external tools.".to_string(),
            ],
            Some("https://docs.vexa.ai/arc/policies/ltt".to_string()),
        );

        let text = expl.format_text(&rule);
        assert!(text.contains("ARC-LTT-001"));
        assert!(text.contains("Lethal Trifecta detected."));
        assert!(text.contains("1. Run local unit tests instead."));
        assert!(text.contains("https://docs.vexa.ai/arc/policies/ltt"));
    }

    #[test]
    fn test_event_contract_versioning_and_serialization() {
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "sess-p0-test",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "github".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "create_pull_request".to_string(),
                arguments: serde_json::json!({"title": "Test PR"}),
            },
        )
        .with_capabilities(vec![
            Capability::ExternalMessaging,
            Capability::NetworkEgress,
        ])
        .with_adapter_version("1.0.0")
        .with_transport("stdio")
        .with_provenance(EventProvenance::Authenticated(AuthenticatedProvenance {
            source_type: ProvenanceSourceType::McpToolResult,
            source_identity: "github".to_string(),
            adapter_id: "mcp-stdio-adapter".to_string(),
            confidence: ProvenanceConfidence::Verified,
            parent_event_id: None,
        }));

        assert_eq!(event.schema_version, "1.0.0");
        assert_eq!(event.capabilities.len(), 2);

        // Serialization roundtrip
        let serialized = serde_json::to_string(&event).expect("serialization failed");
        let deserialized: ActionEvent =
            serde_json::from_str(&serialized).expect("deserialization failed");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_capability_vocabulary_and_risk_classes() {
        assert_eq!(Capability::SecretRead.risk_class(), RiskClass::Critical);
        assert_eq!(
            Capability::ProcessExecution.risk_class(),
            RiskClass::Critical
        );
        assert_eq!(Capability::DatabaseAccess.risk_class(), RiskClass::Critical);
        assert_eq!(Capability::LocalFileRead.risk_class(), RiskClass::Low);
        assert_eq!(Capability::ExternalMessaging.risk_class(), RiskClass::High);

        assert!(Capability::NetworkEgress.is_sink());
        assert!(Capability::ExternalMessaging.is_sink());
        assert!(Capability::ProcessExecution.is_sink());
        assert!(!Capability::LocalFileRead.is_sink());

        let inferred = Capability::infer("slack_post_message", false, false, true);
        assert!(inferred.contains(&Capability::ExternalMessaging));
        assert!(inferred.contains(&Capability::NetworkEgress));
    }
}
