pub mod error;
pub mod event;
pub mod mcp_profile;
pub mod taint;
pub mod verdict;

pub use error::ArcError;
pub use event::{
    Action, ActionEvent, AgentHost, Artifact, Ecosystem, EventProvenance, OsPrincipal, Phase,
    ServerIdentity,
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
}
