use arc_core::event::{Action, ActionEvent};
use arc_core::verdict::{Explanation, Obligation, RuleId, Verdict};
use arc_dlp::detector::SecretScanEngine;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::taint_dag::TaintTracker;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyConfig {
    pub allowed_mcp_servers: HashSet<String>,
    pub block_unapproved_mcp: bool,
    pub enforce_taint_dag: bool,
    pub redact_secrets: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("github".to_string());
        allowed.insert("local-filesystem".to_string());
        allowed.insert("git".to_string());
        allowed.insert("sqlite".to_string());

        Self {
            allowed_mcp_servers: allowed,
            block_unapproved_mcp: false,
            enforce_taint_dag: true,
            redact_secrets: true,
        }
    }
}

impl PolicyConfig {
    /// Loads a policy configuration from an optional project directory (.arc/policy.json or .arc.json)
    /// Falling back to the default configuration if the file does not exist.
    pub fn load_from_dir(dir: &std::path::Path) -> Self {
        let candidate_paths = [dir.join(".arc").join("policy.json"), dir.join(".arc.json")];

        for path in &candidate_paths {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(cfg) = serde_json::from_str::<PolicyConfig>(&content) {
                        return cfg;
                    }
                }
            }
        }

        Self::default()
    }

    /// Saves the policy configuration to .arc/policy.json in the specified directory.
    pub fn save_to_dir(&self, dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let arc_dir = dir.join(".arc");
        std::fs::create_dir_all(&arc_dir)?;
        let path = arc_dir.join("policy.json");
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}

pub struct PolicyEvaluator {
    pub config: RwLock<PolicyConfig>,
    pub taint_tracker: TaintTracker,
    pub dlp_engine: SecretScanEngine,
    known_schemas: RwLock<HashMap<(String, String), [u8; 32]>>, // (session_id, server_name) -> canonical JCS sha256
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl PolicyEvaluator {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config: RwLock::new(config),
            taint_tracker: TaintTracker::new(),
            dlp_engine: SecretScanEngine::new(),
            known_schemas: RwLock::new(HashMap::new()),
        }
    }

    pub fn load_session_state(
        &self,
        dir: &std::path::Path,
        session_id: &str,
    ) -> std::io::Result<Option<crate::taint_dag::SessionTaintDag>> {
        let res = self.taint_tracker.load_session_from_disk(dir, session_id)?;
        if let Some(ref dag) = res {
            let mut schemas = self.known_schemas.write().unwrap();
            for (srv, hash) in &dag.known_schemas {
                schemas.insert((session_id.to_string(), srv.clone()), *hash);
            }
        }
        Ok(res)
    }

    pub fn save_session_state(
        &self,
        dir: &std::path::Path,
        session_id: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        let schemas = self.known_schemas.read().unwrap();
        let session_schemas: HashMap<String, [u8; 32]> = schemas
            .iter()
            .filter(|((s_id, _), _)| s_id == session_id)
            .map(|((_, srv), hash)| (srv.clone(), *hash))
            .collect();
        self.taint_tracker
            .update_session_schemas(session_id, session_schemas);
        self.taint_tracker.save_session_to_disk(dir, session_id)
    }

    pub fn clear_session_state(
        &self,
        dir: Option<&std::path::Path>,
        session_id: &str,
    ) -> std::io::Result<bool> {
        let mut schemas = self.known_schemas.write().unwrap();
        schemas.retain(|(s_id, _), _| s_id != session_id);
        self.taint_tracker.clear_session(dir, session_id)
    }

    /// Evaluates an ActionEvent against enterprise policies and the session Taint DAG.
    pub fn evaluate(&self, event: &ActionEvent) -> Verdict {
        let cfg = self.config.read().unwrap().clone();
        let session_id = &event.host_session_id;

        // 1. Check MCP allow-list
        if let Action::McpToolCall { ref server, .. } = event.action {
            if cfg.block_unapproved_mcp && !cfg.allowed_mcp_servers.contains(&server.config_name) {
                return Verdict::Deny {
                    rule: RuleId("ARC-MCP-001".to_string()),
                    explanation: Explanation::new(
                        format!(
                            "Unapproved MCP server '{}'. Requires enterprise administrator approval.",
                            server.config_name
                        ),
                        vec![
                            format!("Use an approved MCP server: {:?}", cfg.allowed_mcp_servers.iter().cloned().collect::<Vec<_>>()),
                            "Request an exception in the Arc Security Console (https://arc.vexa.ai/policies/mcp)".to_string(),
                        ],
                        Some("https://docs.vexa.ai/arc/policies/ARC-MCP-001".to_string()),
                    ),
                };
            }

            // Check Schema Rug-Pull (Session-scoped)
            if let Some(schema_hash) = server.schema_root {
                let mut schemas = self.known_schemas.write().unwrap();
                let key = (session_id.clone(), server.config_name.clone());
                if let Some(known) = schemas.get(&key) {
                    if known != &schema_hash {
                        return Verdict::Quarantine {
                            rule: RuleId("ARC-RUG-001".to_string()),
                            explanation: Explanation::new(
                                format!(
                                    "Dynamic Schema Rug-Pull detected for MCP server '{}'. Tool schema hash changed unexpectedly mid-session.",
                                    server.config_name
                                ),
                                vec![
                                    "Restart the MCP server to reload clean configuration.".to_string(),
                                    "Review modified tool schemas before approving changes.".to_string(),
                                ],
                                Some("https://docs.vexa.ai/arc/policies/ARC-RUG-001".to_string()),
                            ),
                        };
                    }
                } else {
                    schemas.insert(key, schema_hash);
                }
            }
        }

        // 2. Check Stateful Taint DAG for Lethal Trifecta (Private Data + Untrusted Context -> External Egress)
        if cfg.enforce_taint_dag {
            if let Some(explanation) = self.taint_tracker.check_trifecta(session_id, &event.action)
            {
                return Verdict::Deny {
                    rule: RuleId("ARC-LTT-001".to_string()),
                    explanation,
                };
            }
        }

        // 3. Update session taints with this action and explicit event provenance
        self.taint_tracker.record_event_and_update_taints(event);

        // 4. Secret DLP Check on outbound arguments / prompt text
        let mut obligations = Vec::new();
        if cfg.redact_secrets {
            let bytes_to_scan = match &event.action {
                Action::McpToolCall { arguments, .. } => arguments.to_string().into_bytes(),
                Action::PromptSubmit { text, .. } => text.as_bytes().to_vec(),
                Action::Shell { command, .. } => command.as_bytes().to_vec(),
                _ => Vec::new(),
            };

            if !bytes_to_scan.is_empty() {
                let findings = self.dlp_engine.scan(&bytes_to_scan);
                if !findings.is_empty() {
                    let spans = findings
                        .into_iter()
                        .map(|f| (f.start, f.end, format!("<ARC_SECRET:{}>", f.detector)))
                        .collect();
                    obligations.push(Obligation::Redact { spans });
                }
            }
        }

        Verdict::Allow { obligations }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::event::{Action, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity};
    use std::path::PathBuf;

    #[test]
    fn test_evaluator_unapproved_mcp_block() {
        let cfg = PolicyConfig {
            block_unapproved_mcp: true,
            ..Default::default()
        };
        let evaluator = PolicyEvaluator::new(cfg);

        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "sess-1",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "rogue-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "execute_remote".to_string(),
                arguments: serde_json::json!({}),
            },
        );

        let verdict = evaluator.evaluate(&event);
        assert!(verdict.is_denied());
        if let Verdict::Deny { rule, explanation } = verdict {
            assert_eq!(rule.0, "ARC-MCP-001");
            assert!(explanation.summary.contains("Unapproved MCP server"));
        }
    }

    #[test]
    fn test_evaluator_lethal_trifecta_block() {
        let evaluator = PolicyEvaluator::default();
        let session = "sess-trifecta-eval";

        // Read .env
        let e1 = ActionEvent::new(
            AgentHost::Cursor,
            session,
            OsPrincipal::Uid(1000),
            Phase::Post,
            Action::FileRead {
                path: PathBuf::from(".env"),
            },
        );
        let v1 = evaluator.evaluate(&e1);
        assert!(v1.is_allowed());

        // Read untrusted issue
        let e2 = ActionEvent::new(
            AgentHost::Cursor,
            session,
            OsPrincipal::Uid(1000),
            Phase::Post,
            Action::McpToolResult {
                server: ServerIdentity {
                    config_name: "github".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "github_issue_read".to_string(),
                content: "issue body".to_string(),
                is_error: false,
            },
        );
        let v2 = evaluator.evaluate(&e2);
        assert!(v2.is_allowed());

        // Outbound Slack Post
        let e3 = ActionEvent::new(
            AgentHost::Cursor,
            session,
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "slack".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "slack_post_message".to_string(),
                arguments: serde_json::json!({"text": "leak"}),
            },
        );
        let v3 = evaluator.evaluate(&e3);
        assert!(v3.is_denied());
        if let Verdict::Deny { rule, explanation } = v3 {
            assert_eq!(rule.0, "ARC-LTT-001");
            assert!(explanation.summary.contains("Lethal Trifecta detected"));
        }
    }

    #[test]
    fn test_policy_config_serialization_and_roundtrip() {
        let temp_dir = std::env::temp_dir().join("vexa_arc_test_policy");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut allowed = HashSet::new();
        allowed.insert("custom-mcp".to_string());

        let cfg = PolicyConfig {
            allowed_mcp_servers: allowed,
            block_unapproved_mcp: true,
            enforce_taint_dag: true,
            redact_secrets: true,
        };

        let saved_path = cfg.save_to_dir(&temp_dir).expect("Failed to save policy");
        assert!(saved_path.exists());

        let loaded = PolicyConfig::load_from_dir(&temp_dir);
        assert!(loaded.block_unapproved_mcp);
        assert!(loaded.allowed_mcp_servers.contains("custom-mcp"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_scoped_schema_rug_pull_isolation() {
        let evaluator = PolicyEvaluator::default();

        let schema_a = [1u8; 32];
        let schema_b = [2u8; 32];

        // Session 1 registers schema_a for "mcp-server"
        let event_s1_a = ActionEvent::new(
            AgentHost::ClaudeCode,
            "session-1",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "mcp-server".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: Some(schema_a),
                },
                tool: "search".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let v1 = evaluator.evaluate(&event_s1_a);
        assert!(
            v1.is_allowed(),
            "Session 1 initial schema should be allowed"
        );

        // Session 2 registers schema_b for "mcp-server" - independent session, should NOT be quarantined!
        let event_s2_b = ActionEvent::new(
            AgentHost::ClaudeCode,
            "session-2",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "mcp-server".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: Some(schema_b),
                },
                tool: "search".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let v2 = evaluator.evaluate(&event_s2_b);
        assert!(
            v2.is_allowed(),
            "Session 2 baseline should be independent of Session 1"
        );

        // Session 1 changes to schema_b mid-session - MUST be quarantined!
        let event_s1_mutated = ActionEvent::new(
            AgentHost::ClaudeCode,
            "session-1",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "mcp-server".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: Some(schema_b),
                },
                tool: "search".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let v3 = evaluator.evaluate(&event_s1_mutated);
        assert!(
            v3.is_denied(),
            "Mid-session mutation in Session 1 must be quarantined"
        );
        if let Verdict::Quarantine { rule, .. } = v3 {
            assert_eq!(rule.0, "ARC-RUG-001");
        } else {
            panic!("Expected Quarantine verdict");
        }
    }
}
