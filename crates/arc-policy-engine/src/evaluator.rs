use arc_core::event::{Action, ActionEvent};
use arc_core::verdict::{Explanation, Obligation, RuleId, Verdict};
use arc_dlp::detector::SecretScanEngine;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::taint_dag::TaintTracker;

#[derive(Debug, Clone)]
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

pub struct PolicyEvaluator {
    pub config: RwLock<PolicyConfig>,
    pub taint_tracker: TaintTracker,
    pub dlp_engine: SecretScanEngine,
    known_schemas: RwLock<HashMap<String, [u8; 32]>>, // server name -> canonical JCS sha256
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
        self.taint_tracker.load_session_from_disk(dir, session_id)
    }

    pub fn save_session_state(
        &self,
        dir: &std::path::Path,
        session_id: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        self.taint_tracker.save_session_to_disk(dir, session_id)
    }

    pub fn clear_session_state(
        &self,
        dir: Option<&std::path::Path>,
        session_id: &str,
    ) -> std::io::Result<bool> {
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

            // Check Schema Rug-Pull
            if let Some(schema_hash) = server.schema_root {
                let mut schemas = self.known_schemas.write().unwrap();
                if let Some(known) = schemas.get(&server.config_name) {
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
                    schemas.insert(server.config_name.clone(), schema_hash);
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

        // 3. Update session taints with this action
        self.taint_tracker
            .record_action_and_update_taints(session_id, &event.action);

        // 4. Secret DLP Check on outbound arguments / prompt text
        let mut obligations = Vec::new();
        if cfg.redact_secrets {
            let bytes_to_scan = match &event.action {
                Action::McpToolCall { arguments, .. } => arguments.to_string().into_bytes(),
                Action::PromptSubmit { text } => text.as_bytes().to_vec(),
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
}
