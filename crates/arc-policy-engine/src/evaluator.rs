use arc_core::event::{Action, ActionEvent};
use arc_core::verdict::{Explanation, Obligation, RuleId, Verdict};
use arc_dlp::detector::SecretScanEngine;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::taint_dag::TaintTracker;

fn default_policy_version() -> String {
    "1.0.0".to_string()
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    BuiltInDefault,
    UserGlobal,
    ProjectLocal,
    SignedOrganization,
    EmergencyDeny,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_policy_version")]
    pub version: String,
    #[serde(default)]
    pub source: Option<PolicySource>,
    pub allowed_mcp_servers: HashSet<String>,
    pub block_unapproved_mcp: bool,
    pub enforce_taint_dag: bool,
    pub redact_secrets: bool,
    #[serde(default)]
    pub emergency_deny_servers: HashSet<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("github".to_string());
        allowed.insert("local-filesystem".to_string());
        allowed.insert("git".to_string());
        allowed.insert("sqlite".to_string());

        Self {
            version: default_policy_version(),
            source: Some(PolicySource::BuiltInDefault),
            allowed_mcp_servers: allowed,
            block_unapproved_mcp: false,
            enforce_taint_dag: true,
            redact_secrets: true,
            emergency_deny_servers: HashSet::new(),
        }
    }
}

impl PolicyConfig {
    /// Loads policy with documented precedence (FR-CORE-005):
    /// BuiltInDefault < UserGlobal (~/.arc/policy.json) < ProjectLocal (.arc/policy.json) < SignedOrganization
    pub fn load_with_precedence(project_dir: Option<&std::path::Path>) -> Self {
        let mut effective = Self::default();

        // 1. Check user global path (~/.arc/policy.json)
        if let Some(user_home) = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(std::path::PathBuf::from)
        {
            let user_cfg = user_home.join(".arc").join("policy.json");
            if user_cfg.exists() {
                if let Ok(content) = std::fs::read_to_string(&user_cfg) {
                    if let Ok(mut parsed) = serde_json::from_str::<PolicyConfig>(&content) {
                        parsed.source = Some(PolicySource::UserGlobal);
                        effective.merge_lower_precedence(parsed);
                    }
                }
            }
        }

        // 2. Check project local path (.arc/policy.json or .arc.json)
        if let Some(dir) = project_dir {
            let candidate_paths = [dir.join(".arc").join("policy.json"), dir.join(".arc.json")];
            for path in &candidate_paths {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(mut parsed) = serde_json::from_str::<PolicyConfig>(&content) {
                            parsed.source = Some(PolicySource::ProjectLocal);
                            effective.merge_lower_precedence(parsed);
                            break;
                        }
                    }
                }
            }

            // 3. Check signed organization policy (.arc/signed_policy.json)
            let org_path = dir.join(".arc").join("signed_policy.json");
            if org_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&org_path) {
                    if let Ok(mut parsed) = serde_json::from_str::<PolicyConfig>(&content) {
                        parsed.source = Some(PolicySource::SignedOrganization);
                        effective.merge_lower_precedence(parsed);
                    }
                }
            }
        }

        effective
    }

    /// Merges higher precedence config over current config, preserving emergency deny rules
    pub fn merge_lower_precedence(&mut self, higher: PolicyConfig) {
        self.version = higher.version;
        self.source = higher.source;
        self.block_unapproved_mcp = higher.block_unapproved_mcp;
        self.enforce_taint_dag = higher.enforce_taint_dag;
        self.redact_secrets = higher.redact_secrets;

        // Emergency deny rules cannot be removed by local policy
        for s in higher.emergency_deny_servers {
            self.emergency_deny_servers.insert(s);
        }

        // Allowed servers from higher precedence
        self.allowed_mcp_servers = higher.allowed_mcp_servers;
        // Strip emergency denied servers from allow list
        for denied in &self.emergency_deny_servers {
            self.allowed_mcp_servers.remove(denied);
        }
    }

    /// Loads a policy configuration from an optional project directory (.arc/policy.json or .arc.json)
    /// Falling back to the default configuration if the file does not exist.
    pub fn load_from_dir(dir: &std::path::Path) -> Self {
        Self::load_with_precedence(Some(dir))
    }

    /// Saves the policy configuration to .arc/policy.json in the specified directory atomically (NFR-REL-001).
    pub fn save_to_dir(&self, dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let arc_dir = dir.join(".arc");
        std::fs::create_dir_all(&arc_dir)?;
        let path = arc_dir.join("policy.json");
        let temp_path = arc_dir.join(format!("policy.tmp.{}", uuid::Uuid::now_v7()));

        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&temp_path, json.as_bytes())?;

        #[cfg(windows)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }

        std::fs::rename(&temp_path, &path)?;
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

        // 1. Check MCP allow-list and emergency deny rules
        if let Action::McpToolCall { ref server, .. } = event.action {
            if cfg.emergency_deny_servers.contains(&server.config_name) {
                return Verdict::Deny {
                    rule: RuleId("ARC-EMG-001".to_string()),
                    explanation: Explanation::new(
                        format!(
                            "Emergency Deny: MCP server '{}' is blocked by emergency security policy.",
                            server.config_name
                        ),
                        vec![
                            "Contact security administration for emergency policy exceptions.".to_string(),
                            "Inspect tool server integrity before requesting unblock.".to_string(),
                        ],
                        Some("https://docs.vexa.ai/arc/policies/ARC-EMG-001".to_string()),
                    ),
                };
            }

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
            if let Some(explanation) = self.taint_tracker.check_event_trifecta(event) {
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
            ..Default::default()
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

    #[test]
    fn test_policy_precedence_and_emergency_deny() {
        let mut base = PolicyConfig::default();
        let mut emergency = PolicyConfig::default();
        emergency
            .emergency_deny_servers
            .insert("rogue-corp-mcp".to_string());
        base.merge_lower_precedence(emergency);

        // Even if local policy tries to allow rogue-corp-mcp:
        let mut local_override = PolicyConfig::default();
        local_override
            .allowed_mcp_servers
            .insert("rogue-corp-mcp".to_string());
        base.merge_lower_precedence(local_override);

        assert!(!base.allowed_mcp_servers.contains("rogue-corp-mcp"));
        assert!(base.emergency_deny_servers.contains("rogue-corp-mcp"));

        let evaluator = PolicyEvaluator::new(base);
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "sess-emergency",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "rogue-corp-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "run".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let verdict = evaluator.evaluate(&event);
        assert!(verdict.is_denied());
        if let Verdict::Deny { rule, .. } = verdict {
            assert_eq!(rule.0, "ARC-EMG-001");
        } else {
            panic!("Expected emergency deny");
        }
    }
}
