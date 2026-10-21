use arc_core::event::{Action, ActionEvent};
use arc_core::taint::{SinkClass, Taint};
use arc_core::verdict::Explanation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEntry {
    pub taint: Taint,
    pub origin: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionTaintDag {
    pub session_id: String,
    pub current_taints: Taint,
    pub history: Vec<TaintEntry>,
    #[serde(default)]
    pub known_schemas: HashMap<String, [u8; 32]>,
}

impl SessionTaintDag {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            current_taints: Taint::empty(),
            history: Vec::new(),
            known_schemas: HashMap::new(),
        }
    }

    /// Monotonically adds taint labels to the session.
    /// In accordance with ADR-004, taints are never cleared during an active session.
    pub fn add_taint(&mut self, taint: Taint, origin: impl Into<String>) {
        if taint.is_empty() {
            return;
        }

        self.current_taints.insert(taint);
        self.history.push(TaintEntry {
            taint,
            origin: origin.into(),
            timestamp_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        });
    }

    /// Serializes and writes this session's state to disk under the specified directory.
    pub fn save_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let safe_name: String = self
            .session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{safe_name}.json"));
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Loads a session's state from disk if it exists.
    pub fn load_from_dir(dir: &Path, session_id: &str) -> std::io::Result<Option<Self>> {
        let safe_name: String = session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{safe_name}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)?;
        let dag: Self = serde_json::from_str(&content).map_err(std::io::Error::other)?;
        Ok(Some(dag))
    }

    /// Removes a session's persisted file from disk.
    pub fn delete_from_dir(dir: &Path, session_id: &str) -> std::io::Result<bool> {
        let safe_name: String = session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{safe_name}.json"));
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Evaluates whether the requested sink triggers the Lethal Trifecta:
    /// SessionTaints has PRIVATE_DATA (or SECRET_MATERIAL) AND UNTRUSTED_CONTENT
    /// AND target sink has EXTERNAL_EGRESS or DESTRUCTIVE
    pub fn check_lethal_trifecta(&self, sink: SinkClass) -> Option<Explanation> {
        let has_private = self.current_taints.contains(Taint::PRIVATE_DATA)
            || self.current_taints.contains(Taint::SECRET_MATERIAL)
            || self.current_taints.contains(Taint::PRIVILEGED_DATA);

        let has_untrusted = self.current_taints.contains(Taint::UNTRUSTED_CONTENT);

        let is_sensitive_sink =
            sink.contains(SinkClass::EXTERNAL_EGRESS) || sink.contains(SinkClass::DESTRUCTIVE);

        if has_private && has_untrusted && is_sensitive_sink {
            let private_origins: Vec<_> = self
                .history
                .iter()
                .filter(|e| {
                    e.taint.contains(Taint::PRIVATE_DATA)
                        || e.taint.contains(Taint::SECRET_MATERIAL)
                        || e.taint.contains(Taint::PRIVILEGED_DATA)
                })
                .map(|e| e.origin.as_str())
                .collect();

            let untrusted_origins: Vec<_> = self
                .history
                .iter()
                .filter(|e| e.taint.contains(Taint::UNTRUSTED_CONTENT))
                .map(|e| e.origin.as_str())
                .collect();

            let p_summary = if private_origins.is_empty() {
                "sensitive credentials/files".to_string()
            } else {
                format!("'{}'", private_origins.join("', '"))
            };

            let u_summary = if untrusted_origins.is_empty() {
                "untrusted external data".to_string()
            } else {
                format!("'{}'", untrusted_origins.join("', '"))
            };

            let reason = format!(
                "Lethal Trifecta detected. Session has accessed private context ({p_summary}) and ingested untrusted external context ({u_summary}). Outbound network or destructive action was blocked to prevent indirect prompt injection data exfiltration."
            );

            let options = vec![
                "Run local unit tests or verification commands to inspect changes without exfiltrating context ('cargo test', 'npm test').".to_string(),
                "Clear active session and isolate private credential access from untrusted web/issue queries.".to_string(),
                "Request an explicit policy exception from your security administrator for this MCP server/tool.".to_string(),
            ];

            Some(Explanation::new(
                reason,
                options,
                Some("https://docs.vexa.ai/arc/policies/ARC-LTT-001".to_string()),
            ))
        } else {
            None
        }
    }
}

pub struct TaintTracker {
    sessions: RwLock<HashMap<String, SessionTaintDag>>,
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintTracker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_create(&self, session_id: &str) -> SessionTaintDag {
        let mut guard = self.sessions.write().unwrap();
        guard
            .entry(session_id.to_string())
            .or_insert_with(|| SessionTaintDag::new(session_id))
            .clone()
    }

    pub fn update_session_schemas(&self, session_id: &str, schemas: HashMap<String, [u8; 32]>) {
        let mut guard = self.sessions.write().unwrap();
        if let Some(dag) = guard.get_mut(session_id) {
            dag.known_schemas = schemas;
        }
    }

    pub fn record_action_and_update_taints(&self, session_id: &str, action: &Action) -> Taint {
        let (taint, origin) = Self::classify_action_taints(action);
        if !taint.is_empty() {
            let mut guard = self.sessions.write().unwrap();
            let session = guard
                .entry(session_id.to_string())
                .or_insert_with(|| SessionTaintDag::new(session_id));
            session.add_taint(taint, origin);
        }
        taint
    }

    pub fn record_event_and_update_taints(&self, event: &ActionEvent) -> Taint {
        let (taint, origin) = Self::classify_event_taints(event);
        if !taint.is_empty() {
            let mut guard = self.sessions.write().unwrap();
            let session = guard
                .entry(event.host_session_id.clone())
                .or_insert_with(|| SessionTaintDag::new(&event.host_session_id));
            session.add_taint(taint, origin);
        }
        taint
    }

    pub fn check_trifecta(&self, session_id: &str, action: &Action) -> Option<Explanation> {
        let sink = Self::classify_sink(action);
        let guard = self.sessions.read().unwrap();
        if let Some(session) = guard.get(session_id) {
            session.check_lethal_trifecta(sink)
        } else {
            None
        }
    }

    pub fn load_session_from_disk(
        &self,
        dir: &Path,
        session_id: &str,
    ) -> std::io::Result<Option<SessionTaintDag>> {
        if let Some(dag) = SessionTaintDag::load_from_dir(dir, session_id)? {
            let mut guard = self.sessions.write().unwrap();
            guard.insert(session_id.to_string(), dag.clone());
            Ok(Some(dag))
        } else {
            Ok(None)
        }
    }

    pub fn save_session_to_disk(&self, dir: &Path, session_id: &str) -> std::io::Result<PathBuf> {
        let dag = self.get_or_create(session_id);
        dag.save_to_dir(dir)
    }

    pub fn clear_session(&self, dir: Option<&Path>, session_id: &str) -> std::io::Result<bool> {
        {
            let mut guard = self.sessions.write().unwrap();
            guard.remove(session_id);
        }
        if let Some(d) = dir {
            SessionTaintDag::delete_from_dir(d, session_id)
        } else {
            Ok(false)
        }
    }

    /// Classifies an action into any taints it produces when ingested.
    pub fn classify_action_taints(action: &Action) -> (Taint, String) {
        match action {
            Action::FileRead { path } => {
                let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
                if path_str.contains(".env")
                    || path_str.contains(".ssh")
                    || path_str.contains(".aws")
                    || path_str.contains("credentials")
                    || path_str.contains("secret")
                    || path_str.contains("id_rsa")
                    || path_str.contains("id_ed25519")
                    || path_str.contains("id_ecdsa")
                    || path_str.contains("private")
                    || path_str.contains("token")
                {
                    (
                        Taint::PRIVATE_DATA | Taint::SECRET_MATERIAL,
                        format!("file_read:{}", path.display()),
                    )
                } else {
                    (Taint::PRIVATE_DATA, format!("file_read:{}", path.display()))
                }
            }
            Action::McpToolCall { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("fetch")
                    || tool_lower.contains("web")
                    || tool_lower.contains("crawl")
                    || tool_lower.contains("scrape")
                    || tool_lower.contains("github_issue")
                    || tool_lower.contains("pr_comment")
                    || tool_lower.contains("slack_read")
                {
                    (Taint::UNTRUSTED_CONTENT, format!("mcp_tool_call:{tool}"))
                } else if tool_lower.contains("db")
                    || tool_lower.contains("sql")
                    || tool_lower.contains("query")
                {
                    (Taint::PRIVILEGED_DATA, format!("mcp_tool_call:{tool}"))
                } else {
                    (Taint::empty(), String::new())
                }
            }
            Action::McpToolResult { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("fetch")
                    || tool_lower.contains("web")
                    || tool_lower.contains("crawl")
                    || tool_lower.contains("scrape")
                    || tool_lower.contains("github_issue")
                    || tool_lower.contains("pr_comment")
                    || tool_lower.contains("slack_read")
                {
                    (Taint::UNTRUSTED_CONTENT, format!("mcp_tool:{tool}"))
                } else if tool_lower.contains("db")
                    || tool_lower.contains("sql")
                    || tool_lower.contains("query")
                {
                    (Taint::PRIVILEGED_DATA, format!("mcp_tool:{tool}"))
                } else {
                    (Taint::empty(), String::new())
                }
            }
            Action::PromptSubmit { text, source } => {
                let is_untrusted_source = source
                    .as_deref()
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        s_lower.contains("untrusted")
                            || s_lower.contains("issue")
                            || s_lower.contains("web")
                            || s_lower.contains("pr")
                            || s_lower.contains("external")
                            || s_lower.contains("chat")
                    })
                    .unwrap_or(false);

                let text_lower = text.to_lowercase();
                let has_url_or_issue = text_lower.contains("issue #")
                    || text_lower.contains("http://")
                    || text_lower.contains("https://");

                if is_untrusted_source || has_url_or_issue {
                    let origin = source
                        .clone()
                        .unwrap_or_else(|| "prompt_with_external_url_or_issue".to_string());
                    (Taint::UNTRUSTED_CONTENT, origin)
                } else {
                    (Taint::empty(), String::new())
                }
            }
            _ => (Taint::empty(), String::new()),
        }
    }

    /// Classifies an ActionEvent taking into account explicit provenance metadata.
    pub fn classify_event_taints(event: &ActionEvent) -> (Taint, String) {
        let (mut taint, mut origin) = Self::classify_action_taints(&event.action);
        if let arc_core::event::EventProvenance::UntrustedExternal { source } = &event.provenance {
            taint.insert(Taint::UNTRUSTED_CONTENT);
            if origin.is_empty() {
                origin = format!("provenance:{source}");
            }
        }
        (taint, origin)
    }

    /// Classifies the sink capability of an action.
    pub fn classify_sink(action: &Action) -> SinkClass {
        match action {
            Action::McpToolCall { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("slack_post")
                    || tool_lower.contains("send_email")
                    || tool_lower.contains("http_post")
                    || tool_lower.contains("curl")
                    || tool_lower.contains("fetch")
                    || tool_lower.contains("webhook")
                {
                    SinkClass::EXTERNAL_EGRESS
                } else if tool_lower.contains("git_push") || tool_lower.contains("publish") {
                    SinkClass::PUBLISH
                } else if tool_lower.contains("delete")
                    || tool_lower.contains("drop")
                    || tool_lower.contains("destroy")
                {
                    SinkClass::DESTRUCTIVE
                } else if tool_lower.contains("exec")
                    || tool_lower.contains("shell")
                    || tool_lower.contains("bash")
                {
                    SinkClass::CODE_EXECUTION
                } else {
                    SinkClass::empty()
                }
            }
            Action::Shell { command, .. } => {
                let cmd_lower = command.to_lowercase();
                let mut sink = SinkClass::CODE_EXECUTION;
                if cmd_lower.contains("curl ")
                    || cmd_lower.contains("wget ")
                    || cmd_lower.contains("invoke-webrequest")
                    || cmd_lower.contains("nc ")
                    || cmd_lower.contains("ssh ")
                {
                    sink.insert(SinkClass::EXTERNAL_EGRESS);
                }
                if cmd_lower.contains("rm -rf")
                    || cmd_lower.contains("del /f")
                    || cmd_lower.contains("drop database")
                    || cmd_lower.contains("terraform destroy")
                {
                    sink.insert(SinkClass::DESTRUCTIVE);
                }
                if cmd_lower.contains("git push")
                    || cmd_lower.contains("npm publish")
                    || cmd_lower.contains("cargo publish")
                {
                    sink.insert(SinkClass::PUBLISH);
                }
                sink
            }
            Action::PackageInstall { .. } => SinkClass::CODE_EXECUTION,
            _ => SinkClass::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::event::ServerIdentity;
    use std::path::PathBuf;

    #[test]
    fn test_taint_dag_lethal_trifecta_trigger() {
        let tracker = TaintTracker::new();
        let session = "sess-trifecta-test";

        // Step 1: Agent reads .env (PRIVATE_DATA)
        let read_action = Action::FileRead {
            path: PathBuf::from(".env"),
        };
        let t1 = tracker.record_action_and_update_taints(session, &read_action);
        assert!(t1.contains(Taint::PRIVATE_DATA));

        // Step 2: Agent reads GitHub issue (UNTRUSTED_CONTENT)
        let tool_result = Action::McpToolResult {
            server: ServerIdentity {
                config_name: "github".to_string(),
                artifact: arc_core::event::Artifact::Unknown,
                schema_root: None,
            },
            tool: "github_issue_read".to_string(),
            content: "Please check this issue".to_string(),
            is_error: false,
        };
        let t2 = tracker.record_action_and_update_taints(session, &tool_result);
        assert!(t2.contains(Taint::UNTRUSTED_CONTENT));

        // Step 3: Agent tries to post to Slack (EXTERNAL_EGRESS)
        let slack_action = Action::McpToolCall {
            server: ServerIdentity {
                config_name: "slack".to_string(),
                artifact: arc_core::event::Artifact::Unknown,
                schema_root: None,
            },
            tool: "slack_post_message".to_string(),
            arguments: serde_json::json!({"channel": "#general", "text": "summary"}),
        };

        let trifecta_violation = tracker.check_trifecta(session, &slack_action);
        assert!(
            trifecta_violation.is_some(),
            "Lethal trifecta must be detected"
        );

        let explanation = trifecta_violation.unwrap();
        assert!(explanation.summary.contains("Lethal Trifecta detected"));
        assert_eq!(explanation.options.len(), 3);
    }

    #[test]
    fn test_windows_path_and_key_taint_classification() {
        // Windows backslash path to ssh key
        let action = Action::FileRead {
            path: PathBuf::from(r"C:\Users\test\.ssh\id_ed25519"),
        };
        let (taint, origin) = TaintTracker::classify_action_taints(&action);
        assert!(taint.contains(Taint::PRIVATE_DATA));
        assert!(taint.contains(Taint::SECRET_MATERIAL));
        assert!(origin.contains("id_ed25519"));

        // Windows backslash path to .env
        let action_env = Action::FileRead {
            path: PathBuf::from(r"backend\config\.env.local"),
        };
        let (taint_env, _) = TaintTracker::classify_action_taints(&action_env);
        assert!(taint_env.contains(Taint::PRIVATE_DATA));
        assert!(taint_env.contains(Taint::SECRET_MATERIAL));
    }
}
