use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::Verdict;
use serde_json::Value;

use crate::adapter::{AdapterError, HostAdapter, HostResponse};

pub struct ClaudeCodeAdapter;

impl HostAdapter for ClaudeCodeAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::ClaudeCode
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("session_id")
            .and_then(|s| s.as_str())
            .unwrap_or("claude-default")
            .to_string();

        let mut events = Vec::new();

        if let Some(tool_name) = val.get("tool_name").and_then(|t| t.as_str()) {
            let args = val.get("arguments").cloned().unwrap_or(Value::Null);
            let action = Action::McpToolCall {
                server: ServerIdentity {
                    config_name: val
                        .get("server_name")
                        .and_then(|s| s.as_str())
                        .unwrap_or("claude-mcp")
                        .to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: tool_name.to_string(),
                arguments: args,
            };

            events.push(ActionEvent::new(
                AgentHost::ClaudeCode,
                session_id,
                principal,
                Phase::Pre,
                action,
            ));
        }

        Ok(events)
    }

    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { obligations } => {
                let payload = serde_json::json!({
                    "action": "allow",
                    "obligations": obligations
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: Vec::new(),
                    exit_code: 0,
                }
            }
            Verdict::Deny { rule, explanation } => {
                let payload = serde_json::json!({
                    "action": "block",
                    "rule": rule.0,
                    "reason": explanation.summary,
                    "remediation": explanation.options,
                    "policy_url": explanation.policy_url
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 1,
                }
            }
            Verdict::Quarantine { rule, explanation } => {
                let payload = serde_json::json!({
                    "action": "quarantine",
                    "rule": rule.0,
                    "reason": explanation.summary
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 2,
                }
            }
            Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let payload = serde_json::json!({
                    "action": "require_approval",
                    "rule": rule.0,
                    "reason": explanation.summary
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 3,
                }
            }
        }
    }
}

impl ClaudeCodeAdapter {
    pub const DEFAULT_HOOK_CMD: &'static str =
        "arc intercept eval --session ${CLAUDE_SESSION_ID:-default} --kind mcp_call --target ${TOOL_NAME:-mcp}";

    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let config_path = base_dir.join(".claude.json");
        let mut root: Value = if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&data).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        if !root.is_object() {
            root = serde_json::json!({});
        }

        let hooks_obj = root.as_object_mut().and_then(|o| {
            if !o.contains_key("hooks") {
                o.insert("hooks".to_string(), serde_json::json!({}));
            }
            o.get_mut("hooks").and_then(|h| h.as_object_mut())
        });

        if let Some(hooks) = hooks_obj {
            hooks.insert(
                "preToolUse".to_string(),
                serde_json::Value::String(Self::DEFAULT_HOOK_CMD.to_string()),
            );
        }

        let json = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
        let temp_path = base_dir.join(format!(".claude.tmp.{}", uuid::Uuid::now_v7()));
        std::fs::write(&temp_path, json.as_bytes())?;
        #[cfg(windows)]
        {
            if config_path.exists() {
                let _ = std::fs::remove_file(&config_path);
            }
        }
        std::fs::rename(&temp_path, &config_path)?;
        Ok(config_path)
    }

    pub fn uninstall_integration(base_dir: &std::path::Path) -> std::io::Result<bool> {
        let config_path = base_dir.join(".claude.json");
        if !config_path.exists() {
            return Ok(false);
        }
        let data = std::fs::read_to_string(&config_path)?;
        let mut root: Value = serde_json::from_str(&data).map_err(std::io::Error::other)?;
        let mut modified = false;
        if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
            if hooks.remove("preToolUse").is_some() {
                modified = true;
            }
        }
        if modified {
            let json = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
            std::fs::write(&config_path, json.as_bytes())?;
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> crate::adapter::HostIntegrationStatus {
        let config_path = base_dir.join(".claude.json");
        if !config_path.exists() {
            let has_claude_rules = base_dir.join("CLAUDE.md").exists();
            return crate::adapter::HostIntegrationStatus {
                host: AgentHost::ClaudeCode,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: has_claude_rules,
                message: if has_claude_rules {
                    "CLAUDE.md exists but .claude.json preToolUse hook is missing (unprotected Claude Code session)".to_string()
                } else {
                    "No .claude.json file found in target directory".to_string()
                },
            };
        }

        if let Ok(data) = std::fs::read_to_string(&config_path) {
            if let Ok(val) = serde_json::from_str::<Value>(&data) {
                if let Some(cmd) = val
                    .get("hooks")
                    .and_then(|h| h.get("preToolUse"))
                    .and_then(|c| c.as_str())
                {
                    let is_arc = cmd.contains("arc");
                    return crate::adapter::HostIntegrationStatus {
                        host: AgentHost::ClaudeCode,
                        is_configured: is_arc,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd.to_string()),
                        bypass_risk: !is_arc,
                        message: if is_arc {
                            "Claude Code preToolUse hook is active and protected by Vexa Arc"
                                .to_string()
                        } else {
                            "Claude Code hook is active but does not invoke Arc (bypass risk)"
                                .to_string()
                        },
                    };
                }
            }
        }

        crate::adapter::HostIntegrationStatus {
            host: AgentHost::ClaudeCode,
            is_configured: false,
            hook_path: Some(config_path),
            hook_command: None,
            bypass_risk: true,
            message: ".claude.json exists but preToolUse hook is missing (unprotected Claude Code session)".to_string(),
        }
    }
}
