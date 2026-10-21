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
