use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::Verdict;
use serde_json::Value;
use std::path::PathBuf;

use crate::adapter::{AdapterError, HostAdapter, HostResponse};

pub struct CursorAdapter;

impl HostAdapter for CursorAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::Cursor
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("cursor_session_id")
            .or_else(|| val.get("session_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("cursor-session")
            .to_string();

        let mut events = Vec::new();

        // Check if shell command
        if let Some(cmd) = val.get("command").and_then(|c| c.as_str()) {
            let cwd = val
                .get("cwd")
                .and_then(|c| c.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));

            events.push(ActionEvent::new(
                AgentHost::Cursor,
                session_id,
                principal,
                Phase::Pre,
                Action::Shell {
                    command: cmd.to_string(),
                    cwd,
                },
            ));
        } else if let Some(tool) = val.get("tool").and_then(|t| t.as_str()) {
            let args = val.get("args").cloned().unwrap_or(Value::Null);
            let server_name = val
                .get("server")
                .and_then(|s| s.as_str())
                .unwrap_or("cursor-mcp")
                .to_string();

            events.push(ActionEvent::new(
                AgentHost::Cursor,
                session_id,
                principal,
                Phase::Pre,
                Action::McpToolCall {
                    server: ServerIdentity {
                        config_name: server_name,
                        artifact: Artifact::Unknown,
                        schema_root: None,
                    },
                    tool: tool.to_string(),
                    arguments: args,
                },
            ));
        }

        Ok(events)
    }

    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { .. } => {
                let payload = serde_json::json!({
                    "action": "allow"
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
                    "reason": format!("{}: {}", rule.0, explanation.summary),
                    "remediation_hint": explanation.options.first().cloned().unwrap_or_default()
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 1,
                }
            }
            Verdict::Quarantine { rule, explanation } => {
                let payload = serde_json::json!({
                    "action": "block",
                    "reason": format!("QUARANTINE {}: {}", rule.0, explanation.summary)
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 1,
                }
            }
            Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let payload = serde_json::json!({
                    "action": "require_approval",
                    "reason": format!("{}: {}", rule.0, explanation.summary)
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 1,
                }
            }
        }
    }
}
