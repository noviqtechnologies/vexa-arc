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

impl CursorAdapter {
    pub const DEFAULT_HOOK_CMD: &'static str =
        "arc intercept eval --session ${CURSOR_SESSION_ID:-default} --kind shell --target \"$COMMAND\"";

    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let cursor_dir = base_dir.join(".cursor");
        std::fs::create_dir_all(&cursor_dir)?;
        let config_path = cursor_dir.join("settings.json");
        let mut root: Value = if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&data).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        if !root.is_object() {
            root = serde_json::json!({});
        }

        if let Some(obj) = root.as_object_mut() {
            obj.insert(
                "cursor.agent.preHookCommand".to_string(),
                serde_json::Value::String(Self::DEFAULT_HOOK_CMD.to_string()),
            );
        }

        let json = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
        let temp_path = cursor_dir.join(format!("settings.tmp.{}", uuid::Uuid::now_v7()));
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
        let config_path = base_dir.join(".cursor").join("settings.json");
        if !config_path.exists() {
            return Ok(false);
        }
        let data = std::fs::read_to_string(&config_path)?;
        let mut root: Value = serde_json::from_str(&data).map_err(std::io::Error::other)?;
        let mut modified = false;
        if let Some(obj) = root.as_object_mut() {
            if obj.remove("cursor.agent.preHookCommand").is_some() {
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
        let cursor_dir = base_dir.join(".cursor");
        let config_path = cursor_dir.join("settings.json");
        if !config_path.exists() {
            let has_cursor_rules = base_dir.join(".cursorrules").exists();
            return crate::adapter::HostIntegrationStatus {
                host: AgentHost::Cursor,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: has_cursor_rules,
                message: if has_cursor_rules {
                    ".cursorrules found but .cursor/settings.json preHookCommand is missing (unprotected Cursor session)".to_string()
                } else {
                    "No .cursor/settings.json found in target directory".to_string()
                },
            };
        }

        if let Ok(data) = std::fs::read_to_string(&config_path) {
            if let Ok(val) = serde_json::from_str::<Value>(&data) {
                if let Some(cmd) = val
                    .get("cursor.agent.preHookCommand")
                    .and_then(|c| c.as_str())
                {
                    let is_arc = cmd.contains("arc");
                    return crate::adapter::HostIntegrationStatus {
                        host: AgentHost::Cursor,
                        is_configured: is_arc,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd.to_string()),
                        bypass_risk: !is_arc,
                        message: if is_arc {
                            "Cursor agent preHookCommand is active and protected by Vexa Arc"
                                .to_string()
                        } else {
                            "Cursor preHookCommand is active but does not invoke Arc (bypass risk)"
                                .to_string()
                        },
                    };
                }
            }
        }

        crate::adapter::HostIntegrationStatus {
            host: AgentHost::Cursor,
            is_configured: false,
            hook_path: Some(config_path),
            hook_command: None,
            bypass_risk: true,
            message: ".cursor/settings.json exists but cursor.agent.preHookCommand is missing (unprotected Cursor session)".to_string(),
        }
    }
}
