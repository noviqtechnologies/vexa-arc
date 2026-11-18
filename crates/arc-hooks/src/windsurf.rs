use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use serde_json::Value;
use std::path::PathBuf;

use crate::adapter::{AdapterError, HostAdapter, HostIntegrationStatus, HostResponse};
use crate::host_config::{
    backup_existing_config, find_arc_command, format_hook_command, read_json_object,
    resolve_canonical_arc_binary, upsert_event_entry, validate_hooks_object, write_json_atomic,
    HostInstallSummary,
};

pub struct WindsurfAdapter;

const PRE_EVENTS: [&str; 4] = [
    "pre_run_command",
    "pre_read_code",
    "pre_write_code",
    "pre_mcp_tool_use",
];
const POST_EVENTS: [&str; 1] = ["post_mcp_tool_use"];

fn has_unapplied_redaction(obligations: &[Obligation]) -> bool {
    obligations.iter().any(|obligation| match obligation {
        Obligation::Redact { spans } => !spans.is_empty(),
        _ => false,
    })
}

const DLP_UNAPPLIED_REDACTION_MESSAGE: &str = concat!(
    "[ARC-DLP-001] Secret detected; this hook cannot safely rewrite the action, ",
    "so it was blocked. Remove the secret or use a mediated redaction-capable MCP transport."
);

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(|x| x.as_str()))
}

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

impl HostAdapter for WindsurfAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::Windsurf
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("trajectory_id")
            .or_else(|| val.get("session_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("windsurf-default")
            .to_string();

        let event_name = val
            .get("agent_action_name")
            .or_else(|| val.get("hook_event_name"))
            .and_then(|s| s.as_str())
            .unwrap_or("");

        let info = val.get("tool_info").unwrap_or(&val);
        let cwd = str_field(info, &["cwd"])
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let (phase, action) = match event_name {
            "pre_run_command" => {
                let Some(cmd) = str_field(info, &["command_line", "command"]) else {
                    return Err(AdapterError::Malformed(
                        "missing command_line in Windsurf pre_run_command payload".to_string(),
                    ));
                };
                (
                    Phase::Pre,
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    },
                )
            }
            "pre_read_code" => {
                let Some(p) = str_field(info, &["file_path", "path"]) else {
                    return Err(AdapterError::Malformed(
                        "missing file_path in Windsurf pre_read_code payload".to_string(),
                    ));
                };
                (
                    Phase::Pre,
                    Action::FileRead {
                        path: PathBuf::from(p),
                    },
                )
            }
            "pre_write_code" => {
                let Some(p) = str_field(info, &["file_path", "path"]) else {
                    return Err(AdapterError::Malformed(
                        "missing file_path in Windsurf pre_write_code payload".to_string(),
                    ));
                };
                let content = info
                    .get("edits")
                    .and_then(|e| e.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| item.get("new_string").and_then(|s| s.as_str()))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .or_else(|| str_field(info, &["content", "new_string"]).map(|s| s.to_string()));
                (
                    Phase::Pre,
                    Action::FileWrite {
                        path: PathBuf::from(p),
                        new_content: content,
                    },
                )
            }
            "pre_mcp_tool_use" => {
                let server = str_field(info, &["mcp_server_name", "server_name", "server"])
                    .unwrap_or("windsurf-mcp")
                    .to_string();
                let Some(tool) = str_field(info, &["mcp_tool_name", "tool_name", "tool"]) else {
                    return Err(AdapterError::Malformed(
                        "missing mcp_tool_name in Windsurf pre_mcp_tool_use payload".to_string(),
                    ));
                };
                let args = info
                    .get("mcp_tool_arguments")
                    .or_else(|| info.get("arguments"))
                    .cloned()
                    .unwrap_or(Value::Null);
                (
                    Phase::Pre,
                    Action::McpToolCall {
                        server: server_identity(server),
                        tool: tool.to_string(),
                        arguments: args,
                    },
                )
            }
            "post_mcp_tool_use" => {
                let server = str_field(info, &["mcp_server_name", "server_name", "server"])
                    .unwrap_or("windsurf-mcp")
                    .to_string();
                let Some(tool) = str_field(info, &["mcp_tool_name", "tool_name", "tool"]) else {
                    return Err(AdapterError::Malformed(
                        "missing mcp_tool_name in Windsurf post_mcp_tool_use payload".to_string(),
                    ));
                };
                let content = info
                    .get("mcp_result")
                    .or_else(|| info.get("result"))
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                (
                    Phase::Post,
                    Action::McpToolResult {
                        server: server_identity(server),
                        tool: tool.to_string(),
                        content,
                        is_error: false,
                    },
                )
            }
            _ => {
                return Err(AdapterError::Malformed(format!(
                    "unsupported or missing Windsurf agent_action_name '{event_name}'"
                )));
            }
        };

        Ok(vec![ActionEvent::new(
            AgentHost::Windsurf,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { obligations } if has_unapplied_redaction(obligations) => {
                HostResponse {
                    stdout: Vec::new(),
                    stderr: DLP_UNAPPLIED_REDACTION_MESSAGE.as_bytes().to_vec(),
                    exit_code: 2,
                }
            }
            Verdict::Allow { .. } => HostResponse {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            },
            Verdict::Deny { rule, explanation } | Verdict::Quarantine { rule, explanation } => {
                HostResponse {
                    stdout: Vec::new(),
                    stderr: explanation.format_text(rule).into_bytes(),
                    exit_code: 2,
                }
            }
            Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let payload = serde_json::json!({
                    "permission": "ask",
                    "user_message": explanation.format_text(rule),
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: Vec::new(),
                    exit_code: 0,
                }
            }
        }
    }
}

impl WindsurfAdapter {
    fn hooks_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".windsurf").join("hooks.json")
    }

    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<HostInstallSummary> {
        Self::install_integration_with_custom_exe(base_dir, None)
    }

    pub fn install_integration_with_custom_exe(
        base_dir: &std::path::Path,
        custom_exe: Option<&std::path::Path>,
    ) -> std::io::Result<HostInstallSummary> {
        let config_path = Self::hooks_path(base_dir);
        let (exe_path, volatile_warning) = match custom_exe {
            Some(p) => (p.to_path_buf(), None),
            None => resolve_canonical_arc_binary()?,
        };
        let hook_cmd = format_hook_command(&exe_path, "windsurf");
        let backup_path = backup_existing_config(&config_path)?;

        let mut root = read_json_object(&config_path)?;
        validate_hooks_object(&root, &config_path)?;
        let obj = root.as_object_mut().expect("validated as object");
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));

        for event in PRE_EVENTS.iter().chain(POST_EVENTS.iter()) {
            upsert_event_entry(
                hooks,
                event,
                Some(serde_json::json!({ "command": hook_cmd, "show_output": true })),
            );
        }

        write_json_atomic(&config_path, &root)?;
        Ok(HostInstallSummary {
            host: AgentHost::Windsurf,
            config_path,
            backup_path,
            executable_path: exe_path,
            hook_command: hook_cmd,
            volatile_warning,
        })
    }

    pub fn uninstall_integration(base_dir: &std::path::Path) -> std::io::Result<bool> {
        let config_path = Self::hooks_path(base_dir);
        if !config_path.exists() {
            return Ok(false);
        }
        let mut root = read_json_object(&config_path)?;
        let mut modified = false;
        if let Some(hooks) = root.get_mut("hooks") {
            for event in PRE_EVENTS.iter().chain(POST_EVENTS.iter()) {
                modified |= upsert_event_entry(hooks, event, None);
            }
        }
        if modified {
            write_json_atomic(&config_path, &root)?;
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> HostIntegrationStatus {
        let config_path = Self::hooks_path(base_dir);
        if !config_path.exists() {
            return HostIntegrationStatus {
                host: AgentHost::Windsurf,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: true,
                message: "No .windsurf/hooks.json found.".to_string(),
            };
        }
        match read_json_object(&config_path) {
            Ok(root) => {
                let pre = root
                    .get("hooks")
                    .and_then(|h| h.get("pre_run_command"))
                    .and_then(find_arc_command);
                if let Some(cmd) = pre {
                    HostIntegrationStatus {
                        host: AgentHost::Windsurf,
                        is_configured: true,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd),
                        bypass_risk: false,
                        message: "Windsurf pre-execution hooks active.".to_string(),
                    }
                } else {
                    HostIntegrationStatus {
                        host: AgentHost::Windsurf,
                        is_configured: false,
                        hook_path: Some(config_path),
                        hook_command: None,
                        bypass_risk: true,
                        message: ".windsurf/hooks.json exists without Arc hooks.".to_string(),
                    }
                }
            }
            Err(e) => HostIntegrationStatus {
                host: AgentHost::Windsurf,
                is_configured: false,
                hook_path: Some(config_path),
                hook_command: None,
                bypass_risk: true,
                message: format!("Malformed .windsurf/hooks.json: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::HostAdapter;

    #[test]
    fn windsurf_decode_and_install_roundtrip() {
        let adapter = WindsurfAdapter;
        let payload = br#"{"agent_action_name":"pre_run_command","trajectory_id":"w1","tool_info":{"command_line":"pip install shadow-agent"}}"#;
        let events = adapter.decode(payload, OsPrincipal::Uid(1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, AgentHost::Windsurf);

        let dir = std::env::temp_dir().join(format!("arc_windsurf_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("arc");
        std::fs::write(&exe, b"bin").unwrap();
        WindsurfAdapter::install_integration_with_custom_exe(&dir, Some(&exe)).unwrap();
        assert!(WindsurfAdapter::check_integration(&dir).is_configured);
        assert!(WindsurfAdapter::uninstall_integration(&dir).unwrap());
        assert!(!WindsurfAdapter::check_integration(&dir).is_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
