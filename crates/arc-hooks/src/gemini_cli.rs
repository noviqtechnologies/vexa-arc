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

pub struct GeminiCliAdapter;

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

fn split_mcp_tool(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp__")?;
    match rest.split_once("__") {
        Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
            Some((server.to_string(), tool.to_string()))
        }
        _ => Some(("gemini-mcp".to_string(), rest.to_string())),
    }
}

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

impl HostAdapter for GeminiCliAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::GeminiCli
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("session_id")
            .and_then(|s| s.as_str())
            .unwrap_or("gemini-default")
            .to_string();

        let event_name = val
            .get("hook_event_name")
            .and_then(|s| s.as_str())
            .unwrap_or("BeforeTool");
        let is_post = event_name.eq_ignore_ascii_case("AfterTool")
            || event_name.eq_ignore_ascii_case("PostToolUse");

        let Some(tool_name) = val.get("tool_name").and_then(|t| t.as_str()) else {
            return Err(AdapterError::Malformed(format!(
                "missing tool_name in Gemini CLI {event_name} hook payload"
            )));
        };

        let input = val
            .get("tool_input")
            .or_else(|| val.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        let cwd = val
            .get("cwd")
            .and_then(|c| c.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let (phase, action) = if is_post {
            let resp = val.get("tool_response").unwrap_or(&Value::Null);
            let text = match resp {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let (server, tool) = if let Some((s, t)) = split_mcp_tool(tool_name) {
                (s, t)
            } else if matches!(tool_name, "web_fetch" | "google_web_search") {
                ("gemini-builtin".to_string(), tool_name.to_string())
            } else {
                return Ok(Vec::new());
            };
            (
                Phase::Post,
                Action::McpToolResult {
                    server: server_identity(server),
                    tool,
                    content: text,
                    is_error: false,
                },
            )
        } else {
            let action = match tool_name {
                "run_shell_command" | "shell" | "bash" => {
                    let Some(cmd) = str_field(&input, &["command", "cmd"]) else {
                        return Err(AdapterError::Malformed(
                            "missing command in Gemini CLI shell hook payload".to_string(),
                        ));
                    };
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    }
                }
                "read_file" | "view_file" => {
                    let Some(p) = str_field(&input, &["file_path", "absolute_path", "path"]) else {
                        return Err(AdapterError::Malformed(
                            "missing file_path in Gemini CLI read hook payload".to_string(),
                        ));
                    };
                    Action::FileRead {
                        path: PathBuf::from(p),
                    }
                }
                "write_file" | "replace" | "edit_file" => {
                    let Some(p) = str_field(&input, &["file_path", "TargetFile", "path"]) else {
                        return Err(AdapterError::Malformed(
                            "missing file_path in Gemini CLI write hook payload".to_string(),
                        ));
                    };
                    let content =
                        str_field(&input, &["content", "new_string", "ReplacementContent"])
                            .map(|s| s.to_string());
                    Action::FileWrite {
                        path: PathBuf::from(p),
                        new_content: content,
                    }
                }
                "web_fetch" => {
                    let url = str_field(&input, &["url"]).unwrap_or("");
                    Action::Shell {
                        command: format!("curl {url}"),
                        cwd,
                    }
                }
                name => {
                    if let Some((server, tool)) = split_mcp_tool(name) {
                        Action::McpToolCall {
                            server: server_identity(
                                str_field(&val, &["server_name"])
                                    .map(|s| s.to_string())
                                    .unwrap_or(server),
                            ),
                            tool,
                            arguments: input,
                        }
                    } else if val.get("server_name").is_some() {
                        Action::McpToolCall {
                            server: server_identity(
                                str_field(&val, &["server_name"])
                                    .unwrap_or("gemini-mcp")
                                    .to_string(),
                            ),
                            tool: name.to_string(),
                            arguments: input,
                        }
                    } else {
                        return Ok(Vec::new());
                    }
                }
            };
            (Phase::Pre, action)
        };

        Ok(vec![ActionEvent::new(
            AgentHost::GeminiCli,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { obligations } if has_unapplied_redaction(obligations) => {
                let payload = serde_json::json!({
                    "decision": "deny",
                    "reason": DLP_UNAPPLIED_REDACTION_MESSAGE,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: DLP_UNAPPLIED_REDACTION_MESSAGE.as_bytes().to_vec(),
                    exit_code: 2,
                }
            }
            Verdict::Allow { .. } => HostResponse {
                stdout: serde_json::to_vec(&serde_json::json!({"decision": "allow"}))
                    .unwrap_or_default(),
                stderr: Vec::new(),
                exit_code: 0,
            },
            Verdict::Deny { rule, explanation } | Verdict::Quarantine { rule, explanation } => {
                let reason = explanation.format_text(rule);
                let payload = serde_json::json!({
                    "decision": "deny",
                    "reason": reason,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: reason.into_bytes(),
                    exit_code: 2,
                }
            }
            Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let payload = serde_json::json!({
                    "decision": "ask",
                    "reason": explanation.format_text(rule),
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

impl GeminiCliAdapter {
    fn settings_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".gemini").join("settings.json")
    }

    fn hook_entry_with_cmd(matcher: &str, hook_cmd: &str) -> Value {
        serde_json::json!({
            "matcher": matcher,
            "hooks": [{ "name": "vexa-arc", "type": "command", "command": hook_cmd }]
        })
    }

    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<HostInstallSummary> {
        Self::install_integration_with_custom_exe(base_dir, None)
    }

    pub fn install_integration_with_custom_exe(
        base_dir: &std::path::Path,
        custom_exe: Option<&std::path::Path>,
    ) -> std::io::Result<HostInstallSummary> {
        let config_path = Self::settings_path(base_dir);
        let (exe_path, volatile_warning) = match custom_exe {
            Some(p) => (p.to_path_buf(), None),
            None => resolve_canonical_arc_binary()?,
        };
        let hook_cmd = format_hook_command(&exe_path, "gemini-cli");
        let backup_path = backup_existing_config(&config_path)?;

        let mut root = read_json_object(&config_path)?;
        validate_hooks_object(&root, &config_path)?;
        let obj = root.as_object_mut().expect("validated as object");
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));

        upsert_event_entry(
            hooks,
            "BeforeTool",
            Some(Self::hook_entry_with_cmd("*", &hook_cmd)),
        );
        upsert_event_entry(
            hooks,
            "AfterTool",
            Some(Self::hook_entry_with_cmd(
                "web_fetch|google_web_search|mcp__.*",
                &hook_cmd,
            )),
        );

        write_json_atomic(&config_path, &root)?;
        Ok(HostInstallSummary {
            host: AgentHost::GeminiCli,
            config_path,
            backup_path,
            executable_path: exe_path,
            hook_command: hook_cmd,
            volatile_warning,
        })
    }

    pub fn uninstall_integration(base_dir: &std::path::Path) -> std::io::Result<bool> {
        let config_path = Self::settings_path(base_dir);
        if !config_path.exists() {
            return Ok(false);
        }
        let mut root = read_json_object(&config_path)?;
        let mut modified = false;
        if let Some(hooks) = root.get_mut("hooks") {
            for event in ["BeforeTool", "AfterTool"] {
                modified |= upsert_event_entry(hooks, event, None);
            }
        }
        if modified {
            write_json_atomic(&config_path, &root)?;
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> HostIntegrationStatus {
        let config_path = Self::settings_path(base_dir);
        if !config_path.exists() {
            return HostIntegrationStatus {
                host: AgentHost::GeminiCli,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: true,
                message: "No .gemini/settings.json found.".to_string(),
            };
        }
        match read_json_object(&config_path) {
            Ok(root) => {
                let pre = root
                    .get("hooks")
                    .and_then(|h| h.get("BeforeTool"))
                    .and_then(find_arc_command);
                if let Some(cmd) = pre {
                    HostIntegrationStatus {
                        host: AgentHost::GeminiCli,
                        is_configured: true,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd),
                        bypass_risk: false,
                        message: "Gemini CLI BeforeTool hook active.".to_string(),
                    }
                } else {
                    HostIntegrationStatus {
                        host: AgentHost::GeminiCli,
                        is_configured: false,
                        hook_path: Some(config_path),
                        hook_command: None,
                        bypass_risk: true,
                        message: ".gemini/settings.json exists without Arc BeforeTool hook."
                            .to_string(),
                    }
                }
            }
            Err(e) => HostIntegrationStatus {
                host: AgentHost::GeminiCli,
                is_configured: false,
                hook_path: Some(config_path),
                hook_command: None,
                bypass_risk: true,
                message: format!("Malformed .gemini/settings.json: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::HostAdapter;

    #[test]
    fn gemini_cli_decode_and_install_roundtrip() {
        let adapter = GeminiCliAdapter;
        let payload = br#"{"hook_event_name":"BeforeTool","session_id":"g1","tool_name":"run_shell_command","tool_input":{"command":"curl https://evil.com"}}"#;
        let events = adapter.decode(payload, OsPrincipal::Uid(1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, AgentHost::GeminiCli);

        let dir = std::env::temp_dir().join(format!("arc_gemini_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("arc");
        std::fs::write(&exe, b"bin").unwrap();
        GeminiCliAdapter::install_integration_with_custom_exe(&dir, Some(&exe)).unwrap();
        assert!(GeminiCliAdapter::check_integration(&dir).is_configured);
        assert!(GeminiCliAdapter::uninstall_integration(&dir).unwrap());
        assert!(!GeminiCliAdapter::check_integration(&dir).is_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
