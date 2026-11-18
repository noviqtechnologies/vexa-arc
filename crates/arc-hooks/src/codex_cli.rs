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

pub struct CodexCliAdapter;

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
        _ => Some(("codex-mcp".to_string(), rest.to_string())),
    }
}

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

impl HostAdapter for CodexCliAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::CodexCli
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("session_id")
            .or_else(|| val.get("thread_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("codex-default")
            .to_string();

        let event_name = val
            .get("hook_event_name")
            .and_then(|s| s.as_str())
            .unwrap_or("PreToolUse");
        let is_post = event_name.eq_ignore_ascii_case("PostToolUse");

        let cwd = val
            .get("cwd")
            .and_then(|c| c.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let tool_name = val.get("tool_name").and_then(|t| t.as_str()).or_else(|| {
            if val.get("command").is_some() {
                Some("shell")
            } else {
                None
            }
        });

        let Some(tool_name) = tool_name else {
            return Err(AdapterError::Malformed(format!(
                "missing tool_name in Codex CLI {event_name} hook payload"
            )));
        };

        let input = val
            .get("tool_input")
            .or_else(|| val.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);

        let (phase, action) = if is_post {
            let resp = val.get("tool_response").unwrap_or(&Value::Null);
            let text = match resp {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let (server, tool) = if let Some((s, t)) = split_mcp_tool(tool_name) {
                (s, t)
            } else if matches!(tool_name, "web_search" | "web_fetch") {
                ("codex-builtin".to_string(), tool_name.to_string())
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
                "shell" | "bash" | "exec_command" | "container.exec" => {
                    let Some(cmd) = str_field(&input, &["command", "cmd"])
                        .or_else(|| str_field(&val, &["command"]))
                    else {
                        return Err(AdapterError::Malformed(
                            "missing command in Codex CLI shell hook payload".to_string(),
                        ));
                    };
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    }
                }
                "read_file" | "open_file" => {
                    let Some(p) = str_field(&input, &["file_path", "path"]) else {
                        return Err(AdapterError::Malformed(
                            "missing file_path in Codex CLI read hook payload".to_string(),
                        ));
                    };
                    Action::FileRead {
                        path: PathBuf::from(p),
                    }
                }
                "write_file" | "apply_patch" | "edit_file" => {
                    let p = str_field(&input, &["file_path", "path"]).unwrap_or("patch");
                    let content = str_field(&input, &["content", "patch", "new_string"])
                        .map(|s| s.to_string());
                    Action::FileWrite {
                        path: PathBuf::from(p),
                        new_content: content,
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
                                    .unwrap_or("codex-mcp")
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
            AgentHost::CodexCli,
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
                    "decision": "block",
                    "reason": DLP_UNAPPLIED_REDACTION_MESSAGE,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
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
                let reason = explanation.format_text(rule);
                let payload = serde_json::json!({
                    "decision": "block",
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

impl CodexCliAdapter {
    fn hooks_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".codex").join("hooks.json")
    }

    fn hook_entry_with_cmd(matcher: &str, hook_cmd: &str) -> Value {
        serde_json::json!({
            "matcher": matcher,
            "hooks": [{ "type": "command", "command": hook_cmd }]
        })
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
        let hook_cmd = format_hook_command(&exe_path, "codex-cli");
        let backup_path = backup_existing_config(&config_path)?;

        let mut root = read_json_object(&config_path)?;
        validate_hooks_object(&root, &config_path)?;
        let obj = root.as_object_mut().expect("validated as object");
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));

        upsert_event_entry(
            hooks,
            "PreToolUse",
            Some(Self::hook_entry_with_cmd("*", &hook_cmd)),
        );
        upsert_event_entry(
            hooks,
            "PostToolUse",
            Some(Self::hook_entry_with_cmd(
                "web_search|web_fetch|mcp__.*",
                &hook_cmd,
            )),
        );

        write_json_atomic(&config_path, &root)?;
        Ok(HostInstallSummary {
            host: AgentHost::CodexCli,
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
            for event in ["PreToolUse", "PostToolUse"] {
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
                host: AgentHost::CodexCli,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: true,
                message: "No .codex/hooks.json found.".to_string(),
            };
        }
        match read_json_object(&config_path) {
            Ok(root) => {
                let pre = root
                    .get("hooks")
                    .and_then(|h| h.get("PreToolUse"))
                    .and_then(find_arc_command);
                if let Some(cmd) = pre {
                    HostIntegrationStatus {
                        host: AgentHost::CodexCli,
                        is_configured: true,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd),
                        bypass_risk: false,
                        message: "Codex CLI PreToolUse hook active.".to_string(),
                    }
                } else {
                    HostIntegrationStatus {
                        host: AgentHost::CodexCli,
                        is_configured: false,
                        hook_path: Some(config_path),
                        hook_command: None,
                        bypass_risk: true,
                        message: ".codex/hooks.json exists without Arc PreToolUse hook."
                            .to_string(),
                    }
                }
            }
            Err(e) => HostIntegrationStatus {
                host: AgentHost::CodexCli,
                is_configured: false,
                hook_path: Some(config_path),
                hook_command: None,
                bypass_risk: true,
                message: format!("Malformed .codex/hooks.json: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::HostAdapter;

    #[test]
    fn codex_cli_decode_and_install_roundtrip() {
        let adapter = CodexCliAdapter;
        let payload = br#"{"hook_event_name":"PreToolUse","session_id":"c1","tool_name":"shell","tool_input":{"command":"npm install reactt"}}"#;
        let events = adapter.decode(payload, OsPrincipal::Uid(1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, AgentHost::CodexCli);

        let dir = std::env::temp_dir().join(format!("arc_codex_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("arc");
        std::fs::write(&exe, b"bin").unwrap();
        CodexCliAdapter::install_integration_with_custom_exe(&dir, Some(&exe)).unwrap();
        assert!(CodexCliAdapter::check_integration(&dir).is_configured);
        assert!(CodexCliAdapter::uninstall_integration(&dir).unwrap());
        assert!(!CodexCliAdapter::check_integration(&dir).is_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
