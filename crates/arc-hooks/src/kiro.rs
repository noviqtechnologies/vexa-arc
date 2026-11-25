use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use serde_json::Value;
use std::path::PathBuf;

use crate::adapter::{AdapterError, HostAdapter, HostIntegrationStatus, HostResponse};
use crate::host_config::{
    backup_existing_config, entry_is_arc, find_arc_command, format_hook_command, read_json_object,
    resolve_canonical_arc_binary, validate_binary_path_safe, write_json_atomic, HostInstallSummary,
};

/// Native host adapter for AWS Kiro (`.kiro/hooks/vexa-arc.json`).
///
/// Uses Kiro's `version: "v1"` hook array schema and exit-code-2 hard-blocking protocol
/// for `PreToolUse`, `PostToolUse`, and `UserPromptSubmit`.
pub struct KiroAdapter;

const DLP_UNAPPLIED_REDACTION_MESSAGE: &str = concat!(
    "[ARC-DLP-001] Secret detected; this hook cannot safely rewrite the action, ",
    "so it was blocked. Remove the secret or use a mediated redaction-capable MCP transport."
);

const IGNORED_LIFECYCLE_EVENTS: [&str; 4] = ["SessionStart", "PostFileSave", "Stop", "PreTaskExec"];

fn has_unapplied_redaction(obligations: &[Obligation]) -> bool {
    obligations.iter().any(|obligation| match obligation {
        Obligation::Redact { spans } => !spans.is_empty(),
        _ => false,
    })
}

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(|x| x.as_str()))
}

fn split_mcp_tool(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp__")?;
    match rest.split_once("__") {
        Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
            Some((server.to_string(), tool.to_string()))
        }
        _ => Some(("kiro-mcp".to_string(), rest.to_string())),
    }
}

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

impl KiroAdapter {
    pub fn is_ignored_lifecycle_event(event_name: &str) -> bool {
        IGNORED_LIFECYCLE_EVENTS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(event_name))
    }

    fn hooks_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".kiro").join("hooks").join("vexa-arc.json")
    }

    fn arc_hook_entries(hook_cmd: &str) -> Vec<Value> {
        vec![
            serde_json::json!({
                "name": "vexa-arc-pre-tool-use",
                "trigger": "PreToolUse",
                "matcher": "*",
                "action": {
                    "type": "command",
                    "command": hook_cmd
                }
            }),
            serde_json::json!({
                "name": "vexa-arc-post-tool-use",
                "trigger": "PostToolUse",
                "matcher": "web_fetch|web_search|mcp__.*",
                "action": {
                    "type": "command",
                    "command": hook_cmd
                }
            }),
            serde_json::json!({
                "name": "vexa-arc-user-prompt-submit",
                "trigger": "UserPromptSubmit",
                "action": {
                    "type": "command",
                    "command": hook_cmd
                }
            }),
        ]
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
            Some(p) => (validate_binary_path_safe(p)?, None),
            None => {
                let (p, w) = resolve_canonical_arc_binary()?;
                (validate_binary_path_safe(&p)?, w)
            }
        };
        let hook_cmd = format_hook_command(&exe_path, "kiro");
        let backup_path = backup_existing_config(&config_path)?;

        let mut root = read_json_object(&config_path)?;
        if let Some(existing_hooks) = root.get("hooks") {
            if !existing_hooks.is_array() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} contains a 'hooks' field that is not a JSON array; refusing to overwrite",
                        config_path.display()
                    ),
                ));
            }
        }

        let obj = root.as_object_mut().expect("validated as object");
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::json!("v1"));

        let mut entries: Vec<Value> = obj
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|a| a.iter().filter(|e| !entry_is_arc(e)).cloned().collect())
            .unwrap_or_default();
        entries.extend(Self::arc_hook_entries(&hook_cmd));
        obj.insert("hooks".to_string(), Value::Array(entries));

        write_json_atomic(&config_path, &root)?;
        Ok(HostInstallSummary {
            host: AgentHost::Kiro,
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
        let Some(hooks_arr) = root.get("hooks").and_then(|h| h.as_array()) else {
            return Ok(false);
        };
        let before = hooks_arr.len();
        let remaining: Vec<Value> = hooks_arr
            .iter()
            .filter(|e| !entry_is_arc(e))
            .cloned()
            .collect();
        if remaining.len() == before {
            return Ok(false);
        }
        root.as_object_mut()
            .expect("validated as object")
            .insert("hooks".to_string(), Value::Array(remaining));
        write_json_atomic(&config_path, &root)?;
        Ok(true)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> HostIntegrationStatus {
        let config_path = Self::hooks_path(base_dir);
        if !config_path.exists() {
            let has_kiro = base_dir.join(".kiro").exists();
            return HostIntegrationStatus {
                host: AgentHost::Kiro,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: has_kiro,
                message: if has_kiro {
                    ".kiro exists without Arc PreToolUse hook (unprotected Kiro session)."
                        .to_string()
                } else {
                    "No .kiro/hooks/vexa-arc.json found.".to_string()
                },
            };
        }

        match read_json_object(&config_path) {
            Ok(root) => {
                let cmd = root.get("hooks").and_then(find_arc_command);
                if let Some(cmd) = cmd {
                    HostIntegrationStatus {
                        host: AgentHost::Kiro,
                        is_configured: true,
                        hook_path: Some(config_path),
                        hook_command: Some(cmd),
                        bypass_risk: false,
                        message: "AWS Kiro PreToolUse hook active.".to_string(),
                    }
                } else {
                    HostIntegrationStatus {
                        host: AgentHost::Kiro,
                        is_configured: false,
                        hook_path: Some(config_path),
                        hook_command: None,
                        bypass_risk: true,
                        message: ".kiro/hooks/vexa-arc.json exists without Arc hooks.".to_string(),
                    }
                }
            }
            Err(e) => HostIntegrationStatus {
                host: AgentHost::Kiro,
                is_configured: false,
                hook_path: Some(config_path),
                hook_command: None,
                bypass_risk: true,
                message: format!("Malformed .kiro/hooks/vexa-arc.json: {e}"),
            },
        }
    }
}

impl HostAdapter for KiroAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::Kiro
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = str_field(&val, &["session_id", "sessionId"])
            .unwrap_or("kiro-default")
            .to_string();

        let event_name = str_field(&val, &["trigger", "hook_event_name", "hookEventName"])
            .unwrap_or("PreToolUse");

        if event_name.eq_ignore_ascii_case("UserPromptSubmit") {
            let prompt = str_field(&val, &["prompt", "user_prompt", "text"]).unwrap_or("");
            if prompt.is_empty() {
                return Ok(Vec::new());
            }
            return Ok(vec![ActionEvent::new(
                AgentHost::Kiro,
                session_id,
                principal,
                Phase::Pre,
                Action::PromptSubmit {
                    text: prompt.to_string(),
                    source: Some("user".to_string()),
                },
            )]);
        }

        let is_post = event_name.eq_ignore_ascii_case("PostToolUse");
        let is_mediated = is_post || event_name.eq_ignore_ascii_case("PreToolUse");

        let Some(tool_name) = str_field(&val, &["tool_name", "toolName"]) else {
            if is_mediated {
                return Err(AdapterError::Malformed(format!(
                    "missing tool_name in Kiro {event_name} hook payload"
                )));
            }
            if !Self::is_ignored_lifecycle_event(event_name) {
                eprintln!("[Arc Hook] Ignoring unrecognized Kiro hook event '{event_name}'");
            }
            return Ok(Vec::new());
        };

        let input = val
            .get("tool_input")
            .or_else(|| val.get("toolInput"))
            .or_else(|| val.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        let cwd = str_field(&val, &["cwd"])
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let (phase, action) = if is_post {
            let resp = val
                .get("tool_response")
                .or_else(|| val.get("toolResponse"))
                .unwrap_or(&Value::Null);
            let content = match resp {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let (server, tool) = if let Some((s, t)) = split_mcp_tool(tool_name) {
                (s, t)
            } else if matches!(tool_name, "web_fetch" | "web_search") {
                ("kiro-builtin".to_string(), tool_name.to_string())
            } else {
                return Ok(Vec::new());
            };
            (
                Phase::Post,
                Action::McpToolResult {
                    server: server_identity(server),
                    tool,
                    content,
                    is_error: false,
                },
            )
        } else {
            let tool_lower = tool_name.to_ascii_lowercase();
            let action = match tool_lower.as_str() {
                "shell" | "bash" | "execute_bash" | "run_command" => {
                    let Some(cmd) = str_field(&input, &["command", "cmd"]) else {
                        return Err(AdapterError::Malformed(
                            "missing command in Kiro shell hook payload".to_string(),
                        ));
                    };
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    }
                }
                "read" | "read_file" | "fs_read" => {
                    let Some(p) = str_field(&input, &["path", "file_path", "filePath"]) else {
                        return Err(AdapterError::Malformed(
                            "missing path in Kiro read hook payload".to_string(),
                        ));
                    };
                    Action::FileRead {
                        path: PathBuf::from(p),
                    }
                }
                "write" | "write_file" | "fs_write" | "edit" | "str_replace" => {
                    let Some(p) = str_field(&input, &["path", "file_path", "filePath"]) else {
                        return Err(AdapterError::Malformed(
                            "missing path in Kiro write hook payload".to_string(),
                        ));
                    };
                    let content =
                        str_field(&input, &["content", "file_text", "new_str", "new_string"])
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
                _ => {
                    if let Some((server, tool)) = split_mcp_tool(tool_name) {
                        Action::McpToolCall {
                            server: server_identity(
                                str_field(&val, &["server_name", "serverName"])
                                    .map(|s| s.to_string())
                                    .unwrap_or(server),
                            ),
                            tool,
                            arguments: input,
                        }
                    } else if val.get("server_name").is_some() || val.get("serverName").is_some() {
                        Action::McpToolCall {
                            server: server_identity(
                                str_field(&val, &["server_name", "serverName"])
                                    .unwrap_or("kiro-mcp")
                                    .to_string(),
                            ),
                            tool: tool_name.to_string(),
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
            AgentHost::Kiro,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    /// Encodes Kiro's exit-code-2 blocking semantics (stderr returned to agent).
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
            Verdict::Deny { rule, explanation }
            | Verdict::Quarantine { rule, explanation }
            | Verdict::RequireApproval {
                rule, explanation, ..
            } => HostResponse {
                stdout: Vec::new(),
                stderr: explanation.format_text(rule).into_bytes(),
                exit_code: 2,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kiro_decode_encode_and_install_roundtrip() {
        let adapter = KiroAdapter;
        let payload = br#"{"trigger":"PreToolUse","session_id":"k1","tool_name":"fs_read","tool_input":{"path":".env"}}"#;
        let events = adapter.decode(payload, OsPrincipal::Uid(1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, AgentHost::Kiro);
        assert!(matches!(&events[0].action, Action::FileRead { path } if path.ends_with(".env")));

        let dlp_resp = adapter.encode(&Verdict::Allow {
            obligations: vec![Obligation::Redact {
                spans: vec![(0, 4, "<ARC_SECRET>".to_string())],
            }],
        });
        assert_eq!(dlp_resp.exit_code, 2);

        let dir = std::env::temp_dir().join(format!("arc_kiro_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join(".kiro").join("hooks")).unwrap();
        // Pre-seed a foreign hook to verify preservation
        std::fs::write(
            dir.join(".kiro").join("hooks").join("vexa-arc.json"),
            r#"{"version":"v1","hooks":[{"name":"custom-lint","trigger":"PostFileSave","action":{"type":"command","command":"npm run lint"}}]}"#,
        )
        .unwrap();

        let exe = std::path::Path::new("/usr/local/bin/arc");
        let summary = KiroAdapter::install_integration_with_custom_exe(&dir, Some(exe)).unwrap();
        assert!(summary.backup_path.is_some());
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&summary.config_path).unwrap()).unwrap();
        assert_eq!(v["hooks"].as_array().unwrap().len(), 4);
        assert!(KiroAdapter::check_integration(&dir).is_configured);

        assert!(KiroAdapter::uninstall_integration(&dir).unwrap());
        let v_after: Value =
            serde_json::from_str(&std::fs::read_to_string(&summary.config_path).unwrap()).unwrap();
        assert_eq!(v_after["hooks"].as_array().unwrap().len(), 1);
        assert!(!KiroAdapter::check_integration(&dir).is_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
