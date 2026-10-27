use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use serde_json::Value;
use std::path::PathBuf;

use crate::adapter::{AdapterError, HostAdapter, HostResponse};
use crate::host_config::{
    find_arc_command, read_json_object, upsert_event_entry, write_json_atomic,
};

pub struct CursorAdapter;

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

/// Cursor hook events Arc installs on. Before-hooks enforce; the after-MCP hook reports results
/// so untrusted tool output is tainted.
const BEFORE_EVENTS: [&str; 3] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
];
const AFTER_EVENTS: [&str; 1] = ["afterMCPExecution"];

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

/// Cursor passes `tool_input` as a JSON-encoded string; accept both string and object forms.
fn parse_maybe_json(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(s)) => {
            serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone()))
        }
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

impl HostAdapter for CursorAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::Cursor
    }

    /// Decodes documented Cursor hook payloads (`hook_event_name`, `conversation_id`, `command`,
    /// `cwd`, `tool_name`, `tool_input`, `file_path`, `result_json`) and the legacy flat payload
    /// (`tool`, `args`).
    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("conversation_id")
            .or_else(|| val.get("cursor_session_id"))
            .or_else(|| val.get("session_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("cursor-session")
            .to_string();

        let event_name = val
            .get("hook_event_name")
            .and_then(|s| s.as_str())
            .unwrap_or("");

        let server_name = val
            .get("server")
            .or_else(|| val.get("server_name"))
            .or_else(|| val.get("url"))
            .or_else(|| val.get("server_url"))
            .and_then(|s| s.as_str())
            .unwrap_or("cursor-mcp")
            .to_string();

        let tool = val
            .get("tool_name")
            .or_else(|| val.get("tool"))
            .and_then(|t| t.as_str());

        let (phase, action) = if event_name == "afterMCPExecution" {
            let Some(tool) = tool else {
                return Ok(Vec::new());
            };
            let result = parse_maybe_json(val.get("result_json").or_else(|| val.get("result")));
            let content = match &result {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            (
                Phase::Post,
                Action::McpToolResult {
                    server: server_identity(server_name),
                    tool: tool.to_string(),
                    content,
                    is_error: false,
                },
            )
        } else if let Some(path) = val.get("file_path").and_then(|p| p.as_str()) {
            if event_name == "beforeReadFile" || event_name.is_empty() {
                (
                    Phase::Pre,
                    Action::FileRead {
                        path: PathBuf::from(path),
                    },
                )
            } else {
                // afterFileEdit and similar notifications cannot be blocked; ignore.
                return Ok(Vec::new());
            }
        } else if let Some(cmd) = val.get("command").and_then(|c| c.as_str()) {
            // A bare `command` with a tool name is an stdio MCP server launch descriptor, not a shell.
            if tool.is_some() && event_name == "beforeMCPExecution" {
                let args = parse_maybe_json(val.get("tool_input").or_else(|| val.get("args")));
                (
                    Phase::Pre,
                    Action::McpToolCall {
                        server: server_identity(
                            val.get("server")
                                .and_then(|s| s.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| cmd.to_string()),
                        ),
                        tool: tool.unwrap_or_default().to_string(),
                        arguments: args,
                    },
                )
            } else {
                let cwd = val
                    .get("cwd")
                    .and_then(|c| c.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                (
                    Phase::Pre,
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    },
                )
            }
        } else if let Some(tool) = tool {
            let args = parse_maybe_json(val.get("tool_input").or_else(|| val.get("args")));
            (
                Phase::Pre,
                Action::McpToolCall {
                    server: server_identity(server_name),
                    tool: tool.to_string(),
                    arguments: args,
                },
            )
        } else {
            return Ok(Vec::new());
        };

        Ok(vec![ActionEvent::new(
            AgentHost::Cursor,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    /// Encodes a verdict in Cursor's documented hook response (`permission`, `user_message`,
    /// `agent_message`). Blocking verdicts additionally exit with code 2, which Cursor treats as deny.
    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { obligations } if has_unapplied_redaction(obligations) => {
                let text = DLP_UNAPPLIED_REDACTION_MESSAGE;
                HostResponse {
                    stdout: serde_json::to_vec(&serde_json::json!({
                        "permission": "deny",
                        "user_message": "Blocked by Vexa Arc (ARC-DLP-001): secret detected",
                        "agent_message": text,
                    }))
                    .unwrap_or_default(),
                    stderr: text.as_bytes().to_vec(),
                    exit_code: 2,
                }
            }
            Verdict::Allow { .. } => HostResponse {
                stdout: serde_json::to_vec(&serde_json::json!({"permission": "allow"}))
                    .unwrap_or_default(),
                stderr: Vec::new(),
                exit_code: 0,
            },
            Verdict::Deny { rule, explanation } | Verdict::Quarantine { rule, explanation } => {
                let text = explanation.format_text(rule);
                let payload = serde_json::json!({
                    "permission": "deny",
                    "user_message": format!("Blocked by Vexa Arc ({}): {}", rule.0, explanation.summary),
                    "agent_message": text,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: text.into_bytes(),
                    exit_code: 2,
                }
            }
            Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let payload = serde_json::json!({
                    "permission": "ask",
                    "user_message": format!("Vexa Arc ({}): {}", rule.0, explanation.summary),
                    "agent_message": explanation.format_text(rule),
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

impl CursorAdapter {
    pub const DEFAULT_HOOK_CMD: &'static str = "arc intercept hook --host cursor";
    const LEGACY_KEY: &'static str = "cursor.agent.preHookCommand";

    fn hooks_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".cursor").join("hooks.json")
    }

    fn legacy_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".cursor").join("settings.json")
    }

    /// `failClosed: true` makes Cursor block the action if the hook crashes, times out, or
    /// returns invalid output (Cursor otherwise fails open).
    fn hook_entry() -> Value {
        serde_json::json!({ "command": Self::DEFAULT_HOOK_CMD, "failClosed": true })
    }

    /// Installs enforcement hooks into `.cursor/hooks.json` using Cursor's documented schema.
    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<PathBuf> {
        let config_path = Self::hooks_path(base_dir);
        let mut root = read_json_object(&config_path)?;

        let obj = root.as_object_mut().expect("validated as object");
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::json!(1));
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !hooks.is_object() {
            *hooks = serde_json::json!({});
        }
        for event in BEFORE_EVENTS {
            upsert_event_entry(hooks, event, Some(Self::hook_entry()));
        }
        for event in AFTER_EVENTS {
            // After-hooks only report; they must never break the agent if Arc is unavailable.
            upsert_event_entry(
                hooks,
                event,
                Some(serde_json::json!({ "command": Self::DEFAULT_HOOK_CMD })),
            );
        }

        write_json_atomic(&config_path, &root)?;
        Ok(config_path)
    }

    pub fn uninstall_integration(base_dir: &std::path::Path) -> std::io::Result<bool> {
        let mut modified = false;

        let config_path = Self::hooks_path(base_dir);
        if config_path.exists() {
            let mut root = read_json_object(&config_path)?;
            if let Some(hooks) = root.get_mut("hooks") {
                for event in BEFORE_EVENTS.iter().chain(AFTER_EVENTS.iter()) {
                    modified |= upsert_event_entry(hooks, event, None);
                }
            }
            if modified {
                write_json_atomic(&config_path, &root)?;
            }
        }

        // Remove the invalid legacy setting written by older versions.
        let legacy = Self::legacy_path(base_dir);
        if legacy.exists() {
            if let Ok(mut root) = read_json_object(&legacy) {
                let is_arc = root
                    .get(Self::LEGACY_KEY)
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.contains("arc intercept"));
                if is_arc {
                    if let Some(o) = root.as_object_mut() {
                        o.remove(Self::LEGACY_KEY);
                    }
                    write_json_atomic(&legacy, &root)?;
                    modified = true;
                }
            }
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> crate::adapter::HostIntegrationStatus {
        let config_path = Self::hooks_path(base_dir);
        if !config_path.exists() {
            let has_cursor_rules = base_dir.join(".cursorrules").exists();
            return crate::adapter::HostIntegrationStatus {
                host: AgentHost::Cursor,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: has_cursor_rules,
                message: if has_cursor_rules {
                    ".cursorrules found but .cursor/hooks.json is missing (unprotected Cursor session)".to_string()
                } else {
                    "No .cursor/hooks.json found in target directory".to_string()
                },
            };
        }

        if let Ok(val) = read_json_object(&config_path) {
            let hooks = val.get("hooks");
            let shell = hooks
                .and_then(|h| h.get("beforeShellExecution"))
                .and_then(find_arc_command);
            let mcp = hooks
                .and_then(|h| h.get("beforeMCPExecution"))
                .and_then(find_arc_command);
            let read = hooks
                .and_then(|h| h.get("beforeReadFile"))
                .and_then(find_arc_command);
            let post_mcp = hooks
                .and_then(|h| h.get("afterMCPExecution"))
                .and_then(find_arc_command);
            if let (Some(cmd), Some(_), Some(_), Some(_)) = (shell.clone(), mcp, read, post_mcp) {
                return crate::adapter::HostIntegrationStatus {
                    host: AgentHost::Cursor,
                    is_configured: true,
                    hook_path: Some(config_path),
                    hook_command: Some(cmd),
                    bypass_risk: true,
                    message: "Arc's Cursor shell/MCP/read hooks are active, but ordinary editor file writes are not intercepted; Cursor has no configured pre-file-write hook here.".to_string(),
                };
            }
            if shell.is_some() {
                return crate::adapter::HostIntegrationStatus {
                    host: AgentHost::Cursor,
                    is_configured: false,
                    hook_path: Some(config_path),
                    hook_command: shell,
                    bypass_risk: true,
                    message:
                        "Cursor beforeMCPExecution hook does not invoke Arc (MCP calls unprotected)"
                            .to_string(),
                };
            }
        }

        crate::adapter::HostIntegrationStatus {
            host: AgentHost::Cursor,
            is_configured: false,
            hook_path: Some(config_path),
            hook_command: None,
            bypass_risk: true,
            message:
                ".cursor/hooks.json exists but Arc hooks are missing (unprotected Cursor session)"
                    .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(v: Value) -> Vec<ActionEvent> {
        CursorAdapter
            .decode(v.to_string().as_bytes(), OsPrincipal::Uid(1000))
            .unwrap()
    }

    #[test]
    fn hook_denies_when_redaction_obligation_cannot_be_applied() {
        let verdict = Verdict::Allow {
            obligations: vec![Obligation::Redact {
                spans: vec![(0, 12, "<ARC_SECRET>".to_string())],
            }],
        };

        let response = CursorAdapter.encode(&verdict);
        assert_eq!(response.exit_code, 2);
        let payload: Value = serde_json::from_slice(&response.stdout).unwrap();
        assert_eq!(payload["permission"], "deny");
        assert!(payload["agent_message"]
            .as_str()
            .unwrap()
            .contains("ARC-DLP-001"));
    }

    #[test]
    fn decodes_documented_shell_mcp_and_read_payloads() {
        let s = decode(serde_json::json!({
            "hook_event_name":"beforeShellExecution","conversation_id":"c1",
            "command":"git push","cwd":"/w"
        }));
        assert_eq!(s[0].host_session_id, "c1");
        assert!(matches!(&s[0].action, Action::Shell { command, .. } if command == "git push"));

        let m = decode(serde_json::json!({
            "hook_event_name":"beforeMCPExecution","tool_name":"get_issue",
            "tool_input":"{\"n\":7}","url":"https://mcp.example"
        }));
        match &m[0].action {
            Action::McpToolCall {
                tool,
                arguments,
                server,
            } => {
                assert_eq!(tool, "get_issue");
                assert_eq!(arguments["n"], 7);
                assert_eq!(server.config_name, "https://mcp.example");
            }
            other => panic!("unexpected {other:?}"),
        }

        let r = decode(serde_json::json!({
            "hook_event_name":"beforeReadFile","file_path":"/w/.env","content":"K=V"
        }));
        assert!(matches!(&r[0].action, Action::FileRead { path } if path.ends_with(".env")));
    }

    #[test]
    fn decodes_after_mcp_as_result() {
        let e = decode(serde_json::json!({
            "hook_event_name":"afterMCPExecution","tool_name":"get_issue",
            "tool_input":"{}","result_json":"{\"body\":\"hi\"}"
        }));
        assert!(matches!(&e[0].action, Action::McpToolResult { .. }));
        assert_eq!(e[0].phase, Phase::Post);
    }

    #[test]
    fn install_writes_hooks_json_with_fail_closed() {
        let dir = std::env::temp_dir().join(format!("arc_cursor_schema_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = CursorAdapter::install_integration(&dir).unwrap();
        CursorAdapter::install_integration(&dir).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        let shell = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell.len(), 1);
        assert_eq!(shell[0]["failClosed"], true);
        assert!(v["hooks"]["beforeMCPExecution"].is_array());
        assert!(CursorAdapter::uninstall_integration(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
