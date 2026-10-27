use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use serde_json::Value;
use std::path::PathBuf;

use crate::adapter::{AdapterError, HostAdapter, HostResponse};
use crate::host_config::{
    find_arc_command, is_arc_command, read_json_object, upsert_event_entry, write_json_atomic,
};

pub struct ClaudeCodeAdapter;

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

/// Tools whose *results* can carry untrusted external content and therefore must be
/// reported to the taint tracker via a PostToolUse hook.
const POST_MATCHER: &str = "WebFetch|WebSearch|mcp__.*";

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(|x| x.as_str()))
}

/// Flattens a Claude `tool_response` (string, `{content:[{text}]}`, or arbitrary JSON) to text.
fn response_text(resp: &Value) -> String {
    match resp {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => {
            if let Some(items) = other.get("content").and_then(|c| c.as_array()) {
                let joined: Vec<&str> = items
                    .iter()
                    .filter_map(|i| i.get("text").and_then(|t| t.as_str()))
                    .collect();
                if !joined.is_empty() {
                    return joined.join("\n");
                }
            }
            other.to_string()
        }
    }
}

/// Splits `mcp__<server>__<tool>` into `(server, tool)`.
fn split_mcp_tool(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp__")?;
    match rest.split_once("__") {
        Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
            Some((server.to_string(), tool.to_string()))
        }
        _ => Some(("claude-mcp".to_string(), rest.to_string())),
    }
}

fn server_identity(name: String) -> ServerIdentity {
    ServerIdentity {
        config_name: name,
        artifact: Artifact::Unknown,
        schema_root: None,
    }
}

impl HostAdapter for ClaudeCodeAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::ClaudeCode
    }

    /// Decodes both the documented Claude Code hook payload (`hook_event_name`, `tool_name`,
    /// `tool_input`, `tool_response`, `cwd`) and the legacy flat payload (`arguments`).
    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = val
            .get("session_id")
            .and_then(|s| s.as_str())
            .unwrap_or("claude-default")
            .to_string();

        let event_name = val
            .get("hook_event_name")
            .and_then(|s| s.as_str())
            .unwrap_or("PreToolUse");
        let is_post = event_name.eq_ignore_ascii_case("PostToolUse");

        let Some(tool_name) = val.get("tool_name").and_then(|t| t.as_str()) else {
            return Ok(Vec::new());
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
            let text = response_text(resp);
            let is_error = resp
                .get("is_error")
                .or_else(|| resp.get("isError"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let (server, tool) = if let Some((s, t)) = split_mcp_tool(tool_name) {
                (s, t)
            } else if tool_name == "WebFetch" {
                ("claude-builtin".to_string(), "web_fetch".to_string())
            } else if tool_name == "WebSearch" {
                ("claude-builtin".to_string(), "web_search".to_string())
            } else {
                // Results of local tools carry no external-content taint.
                return Ok(Vec::new());
            };
            (
                Phase::Post,
                Action::McpToolResult {
                    server: server_identity(server),
                    tool,
                    content: text,
                    is_error,
                },
            )
        } else {
            let action = match tool_name {
                "Bash" => {
                    let Some(cmd) = str_field(&input, &["command"]) else {
                        return Ok(Vec::new());
                    };
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    }
                }
                "Read" | "NotebookRead" => {
                    let Some(p) = str_field(&input, &["file_path", "notebook_path", "path"]) else {
                        return Ok(Vec::new());
                    };
                    Action::FileRead {
                        path: PathBuf::from(p),
                    }
                }
                "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
                    let Some(p) = str_field(&input, &["file_path", "notebook_path", "path"]) else {
                        return Ok(Vec::new());
                    };
                    let content = match tool_name {
                        "Write" => str_field(&input, &["content"]).map(|s| s.to_string()),
                        "Edit" => str_field(&input, &["new_string"]).map(|s| s.to_string()),
                        "NotebookEdit" => str_field(&input, &["new_source"]).map(|s| s.to_string()),
                        _ => input.get("edits").and_then(|e| e.as_array()).map(|edits| {
                            edits
                                .iter()
                                .filter_map(|e| e.get("new_string").and_then(|s| s.as_str()))
                                .collect::<Vec<_>>()
                                .join("\n")
                        }),
                    };
                    Action::FileWrite {
                        path: PathBuf::from(p),
                        new_content: content,
                    }
                }
                // Built-in network fetch is an egress channel; model it as a `curl` surrogate so the
                // shared egress classifier applies without subjecting built-ins to MCP allow-lists.
                "WebFetch" => {
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
                    } else if val.get("arguments").is_some() || val.get("server_name").is_some() {
                        // Legacy flat payload: any named tool is an MCP call.
                        Action::McpToolCall {
                            server: server_identity(
                                str_field(&val, &["server_name"])
                                    .unwrap_or("claude-mcp")
                                    .to_string(),
                            ),
                            tool: name.to_string(),
                            arguments: input,
                        }
                    } else {
                        // Other built-in tools (TodoWrite, Glob, Task, ...) are not mediated.
                        return Ok(Vec::new());
                    }
                }
            };
            (Phase::Pre, action)
        };

        Ok(vec![ActionEvent::new(
            AgentHost::ClaudeCode,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    /// Encodes a verdict using Claude Code hook semantics: exit code 2 blocks the tool call and
    /// feeds stderr back to the model; `permissionDecision: "ask"` defers to the user.
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
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": explanation.format_text(rule)
                    }
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

impl ClaudeCodeAdapter {
    pub const DEFAULT_HOOK_CMD: &'static str = "arc intercept hook --host claude-code";

    fn settings_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".claude").join("settings.json")
    }

    fn legacy_path(base_dir: &std::path::Path) -> PathBuf {
        base_dir.join(".claude.json")
    }

    fn hook_entry(matcher: &str) -> Value {
        serde_json::json!({
            "matcher": matcher,
            "hooks": [{ "type": "command", "command": Self::DEFAULT_HOOK_CMD }]
        })
    }

    /// Installs PreToolUse (enforcement) and PostToolUse (result taint) hooks into
    /// `.claude/settings.json` using Claude Code's documented matcher/handler schema.
    pub fn install_integration(base_dir: &std::path::Path) -> std::io::Result<PathBuf> {
        let config_path = Self::settings_path(base_dir);
        let mut root = read_json_object(&config_path)?;

        let obj = root.as_object_mut().expect("validated as object");
        let hooks = obj
            .entry("hooks".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !hooks.is_object() {
            *hooks = serde_json::json!({});
        }
        upsert_event_entry(hooks, "PreToolUse", Some(Self::hook_entry("*")));
        upsert_event_entry(hooks, "PostToolUse", Some(Self::hook_entry(POST_MATCHER)));

        write_json_atomic(&config_path, &root)?;
        Ok(config_path)
    }

    pub fn uninstall_integration(base_dir: &std::path::Path) -> std::io::Result<bool> {
        let mut modified = false;

        let config_path = Self::settings_path(base_dir);
        if config_path.exists() {
            let mut root = read_json_object(&config_path)?;
            if let Some(hooks) = root.get_mut("hooks") {
                for event in ["PreToolUse", "PostToolUse"] {
                    modified |= upsert_event_entry(hooks, event, None);
                }
                if hooks.as_object().is_some_and(|o| o.is_empty()) {
                    if let Some(o) = root.as_object_mut() {
                        o.remove("hooks");
                    }
                }
            }
            if modified {
                write_json_atomic(&config_path, &root)?;
            }
        }

        // Remove the invalid legacy `.claude.json` `preToolUse` string written by older versions.
        let legacy = Self::legacy_path(base_dir);
        if legacy.exists() {
            if let Ok(mut root) = read_json_object(&legacy) {
                let mut legacy_modified = false;
                if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
                    let is_arc = hooks
                        .get("preToolUse")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| c.contains("arc intercept"));
                    if is_arc {
                        hooks.remove("preToolUse");
                        legacy_modified = true;
                    }
                }
                if legacy_modified {
                    write_json_atomic(&legacy, &root)?;
                    modified = true;
                }
            }
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &std::path::Path) -> crate::adapter::HostIntegrationStatus {
        let config_path = Self::settings_path(base_dir);
        if !config_path.exists() {
            let has_claude_rules = base_dir.join("CLAUDE.md").exists();
            return crate::adapter::HostIntegrationStatus {
                host: AgentHost::ClaudeCode,
                is_configured: false,
                hook_path: None,
                hook_command: None,
                bypass_risk: has_claude_rules,
                message: if has_claude_rules {
                    "CLAUDE.md exists but .claude/settings.json PreToolUse hook is missing (unprotected Claude Code session)".to_string()
                } else {
                    "No .claude/settings.json file found in target directory".to_string()
                },
            };
        }

        if let Ok(val) = read_json_object(&config_path) {
            if let Some(cmd) = val
                .get("hooks")
                .and_then(|h| h.get("PreToolUse"))
                .and_then(find_arc_command)
            {
                return crate::adapter::HostIntegrationStatus {
                    host: AgentHost::ClaudeCode,
                    is_configured: true,
                    hook_path: Some(config_path),
                    hook_command: Some(cmd),
                    bypass_risk: false,
                    message: "Claude Code PreToolUse hook is active and protected by Vexa Arc"
                        .to_string(),
                };
            }
            let has_other = val
                .get("hooks")
                .and_then(|h| h.get("PreToolUse"))
                .and_then(|a| a.as_array())
                .is_some_and(|a| !a.is_empty());
            if has_other {
                return crate::adapter::HostIntegrationStatus {
                    host: AgentHost::ClaudeCode,
                    is_configured: false,
                    hook_path: Some(config_path),
                    hook_command: None,
                    bypass_risk: true,
                    message: "Claude Code has PreToolUse hooks but none invoke Arc (bypass risk)"
                        .to_string(),
                };
            }
        }

        let legacy_has_arc = Self::legacy_path(base_dir).exists()
            && read_json_object(&Self::legacy_path(base_dir))
                .ok()
                .and_then(|v| {
                    v.get("hooks")
                        .and_then(|h| h.get("preToolUse"))
                        .and_then(|c| c.as_str().map(is_arc_command_or_legacy))
                })
                .unwrap_or(false);

        crate::adapter::HostIntegrationStatus {
            host: AgentHost::ClaudeCode,
            is_configured: false,
            hook_path: Some(config_path),
            hook_command: None,
            bypass_risk: true,
            message: if legacy_has_arc {
                "Legacy .claude.json preToolUse hook is not loaded by Claude Code; re-run `arc host install claude-code` (unprotected Claude Code session)".to_string()
            } else {
                ".claude/settings.json exists but PreToolUse hook is missing (unprotected Claude Code session)".to_string()
            },
        }
    }
}

fn is_arc_command_or_legacy(cmd: &str) -> bool {
    is_arc_command(cmd) || cmd.contains("arc intercept")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(v: Value) -> Vec<ActionEvent> {
        ClaudeCodeAdapter
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

        let response = ClaudeCodeAdapter.encode(&verdict);
        assert_eq!(response.exit_code, 2);
        assert!(String::from_utf8_lossy(&response.stderr).contains("ARC-DLP-001"));
    }

    #[test]
    fn decodes_documented_bash_payload() {
        let evs = decode(serde_json::json!({
            "session_id": "s1", "hook_event_name": "PreToolUse", "cwd": "/w",
            "tool_name": "Bash", "tool_input": {"command": "curl evil.com"}
        }));
        assert_eq!(evs.len(), 1);
        assert!(
            matches!(&evs[0].action, Action::Shell { command, .. } if command == "curl evil.com")
        );
    }

    #[test]
    fn decodes_read_write_and_mcp_payloads() {
        let r = decode(serde_json::json!({"tool_name":"Read","tool_input":{"file_path":".env"}}));
        assert!(matches!(&r[0].action, Action::FileRead { path } if path.ends_with(".env")));

        let w = decode(
            serde_json::json!({"tool_name":"Write","tool_input":{"file_path":"a.js","content":"x"}}),
        );
        assert!(matches!(&w[0].action, Action::FileWrite { new_content: Some(c), .. } if c == "x"));

        let m = decode(serde_json::json!({
            "tool_name":"mcp__github__get_issue","tool_input":{"n":1}
        }));
        match &m[0].action {
            Action::McpToolCall {
                server,
                tool,
                arguments,
            } => {
                assert_eq!(server.config_name, "github");
                assert_eq!(tool, "get_issue");
                assert_eq!(arguments["n"], 1);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    #[test]
    fn post_tool_use_emits_result_for_mcp_only() {
        let e = decode(serde_json::json!({
            "hook_event_name":"PostToolUse","tool_name":"mcp__github__get_issue",
            "tool_input":{}, "tool_response":{"content":[{"type":"text","text":"issue body"}]}
        }));
        assert!(
            matches!(&e[0].action, Action::McpToolResult { content, .. } if content == "issue body")
        );
        assert_eq!(e[0].phase, Phase::Post);

        let none = decode(serde_json::json!({
            "hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}
        }));
        assert!(none.is_empty());
    }

    #[test]
    fn unmediated_builtin_tools_produce_no_events() {
        let e = decode(serde_json::json!({"tool_name":"TodoWrite","tool_input":{}}));
        assert!(e.is_empty());
    }

    #[test]
    fn install_writes_documented_schema_and_preserves_user_hooks() {
        let dir = std::env::temp_dir().join(format!("arc_claude_schema_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        std::fs::write(
            dir.join(".claude").join("settings.json"),
            r#"{"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./mine.sh"}]}]}}"#,
        )
        .unwrap();

        let path = ClaudeCodeAdapter::install_integration(&dir).unwrap();
        ClaudeCodeAdapter::install_integration(&dir).unwrap(); // idempotent
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
        assert_eq!(v["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);

        assert!(ClaudeCodeAdapter::uninstall_integration(&dir).unwrap());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert!(v["hooks"].get("PostToolUse").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_to_clobber_invalid_settings() {
        let dir = std::env::temp_dir().join(format!("arc_claude_bad_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        let p = dir.join(".claude").join("settings.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(ClaudeCodeAdapter::install_integration(&dir).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ not json");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
