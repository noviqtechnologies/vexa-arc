use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::adapter::{AdapterError, HostAdapter, HostIntegrationStatus, HostResponse};
use crate::host_config::{
    format_posix_hook_command, format_powershell_hook_command, resolve_canonical_arc_binary,
    validate_binary_path_safe, HostInstallSummary,
};

/// Native host adapter for Cline (`.clinerules/hooks/`).
///
/// Installs cross-platform Arc-managed wrapper scripts:
/// - POSIX shell scripts (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, mode `0755` on Unix)
/// - Windows PowerShell scripts (`PreToolUse.ps1`, `PostToolUse.ps1`, `UserPromptSubmit.ps1`)
///
/// Refuses to overwrite existing non-Arc user scripts so custom hooks are never clobbered.
pub struct ClineAdapter;

const ARC_SCRIPT_MARKER: &str = "# vexa-arc-managed-hook";
const HOOK_EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "UserPromptSubmit"];

const DLP_UNAPPLIED_REDACTION_MESSAGE: &str = concat!(
    "[ARC-DLP-001] Secret detected; this hook cannot safely rewrite the action, ",
    "so it was blocked. Remove the secret or use a mediated redaction-capable MCP transport."
);

const IGNORED_LIFECYCLE_EVENTS: [&str; 5] = [
    "TaskStart",
    "TaskResume",
    "TaskCancel",
    "TaskComplete",
    "PreCompact",
];

fn has_unapplied_redaction(obligations: &[Obligation]) -> bool {
    obligations.iter().any(|obligation| match obligation {
        Obligation::Redact { spans } => !spans.is_empty(),
        _ => false,
    })
}

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

fn write_atomic_script(path: &Path, contents: &str, executable: bool) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".arc-tmp.{}", uuid::Uuid::now_v7()));
    std::fs::write(&tmp, contents.as_bytes())?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    let _ = executable;

    if let Err(first) = std::fs::rename(&tmp, path) {
        #[cfg(windows)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
                if std::fs::rename(&tmp, path).is_ok() {
                    return Ok(());
                }
            }
        }
        let _ = std::fs::remove_file(&tmp);
        return Err(first);
    }
    Ok(())
}

impl ClineAdapter {
    pub fn is_ignored_lifecycle_event(event_name: &str) -> bool {
        IGNORED_LIFECYCLE_EVENTS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(event_name))
    }

    fn hooks_dir(base_dir: &Path) -> PathBuf {
        base_dir.join(".clinerules").join("hooks")
    }

    fn posix_wrapper(exe_path: &Path) -> String {
        let cmd = format_posix_hook_command(exe_path, "cline");
        format!("#!/usr/bin/env sh\n{ARC_SCRIPT_MARKER}\nexec {cmd}\n")
    }

    fn powershell_wrapper(exe_path: &Path) -> String {
        let cmd = format_powershell_hook_command(exe_path, "cline");
        format!(
            "{ARC_SCRIPT_MARKER}\n$ErrorActionPreference = 'Stop'\n$input | {cmd}\nexit $LASTEXITCODE\n"
        )
    }

    fn ensure_safe_to_write(path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let existing = std::fs::read_to_string(path)?;
        if existing.contains(ARC_SCRIPT_MARKER) {
            return Ok(());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} already exists and is not managed by Vexa Arc; refusing to overwrite user hook script",
                path.display()
            ),
        ))
    }

    pub fn install_integration(base_dir: &Path) -> std::io::Result<HostInstallSummary> {
        Self::install_integration_with_custom_exe(base_dir, None)
    }

    pub fn install_integration_with_custom_exe(
        base_dir: &Path,
        custom_exe: Option<&Path>,
    ) -> std::io::Result<HostInstallSummary> {
        let hooks_dir = Self::hooks_dir(base_dir);
        let (exe_path, volatile_warning) = match custom_exe {
            Some(p) => (validate_binary_path_safe(p)?, None),
            None => {
                let (p, w) = resolve_canonical_arc_binary()?;
                (validate_binary_path_safe(&p)?, w)
            }
        };

        // Preflight all target files before writing any of them
        for event in HOOK_EVENTS {
            Self::ensure_safe_to_write(&hooks_dir.join(event))?;
            Self::ensure_safe_to_write(&hooks_dir.join(format!("{event}.ps1")))?;
        }

        let sh_body = Self::posix_wrapper(&exe_path);
        let ps_body = Self::powershell_wrapper(&exe_path);

        for event in HOOK_EVENTS {
            write_atomic_script(&hooks_dir.join(event), &sh_body, true)?;
            write_atomic_script(&hooks_dir.join(format!("{event}.ps1")), &ps_body, false)?;
        }

        let hook_cmd = if cfg!(windows) {
            format_powershell_hook_command(&exe_path, "cline")
        } else {
            format_posix_hook_command(&exe_path, "cline")
        };

        Ok(HostInstallSummary {
            host: AgentHost::Cline,
            config_path: hooks_dir,
            backup_path: None,
            executable_path: exe_path,
            hook_command: hook_cmd,
            volatile_warning,
        })
    }

    pub fn uninstall_integration(base_dir: &Path) -> std::io::Result<bool> {
        let hooks_dir = Self::hooks_dir(base_dir);
        if !hooks_dir.exists() {
            return Ok(false);
        }
        let mut modified = false;
        for event in HOOK_EVENTS {
            for candidate in [
                hooks_dir.join(event),
                hooks_dir.join(format!("{event}.ps1")),
            ] {
                if candidate.exists() {
                    if let Ok(content) = std::fs::read_to_string(&candidate) {
                        if content.contains(ARC_SCRIPT_MARKER) {
                            std::fs::remove_file(&candidate)?;
                            modified = true;
                        }
                    }
                }
            }
        }
        Ok(modified)
    }

    pub fn check_integration(base_dir: &Path) -> HostIntegrationStatus {
        let hooks_dir = Self::hooks_dir(base_dir);
        let primary = if cfg!(windows) {
            hooks_dir.join("PreToolUse.ps1")
        } else {
            hooks_dir.join("PreToolUse")
        };
        let secondary = if cfg!(windows) {
            hooks_dir.join("PreToolUse")
        } else {
            hooks_dir.join("PreToolUse.ps1")
        };

        for candidate in [&primary, &secondary] {
            if let Ok(content) = std::fs::read_to_string(candidate) {
                if content.contains(ARC_SCRIPT_MARKER) && content.contains("intercept hook") {
                    return HostIntegrationStatus {
                        host: AgentHost::Cline,
                        is_configured: true,
                        hook_path: Some(candidate.clone()),
                        hook_command: Some("arc intercept hook --host cline".to_string()),
                        bypass_risk: false,
                        message: "Cline PreToolUse hook active (cross-platform sh + ps1)."
                            .to_string(),
                    };
                }
            }
        }

        let has_cline = base_dir.join(".clinerules").exists() || base_dir.join(".cline").exists();
        HostIntegrationStatus {
            host: AgentHost::Cline,
            is_configured: false,
            hook_path: if hooks_dir.exists() {
                Some(hooks_dir)
            } else {
                None
            },
            hook_command: None,
            bypass_risk: has_cline,
            message: if has_cline {
                ".clinerules/.cline exists without Arc PreToolUse hook (unprotected Cline session)."
                    .to_string()
            } else {
                "No .clinerules/hooks/PreToolUse hook found.".to_string()
            },
        }
    }
}

impl HostAdapter for ClineAdapter {
    fn host(&self) -> AgentHost {
        AgentHost::Cline
    }

    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError> {
        let val: Value =
            serde_json::from_slice(raw).map_err(|e| AdapterError::Malformed(e.to_string()))?;

        let session_id = str_field(&val, &["taskId", "session_id", "sessionId"])
            .unwrap_or("cline-default")
            .to_string();

        let event_name = str_field(&val, &["hookName", "hook_event_name"]).unwrap_or_else(|| {
            if val.get("postToolUse").is_some() {
                "PostToolUse"
            } else if val.get("userPromptSubmit").is_some() {
                "UserPromptSubmit"
            } else {
                "PreToolUse"
            }
        });

        if event_name.eq_ignore_ascii_case("UserPromptSubmit") {
            let prompt_obj = val.get("userPromptSubmit").unwrap_or(&val);
            let prompt = str_field(prompt_obj, &["prompt", "text"]).unwrap_or("");
            if prompt.is_empty() {
                return Ok(Vec::new());
            }
            return Ok(vec![ActionEvent::new(
                AgentHost::Cline,
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

        let nested = if is_post {
            val.get("postToolUse")
                .or_else(|| val.get("tool_call"))
                .unwrap_or(&val)
        } else {
            val.get("preToolUse")
                .or_else(|| val.get("tool_call"))
                .unwrap_or(&val)
        };

        let Some(tool_name) = str_field(nested, &["toolName", "name", "tool_name"])
            .or_else(|| str_field(&val, &["tool_name", "toolName"]))
        else {
            if is_mediated {
                return Err(AdapterError::Malformed(format!(
                    "missing toolName in Cline {event_name} hook payload"
                )));
            }
            if !Self::is_ignored_lifecycle_event(event_name) {
                eprintln!("[Arc Hook] Ignoring unrecognized Cline hook event '{event_name}'");
            }
            return Ok(Vec::new());
        };

        let params = nested
            .get("parameters")
            .or_else(|| nested.get("input"))
            .or_else(|| val.get("tool_input"))
            .cloned()
            .unwrap_or(Value::Null);

        let cwd = val
            .get("workspaceRoots")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.as_str())
            .or_else(|| str_field(&val, &["cwd"]))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));

        let (phase, action) = if is_post {
            let result_text = nested
                .get("result")
                .or_else(|| val.get("tool_response"))
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            let is_error = nested
                .get("success")
                .and_then(|b| b.as_bool())
                .map(|s| !s)
                .unwrap_or(false);

            match tool_name {
                "use_mcp_tool" | "access_mcp_resource" => {
                    let server = str_field(&params, &["server_name", "serverName"])
                        .unwrap_or("cline-mcp")
                        .to_string();
                    let tool = str_field(&params, &["tool_name", "toolName", "uri"])
                        .unwrap_or(tool_name)
                        .to_string();
                    (
                        Phase::Post,
                        Action::McpToolResult {
                            server: server_identity(server),
                            tool,
                            content: result_text,
                            is_error,
                        },
                    )
                }
                "web_fetch" | "browser_action" => (
                    Phase::Post,
                    Action::McpToolResult {
                        server: server_identity("cline-builtin".to_string()),
                        tool: tool_name.to_string(),
                        content: result_text,
                        is_error,
                    },
                ),
                _ => return Ok(Vec::new()),
            }
        } else {
            let action = match tool_name {
                "execute_command" | "run_commands" | "bash" | "shell" => {
                    let Some(cmd) = str_field(&params, &["command", "cmd"]) else {
                        return Err(AdapterError::Malformed(
                            "missing command in Cline execute_command hook payload".to_string(),
                        ));
                    };
                    Action::Shell {
                        command: cmd.to_string(),
                        cwd,
                    }
                }
                "read_file" => {
                    let Some(p) = str_field(&params, &["path", "file_path"]) else {
                        return Err(AdapterError::Malformed(
                            "missing path in Cline read_file hook payload".to_string(),
                        ));
                    };
                    Action::FileRead {
                        path: PathBuf::from(p),
                    }
                }
                "write_to_file" | "replace_in_file" | "write_file" | "edit_file" => {
                    let Some(p) = str_field(&params, &["path", "file_path"]) else {
                        return Err(AdapterError::Malformed(format!(
                            "missing path in Cline {tool_name} hook payload"
                        )));
                    };
                    let content = str_field(&params, &["content", "diff", "new_string"])
                        .map(|s| s.to_string());
                    Action::FileWrite {
                        path: PathBuf::from(p),
                        new_content: content,
                    }
                }
                "use_mcp_tool" => {
                    let server = str_field(&params, &["server_name", "serverName"])
                        .unwrap_or("cline-mcp")
                        .to_string();
                    let Some(tool) = str_field(&params, &["tool_name", "toolName"]) else {
                        return Err(AdapterError::Malformed(
                            "missing tool_name in Cline use_mcp_tool hook payload".to_string(),
                        ));
                    };
                    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                    Action::McpToolCall {
                        server: server_identity(server),
                        tool: tool.to_string(),
                        arguments,
                    }
                }
                "access_mcp_resource" => {
                    let server = str_field(&params, &["server_name", "serverName"])
                        .unwrap_or("cline-mcp")
                        .to_string();
                    let uri = str_field(&params, &["uri"]).unwrap_or("resource");
                    Action::McpToolCall {
                        server: server_identity(server),
                        tool: format!("resource:{uri}"),
                        arguments: params,
                    }
                }
                "web_fetch" => {
                    let url = str_field(&params, &["url"]).unwrap_or("");
                    Action::Shell {
                        command: format!("curl {url}"),
                        cwd,
                    }
                }
                _ => return Ok(Vec::new()),
            };
            (Phase::Pre, action)
        };

        Ok(vec![ActionEvent::new(
            AgentHost::Cline,
            session_id,
            principal,
            phase,
            action,
        )])
    }

    /// Encodes Cline's documented stdout JSON protocol (`{"cancel": true|false, "errorMessage": "..."}`).
    fn encode(&self, verdict: &Verdict) -> HostResponse {
        match verdict {
            Verdict::Allow { obligations } if has_unapplied_redaction(obligations) => {
                let payload = serde_json::json!({
                    "cancel": true,
                    "errorMessage": DLP_UNAPPLIED_REDACTION_MESSAGE,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: DLP_UNAPPLIED_REDACTION_MESSAGE.as_bytes().to_vec(),
                    exit_code: 0,
                }
            }
            Verdict::Allow { .. } => HostResponse {
                stdout: serde_json::to_vec(&serde_json::json!({"cancel": false}))
                    .unwrap_or_default(),
                stderr: Vec::new(),
                exit_code: 0,
            },
            Verdict::Deny { rule, explanation }
            | Verdict::Quarantine { rule, explanation }
            | Verdict::RequireApproval {
                rule, explanation, ..
            } => {
                let reason = explanation.format_text(rule);
                let payload = serde_json::json!({
                    "cancel": true,
                    "errorMessage": reason,
                });
                HostResponse {
                    stdout: serde_json::to_vec(&payload).unwrap_or_default(),
                    stderr: reason.into_bytes(),
                    exit_code: 0,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cline_decode_encode_and_cross_platform_install_roundtrip() {
        let adapter = ClineAdapter;
        let payload = br#"{"hookName":"PreToolUse","taskId":"t1","workspaceRoots":["/repo"],"preToolUse":{"toolName":"execute_command","parameters":{"command":"rm -rf /tmp/prod"}}}"#;
        let events = adapter.decode(payload, OsPrincipal::Uid(1000)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].host, AgentHost::Cline);
        assert!(
            matches!(&events[0].action, Action::Shell { command, .. } if command.contains("rm -rf"))
        );

        let mcp_payload = br#"{"hookName":"PreToolUse","taskId":"t1","preToolUse":{"toolName":"use_mcp_tool","parameters":{"server_name":"slack","tool_name":"post_message","arguments":{"text":"hi"}}}}"#;
        let mcp_ev = adapter.decode(mcp_payload, OsPrincipal::Uid(1000)).unwrap();
        assert!(
            matches!(&mcp_ev[0].action, Action::McpToolCall { server, tool, .. } if server.config_name == "slack" && tool == "post_message")
        );

        let allow_resp = adapter.encode(&Verdict::Allow {
            obligations: vec![],
        });
        assert_eq!(allow_resp.exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&allow_resp.stdout),
            r#"{"cancel":false}"#
        );

        let dlp_resp = adapter.encode(&Verdict::Allow {
            obligations: vec![Obligation::Redact {
                spans: vec![(0, 5, "<ARC_SECRET>".to_string())],
            }],
        });
        assert!(String::from_utf8_lossy(&dlp_resp.stdout).contains("\"cancel\":true"));

        let dir = std::env::temp_dir().join(format!("arc_cline_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = Path::new("/usr/local/bin/arc");
        ClineAdapter::install_integration_with_custom_exe(&dir, Some(exe)).unwrap();
        assert!(dir.join(".clinerules/hooks/PreToolUse").exists());
        assert!(dir.join(".clinerules/hooks/PreToolUse.ps1").exists());
        assert!(ClineAdapter::check_integration(&dir).is_configured);

        assert!(ClineAdapter::uninstall_integration(&dir).unwrap());
        assert!(!ClineAdapter::check_integration(&dir).is_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cline_refuses_to_clobber_user_written_hook_script() {
        let dir = std::env::temp_dir().join(format!("arc_cline_user_{}", uuid::Uuid::now_v7()));
        let hooks = dir.join(".clinerules").join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("PreToolUse"), "#!/bin/sh\necho custom\n").unwrap();

        let err =
            ClineAdapter::install_integration_with_custom_exe(&dir, Some(Path::new("/bin/arc")));
        assert!(err.is_err());
        assert_eq!(
            std::fs::read_to_string(hooks.join("PreToolUse")).unwrap(),
            "#!/bin/sh\necho custom\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
