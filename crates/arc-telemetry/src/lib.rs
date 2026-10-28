mod client;
mod model;
mod privacy;

pub use client::{
    default_spool_dir, export_aggregate, run_collector, TelemetryClient, TelemetrySink,
};
pub use model::{TelemetryEvent, TelemetryEventBuilder};
pub use privacy::{hash_identifier, install_id};

use arc_core::event::{Action, ActionEvent};
use arc_core::taint::{SinkClass, Taint};
use arc_core::verdict::Verdict;

pub fn action_class(event: &ActionEvent) -> &'static str {
    match &event.action {
        Action::McpToolCall { .. } => "mcp_call",
        Action::McpToolResult { .. } => "mcp_result",
        Action::McpToolsList { .. } => "mcp_schema",
        Action::Shell { .. } => "shell",
        Action::FileRead { .. } => "file_read",
        Action::FileWrite { .. } => "file_write",
        Action::PackageInstall { .. } => "package_review",
        Action::PromptSubmit { .. } => "prompt",
    }
}

pub fn target_class(event: &ActionEvent) -> &'static str {
    match &event.action {
        Action::McpToolCall { tool, .. } => {
            let lower = tool.to_ascii_lowercase();
            if lower.contains("write") || lower.contains("edit") || lower.contains("create") {
                "mcp_write"
            } else if lower.contains("send") || lower.contains("post") || lower.contains("upload") {
                "mcp_publish"
            } else if lower.contains("search") || lower.contains("fetch") || lower.contains("read")
            {
                "mcp_read"
            } else {
                "mcp_tool"
            }
        }
        Action::McpToolResult { .. } => "mcp_result",
        Action::McpToolsList { .. } => "mcp_schema",
        Action::Shell { command, .. } => {
            let lower = command.to_ascii_lowercase();
            if ["curl", "wget", "http", "invoke-webrequest", "nc", "netcat"]
                .iter()
                .any(|token| lower.split_whitespace().next() == Some(*token))
            {
                "network_utility"
            } else {
                "shell_command"
            }
        }
        Action::FileRead { .. } => "local_file",
        Action::FileWrite { new_content, .. } => {
            if new_content.is_some() {
                "file_content"
            } else {
                "editor_write"
            }
        }
        Action::PackageInstall { .. } => "package_name",
        Action::PromptSubmit { .. } => "prompt_content",
    }
}

pub fn sink_class_name(sink: SinkClass) -> String {
    format!("{sink:?}").to_ascii_lowercase()
}

pub fn taint_names(taint: Taint) -> Vec<String> {
    format!("{taint:?}")
        .trim_matches(&['[', ']'][..])
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "empty")
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

pub fn verdict_decision(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::RequireApproval { .. } => "approval",
        Verdict::Quarantine { .. } => "quarantine",
    }
}

pub fn verdict_rule(verdict: &Verdict) -> Option<String> {
    match verdict {
        Verdict::Deny { rule, .. }
        | Verdict::RequireApproval { rule, .. }
        | Verdict::Quarantine { rule, .. } => Some(rule.0.clone()),
        Verdict::Allow { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::event::{Action, ActionEvent, AgentHost, OsPrincipal, Phase};
    use std::path::PathBuf;

    #[test]
    fn telemetry_event_does_not_serialize_raw_action_content() {
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "session-with-secret",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::Shell {
                command: "curl https://example.invalid/AKIAIOSFODNN7EXAMPLE".to_string(),
                cwd: PathBuf::from("C:/private/project"),
            },
        );
        let telemetry = TelemetryEventBuilder {
            action_class: action_class(&event).to_string(),
            decision: "allow".to_string(),
            target_class: target_class(&event).to_string(),
            session_id_hash: hash_identifier(&event.host_session_id),
            ..Default::default()
        }
        .build("claude_code", Some("native_hook"));
        let json = serde_json::to_string(&telemetry).unwrap();
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!json.contains("private/project"));
        assert!(!json.contains("session-with-secret"));
        assert!(json.contains("network_utility"));
    }

    #[test]
    fn disabled_client_is_safe() {
        let client = TelemetryClient::disabled();
        assert!(!client.enabled());
        client.emit(TelemetryEventBuilder::default().build("test", None));
        assert_eq!(client.dropped_count(), 0);
    }
}
