pub mod adapter;
pub mod broker;
pub mod claude_code;
pub mod cursor;
pub mod mcp_jsonrpc;

pub use adapter::{AdapterError, HostAdapter, HostResponse};
pub use broker::{BrokerError, ClientMessageOutcome, McpStdioBroker, ServerMessageOutcome};
pub use claude_code::ClaudeCodeAdapter;
pub use cursor::CursorAdapter;
pub use mcp_jsonrpc::McpJsonRpcInterceptor;

#[cfg(test)]
mod tests {
    use super::*;
    use arc_policy_engine::evaluator::{PolicyConfig, PolicyEvaluator};
    use std::collections::HashSet;

    #[test]
    fn test_broker_runtime_schema_capture_and_jcs_fingerprint() {
        let evaluator = PolicyEvaluator::default();
        let mut broker = McpStdioBroker::new("test-mcp", "sess-broker-test", evaluator);

        let server_tools_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "calculate",
                        "description": "Performs math calculations",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        });

        let line = server_tools_payload.to_string();
        let outcome = broker.handle_server_message(&line);
        if let ServerMessageOutcome::CapturedSchema {
            fingerprint,
            forward_line,
        } = outcome
        {
            assert_eq!(broker.current_schema_hash, Some(fingerprint));
            assert_eq!(forward_line, line);
        } else {
            panic!("Expected CapturedSchema outcome from server tools payload");
        }
    }

    #[test]
    fn test_broker_intercept_and_block_unapproved_server() {
        let mut allowed = HashSet::new();
        allowed.insert("approved-mcp".to_string());
        let cfg = PolicyConfig {
            allowed_mcp_servers: allowed,
            block_unapproved_mcp: true,
            ..Default::default()
        };
        let evaluator = PolicyEvaluator::new(cfg);
        let mut broker = McpStdioBroker::new("unapproved-rogue", "sess-broker-block", evaluator);

        let call_line = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "execute_shell",
                "arguments": { "command": "whoami" }
            }
        })
        .to_string();

        let outcome = broker.handle_client_message(&call_line);
        match outcome {
            ClientMessageOutcome::RespondLocally(resp) => {
                assert_eq!(resp.get("id"), Some(&serde_json::json!("call-1")));
                let is_error = resp
                    .get("result")
                    .and_then(|r| r.get("isError"))
                    .and_then(|e| e.as_bool());
                assert_eq!(is_error, Some(true));
                assert_eq!(broker.requests_blocked, 1);
            }
            _ => panic!("Expected RespondLocally when server is unapproved"),
        }
    }

    #[test]
    fn test_broker_dlp_secret_redaction_before_forwarding() {
        let evaluator = PolicyEvaluator::default();
        let mut broker = McpStdioBroker::new("github", "sess-broker-dlp", evaluator);

        let call_with_secret = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "call-secret",
            "method": "tools/call",
            "params": {
                "name": "post_issue",
                "arguments": {
                    "text": "Leaked key: AKIAIOSFODNN7EXAMPLE in code"
                }
            }
        })
        .to_string();

        let outcome = broker.handle_client_message(&call_with_secret);
        match outcome {
            ClientMessageOutcome::Forward(forwarded) => {
                assert!(
                    !forwarded.contains("AKIAIOSFODNN7EXAMPLE"),
                    "Secret must be redacted before forwarding!"
                );
                assert!(
                    forwarded.contains("<ARC_SECRET:"),
                    "Forwarded payload must contain redaction token"
                );
                assert_eq!(broker.secrets_redacted, 1);
            }
            _ => panic!("Expected Forward with redacted payload"),
        }
    }
}
