use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::Verdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

pub struct McpJsonRpcInterceptor;

impl McpJsonRpcInterceptor {
    /// Parses an incoming JSON-RPC request from an agent to an MCP server into an ActionEvent.
    pub fn parse_request(
        raw_bytes: &[u8],
        server_name: &str,
        session_id: &str,
    ) -> Result<(JsonRpcRequest, ActionEvent), String> {
        let req: JsonRpcRequest =
            serde_json::from_slice(raw_bytes).map_err(|e| format!("Invalid JSON-RPC: {e}"))?;

        let action = if req.method == "tools/call" {
            let params = req.params.clone().unwrap_or(serde_json::Value::Null);
            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown_tool")
                .to_string();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: server_name.to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: tool_name,
                arguments: args,
            }
        } else if req.method == "tools/list" {
            Action::McpToolsList {
                server: ServerIdentity {
                    config_name: server_name.to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tools_json: String::new(),
            }
        } else {
            return Err(format!("Unsupported method: {}", req.method));
        };

        let event = ActionEvent::new(
            AgentHost::CustomMcpClient,
            session_id,
            OsPrincipal::Uid(1000),
            Phase::Pre,
            action,
        );

        Ok((req, event))
    }

    /// Formats a Verdict into a valid JSON-RPC 2.0 tool execution response.
    /// When denied, it returns a 2.0 result with `isError: true` so the agent model
    /// can receive the structured explanation directly in its context window and adapt!
    pub fn format_response(req_id: &serde_json::Value, verdict: &Verdict) -> serde_json::Value {
        match verdict {
            Verdict::Allow { obligations } => {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "status": "allowed",
                        "obligations": obligations
                    }
                })
            }
            Verdict::Deny { rule, explanation } => {
                let text = explanation.format_text(rule);
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": true,
                        "content": [
                            {
                                "type": "text",
                                "text": text
                            }
                        ]
                    }
                })
            }
            Verdict::Quarantine { rule, explanation } => {
                let text = format!("QUARANTINED: {}", explanation.format_text(rule));
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": true,
                        "content": [
                            {
                                "type": "text",
                                "text": text
                            }
                        ]
                    }
                })
            }
            Verdict::RequireApproval {
                rule,
                explanation,
                timeout_secs,
                ..
            } => {
                let text = format!(
                    "APPROVAL REQUIRED (timeout: {}s): {}",
                    timeout_secs,
                    explanation.format_text(rule)
                );
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": true,
                        "content": [
                            {
                                "type": "text",
                                "text": text
                            }
                        ]
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::verdict::{Explanation, RuleId};

    #[test]
    fn test_mcp_jsonrpc_parse_and_error_response() {
        let req_json = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"slack_post","arguments":{"msg":"hello"}}}"#;
        let (req, event) =
            McpJsonRpcInterceptor::parse_request(req_json, "slack", "session-42").unwrap();

        assert_eq!(req.id, serde_json::json!(42));
        if let Action::McpToolCall { tool, .. } = event.action {
            assert_eq!(tool, "slack_post");
        } else {
            panic!("Expected McpToolCall");
        }

        let deny = Verdict::Deny {
            rule: RuleId("ARC-LTT-001".to_string()),
            explanation: Explanation::new(
                "Lethal Trifecta triggered",
                vec!["Check logs".to_string()],
                None,
            ),
        };

        let resp = McpJsonRpcInterceptor::format_response(&req.id, &deny);
        assert_eq!(resp["result"]["isError"], true);
        let content_str = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_str.contains("ARC-LTT-001"));
        assert!(content_str.contains("Lethal Trifecta triggered"));
    }
}
