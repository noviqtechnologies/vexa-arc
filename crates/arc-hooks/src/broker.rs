use arc_core::capability::Capability;
use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Explanation, Obligation, RuleId, Verdict};
use arc_policy_engine::evaluator::PolicyEvaluator;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;

use crate::process_containment::{ContainmentLimits, OsProcessSupervisor};

/// Upper bound on in-flight `tools/call` requests tracked for result taint attribution.
const MAX_PENDING_CALLS: usize = 4096;

fn command_fingerprint(command: &[String]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"VEXA-ARC-MCP-COMMAND-ARGV\0v1");
    for part in command {
        let bytes = part.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("Failed to spawn child MCP server: {0}")]
    SpawnError(#[from] std::io::Error),

    #[error("Child process terminated unexpectedly")]
    ChildTerminated,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Payload exceeded maximum allowed size: {0} bytes")]
    PayloadTooLarge(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientMessageOutcome {
    /// Action is permitted; forward the (possibly redacted) line to child server
    Forward(String),
    /// Action was blocked or quarantined; send structured error directly to client
    RespondLocally(Value),
    /// Malformed line or protocol violation
    ProtocolError(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessageOutcome {
    /// Forward message to client
    Forward(String),
    /// Updated schema detected and captured
    CapturedSchema {
        fingerprint: [u8; 32],
        forward_line: String,
    },
}

pub struct McpStdioBroker {
    pub server_name: String,
    pub session_id: String,
    pub evaluator: PolicyEvaluator,
    pub command: Vec<String>,
    pub max_payload_bytes: usize,
    pub current_schema_hash: Option<[u8; 32]>,
    pub requests_processed: usize,
    pub requests_blocked: usize,
    pub secrets_redacted: usize,
    /// When set, the first (and every later) `tools/list` schema must hash to this value.
    pub pinned_schema_hash: Option<[u8; 32]>,
    /// When true, a trusted pin is mandatory and TOFU is not accepted.
    schema_pin_required: bool,
    /// Set once a `tools/list` response failed the pin check; all tool calls are then denied.
    pub schema_pin_violated: bool,
    pub limits: ContainmentLimits,
    /// In-flight `tools/call` request id (JSON text) -> tool name, for result taint attribution.
    pending_calls: HashMap<String, String>,
}

impl McpStdioBroker {
    pub fn new(
        server_name: impl Into<String>,
        session_id: impl Into<String>,
        evaluator: PolicyEvaluator,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            session_id: session_id.into(),
            evaluator,
            command: Vec::new(),
            max_payload_bytes: 10 * 1024 * 1024, // 10MB limit (NFR-PERF-003)
            current_schema_hash: None,
            requests_processed: 0,
            requests_blocked: 0,
            secrets_redacted: 0,
            pinned_schema_hash: None,
            schema_pin_required: true,
            schema_pin_violated: false,
            limits: ContainmentLimits::default(),
            pending_calls: HashMap::new(),
        }
    }

    pub fn with_command(mut self, command: Vec<String>) -> Self {
        self.command = command;
        self
    }

    pub fn with_max_payload(mut self, max_bytes: usize) -> Self {
        self.max_payload_bytes = max_bytes;
        self
    }

    /// Requires the server's `tools/list` JCS schema hash to equal `hash` (trust anchor for the
    /// initial schema; without it the first observed schema is simply trusted-on-first-use).
    pub fn with_pinned_schema(mut self, hash: [u8; 32]) -> Self {
        self.pinned_schema_hash = Some(hash);
        self
    }

    /// Requires an externally provisioned schema pin; the first observed schema is not trusted.
    pub fn require_schema_pin(mut self) -> Self {
        self.schema_pin_required = true;
        self
    }

    /// Explicitly enables trust-on-first-use for controlled development/bootstrap only.
    pub fn allow_schema_tofu(mut self) -> Self {
        self.schema_pin_required = false;
        self
    }

    pub fn with_limits(mut self, limits: ContainmentLimits) -> Self {
        self.limits = limits;
        self
    }

    fn deny_verdict(rule: &str, summary: String, options: Vec<String>) -> Verdict {
        Verdict::Deny {
            rule: RuleId(rule.to_string()),
            explanation: Explanation::new(
                summary,
                options,
                Some(format!("https://docs.vexa.ai/arc/policies/{rule}")),
            ),
        }
    }

    /// Processes an incoming message from the host agent to the MCP server.
    /// If blocked by policy or schema rug-pull, returns RespondLocally without forwarding.
    pub fn handle_client_message(&mut self, line: &str) -> ClientMessageOutcome {
        if line.len() > self.max_payload_bytes {
            return ClientMessageOutcome::ProtocolError(format!(
                "Payload size {} exceeds maximum limit of {} bytes",
                line.len(),
                self.max_payload_bytes
            ));
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ClientMessageOutcome::Forward(line.to_string());
        }

        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => return ClientMessageOutcome::ProtocolError(format!("Malformed JSON: {e}")),
        };

        self.requests_processed += 1;

        let method = parsed.get("method").and_then(|m| m.as_str());
        let req_id = parsed.get("id").cloned().unwrap_or(Value::Null);

        match method {
            Some("tools/call") => {
                if self.schema_pin_violated
                    || (self.schema_pin_required && self.current_schema_hash.is_none())
                {
                    self.requests_blocked += 1;
                    let verdict = Self::deny_verdict(
                        "ARC-MCP-003",
                        format!(
                            "MCP server '{}' cannot be used because its schema has not passed a trusted pin check; tool calls are disabled.",
                            self.server_name,
                        ),
                        vec![
                            "Verify the server binary/version and update the pinned schema hash."
                                .to_string(),
                        ],
                    );
                    return ClientMessageOutcome::RespondLocally(
                        crate::mcp_jsonrpc::McpJsonRpcInterceptor::format_response(
                            &req_id, &verdict,
                        ),
                    );
                }

                let params = parsed.get("params").cloned().unwrap_or(Value::Null);
                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown_tool")
                    .to_string();
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);

                let caps = Capability::infer(&tool_name, false, false, false);

                let artifact = if !self.command.is_empty() {
                    Artifact::Local {
                        command_sha256: command_fingerprint(&self.command),
                    }
                } else {
                    Artifact::Unknown
                };

                let action = Action::McpToolCall {
                    server: ServerIdentity {
                        config_name: self.server_name.clone(),
                        artifact,
                        schema_root: self.current_schema_hash,
                    },
                    tool: tool_name.clone(),
                    arguments: args.clone(),
                };

                let event = ActionEvent::new(
                    AgentHost::ClaudeCode,
                    &self.session_id,
                    OsPrincipal::Uid(1000),
                    Phase::Pre,
                    action,
                )
                .with_capabilities(caps)
                .with_transport("stdio");

                let verdict = self.evaluator.evaluate(&event);

                if verdict.is_denied() {
                    self.requests_blocked += 1;
                    let local_resp = crate::mcp_jsonrpc::McpJsonRpcInterceptor::format_response(
                        &req_id, &verdict,
                    );
                    return ClientMessageOutcome::RespondLocally(local_resp);
                }

                // Remember the call so its result can be attributed (and taint-classified).
                if !req_id.is_null() {
                    if self.pending_calls.len() >= MAX_PENDING_CALLS {
                        self.pending_calls.clear();
                    }
                    self.pending_calls
                        .insert(req_id.to_string(), tool_name.clone());
                }

                // If allowed with DLP obligations, redact arguments before forwarding!
                if let Verdict::Allow { ref obligations } = verdict {
                    let mut modified_args = args;
                    for ob in obligations {
                        if let Obligation::Redact { spans } = ob {
                            if !spans.is_empty() {
                                self.secrets_redacted += spans.len();
                                // Redact secret spans in the JSON arguments string
                                let mut args_str = modified_args.to_string();
                                for (start, end, token) in spans.iter().rev() {
                                    if *start < args_str.len()
                                        && *end <= args_str.len()
                                        && start <= end
                                    {
                                        args_str.replace_range(*start..*end, token);
                                    }
                                }
                                if let Ok(redacted_val) = serde_json::from_str(&args_str) {
                                    modified_args = redacted_val;
                                }
                            }
                        }
                    }

                    let mut forward_val = parsed.clone();
                    if let Some(params_obj) = forward_val
                        .get_mut("params")
                        .and_then(|p| p.as_object_mut())
                    {
                        params_obj.insert("arguments".to_string(), modified_args);
                    }

                    return ClientMessageOutcome::Forward(forward_val.to_string());
                }

                ClientMessageOutcome::Forward(line.to_string())
            }
            _ => ClientMessageOutcome::Forward(line.to_string()),
        }
    }

    /// Flattens an MCP `tools/call` result (`content[].text`, `structuredContent`, or raw JSON).
    fn result_text(result: &Value) -> String {
        if let Some(items) = result.get("content").and_then(|c| c.as_array()) {
            let texts: Vec<&str> = items
                .iter()
                .filter_map(|i| i.get("text").and_then(|t| t.as_str()))
                .collect();
            if !texts.is_empty() {
                return texts.join("\n");
            }
        }
        result.to_string()
    }

    /// Processes a message emitted by the MCP server child process.
    /// * Intercepts runtime tool schemas from `tools/list` responses to compute the RFC 8785 JCS
    ///   fingerprint (and enforce the optional schema pin).
    /// * Routes `tools/call` results through the taint classifier so externally-authored content
    ///   (issues, web pages, messages) taints the session.
    pub fn handle_server_message(&mut self, line: &str) -> ServerMessageOutcome {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ServerMessageOutcome::Forward(line.to_string());
        }

        let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
            return ServerMessageOutcome::Forward(line.to_string());
        };

        // Check for tools/list response
        if let Some(tools) = parsed.get("result").and_then(|r| r.get("tools")) {
            if self.schema_pin_required && self.pinned_schema_hash.is_none() {
                self.schema_pin_violated = true;
                self.requests_blocked += 1;
                let id = parsed.get("id").cloned().unwrap_or(Value::Null);
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": format!(
                            "[ARC-MCP-003] No trusted schema pin is configured for MCP server '{}'; refusing TOFU.",
                            self.server_name
                        )
                    }
                });
                return ServerMessageOutcome::Forward(err.to_string());
            }

            if let Ok(tools_bytes) = serde_json::to_vec(tools) {
                if let Ok(hash) = arc_core::compute_jcs_schema_hash(&tools_bytes) {
                    if let Some(pin) = self.pinned_schema_hash {
                        if pin != hash {
                            self.schema_pin_violated = true;
                            self.requests_blocked += 1;
                            let id = parsed.get("id").cloned().unwrap_or(Value::Null);
                            let err = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32001,
                                    "message": format!(
                                        "[ARC-MCP-003] tools/list schema hash {} does not match pinned hash {}",
                                        hex::encode(hash),
                                        hex::encode(pin)
                                    )
                                }
                            });
                            return ServerMessageOutcome::Forward(err.to_string());
                        }
                    }

                    self.current_schema_hash = Some(hash);
                    // Register in session
                    let event = ActionEvent::new(
                        AgentHost::ClaudeCode,
                        &self.session_id,
                        OsPrincipal::Uid(1000),
                        Phase::Post,
                        Action::McpToolsList {
                            server: ServerIdentity {
                                config_name: self.server_name.clone(),
                                artifact: Artifact::Unknown,
                                schema_root: Some(hash),
                            },
                            tools_json: serde_json::to_string(tools).unwrap_or_default(),
                        },
                    )
                    .with_schema_fingerprint(hash);

                    self.evaluator
                        .taint_tracker
                        .record_event_and_update_taints(&event);

                    return ServerMessageOutcome::CapturedSchema {
                        fingerprint: hash,
                        forward_line: line.to_string(),
                    };
                }
            }
        }

        // Correlate tools/call responses with their requests and classify the result for taint.
        if let Some(id) = parsed.get("id").filter(|i| !i.is_null()) {
            if let Some(tool) = self.pending_calls.remove(&id.to_string()) {
                if let Some(result) = parsed.get("result") {
                    let is_error = result
                        .get("isError")
                        .and_then(|b| b.as_bool())
                        .unwrap_or(false);
                    let event = ActionEvent::new(
                        AgentHost::ClaudeCode,
                        &self.session_id,
                        OsPrincipal::Uid(1000),
                        Phase::Post,
                        Action::McpToolResult {
                            server: ServerIdentity {
                                config_name: self.server_name.clone(),
                                artifact: Artifact::Unknown,
                                schema_root: self.current_schema_hash,
                            },
                            tool,
                            content: Self::result_text(result),
                            is_error,
                        },
                    )
                    .with_transport("stdio");
                    self.evaluator
                        .taint_tracker
                        .record_event_and_update_taints(&event);
                }
            }
        }

        ServerMessageOutcome::Forward(line.to_string())
    }

    /// Runs mediation between client stdio and child process streams with OS-level containment (FR-MCP-001 / FR-HOOKS-003)
    pub fn run_stdio(&mut self) -> Result<(), BrokerError> {
        if self.command.is_empty() {
            return Err(BrokerError::ProtocolError(
                "No target command specified for stdio broker".to_string(),
            ));
        }

        let supervisor = OsProcessSupervisor::with_limits(self.limits)?;

        let mut cmd = Command::new(&self.command[0]);
        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit()); // Stderr preserved separately (FR-MCP-001)

        // Spawn with containment armed before the child can execute any code (suspended-create +
        // job assignment on Windows; process group + PDEATHSIG on Unix).
        let mut child = supervisor.spawn(&mut cmd)?;

        let mut child_stdin = child.stdin.take().ok_or(BrokerError::ChildTerminated)?;
        let child_stdout = child.stdout.take().ok_or(BrokerError::ChildTerminated)?;

        let running = AtomicBool::new(true);
        let running_ref = &running;
        // Serialises writes from the relay thread and the policy (local response) path so that
        // neither holds the process-wide stdout lock for its whole lifetime.
        let out = Mutex::new(std::io::stdout());
        let out_ref = &out;
        let shared = Mutex::new(&mut *self);
        let shared_ref = &shared;

        fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
            m.lock().unwrap_or_else(|e| e.into_inner())
        }
        fn write_line(out: &Mutex<std::io::Stdout>, text: &str) {
            let mut o = lock(out);
            let _ = o.write_all(text.as_bytes());
            if !text.ends_with('\n') {
                let _ = o.write_all(b"\n");
            }
            let _ = o.flush();
        }

        std::thread::scope(|scope| {
            // Child server stdout -> (schema capture / result taint) -> host stdout
            let relay = scope.spawn(move || {
                let mut reader = BufReader::new(child_stdout);
                let mut line_buf = String::new();
                while running_ref.load(Ordering::Relaxed) {
                    line_buf.clear();
                    match reader.read_line(&mut line_buf) {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let outcome = lock(shared_ref).handle_server_message(&line_buf);
                            let forward = match outcome {
                                ServerMessageOutcome::Forward(l) => l,
                                ServerMessageOutcome::CapturedSchema {
                                    fingerprint,
                                    forward_line,
                                } => {
                                    eprintln!(
                                        "[Arc Protect] Observed MCP schema JCS SHA-256: {}",
                                        hex::encode(fingerprint)
                                    );
                                    forward_line
                                }
                            };
                            write_line(out_ref, &forward);
                        }
                        Err(_) => break,
                    }
                }
            });

            // Host stdin -> policy evaluation -> child server stdin
            let stdin = std::io::stdin().lock();
            let mut reader = BufReader::new(stdin);
            let mut line_buf = String::new();

            while running.load(Ordering::Relaxed) {
                line_buf.clear();
                match reader.read_line(&mut line_buf) {
                    Ok(0) => break, // Host closed stdin
                    Ok(_) => {
                        let outcome = lock(shared_ref).handle_client_message(&line_buf);
                        match outcome {
                            ClientMessageOutcome::Forward(forward_str) => {
                                let _ = child_stdin.write_all(forward_str.as_bytes());
                                if !forward_str.ends_with('\n') {
                                    let _ = child_stdin.write_all(b"\n");
                                }
                                let _ = child_stdin.flush();
                            }
                            ClientMessageOutcome::RespondLocally(resp) => {
                                write_line(out_ref, &resp.to_string());
                            }
                            ClientMessageOutcome::ProtocolError(err) => {
                                let err_resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32600,
                                        "message": err
                                    }
                                });
                                write_line(out_ref, &err_resp.to_string());
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            running.store(false, Ordering::Relaxed);
            let _ = supervisor.terminate(&mut child);
            let _ = relay.join();
        });

        Ok(())
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::command_fingerprint;

    #[test]
    fn command_fingerprint_preserves_argument_boundaries() {
        let split = vec!["ab".to_string(), "c".to_string()];
        let joined = vec!["a".to_string(), "bc".to_string()];
        assert_ne!(command_fingerprint(&split), command_fingerprint(&joined));
        assert_eq!(command_fingerprint(&split), command_fingerprint(&split));
        assert_ne!(command_fingerprint(&[]), command_fingerprint(&[String::new()]));
    }
}
