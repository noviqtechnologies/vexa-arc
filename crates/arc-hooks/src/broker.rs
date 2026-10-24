use arc_core::capability::Capability;
use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::{Obligation, Verdict};
use arc_policy_engine::evaluator::PolicyEvaluator;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

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
                let params = parsed.get("params").cloned().unwrap_or(Value::Null);
                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown_tool")
                    .to_string();
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);

                let caps = Capability::infer(&tool_name, false, false, false);

                let artifact = if !self.command.is_empty() {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    for part in &self.command {
                        hasher.update(part.as_bytes());
                    }
                    Artifact::Local {
                        command_sha256: hasher.finalize().into(),
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

    /// Processes a message emitted by the MCP server child process.
    /// Intercepts runtime tool schemas from `tools/list` responses to compute RFC 8785 JCS fingerprint.
    pub fn handle_server_message(&mut self, line: &str) -> ServerMessageOutcome {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ServerMessageOutcome::Forward(line.to_string());
        }

        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            // Check for tools/list response
            if let Some(result) = parsed.get("result") {
                if let Some(tools) = result.get("tools") {
                    if let Ok(tools_bytes) = serde_json::to_vec(tools) {
                        if let Ok(hash) = arc_core::compute_jcs_schema_hash(&tools_bytes) {
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

        let supervisor = crate::process_containment::OsProcessSupervisor::new()?;

        let mut cmd = Command::new(&self.command[0]);
        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit()); // Stderr preserved separately (FR-MCP-001)

        supervisor.configure_command(&mut cmd);
        let mut child = cmd.spawn()?;
        supervisor.supervise_child(&child)?;

        let mut child_stdin = child.stdin.take().ok_or(BrokerError::ChildTerminated)?;
        let child_stdout = child.stdout.take().ok_or(BrokerError::ChildTerminated)?;

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        // Background thread reading from child server stdout -> host stdout
        let stdout_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(child_stdout);
            let mut stdout = std::io::stdout().lock();
            let mut line_buf = String::new();

            while running_clone.load(Ordering::Relaxed) {
                line_buf.clear();
                match reader.read_line(&mut line_buf) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let _ = stdout.write_all(line_buf.as_bytes());
                        let _ = stdout.flush();
                    }
                    Err(_) => break,
                }
            }
        });

        // Main thread reading from host stdin -> policy evaluation -> child server stdin
        let stdin = std::io::stdin().lock();
        let mut reader = BufReader::new(stdin);
        let mut client_stdout = std::io::stdout().lock();
        let mut line_buf = String::new();

        while running.load(Ordering::Relaxed) {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => break, // Host closed stdin
                Ok(_) => match self.handle_client_message(&line_buf) {
                    ClientMessageOutcome::Forward(forward_str) => {
                        let _ = child_stdin.write_all(forward_str.as_bytes());
                        if !forward_str.ends_with('\n') {
                            let _ = child_stdin.write_all(b"\n");
                        }
                        let _ = child_stdin.flush();
                    }
                    ClientMessageOutcome::RespondLocally(resp) => {
                        let mut resp_str = resp.to_string();
                        resp_str.push('\n');
                        let _ = client_stdout.write_all(resp_str.as_bytes());
                        let _ = client_stdout.flush();
                    }
                    ClientMessageOutcome::ProtocolError(err) => {
                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": err
                            }
                        });
                        let mut resp_str = err_resp.to_string();
                        resp_str.push('\n');
                        let _ = client_stdout.write_all(resp_str.as_bytes());
                        let _ = client_stdout.flush();
                    }
                },
                Err(_) => break,
            }
        }

        running.store(false, Ordering::Relaxed);
        let _ = supervisor.terminate(&mut child);
        let _ = stdout_thread.join();

        Ok(())
    }
}
