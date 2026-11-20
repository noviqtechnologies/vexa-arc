use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::broker::{ClientMessageOutcome, McpStdioBroker, ServerMessageOutcome};

const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug)]
struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, String> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let n = reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| format!("read request line failed: {e}"))?;
    if n == 0 {
        return Err("connection closed".to_string());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?
        .to_string();

    let mut headers = HashMap::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read header failed: {e}"))?;
        if bytes == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                let parsed = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid Content-Length header '{val}'"))?;
                if let Some(prev) = content_length {
                    if prev != parsed {
                        return Err("conflicting Content-Length headers".to_string());
                    }
                }
                content_length = Some(parsed);
            } else if key == "transfer-encoding" {
                let lower = val.to_ascii_lowercase();
                if lower.split(',').map(str::trim).any(|enc| enc == "chunked") {
                    is_chunked = true;
                } else {
                    return Err(format!("unsupported Transfer-Encoding '{val}'"));
                }
            }
            headers.insert(key, val);
        }
    }

    if is_chunked && content_length.is_some() {
        return Err(
            "ambiguous HTTP framing: both Transfer-Encoding: chunked and Content-Length present"
                .to_string(),
        );
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader, MAX_HTTP_BODY_BYTES).await?
    } else {
        let len = content_length.unwrap_or(0);
        if len > MAX_HTTP_BODY_BYTES {
            return Err(format!(
                "HTTP body size {len} exceeds max {MAX_HTTP_BODY_BYTES} bytes"
            ));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("read body failed: {e}"))?;
        }
        buf
    };

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn read_chunked_body<R: AsyncBufReadExt + AsyncReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = reader
            .read_line(&mut size_line)
            .await
            .map_err(|e| format!("read chunk size failed: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF while reading chunked body".to_string());
        }
        let size_hex = size_line
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size '{size_hex}'"))?;
        if chunk_len == 0 {
            // Drain optional trailers until blank line
            loop {
                let mut trailer = String::new();
                let tn = reader
                    .read_line(&mut trailer)
                    .await
                    .map_err(|e| format!("read chunk trailer failed: {e}"))?;
                if tn == 0 || trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > max_bytes {
            return Err(format!(
                "chunked HTTP body exceeds max {max_bytes} bytes"
            ));
        }
        let start = out.len();
        out.resize(start + chunk_len, 0);
        reader
            .read_exact(&mut out[start..])
            .await
            .map_err(|e| format!("read chunk data failed: {e}"))?;
        // Consume trailing CRLF after chunk payload
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf).await;
    }
    Ok(out)
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("write response head failed: {e}"))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .map_err(|e| format!("write response body failed: {e}"))?;
    }
    let _ = stream.flush().await;
    Ok(())
}

fn build_target_url(base: &str, req_path: &str) -> String {
    let trimmed_base = base.trim_end_matches('/');
    if req_path == "/" || req_path.is_empty() || trimmed_base.ends_with(req_path) {
        base.to_string()
    } else {
        format!("{trimmed_base}{req_path}")
    }
}

/// Stateful line-buffered SSE mediator that reassembles `data: ...` JSON-RPC frames
/// split across arbitrary TCP chunk boundaries before passing them to `McpStdioBroker`.
struct SseStreamMediator {
    pending: String,
}

impl SseStreamMediator {
    fn new() -> Self {
        Self {
            pending: String::new(),
        }
    }

    fn mediate_line(broker: &mut McpStdioBroker, line: &str) -> String {
        if let Some(rest) = line.strip_prefix("data:") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() && trimmed != "[DONE]" && trimmed.starts_with('{') {
                let mediated = match broker.handle_server_message(trimmed) {
                    ServerMessageOutcome::Forward(l) => l,
                    ServerMessageOutcome::CapturedSchema {
                        fingerprint,
                        forward_line,
                    } => {
                        eprintln!(
                            "[Arc Protect HTTP] Observed MCP schema JCS SHA-256: {}",
                            hex::encode(fingerprint)
                        );
                        forward_line
                    }
                };
                let mut out = String::with_capacity(mediated.len() + 8);
                out.push_str("data: ");
                out.push_str(mediated.trim_end_matches(['\r', '\n']));
                if line.ends_with("\r\n") {
                    out.push_str("\r\n");
                } else if line.ends_with('\n') {
                    out.push('\n');
                }
                return out;
            }
        }
        line.to_string()
    }

    fn push_chunk(&mut self, broker: &mut McpStdioBroker, chunk: &str) -> String {
        self.pending.push_str(chunk);
        let mut out = String::with_capacity(chunk.len());
        while let Some(pos) = self.pending.find('\n') {
            let line: String = self.pending.drain(..=pos).collect();
            out.push_str(&Self::mediate_line(broker, &line));
        }
        out
    }

    fn finish(&mut self, broker: &mut McpStdioBroker) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        let remainder = std::mem::take(&mut self.pending);
        Self::mediate_line(broker, &remainder)
    }
}

#[cfg(test)]
fn process_sse_chunk(broker: &mut McpStdioBroker, chunk: &str) -> String {
    let mut mediator = SseStreamMediator::new();
    let mut out = mediator.push_chunk(broker, chunk);
    out.push_str(&mediator.finish(broker));
    out
}

async fn handle_connection(
    mut stream: TcpStream,
    broker: Arc<Mutex<McpStdioBroker>>,
    client: reqwest::Client,
    target_url: String,
) {
    let req = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            let _ = write_http_response(
                &mut stream,
                400,
                "Bad Request",
                "application/json",
                &[],
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": e }
                })
                .to_string()
                .as_bytes(),
            )
            .await;
            return;
        }
    };

    let mut forward_body = req.body.clone();
    if req.method == "POST" && !req.body.is_empty() {
        let body_str = match std::str::from_utf8(&req.body) {
            Ok(s) => s,
            Err(_) => {
                let _ = write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "application/json",
                    &[],
                    b"{\"error\":\"invalid UTF-8 payload\"}",
                )
                .await;
                return;
            }
        };

        let outcome = {
            let mut guard = broker.lock().await;
            guard.handle_client_message(body_str)
        };

        match outcome {
            ClientMessageOutcome::Forward(mediated) => {
                forward_body = mediated.into_bytes();
            }
            ClientMessageOutcome::RespondLocally(resp_val) => {
                let payload = resp_val.to_string();
                let _ = write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    "application/json",
                    &[],
                    payload.as_bytes(),
                )
                .await;
                return;
            }
            ClientMessageOutcome::ProtocolError(err) => {
                let payload = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": err }
                })
                .to_string();
                let _ = write_http_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "application/json",
                    &[],
                    payload.as_bytes(),
                )
                .await;
                return;
            }
        }
    }

    let upstream_url = build_target_url(&target_url, &req.path);
    let method =
        reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut builder = client.request(method, &upstream_url);

    for header_name in ["authorization", "accept", "content-type", "mcp-session-id"] {
        if let Some(val) = req.headers.get(header_name) {
            builder = builder.header(header_name, val);
        }
    }
    if !forward_body.is_empty() {
        builder = builder.body(forward_body);
    }

    let mut upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32002, "message": format!("Upstream MCP error: {e}") }
            })
            .to_string();
            let _ = write_http_response(
                &mut stream,
                502,
                "Bad Gateway",
                "application/json",
                &[],
                payload.as_bytes(),
            )
            .await;
            return;
        }
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let session_hdr = upstream_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if content_type
        .to_ascii_lowercase()
        .contains("text/event-stream")
    {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nConnection: close\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("OK")
        );
        if let Some(ref sid) = session_hdr {
            head.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let mut sse = SseStreamMediator::new();
        while let Ok(Some(chunk)) = upstream_resp.chunk().await {
            let text = String::from_utf8_lossy(&chunk);
            let mediated = {
                let mut guard = broker.lock().await;
                sse.push_chunk(&mut guard, &text)
            };
            if !mediated.is_empty() && stream.write_all(mediated.as_bytes()).await.is_err() {
                break;
            }
            let _ = stream.flush().await;
        }
        let tail = {
            let mut guard = broker.lock().await;
            sse.finish(&mut guard)
        };
        if !tail.is_empty() {
            let _ = stream.write_all(tail.as_bytes()).await;
            let _ = stream.flush().await;
        }
        return;
    }

    let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
    let final_body = if content_type
        .to_ascii_lowercase()
        .contains("application/json")
    {
        if let Ok(resp_str) = std::str::from_utf8(&resp_bytes) {
            let mut guard = broker.lock().await;
            match guard.handle_server_message(resp_str) {
                ServerMessageOutcome::Forward(l) => l.into_bytes(),
                ServerMessageOutcome::CapturedSchema {
                    fingerprint,
                    forward_line,
                } => {
                    eprintln!(
                        "[Arc Protect HTTP] Observed MCP schema JCS SHA-256: {}",
                        hex::encode(fingerprint)
                    );
                    forward_line.into_bytes()
                }
            }
        } else {
            resp_bytes.to_vec()
        }
    } else {
        resp_bytes.to_vec()
    };

    let mut extra = Vec::new();
    if let Some(ref sid) = session_hdr {
        extra.push(("Mcp-Session-Id", sid.as_str()));
    }
    let _ = write_http_response(
        &mut stream,
        status.as_u16(),
        status.canonical_reason().unwrap_or("OK"),
        &content_type,
        &extra,
        &final_body,
    )
    .await;
}

pub async fn run_http_proxy_on_listener(
    listener: TcpListener,
    broker: McpStdioBroker,
    target_url: String,
) -> Result<(), String> {
    let shared_broker = Arc::new(Mutex::new(broker));
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("HTTP accept failed: {e}"))?;
        let b = Arc::clone(&shared_broker);
        let c = client.clone();
        let t = target_url.clone();
        tokio::spawn(async move {
            handle_connection(stream, b, c, t).await;
        });
    }
}

pub fn run_http_proxy(
    listen_addr: &str,
    target_url: &str,
    broker: McpStdioBroker,
) -> Result<(), String> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("Invalid listen address '{listen_addr}': {e}"))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;

    rt.block_on(async move {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind {addr}: {e}"))?;
        eprintln!("[Arc Protect HTTP] Listening on http://{addr} -> {target_url}");
        run_http_proxy_on_listener(listener, broker, target_url.to_string()).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::compute_jcs_schema_hash;
    use arc_policy_engine::evaluator::{PolicyConfig, PolicyEvaluator};

    #[tokio::test]
    async fn http_proxy_enforces_schema_pin_sanitizes_results_and_blocks_trifecta() {
        let tools_json = serde_json::json!([
            { "name": "fetch_issue", "description": "Fetch external issue" }
        ]);
        let pin = compute_jcs_schema_hash(&serde_json::to_vec(&tools_json).unwrap()).unwrap();

        // Spawn mock upstream MCP HTTP server
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let req = read_http_request(&mut s).await.unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let id = body.get("id").cloned().unwrap_or(serde_json::Value::Null);
                    let resp = if method == "tools/list" {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "tools": [{ "name": "fetch_issue", "description": "Fetch external issue" }] }
                        })
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{ "type": "text", "text": "Hello\u{200B} World\u{202E}" }]
                            }
                        })
                    };
                    let _ = write_http_response(
                        &mut s,
                        200,
                        "OK",
                        "application/json",
                        &[],
                        resp.to_string().as_bytes(),
                    )
                    .await;
                });
            }
        });

        let mut cfg = PolicyConfig::default();
        cfg.allowed_mcp_servers.insert("slack".to_string());
        let evaluator = PolicyEvaluator::new(cfg);
        let broker =
            McpStdioBroker::new("github", "http-test-sess", evaluator).with_pinned_schema(pin);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let target = format!("http://{upstream_addr}");
        tokio::spawn(async move {
            let _ = run_http_proxy_on_listener(proxy_listener, broker, target).await;
        });

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{proxy_addr}/mcp");

        // 1. tools/list succeeds with matching pin
        let r1: serde_json::Value = client
            .post(&proxy_url)
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(r1["result"]["tools"].is_array());

        // 2. tools/call result is sanitized (invisible Unicode removed)
        let r2: serde_json::Value = client
            .post(&proxy_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "fetch_issue", "arguments": { "id": 1 } }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let text = r2["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "Hello World");
    }

    #[test]
    fn sse_chunk_mediation_sanitizes_data_lines() {
        let mut broker = McpStdioBroker::new("github", "sse-test", PolicyEvaluator::default());
        let chunk = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Hi\\u200B!\"}]}}\n\n";
        let out = process_sse_chunk(&mut broker, chunk);
        assert!(out.contains("Hi!"));
        assert!(!out.contains("\\u200B"));
    }

    #[test]
    fn sse_stream_mediator_reassembles_json_split_across_tcp_chunks() {
        let mut broker = McpStdioBroker::new("github", "sse-split", PolicyEvaluator::default());
        let mut sse = SseStreamMediator::new();
        let part1 = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",";
        let part2 = "\"text\":\"Split\\u200BPayload\\u202E\"}]}}\n\n";

        let out1 = sse.push_chunk(&mut broker, part1);
        let out2 = sse.push_chunk(&mut broker, part2);
        let tail = sse.finish(&mut broker);
        let combined = format!("{out1}{out2}{tail}");

        assert!(combined.contains("SplitPayload"), "combined={combined}");
        assert!(!combined.contains('\u{200B}'));
        assert!(!combined.contains('\u{202E}'));
    }

    #[tokio::test]
    async fn read_http_request_decodes_chunked_transfer_encoding_and_rejects_smuggling() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let body_json = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#;
        let split_at = 18;
        let c1 = &body_json[..split_at];
        let c2 = &body_json[split_at..];
        let raw_chunked = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            c1.len(),
            c1,
            c2.len(),
            c2
        );

        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(raw_chunked.as_bytes()).await.unwrap();
            let _ = client.shutdown().await;
        });

        let (mut srv, _) = listener.accept().await.unwrap();
        let req = read_http_request(&mut srv).await.unwrap();
        writer.await.unwrap();
        assert_eq!(String::from_utf8(req.body).unwrap(), body_json);

        // Dual Transfer-Encoding + Content-Length must be rejected (HTTP request smuggling protection)
        let smuggle_raw = "POST /mcp HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let writer2 = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(smuggle_raw.as_bytes()).await.unwrap();
            let _ = client.shutdown().await;
        });
        let (mut srv2, _) = listener.accept().await.unwrap();
        let err = read_http_request(&mut srv2).await.unwrap_err();
        writer2.await.unwrap();
        assert!(err.contains("ambiguous HTTP framing"), "err={err}");
    }
}
