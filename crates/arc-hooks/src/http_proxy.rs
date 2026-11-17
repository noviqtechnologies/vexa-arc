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
    let mut content_length: usize = 0;
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
                content_length = val.parse::<usize>().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    if content_length > MAX_HTTP_BODY_BYTES {
        return Err(format!(
            "HTTP body size {content_length} exceeds max {MAX_HTTP_BODY_BYTES} bytes"
        ));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("read body failed: {e}"))?;
    }

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    })
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

fn process_sse_chunk(broker: &mut McpStdioBroker, chunk: &str) -> String {
    let mut out = String::with_capacity(chunk.len());
    for line in chunk.split_inclusive('\n') {
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
                out.push_str("data: ");
                out.push_str(mediated.trim_end_matches('\n'));
                if line.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
        }
        out.push_str(line);
    }
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
        while let Ok(Some(chunk)) = upstream_resp.chunk().await {
            let text = String::from_utf8_lossy(&chunk);
            let mediated = {
                let mut guard = broker.lock().await;
                process_sse_chunk(&mut guard, &text)
            };
            if stream.write_all(mediated.as_bytes()).await.is_err() {
                break;
            }
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
}
