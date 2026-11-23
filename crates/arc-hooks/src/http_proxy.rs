use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::broker::{ClientMessageOutcome, McpStdioBroker, ServerMessageOutcome};

const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HEADER_COUNT: usize = 64;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_TOTAL_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_RATE_LIMIT_PER_MIN: usize = 120;
const DEFAULT_READ_TIMEOUT_SECS: u64 = 15;
const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 30;
const MIN_AUTH_TOKEN_LEN: usize = 16;

/// Policy governing how credentials are forwarded to the upstream MCP server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CredentialForwardingPolicy {
    /// Default: never forward inbound `Authorization` headers to the upstream server.
    #[default]
    Strip,
    /// Inject a separately configured upstream bearer token; never echo inbound client auth.
    StaticUpstreamToken(String),
    /// Explicitly opt-in forwarding of inbound `Authorization` (still refuses to forward
    /// the proxy's own client authentication token).
    ForwardInbound,
}

/// Security and operational configuration for the HTTP MCP forward proxy.
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    /// Explicitly allow binding to a non-loopback address.
    /// Requires `auth_token`, `tls_cert_path`, and `tls_key_path`.
    pub allow_non_loopback: bool,
    /// Required bearer token for client authentication (mandatory for non-loopback; optional on loopback).
    pub auth_token: Option<String>,
    /// PEM-encoded TLS certificate chain path (mandatory for non-loopback).
    pub tls_cert_path: Option<PathBuf>,
    /// PEM-encoded TLS private key path (mandatory for non-loopback).
    pub tls_key_path: Option<PathBuf>,
    /// Allowed `Host` header values (without port or with port). When empty on loopback,
    /// only `localhost`, `127.0.0.1`, and `[::1]` are accepted to prevent DNS rebinding.
    pub allowed_hosts: Vec<String>,
    /// Allowed `Origin` header values. When empty, cross-origin browser requests are rejected.
    pub allowed_origins: Vec<String>,
    /// Credential forwarding policy to the upstream MCP server (defaults to `Strip`).
    pub credential_forwarding: CredentialForwardingPolicy,
    /// Maximum HTTP request body size in bytes.
    pub max_body_bytes: usize,
    /// Maximum concurrent client connections.
    pub max_connections: usize,
    /// Maximum requests per minute per client IP.
    pub rate_limit_per_minute: usize,
    /// Maximum time allowed to read an inbound HTTP request.
    pub read_timeout: Duration,
    /// Maximum time allowed for an upstream MCP request.
    pub upstream_timeout: Duration,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            allow_non_loopback: false,
            auth_token: None,
            tls_cert_path: None,
            tls_key_path: None,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            credential_forwarding: CredentialForwardingPolicy::Strip,
            max_body_bytes: DEFAULT_MAX_HTTP_BODY_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MIN,
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
            upstream_timeout: Duration::from_secs(DEFAULT_UPSTREAM_TIMEOUT_SECS),
        }
    }
}

impl HttpProxyConfig {
    /// Validate that the configuration is safe for the requested bind address.
    /// Hard-rejects any non-loopback listener unless explicit secure-server mode
    /// (authentication + TLS) is configured.
    pub fn validate_for_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let has_cert = self.tls_cert_path.is_some();
        let has_key = self.tls_key_path.is_some();
        if has_cert != has_key {
            return Err(
                "Incomplete TLS configuration: both --tls-cert and --tls-key must be provided together"
                    .to_string(),
            );
        }

        if let Some(ref tok) = self.auth_token {
            if tok.trim().len() < MIN_AUTH_TOKEN_LEN {
                return Err(format!(
                    "Proxy auth token must be at least {MIN_AUTH_TOKEN_LEN} characters"
                ));
            }
        }

        if !is_loopback_socket_addr(addr) {
            if !self.allow_non_loopback {
                return Err(format!(
                    "Refusing to bind non-loopback address '{addr}': HTTP MCP proxy is loopback-only by default. \
                     To expose beyond loopback, pass --allow-non-loopback together with --auth-token (or ARC_PROXY_AUTH_TOKEN), --tls-cert, and --tls-key."
                ));
            }
            if self.auth_token.is_none() {
                return Err(format!(
                    "Refusing to bind non-loopback address '{addr}' without client authentication: \
                     provide --auth-token (or ARC_PROXY_AUTH_TOKEN) with at least {MIN_AUTH_TOKEN_LEN} characters."
                ));
            }
            if !has_cert || !has_key {
                return Err(format!(
                    "Refusing to bind non-loopback address '{addr}' without TLS: \
                     provide both --tls-cert and --tls-key."
                ));
            }
        }

        if self.max_body_bytes == 0 || self.max_connections == 0 || self.rate_limit_per_minute == 0
        {
            return Err(
                "Proxy limits (max_body_bytes, max_connections, rate_limit_per_minute) must be > 0"
                    .to_string(),
            );
        }

        Ok(())
    }

    fn build_tls_acceptor(&self) -> Result<Option<TlsAcceptor>, String> {
        let (Some(cert_path), Some(key_path)) = (&self.tls_cert_path, &self.tls_key_path) else {
            return Ok(None);
        };

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| {
                format!(
                    "Failed to read TLS certificate '{}': {e}",
                    cert_path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                format!(
                    "Failed to parse TLS certificate '{}': {e}",
                    cert_path.display()
                )
            })?;
        if certs.is_empty() {
            return Err(format!(
                "TLS certificate file '{}' contains no certificates",
                cert_path.display()
            ));
        }

        let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
            format!(
                "Failed to read TLS private key '{}': {e}",
                key_path.display()
            )
        })?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Failed to configure TLS protocol versions: {e}"))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("Invalid TLS certificate/key pair: {e}"))?;

        Ok(Some(TlsAcceptor::from(Arc::new(server_cfg))))
    }
}

/// Strictly checks whether a `SocketAddr` is a true loopback address (`127.0.0.0/8` or `::1`).
/// Rejects `0.0.0.0`, `::`, IPv4-mapped IPv6 addresses, link-local, LAN, and public addresses.
pub fn is_loopback_socket_addr(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Constant-time byte comparison for bearer tokens to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

struct IpRateLimiter {
    window: Duration,
    max_requests: usize,
    buckets: HashMap<IpAddr, VecDeque<Instant>>,
}

impl IpRateLimiter {
    fn new(max_requests_per_minute: usize) -> Self {
        Self {
            window: Duration::from_secs(60),
            max_requests: max_requests_per_minute,
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.buckets.entry(ip).or_default();
        while let Some(&front) = entry.front() {
            if now.duration_since(front) >= self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= self.max_requests {
            return false;
        }
        entry.push_back(now);
        // Prevent unbounded memory growth from distinct client IPs
        if self.buckets.len() > 4096 {
            self.buckets.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.duration_since(*t) < self.window)
            });
        }
        true
    }
}

#[derive(Debug)]
struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_body_bytes: usize,
) -> Result<ParsedHttpRequest, (u16, &'static str, String)> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await.map_err(|_| {
        (
            400,
            "Bad Request",
            "failed to read request line".to_string(),
        )
    })?;
    if n == 0 {
        return Err((400, "Bad Request", "connection closed".to_string()));
    }
    if request_line.len() > MAX_HEADER_LINE_BYTES {
        return Err((
            431,
            "Request Header Fields Too Large",
            "request line exceeds maximum length".to_string(),
        ));
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| (400, "Bad Request", "missing HTTP method".to_string()))?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or_else(|| (400, "Bad Request", "missing HTTP path".to_string()))?
        .to_string();

    if !path.starts_with('/') {
        return Err((
            400,
            "Bad Request",
            "invalid HTTP request target".to_string(),
        ));
    }

    let mut headers = HashMap::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut total_header_bytes = request_line.len();
    let mut header_count = 0usize;

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|_| (400, "Bad Request", "failed to read header".to_string()))?;
        if bytes == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        header_count += 1;
        total_header_bytes = total_header_bytes.saturating_add(bytes);
        if header_count > MAX_HEADER_COUNT
            || bytes > MAX_HEADER_LINE_BYTES
            || total_header_bytes > MAX_TOTAL_HEADER_BYTES
        {
            return Err((
                431,
                "Request Header Fields Too Large",
                "HTTP headers exceed allowed limits".to_string(),
            ));
        }

        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                let parsed = val.parse::<usize>().map_err(|_| {
                    (
                        400,
                        "Bad Request",
                        "invalid Content-Length header".to_string(),
                    )
                })?;
                if let Some(prev) = content_length {
                    if prev != parsed {
                        return Err((
                            400,
                            "Bad Request",
                            "conflicting Content-Length headers".to_string(),
                        ));
                    }
                }
                content_length = Some(parsed);
            } else if key == "transfer-encoding" {
                let lower = val.to_ascii_lowercase();
                if lower.split(',').map(str::trim).any(|enc| enc == "chunked") {
                    is_chunked = true;
                } else {
                    return Err((
                        400,
                        "Bad Request",
                        "unsupported Transfer-Encoding".to_string(),
                    ));
                }
            }
            headers.insert(key, val);
        }
    }

    if is_chunked && content_length.is_some() {
        return Err((
            400,
            "Bad Request",
            "ambiguous HTTP framing: both Transfer-Encoding: chunked and Content-Length present"
                .to_string(),
        ));
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader, max_body_bytes).await?
    } else {
        let len = content_length.unwrap_or(0);
        if len > max_body_bytes {
            return Err((
                413,
                "Payload Too Large",
                format!("HTTP body exceeds max {max_body_bytes} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut buf).await.map_err(|_| {
                (
                    400,
                    "Bad Request",
                    "failed to read request body".to_string(),
                )
            })?;
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
) -> Result<Vec<u8>, (u16, &'static str, String)> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = reader
            .read_line(&mut size_line)
            .await
            .map_err(|_| (400, "Bad Request", "read chunk size failed".to_string()))?;
        if n == 0 {
            return Err((
                400,
                "Bad Request",
                "unexpected EOF while reading chunked body".to_string(),
            ));
        }
        let size_hex = size_line.trim().split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| (400, "Bad Request", "invalid chunk size".to_string()))?;
        if chunk_len == 0 {
            loop {
                let mut trailer = String::new();
                let tn = reader
                    .read_line(&mut trailer)
                    .await
                    .map_err(|_| (400, "Bad Request", "read chunk trailer failed".to_string()))?;
                if tn == 0 || trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > max_bytes {
            return Err((
                413,
                "Payload Too Large",
                format!("chunked HTTP body exceeds max {max_bytes} bytes"),
            ));
        }
        let start = out.len();
        out.resize(start + chunk_len, 0);
        reader
            .read_exact(&mut out[start..])
            .await
            .map_err(|_| (400, "Bad Request", "read chunk data failed".to_string()))?;
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf).await;
    }
    Ok(out)
}

async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
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
    let _ = stream.shutdown().await;
    Ok(())
}

fn validate_host_header(
    headers: &HashMap<String, String>,
    config: &HttpProxyConfig,
    bound_is_loopback: bool,
) -> Result<(), &'static str> {
    let Some(host_raw) = headers.get("host") else {
        return Err("Missing Host header");
    };
    let host = host_raw.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err("Empty Host header");
    }

    // Extract hostname without optional :port (handling IPv6 brackets like [::1]:8787)
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };

    if !config.allowed_hosts.is_empty() {
        let ok = config.allowed_hosts.iter().any(|allowed| {
            let a = allowed.trim().to_ascii_lowercase();
            a == host || a == hostname
        });
        if !ok {
            return Err("Host header not allowed");
        }
        return Ok(());
    }

    if bound_is_loopback {
        if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
            return Ok(());
        }
        return Err("Host header rejected for loopback proxy (DNS rebinding protection)");
    }

    Ok(())
}

fn validate_origin_header(
    headers: &HashMap<String, String>,
    config: &HttpProxyConfig,
    bound_is_loopback: bool,
) -> Result<(), &'static str> {
    let Some(origin_raw) = headers.get("origin") else {
        return Ok(());
    };
    let origin = origin_raw.trim().to_ascii_lowercase();
    if !config.allowed_origins.is_empty() {
        let ok = config
            .allowed_origins
            .iter()
            .any(|allowed| allowed.trim().to_ascii_lowercase() == origin);
        if ok {
            return Ok(());
        }
        return Err("Origin header not allowed");
    }

    if bound_is_loopback {
        let is_local_origin = origin.starts_with("http://localhost")
            || origin.starts_with("https://localhost")
            || origin.starts_with("http://127.0.0.1")
            || origin.starts_with("https://127.0.0.1")
            || origin.starts_with("http://[::1]")
            || origin.starts_with("https://[::1]");
        if is_local_origin {
            return Ok(());
        }
    }

    Err("Cross-origin request rejected")
}

fn authenticate_request(headers: &HashMap<String, String>, expected_token: &str) -> bool {
    if let Some(hdr) = headers.get("x-arc-proxy-auth") {
        if constant_time_eq(hdr.trim().as_bytes(), expected_token.as_bytes()) {
            return true;
        }
    }
    if let Some(auth) = headers.get("authorization") {
        let trimmed = auth.trim();
        if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            let candidate = trimmed[7..].trim();
            if constant_time_eq(candidate.as_bytes(), expected_token.as_bytes()) {
                return true;
            }
        }
    }
    false
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

#[allow(clippy::too_many_arguments)]
async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer_ip: IpAddr,
    bound_is_loopback: bool,
    config: Arc<HttpProxyConfig>,
    rate_limiter: Arc<Mutex<IpRateLimiter>>,
    broker: Arc<Mutex<McpStdioBroker>>,
    client: reqwest::Client,
    target_url: String,
) {
    // 1. Per-IP rate limiting before reading body
    {
        let mut rl = rate_limiter.lock().await;
        if !rl.allow(peer_ip) {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32005, "message": "Rate limit exceeded" }
            })
            .to_string();
            let _ = write_http_response(
                &mut stream,
                429,
                "Too Many Requests",
                "application/json",
                &[("Retry-After", "60")],
                payload.as_bytes(),
            )
            .await;
            return;
        }
    }

    // 2. Bounded read with timeout
    let req = match tokio::time::timeout(
        config.read_timeout,
        read_http_request(&mut stream, config.max_body_bytes),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err((status, reason, msg))) => {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32600, "message": msg }
            })
            .to_string();
            let _ = write_http_response(
                &mut stream,
                status,
                reason,
                "application/json",
                &[],
                payload.as_bytes(),
            )
            .await;
            return;
        }
        Err(_) => {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32008, "message": "Request timed out" }
            })
            .to_string();
            let _ = write_http_response(
                &mut stream,
                408,
                "Request Timeout",
                "application/json",
                &[],
                payload.as_bytes(),
            )
            .await;
            return;
        }
    };

    // 3. Host & Origin validation (DNS rebinding / CSRF defense)
    if let Err(msg) = validate_host_header(&req.headers, &config, bound_is_loopback) {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32003, "message": msg }
        })
        .to_string();
        let _ = write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "application/json",
            &[],
            payload.as_bytes(),
        )
        .await;
        return;
    }
    if let Err(msg) = validate_origin_header(&req.headers, &config, bound_is_loopback) {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32003, "message": msg }
        })
        .to_string();
        let _ = write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "application/json",
            &[],
            payload.as_bytes(),
        )
        .await;
        return;
    }

    // 4. Mandatory client authentication (before any MCP broker/upstream activity)
    if let Some(ref expected_token) = config.auth_token {
        if !authenticate_request(&req.headers, expected_token) {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32001, "message": "Authentication required" }
            })
            .to_string();
            let _ = write_http_response(
                &mut stream,
                401,
                "Unauthorized",
                "application/json",
                &[("WWW-Authenticate", "Bearer realm=\"vexa-arc-proxy\"")],
                payload.as_bytes(),
            )
            .await;
            return;
        }
    }

    // 5. Mediate client JSON-RPC payload through Arc broker
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

    // 6. Forward request to upstream with explicit credential-forwarding policy
    let upstream_url = build_target_url(&target_url, &req.path);
    let method =
        reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut builder = client.request(method, &upstream_url);

    for header_name in ["accept", "content-type", "mcp-session-id"] {
        if let Some(val) = req.headers.get(header_name) {
            builder = builder.header(header_name, val);
        }
    }

    match &config.credential_forwarding {
        CredentialForwardingPolicy::Strip => {
            // Explicitly strip inbound Authorization header; never forward.
        }
        CredentialForwardingPolicy::StaticUpstreamToken(tok) => {
            builder = builder.header("authorization", format!("Bearer {tok}"));
        }
        CredentialForwardingPolicy::ForwardInbound => {
            if let Some(val) = req.headers.get("authorization") {
                // Never forward the proxy's own auth token to upstream even when ForwardInbound is set
                let is_proxy_token = config.auth_token.as_deref().is_some_and(|proxy_tok| {
                    let trimmed = val.trim();
                    trimmed.len() > 7
                        && trimmed[..7].eq_ignore_ascii_case("bearer ")
                        && constant_time_eq(trimmed[7..].trim().as_bytes(), proxy_tok.as_bytes())
                });
                if !is_proxy_token {
                    builder = builder.header("authorization", val);
                }
            }
        }
    }

    if !forward_body.is_empty() {
        builder = builder.body(forward_body);
    }

    let mut upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(_) => {
            // Safe error handling: never leak upstream URLs, tokens, or internal error details to clients
            eprintln!("[Arc Protect HTTP] Upstream MCP request failed (details redacted)");
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32002, "message": "Upstream MCP request failed" }
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
    run_http_proxy_on_listener_with_config(listener, broker, target_url, HttpProxyConfig::default())
        .await
}

pub async fn run_http_proxy_on_listener_with_config(
    listener: TcpListener,
    broker: McpStdioBroker,
    target_url: String,
    config: HttpProxyConfig,
) -> Result<(), String> {
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to read listener local address: {e}"))?;
    config.validate_for_addr(local_addr)?;
    let tls_acceptor = config.build_tls_acceptor()?;
    let bound_is_loopback = is_loopback_socket_addr(local_addr);

    let shared_broker = Arc::new(Mutex::new(broker));
    let shared_cfg = Arc::new(config);
    let conn_semaphore = Arc::new(Semaphore::new(shared_cfg.max_connections));
    let rate_limiter = Arc::new(Mutex::new(IpRateLimiter::new(
        shared_cfg.rate_limit_per_minute,
    )));
    let client = reqwest::Client::builder()
        .timeout(shared_cfg.upstream_timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    loop {
        let (mut stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|e| format!("HTTP accept failed: {e}"))?;

        let permit = match Arc::clone(&conn_semaphore).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let _ = write_http_response(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "application/json",
                    &[],
                    b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32006,\"message\":\"Connection limit reached\"}}",
                )
                .await;
                continue;
            }
        };

        let b = Arc::clone(&shared_broker);
        let cfg = Arc::clone(&shared_cfg);
        let rl = Arc::clone(&rate_limiter);
        let c = client.clone();
        let t = target_url.clone();
        let tls = tls_acceptor.clone();
        let peer_ip = peer_addr.ip();

        tokio::spawn(async move {
            let _permit = permit;
            if let Some(acceptor) = tls {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                    Ok(Ok(tls_stream)) => {
                        handle_connection(tls_stream, peer_ip, bound_is_loopback, cfg, rl, b, c, t)
                            .await;
                    }
                    _ => {
                        eprintln!("[Arc Protect HTTP] TLS handshake failed or timed out");
                    }
                }
            } else {
                handle_connection(stream, peer_ip, bound_is_loopback, cfg, rl, b, c, t).await;
            }
        });
    }
}

pub fn run_http_proxy(
    listen_addr: &str,
    target_url: &str,
    broker: McpStdioBroker,
) -> Result<(), String> {
    run_http_proxy_with_config(listen_addr, target_url, broker, HttpProxyConfig::default())
}

pub fn run_http_proxy_with_config(
    listen_addr: &str,
    target_url: &str,
    broker: McpStdioBroker,
    config: HttpProxyConfig,
) -> Result<(), String> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("Invalid listen address '{listen_addr}': {e}"))?;
    // Validate BEFORE binding any socket so unsafe listeners can never open.
    config.validate_for_addr(addr)?;
    // Validate TLS material early before starting runtime.
    let _ = config.build_tls_acceptor()?;

    let scheme = if config.tls_cert_path.is_some() {
        "https"
    } else {
        "http"
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;

    rt.block_on(async move {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind {addr}: {e}"))?;
        eprintln!(
            "[Arc Protect HTTP] Listening on {scheme}://{addr} (auth={}, cred_policy={:?})",
            if config.auth_token.is_some() {
                "required"
            } else {
                "loopback-only"
            },
            match config.credential_forwarding {
                CredentialForwardingPolicy::Strip => "strip",
                CredentialForwardingPolicy::StaticUpstreamToken(_) => "static-upstream-token",
                CredentialForwardingPolicy::ForwardInbound => "forward-inbound",
            }
        );
        run_http_proxy_on_listener_with_config(listener, broker, target_url.to_string(), config)
            .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::compute_jcs_schema_hash;
    use arc_policy_engine::evaluator::{PolicyConfig, PolicyEvaluator};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpStream;

    #[test]
    fn non_loopback_addresses_are_rejected_by_default_across_address_families() {
        let default_cfg = HttpProxyConfig::default();
        for addr_str in [
            "0.0.0.0:8787",
            "[::]:8787",
            "192.0.2.10:8787",
            "10.0.0.5:8787",
            "[2001:db8::1]:8787",
            "[::ffff:127.0.0.1]:8787",
        ] {
            let addr: SocketAddr = addr_str.parse().unwrap();
            let err = default_cfg.validate_for_addr(addr).unwrap_err();
            assert!(
                err.contains("Refusing to bind non-loopback"),
                "expected rejection for {addr_str}, got: {err}"
            );
        }

        // Loopback IPv4 and IPv6 are allowed by default
        for addr_str in ["127.0.0.1:8787", "127.0.0.2:8787", "[::1]:8787"] {
            let addr: SocketAddr = addr_str.parse().unwrap();
            assert!(
                default_cfg.validate_for_addr(addr).is_ok(),
                "expected loopback {addr_str} to pass"
            );
        }
    }

    #[test]
    fn non_loopback_requires_allow_flag_auth_token_and_tls() {
        let addr: SocketAddr = "0.0.0.0:8787".parse().unwrap();

        // allow_non_loopback without auth or TLS -> rejected
        let cfg1 = HttpProxyConfig {
            allow_non_loopback: true,
            ..Default::default()
        };
        assert!(cfg1
            .validate_for_addr(addr)
            .unwrap_err()
            .contains("without client authentication"));

        // allow_non_loopback + auth, but no TLS -> rejected
        let cfg2 = HttpProxyConfig {
            allow_non_loopback: true,
            auth_token: Some("super-secret-proxy-token-1234".to_string()),
            ..Default::default()
        };
        assert!(cfg2
            .validate_for_addr(addr)
            .unwrap_err()
            .contains("without TLS"));

        // short auth token -> rejected
        let cfg_short = HttpProxyConfig {
            allow_non_loopback: true,
            auth_token: Some("short".to_string()),
            tls_cert_path: Some(PathBuf::from("cert.pem")),
            tls_key_path: Some(PathBuf::from("key.pem")),
            ..Default::default()
        };
        assert!(cfg_short
            .validate_for_addr(addr)
            .unwrap_err()
            .contains("at least 16"));

        // allow_non_loopback + strong auth + TLS cert/key -> validated
        let cfg_ok = HttpProxyConfig {
            allow_non_loopback: true,
            auth_token: Some("super-secret-proxy-token-1234".to_string()),
            tls_cert_path: Some(PathBuf::from("cert.pem")),
            tls_key_path: Some(PathBuf::from("key.pem")),
            ..Default::default()
        };
        assert!(cfg_ok.validate_for_addr(addr).is_ok());
    }

    #[test]
    fn run_http_proxy_rejects_0_0_0_0_before_binding() {
        let broker = McpStdioBroker::new("github", "reject-bind", PolicyEvaluator::default());
        let err = run_http_proxy("0.0.0.0:0", "http://127.0.0.1:9999", broker).unwrap_err();
        assert!(err.contains("Refusing to bind non-loopback"));
    }

    #[tokio::test]
    async fn authenticated_proxy_blocks_unauth_before_upstream_and_strips_inbound_credentials() {
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let seen_auth = Arc::new(Mutex::new(Option::<String>::None));

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let hits_clone = Arc::clone(&upstream_hits);
        let auth_clone = Arc::clone(&seen_auth);
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = upstream_listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&hits_clone);
                let auth_seen = Arc::clone(&auth_clone);
                tokio::spawn(async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let req = read_http_request(&mut s, DEFAULT_MAX_HTTP_BODY_BYTES)
                        .await
                        .unwrap();
                    *auth_seen.lock().await = req.headers.get("authorization").cloned();
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": { "ok": true }
                    });
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

        let broker = McpStdioBroker::new("github", "auth-test", PolicyEvaluator::default());
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_token = "arc-proxy-secret-token-2026-xyz";
        let cfg = HttpProxyConfig {
            auth_token: Some(proxy_token.to_string()),
            credential_forwarding: CredentialForwardingPolicy::Strip,
            ..Default::default()
        };
        let target = format!("http://{upstream_addr}");
        tokio::spawn(async move {
            let _ =
                run_http_proxy_on_listener_with_config(proxy_listener, broker, target, cfg).await;
        });

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{proxy_addr}/mcp");

        // 1. Unauthenticated request must fail with 401 and NEVER reach upstream
        let unauth_resp = client
            .post(&proxy_url)
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_resp.status().as_u16(), 401);
        let unauth_body = unauth_resp.text().await.unwrap();
        assert!(!unauth_body.contains(proxy_token));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

        // 2. Wrong bearer token must also fail with 401 and never reach upstream
        let wrong_resp = client
            .post(&proxy_url)
            .header("Authorization", "Bearer wrong-token-0000000000")
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_resp.status().as_u16(), 401);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

        // 3. Valid bearer token succeeds, and Authorization header is NOT leaked to upstream
        let ok_resp = client
            .post(&proxy_url)
            .header("Authorization", format!("Bearer {proxy_token}"))
            .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .send()
            .await
            .unwrap();
        assert_eq!(ok_resp.status().as_u16(), 200);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen_auth.lock().await,
            None,
            "Proxy auth token must never be forwarded to upstream"
        );
    }

    #[tokio::test]
    async fn proxy_enforces_host_origin_and_rate_limit() {
        let broker = McpStdioBroker::new("github", "limit-test", PolicyEvaluator::default());
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let cfg = HttpProxyConfig {
            rate_limit_per_minute: 2,
            ..Default::default()
        };
        tokio::spawn(async move {
            let _ = run_http_proxy_on_listener_with_config(
                proxy_listener,
                broker,
                "http://127.0.0.1:1".to_string(),
                cfg,
            )
            .await;
        });

        // 1. Cross-origin request is rejected with 403
        let mut s1 = TcpStream::connect(proxy_addr).await.unwrap();
        s1.write_all(
            b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();
        let mut resp1 = String::new();
        BufReader::new(&mut s1).read_line(&mut resp1).await.unwrap();
        assert!(resp1.starts_with("HTTP/1.1 403 Forbidden"), "resp1={resp1}");

        // 2. DNS rebinding Host header is rejected with 403
        let mut s2 = TcpStream::connect(proxy_addr).await.unwrap();
        s2.write_all(
            b"POST /mcp HTTP/1.1\r\nHost: attacker.example\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();
        let mut resp2 = String::new();
        BufReader::new(&mut s2).read_line(&mut resp2).await.unwrap();
        assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "resp2={resp2}");

        // 3. 3rd request within 1 minute hits rate limit (429)
        // Use BufReader::read_line so macOS/BSD TCP RST after unread client bytes never causes ECONNRESET on EOF.
        let mut s3 = TcpStream::connect(proxy_addr).await.unwrap();
        let _ = s3
            .write_all(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}")
            .await;
        let mut resp3 = String::new();
        BufReader::new(&mut s3).read_line(&mut resp3).await.unwrap();
        assert!(
            resp3.starts_with("HTTP/1.1 429 Too Many Requests"),
            "resp3={resp3}"
        );
    }

    #[tokio::test]
    async fn http_proxy_enforces_schema_pin_sanitizes_results_and_blocks_trifecta() {
        let tools_json = serde_json::json!([
            { "name": "fetch_issue", "description": "Fetch external issue" }
        ]);
        let pin = compute_jcs_schema_hash(&serde_json::to_vec(&tools_json).unwrap()).unwrap();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = upstream_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let req = read_http_request(&mut s, DEFAULT_MAX_HTTP_BODY_BYTES)
                        .await
                        .unwrap();
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
        let req = read_http_request(&mut srv, DEFAULT_MAX_HTTP_BODY_BYTES)
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(String::from_utf8(req.body).unwrap(), body_json);

        let smuggle_raw =
            "POST /mcp HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let writer2 = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(smuggle_raw.as_bytes()).await.unwrap();
            let _ = client.shutdown().await;
        });
        let (mut srv2, _) = listener.accept().await.unwrap();
        let (_, _, err) = read_http_request(&mut srv2, DEFAULT_MAX_HTTP_BODY_BYTES)
            .await
            .unwrap_err();
        writer2.await.unwrap();
        assert!(err.contains("ambiguous HTTP framing"), "err={err}");
    }
}
