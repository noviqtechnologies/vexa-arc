use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_VEXA_API_BASE_URL: &str = "https://api.vexasec.io/sca/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredVexaCredentials {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudFirewallEvent {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub action: String, // "BLOCKED" | "ALLOWED"
    pub rule_triggered: String,
    pub reason: String,
    pub actor: String,
    pub os: String,
    pub timestamp: String,
}

pub struct VexaCloudAuth;

impl VexaCloudAuth {
    /// Returns true if offline mode is active via `ARC_OFFLINE` or `VEXA_FIREWALL_OFFLINE`.
    pub fn is_offline() -> bool {
        for var in ["ARC_OFFLINE", "VEXA_FIREWALL_OFFLINE"] {
            if let Ok(val) = std::env::var(var) {
                let v = val.trim();
                if v == "1" || v.eq_ignore_ascii_case("true") {
                    return true;
                }
            }
        }
        false
    }

    /// Resolve the Vexa Cloud API base URL:
    /// `override_url` -> `VEXA_API_URL` -> `VEXA_API_BASE_URL` -> stored `api_base_url` -> default.
    pub fn resolve_api_base_url(override_url: Option<&str>) -> String {
        if let Some(url) = override_url {
            let trimmed = url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        for var in ["VEXA_API_URL", "VEXA_API_BASE_URL"] {
            if let Ok(url) = std::env::var(var) {
                let trimmed = url.trim().trim_end_matches('/');
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        if let Some(stored_url) = Self::load_stored_credentials().and_then(|c| c.api_base_url) {
            let trimmed = stored_url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        DEFAULT_VEXA_API_BASE_URL.to_string()
    }

    /// Standard path to `~/.vexa/credentials.json` (shared with `vexa-sca`), with `VEXA_CREDENTIALS_PATH` override.
    pub fn credentials_path() -> PathBuf {
        if let Ok(custom) = std::env::var("VEXA_CREDENTIALS_PATH") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".vexa").join("credentials.json")
    }

    pub fn load_stored_credentials() -> Option<StoredVexaCredentials> {
        // Isolate `cargo test` (unit & integration tests) from the developer's real
        // `~/.vexa/credentials.json` unless a test explicitly sets `VEXA_CREDENTIALS_PATH`.
        let has_explicit_cred_path = std::env::var_os("VEXA_CREDENTIALS_PATH")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let in_cargo_test = cfg!(test)
            || std::env::var_os("CARGO_TARGET_TMPDIR")
                .map(|v| !v.is_empty())
                .unwrap_or(false);
        if in_cargo_test && !has_explicit_cred_path {
            return None;
        }

        let path = Self::credentials_path();
        if !path.exists() {
            return None;
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return None;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save_credentials(
        token: &str,
        org_slug: Option<&str>,
        user_email: Option<&str>,
    ) -> Result<PathBuf, String> {
        Self::save_credentials_with_url(token, org_slug, user_email, None)
    }

    pub fn save_credentials_with_url(
        token: &str,
        org_slug: Option<&str>,
        user_email: Option<&str>,
        api_base_url: Option<&str>,
    ) -> Result<PathBuf, String> {
        let path = Self::credentials_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create credentials directory: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        if path.exists() {
            let meta = fs::symlink_metadata(&path)
                .map_err(|e| format!("Failed to inspect credentials path: {e}"))?;
            if meta.file_type().is_symlink() {
                return Err(
                    "Credentials path is a symlink, refusing to overwrite for security".to_string(),
                );
            }
        }

        let clean_url = api_base_url
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty());

        let creds = StoredVexaCredentials {
            token: token.trim().to_string(),
            org_slug: org_slug.map(|s| s.to_string()),
            user_email: user_email.map(|s| s.to_string()),
            api_base_url: clean_url,
            created_at: Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string_pretty(&creds)
            .map_err(|e| format!("Failed to serialize credentials: {e}"))?;

        let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| format!("Failed to open temp credentials file: {e}"))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write credentials: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync credentials: {e}"))?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("Failed to open temp credentials file: {e}"))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write credentials: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync credentials: {e}"))?;
        }

        fs::rename(&tmp_path, &path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("Failed to atomically commit credentials file: {e}")
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }

        Ok(path)
    }

    pub fn logout() -> Result<bool, String> {
        let path = Self::credentials_path();
        if path.exists() {
            fs::remove_file(&path).map_err(|e| format!("Failed to delete credentials: {e}"))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Resolve active cloud token from environment or `~/.vexa/credentials.json`.
    pub fn get_token() -> Option<String> {
        for var in [
            "VEXA_SCA_SECURITY_API_KEY",
            "VEXA_SECURITY_API_KEY",
            "VEXA_TOKEN",
            "VEXA_API_KEY",
            "VEXA_SCA_API_KEY",
            "ARC_API_TOKEN",
            "SOCKET_SECURITY_API_KEY",
        ] {
            if let Ok(tok) = std::env::var(var) {
                let t = tok.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
        Self::load_stored_credentials().map(|c| c.token)
    }

    /// Resolve active organization slug from environment or `~/.vexa/credentials.json`.
    pub fn get_org_slug() -> Option<String> {
        for var in ["VEXA_ORG", "VEXA_ORG_SLUG"] {
            if let Ok(org) = std::env::var(var) {
                let trimmed = org.trim().to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
        Self::load_stored_credentials().and_then(|c| c.org_slug)
    }

    pub fn current_actor() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "workstation".to_string())
    }
}

/// Runs an async future synchronously without panicking if the caller is already
/// executing inside a Tokio runtime (e.g. `arc protect http` or async tests).
fn run_blocking_future<F, T>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::Builder::new()
            .name("arc-cloud-io".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;
                Ok(rt.block_on(fut))
            })
            .map_err(|e| format!("Failed to spawn cloud I/O thread: {e}"))?
            .join()
            .map_err(|_| "Cloud I/O worker thread panicked".to_string())?
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;
        Ok(rt.block_on(fut))
    }
}

/// Sanitize a reason string so raw secrets, credentials, PII (emails/IPs),
/// OS home-directory paths containing usernames (Windows/macOS/Linux/WSL),
/// or multi-line outputs never leave the workstation.
pub fn sanitize_cloud_reason(raw: &str) -> String {
    use regex::Regex;

    static DLP: std::sync::OnceLock<arc_dlp::detector::SecretScanEngine> =
        std::sync::OnceLock::new();
    static RE_AUTH_HEADER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_QUERY_SECRET: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_WIN_USER_PATH: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_WIN_FWD_USER_PATH: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_UNIX_USER_PATH: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_EMAIL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static RE_IPV4: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

    let dlp = DLP.get_or_init(arc_dlp::detector::SecretScanEngine::new);
    let re_auth = RE_AUTH_HEADER.get_or_init(|| {
        Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}").expect("valid regex")
    });
    let re_query = RE_QUERY_SECRET.get_or_init(|| {
        Regex::new(
            r"(?i)([?&](?:token|api_key|apikey|secret|password|passwd|auth|key|access_token)=)[^&\s]+",
        )
        .expect("valid regex")
    });
    let re_win_path = RE_WIN_USER_PATH
        .get_or_init(|| Regex::new(r#"(?i)\b[A-Z]:\\Users\\[^\\\s"']+"#).expect("valid regex"));
    let re_win_fwd = RE_WIN_FWD_USER_PATH.get_or_init(|| {
        Regex::new(r#"(?i)(?:\b[A-Z]:/Users/|/mnt/[a-z]/Users/)[^/\s"']+"#).expect("valid regex")
    });
    let re_unix_path = RE_UNIX_USER_PATH
        .get_or_init(|| Regex::new(r#"(?:/Users/|/home/)[^/\s"']+"#).expect("valid regex"));
    let re_email = RE_EMAIL.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").expect("valid regex")
    });
    let re_ipv4 = RE_IPV4.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .expect("valid regex")
    });

    let first_line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();

    // 1. DLP secret/credential redaction
    let findings = dlp.scan(first_line.as_bytes());
    let mut redacted = if findings.is_empty() {
        first_line.to_string()
    } else {
        let mut buf = first_line.to_string();
        for f in findings.iter().rev() {
            if f.start < buf.len() && f.end <= buf.len() && f.start <= f.end {
                buf.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.detector));
            }
        }
        buf
    };

    // 2. Auth headers & query-string secrets
    redacted = re_auth
        .replace_all(&redacted, "$1 [REDACTED:auth_header]")
        .into_owned();
    redacted = re_query
        .replace_all(&redacted, "${1}[REDACTED:query_secret]")
        .into_owned();

    // 3. Cross-OS user home paths (Windows, WSL, macOS, Linux) -> ~
    redacted = re_win_path.replace_all(&redacted, "~").into_owned();
    redacted = re_win_fwd.replace_all(&redacted, "~").into_owned();
    redacted = re_unix_path.replace_all(&redacted, "~").into_owned();

    // 4. PII: email addresses and IPv4 addresses
    redacted = re_email
        .replace_all(&redacted, "[REDACTED:email]")
        .into_owned();
    redacted = re_ipv4.replace_all(&redacted, "[REDACTED:ip]").into_owned();

    if redacted.chars().count() <= 160 {
        redacted
    } else {
        let prefix: String = redacted.chars().take(157).collect();
        format!("{prefix}...")
    }
}

/// Sanitize the `actor` field before cloud egress across Windows, macOS, and Linux.
///
/// - Strips Windows `DOMAIN\` prefixes (never leaks AD domain names).
/// - If `ARC_ANONYMIZE_ACTOR=1` (or `true`), replaces the username with a deterministic
///   one-way SHA-256 pseudonym (`anon_<12-hex>`) for strict zero-PII environments.
/// - Redacts any accidentally embedded email/secret patterns.
pub fn sanitize_cloud_actor(actor: &str) -> String {
    use sha2::{Digest, Sha256};

    let trimmed = actor.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let clean = trimmed
        .rsplit_once('\\')
        .map(|(_, user)| user)
        .unwrap_or(trimmed);

    let anonymize = std::env::var("ARC_ANONYMIZE_ACTOR")
        .ok()
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);

    if anonymize {
        let mut hasher = Sha256::new();
        hasher.update(b"vexa-arc-actor-v1:");
        hasher.update(clean.as_bytes());
        let digest = hex::encode(hasher.finalize());
        return format!("anon_{}", &digest[..12]);
    }

    if clean.contains('@') {
        let mut hasher = Sha256::new();
        hasher.update(b"vexa-arc-actor-v1:");
        hasher.update(clean.as_bytes());
        let digest = hex::encode(hasher.finalize());
        return format!("user_{}", &digest[..12]);
    }

    clean.chars().take(64).collect()
}

/// Emits a zero-code firewall/hook telemetry event to `vexa-sca-cloud` (`POST {base_url}/firewall/events`).
/// Bounded to an 800ms timeout and returns `false` without error if unauthenticated or offline.
pub fn emit_cloud_firewall_event(event: &CloudFirewallEvent, api_base_url: Option<&str>) -> bool {
    if VexaCloudAuth::is_offline() {
        return false;
    }
    let Some(token) = VexaCloudAuth::get_token() else {
        return false;
    };
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/firewall/events", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();

    let payload = CloudFirewallEvent {
        package: event.package.clone(),
        version: event.version.clone(),
        ecosystem: event.ecosystem.clone(),
        action: event.action.clone(),
        rule_triggered: event.rule_triggered.clone(),
        reason: sanitize_cloud_reason(&event.reason),
        actor: sanitize_cloud_actor(&event.actor),
        os: event.os.clone(),
        timestamp: event.timestamp.clone(),
    };

    run_blocking_future(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_millis(800))
            .build()
        else {
            return false;
        };
        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.trim()));
        if let Some(org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }
        match req.json(&payload).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    })
    .unwrap_or(false)
}

#[cfg(test)]
static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn credentials_roundtrip_and_cloud_event_post_succeeds() {
        let _guard = crate::cloud::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("arc_cloud_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cred_file = tmp_dir.join("credentials.json");

        std::env::set_var("VEXA_CREDENTIALS_PATH", &cred_file);
        std::env::remove_var("ARC_OFFLINE");
        std::env::remove_var("VEXA_FIREWALL_OFFLINE");

        let saved_path = VexaCloudAuth::save_credentials(
            "vexa_pat_test_1234567890abcdef",
            Some("acme-sec"),
            Some("dev@acme.io"),
        )
        .unwrap();
        assert_eq!(saved_path, cred_file);

        let loaded = VexaCloudAuth::load_stored_credentials().unwrap();
        assert_eq!(loaded.token, "vexa_pat_test_1234567890abcdef");
        assert_eq!(loaded.org_slug.as_deref(), Some("acme-sec"));
        assert_eq!(loaded.user_email.as_deref(), Some("dev@acme.io"));

        // Spin up a local one-shot HTTP server to verify /firewall/events payload
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp =
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"status\":\"accepted\"}";
            let _ = stream.write_all(resp.as_bytes());
            req_str
        });

        let ev = CloudFirewallEvent {
            package: "shell:network_utility".to_string(),
            version: "pre-hook".to_string(),
            ecosystem: "arc-hook:claude-code".to_string(),
            action: "BLOCKED".to_string(),
            rule_triggered: "ARC-LTT-001".to_string(),
            reason: "Lethal Trifecta exfiltration blocked".to_string(),
            actor: "alice".to_string(),
            os: std::env::consts::OS.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };

        let api_base = format!("http://{addr}/sca/v1");
        let ok = emit_cloud_firewall_event(&ev, Some(&api_base));
        assert!(ok);

        let received = server_handle.join().unwrap();
        assert!(received.contains("POST /sca/v1/firewall/events"));
        assert!(received.contains("ARC-LTT-001"));
        assert!(received.contains("arc-hook:claude-code"));

        assert!(VexaCloudAuth::logout().unwrap());
        assert!(!cred_file.exists());
        std::env::remove_var("VEXA_CREDENTIALS_PATH");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

/// Zero-code-retention runtime telemetry event sent in batches to `POST {base_url}/arc/events`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudArcEvent {
    pub event_id: String,
    pub install_id: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub phase: String,
    pub action_class: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub taint_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_class: Option<String>,
    pub target_class: String,
    pub session_id_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_pin_status: Option<String>,
    pub latency_ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudArcHeartbeat {
    pub install_id: String,
    pub actor: String,
    pub os: String,
    pub host_adapters: Vec<String>,
    pub arc_version: String,
    pub policy_mode: String,
    pub active_policy_seq: i64,
    pub doctor_status: String,
}

pub fn cloud_spool_path() -> PathBuf {
    crate::default_spool_dir().join("arc_cloud_queue.jsonl")
}

/// Appends a privacy-preserving `TelemetryEvent` to the local cloud-flush spool without network I/O.
/// Safe to call on the pre-execution hook hot path across Windows, macOS, and Linux.
pub fn spool_arc_event(
    event: &crate::TelemetryEvent,
    repo_name: Option<&str>,
) -> Result<(), String> {
    use std::io::Write;
    let path = cloud_spool_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create telemetry spool dir: {e}"))?;
    }
    let occurred_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(event.occurred_at_unix_ms as i64)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());

    let cloud_ev = CloudArcEvent {
        event_id: event.event_id.to_string(),
        install_id: event.install_id.clone(),
        host: event.host.clone(),
        transport: event.transport.clone(),
        phase: event.phase.clone(),
        action_class: event.action_class.clone(),
        decision: event.decision.clone(),
        rule_id: event.rule_id.clone(),
        taint_flags: event.taint_flags.clone(),
        sink_class: event.sink_class.clone(),
        target_class: event.target_class.clone(),
        session_id_hash: event.session_id_hash.clone(),
        project_id_hash: event.project_id_hash.clone(),
        repo_name: repo_name.map(str::to_string),
        schema_pin_status: event.schema_pin_status.clone(),
        latency_ms: event.latency_ms,
        error_class: event.error_class.clone(),
        occurred_at,
    };

    let line = serde_json::to_string(&cloud_ev)
        .map_err(|e| format!("Failed to serialize cloud Arc event: {e}"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open cloud telemetry spool: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("Failed to write cloud telemetry spool: {e}"))
}

/// Flushes up to 500 spooled Arc events to `POST {base_url}/arc/events` in a single batch.
/// Preserves unacknowledged events in the spool on offline, unauthenticated, or 429/5xx responses.
pub fn flush_arc_event_spool(api_base_url: Option<&str>) -> usize {
    if VexaCloudAuth::is_offline() {
        return 0;
    }
    let Some(token) = VexaCloudAuth::get_token() else {
        return 0;
    };
    let path = cloud_spool_path();
    if !path.exists() {
        return 0;
    }
    let Ok(content) = fs::read_to_string(&path) else {
        return 0;
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return 0;
    }

    let batch_count = lines.len().min(500);
    let mut batch = Vec::with_capacity(batch_count);
    for line in &lines[..batch_count] {
        if let Ok(ev) = serde_json::from_str::<CloudArcEvent>(line) {
            batch.push(ev);
        }
    }
    if batch.is_empty() {
        let _ = fs::remove_file(&path);
        return 0;
    }

    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/arc/events", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();

    let sent_count = batch.len();
    let ok = run_blocking_future(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        else {
            return false;
        };
        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.trim()));
        if let Some(org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }
        match req
            .json(&serde_json::json!({ "events": batch }))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    })
    .unwrap_or(false);

    if !ok {
        return 0;
    }

    let remaining = &lines[batch_count..];
    if remaining.is_empty() {
        let _ = fs::remove_file(&path);
    } else {
        let new_content = format!("{}\n", remaining.join("\n"));
        let _ = fs::write(&path, new_content);
    }
    sent_count
}

pub fn emit_cloud_heartbeat(hb: &CloudArcHeartbeat, api_base_url: Option<&str>) -> bool {
    if VexaCloudAuth::is_offline() {
        return false;
    }
    let Some(token) = VexaCloudAuth::get_token() else {
        return false;
    };
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/arc/heartbeat", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();
    let mut hb_owned = hb.clone();
    hb_owned.actor = sanitize_cloud_actor(&hb_owned.actor);

    run_blocking_future(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
        else {
            return false;
        };
        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.trim()));
        if let Some(org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }
        match req.json(&hb_owned).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    })
    .unwrap_or(false)
}

pub fn upload_arc_inventory(
    payload: &serde_json::Value,
    api_base_url: Option<&str>,
) -> Result<serde_json::Value, String> {
    if VexaCloudAuth::is_offline() {
        return Err("Cloud upload skipped: offline mode is active".to_string());
    }
    let token = VexaCloudAuth::get_token().ok_or_else(|| {
        "Authentication required. Run `arc auth login --token <VEXA_TOKEN>` first.".to_string()
    })?;
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/arc/inventory", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();
    let payload_owned = payload.clone();

    run_blocking_future(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.trim()));
        if let Some(org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }
        let resp = req
            .json(&payload_owned)
            .send()
            .await
            .map_err(|e| format!("Failed to upload Arc inventory to {url}: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "Vexa Cloud inventory upload rejected ({status}): {text}"
            ));
        }
        serde_json::from_str(&text)
            .map_err(|e| format!("Invalid JSON response from Vexa Cloud: {e}"))
    })?
}

pub fn fetch_signed_policy_bundle(api_base_url: Option<&str>) -> Result<serde_json::Value, String> {
    if VexaCloudAuth::is_offline() {
        return Err("Policy sync skipped: offline mode is active".to_string());
    }
    let token = VexaCloudAuth::get_token().ok_or_else(|| {
        "Authentication required. Run `arc auth login --token <VEXA_TOKEN>` first.".to_string()
    })?;
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/arc/policy/bundle", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();

    run_blocking_future(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let mut req = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.trim()));
        if let Some(org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("Failed to fetch signed policy from {url}: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("Policy sync failed ({status}): {text}"));
        }
        serde_json::from_str(&text)
            .map_err(|e| format!("Invalid JSON response from Vexa Cloud: {e}"))
    })?
}

#[cfg(test)]
mod arc_spool_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn spool_and_batch_flush_preserves_queue_on_503_and_drains_on_202() {
        let _guard = crate::cloud::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("arc_spool_test_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cred_file = tmp_dir.join("credentials.json");

        std::env::set_var("ARC_TELEMETRY_DIR", &tmp_dir);
        std::env::set_var("VEXA_CREDENTIALS_PATH", &cred_file);
        std::env::remove_var("ARC_OFFLINE");
        std::env::remove_var("VEXA_FIREWALL_OFFLINE");

        VexaCloudAuth::save_credentials("vexa_pat_test_spool_1234", Some("acme"), None).unwrap();

        let ev = crate::TelemetryEventBuilder {
            action_class: "shell".to_string(),
            decision: "deny".to_string(),
            rule_id: Some("ARC-LTT-001".to_string()),
            target_class: "network_utility".to_string(),
            session_id_hash: crate::hash_identifier("secret-session-id"),
            ..Default::default()
        }
        .build("claude_code", Some("native_hook"));

        spool_arc_event(&ev, Some("noviq/vexa-arc")).unwrap();
        assert!(cloud_spool_path().exists());

        // 1. Server returns 503 -> spool must remain intact
        let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let a1 = l1.local_addr().unwrap();
        let h1 = std::thread::spawn(move || {
            let (mut s, _) = l1.accept().unwrap();
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b);
            let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
        });
        let flushed_err = flush_arc_event_spool(Some(&format!("http://{a1}/sca/v1")));
        h1.join().unwrap();
        assert_eq!(flushed_err, 0);
        assert!(
            cloud_spool_path().exists(),
            "spool must not be deleted on 503"
        );

        // 2. Server returns 202 -> spool drains and returns 1
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let a2 = l2.local_addr().unwrap();
        let h2 = std::thread::spawn(move || {
            let (mut s, _) = l2.accept().unwrap();
            let mut b = [0u8; 8192];
            let n = s.read(&mut b).unwrap_or(0);
            let req = String::from_utf8_lossy(&b[..n]).to_string();
            let _ = s.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n{}");
            req
        });
        let flushed_ok = flush_arc_event_spool(Some(&format!("http://{a2}/sca/v1")));
        let received = h2.join().unwrap();
        assert_eq!(flushed_ok, 1);
        assert!(received.contains("POST /sca/v1/arc/events"));
        assert!(received.contains("ARC-LTT-001"));
        assert!(!received.contains("secret-session-id"));
        assert!(
            !cloud_spool_path().exists(),
            "spool should be removed once empty"
        );

        std::env::remove_var("ARC_TELEMETRY_DIR");
        std::env::remove_var("VEXA_CREDENTIALS_PATH");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

/// OAuth 2.0 Device Flow (RFC 8628) initiation response from Vexa Cloud.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeSession {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_device_expires")]
    pub expires_in: u64,
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

fn default_device_expires() -> u64 {
    600
}

fn default_device_interval() -> u64 {
    2
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceTokenPollResult {
    Pending,
    Authorized {
        token: String,
        org_slug: Option<String>,
        user_email: Option<String>,
    },
    Denied(String),
    Expired,
}

/// Request a new Device Flow code pair (`POST {base_url}/auth/device/code`).
pub fn request_device_code(api_base_url: Option<&str>) -> Result<DeviceCodeSession, String> {
    if VexaCloudAuth::is_offline() {
        return Err("Device login skipped: offline mode is active".to_string());
    }
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/auth/device/code", base_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "install_id": crate::install_id(),
        "os": std::env::consts::OS,
        "actor": VexaCloudAuth::current_actor(),
    });

    run_blocking_future(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Failed to reach {url}: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("Device code request failed ({status}): {text}"));
        }
        serde_json::from_str(&text).map_err(|e| format!("Invalid device code response JSON: {e}"))
    })?
}

/// Poll `POST {base_url}/auth/device/token` once for approval status.
pub fn poll_device_token(
    device_code: &str,
    api_base_url: Option<&str>,
) -> Result<DeviceTokenPollResult, String> {
    if VexaCloudAuth::is_offline() {
        return Err("Offline mode is active".to_string());
    }
    let base_url = VexaCloudAuth::resolve_api_base_url(api_base_url);
    let url = format!("{}/auth/device/token", base_url.trim_end_matches('/'));
    let code = device_code.to_string();

    run_blocking_future(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let resp = client
            .post(&url)
            .json(&serde_json::json!({ "device_code": code }))
            .send()
            .await
            .map_err(|e| format!("Failed to poll {url}: {e}"))?;
        let status = resp.status();
        let val: serde_json::Value = resp.json().await.unwrap_or_default();

        if status.as_u16() == 202
            || val.get("error").and_then(|v| v.as_str()) == Some("authorization_pending")
        {
            return Ok(DeviceTokenPollResult::Pending);
        }
        if status.as_u16() == 403
            || val.get("error").and_then(|v| v.as_str()) == Some("access_denied")
        {
            let msg = val
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Authorization denied")
                .to_string();
            return Ok(DeviceTokenPollResult::Denied(msg));
        }
        if val.get("error").and_then(|v| v.as_str()) == Some("expired_token") {
            return Ok(DeviceTokenPollResult::Expired);
        }
        if status.is_success() {
            if let Some(tok) = val.get("token").and_then(|v| v.as_str()) {
                return Ok(DeviceTokenPollResult::Authorized {
                    token: tok.to_string(),
                    org_slug: val
                        .get("org_slug")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    user_email: val
                        .get("user_email")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                });
            }
        }
        Err(format!(
            "Unexpected device token response ({status}): {val}"
        ))
    })?
}

/// Spawns a detached, windowless `arc telemetry flush --quiet` child process if:
/// - Offline mode is NOT active,
/// - Cloud credentials exist, and
/// - At least `cooldown_secs` (60s) have elapsed since the last background sync.
///
/// Never blocks the caller (<1ms on hook hot path) and works across Windows, macOS, and Linux.
pub fn maybe_spawn_background_flush(cooldown_secs: u64) -> bool {
    if VexaCloudAuth::is_offline() || VexaCloudAuth::get_token().is_none() {
        return false;
    }
    let dir = crate::default_spool_dir();
    if fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let stamp_path = dir.join("last_sync_at");
    let now_secs = Utc::now().timestamp().max(0) as u64;
    if let Ok(raw) = fs::read_to_string(&stamp_path) {
        if let Ok(prev) = raw.trim().parse::<u64>() {
            if now_secs.saturating_sub(prev) < cooldown_secs {
                return false;
            }
        }
    }
    let _ = fs::write(&stamp_path, now_secs.to_string());

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["telemetry", "flush", "--quiet"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW (0x08000000) | DETACHED_PROCESS (0x00000008)
        cmd.creation_flags(0x0800_0000 | 0x0000_0008);
    }

    cmd.spawn().is_ok()
}

#[cfg(test)]
mod multi_env_device_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn credentials_persist_and_resolve_custom_api_base_url() {
        let _guard = crate::cloud::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("arc_url_persist_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cred_file = tmp_dir.join("credentials.json");

        std::env::set_var("VEXA_CREDENTIALS_PATH", &cred_file);
        std::env::remove_var("VEXA_API_URL");
        std::env::remove_var("VEXA_API_BASE_URL");

        VexaCloudAuth::save_credentials_with_url(
            "vexa_pat_preprod_1234567890",
            Some("acme-preprod"),
            Some("dev@acme.io"),
            Some("https://preprod-api.acme.internal/v1/"),
        )
        .unwrap();

        assert_eq!(
            VexaCloudAuth::resolve_api_base_url(None),
            "https://preprod-api.acme.internal/v1"
        );

        std::env::remove_var("VEXA_CREDENTIALS_PATH");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn device_flow_client_polls_pending_then_receives_token() {
        let _guard = crate::cloud::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("ARC_OFFLINE");
        std::env::remove_var("VEXA_FIREWALL_OFFLINE");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            // 1. /auth/device/code
            let (mut s1, _) = listener.accept().unwrap();
            let mut b = [0u8; 4096];
            let _ = s1.read(&mut b);
            let body1 = r#"{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"https://dev.example/auth/device","expires_in":600,"interval":1}"#;
            let _ = s1.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body1.len(), body1).as_bytes(),
            );
            // 2. /auth/device/token -> 202 pending
            let (mut s2, _) = listener.accept().unwrap();
            let _ = s2.read(&mut b);
            let body2 = r#"{"error":"authorization_pending","status":"pending"}"#;
            let _ = s2.write_all(
                format!("HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body2.len(), body2).as_bytes(),
            );
            // 3. /auth/device/token -> 200 authorized
            let (mut s3, _) = listener.accept().unwrap();
            let _ = s3.read(&mut b);
            let body3 = r#"{"token":"vexa_pat_minted_999","token_type":"Bearer","status":"authorized","org_slug":"acme","user_email":"dev@acme.io"}"#;
            let _ = s3.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body3.len(), body3).as_bytes(),
            );
        });

        let api_base = format!("http://{addr}/v1");
        let sess = request_device_code(Some(&api_base)).unwrap();
        assert_eq!(sess.user_code, "ABCD-1234");
        assert_eq!(
            poll_device_token(&sess.device_code, Some(&api_base)).unwrap(),
            DeviceTokenPollResult::Pending
        );
        assert_eq!(
            poll_device_token(&sess.device_code, Some(&api_base)).unwrap(),
            DeviceTokenPollResult::Authorized {
                token: "vexa_pat_minted_999".to_string(),
                org_slug: Some("acme".to_string()),
                user_email: Some("dev@acme.io".to_string()),
            }
        );
        srv.join().unwrap();
    }

    #[test]
    fn sanitize_cloud_reason_redacts_secrets_before_egress() {
        let raw = "Blocked command containing AKIAIOSFODNN7EXAMPLE and ghp_111122223333444455556666777788889999\nsecond line";
        let clean = sanitize_cloud_reason(raw);
        assert!(
            !clean.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key leaked: {clean}"
        );
        assert!(
            !clean.contains("ghp_111122223333444455556666777788889999"),
            "GitHub PAT leaked: {clean}"
        );
        assert!(clean.contains("[REDACTED:SEC-AWS-001]"), "clean={clean}");
        assert!(clean.contains("[REDACTED:SEC-GTH-001]"), "clean={clean}");
        assert!(!clean.contains("second line"));
    }

    #[test]
    fn sanitize_cloud_reason_scrubs_cross_os_paths_pii_and_auth_headers() {
        let win = sanitize_cloud_reason(r"Denied read of C:\Users\wasim\.env by wasim@corp.io");
        assert!(!win.contains("wasim"), "Windows username leaked: {win}");
        assert!(!win.contains("wasim@corp.io"), "Email leaked: {win}");
        assert!(win.contains(r"~\.env"), "win={win}");
        assert!(win.contains("[REDACTED:email]"), "win={win}");

        let mac = sanitize_cloud_reason("Denied /Users/alice/.aws/credentials to 192.168.1.42");
        assert!(!mac.contains("alice"), "macOS username leaked: {mac}");
        assert!(!mac.contains("192.168.1.42"), "IPv4 leaked: {mac}");
        assert!(mac.contains("~/.aws/credentials"), "mac={mac}");
        assert!(mac.contains("[REDACTED:ip]"), "mac={mac}");

        let linux = sanitize_cloud_reason("Blocked /home/bob/.ssh/id_rsa and /mnt/c/Users/bob/app");
        assert!(!linux.contains("bob"), "Linux/WSL username leaked: {linux}");
        assert!(linux.contains("~/.ssh/id_rsa"), "linux={linux}");
        assert!(linux.contains("~/app"), "linux={linux}");

        let auth = sanitize_cloud_reason(
            "Blocked Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig https://api.example.com?token=secret123",
        );
        assert!(
            !auth.contains("eyJhbGciOiJIUzI1NiJ9"),
            "Bearer leaked: {auth}"
        );
        assert!(!auth.contains("secret123"), "Query token leaked: {auth}");
        assert!(auth.contains("[REDACTED:auth_header]"), "auth={auth}");
        assert!(auth.contains("[REDACTED:query_secret]"), "auth={auth}");
    }

    #[test]
    fn sanitize_cloud_actor_strips_domain_hashes_emails_and_honors_anonymize_flag() {
        std::env::remove_var("ARC_ANONYMIZE_ACTOR");

        assert_eq!(sanitize_cloud_actor(r"CORP\wasim"), "wasim");
        assert_eq!(sanitize_cloud_actor(""), "unknown");

        let email_actor = sanitize_cloud_actor("wasim@company.com");
        assert!(!email_actor.contains("wasim"));
        assert!(!email_actor.contains('@'));
        assert!(email_actor.starts_with("user_"));

        std::env::set_var("ARC_ANONYMIZE_ACTOR", "1");
        let anon = sanitize_cloud_actor("wasim");
        std::env::remove_var("ARC_ANONYMIZE_ACTOR");
        assert!(!anon.contains("wasim"));
        assert!(anon.starts_with("anon_"));
        assert_eq!(anon.len(), "anon_".len() + 12);
    }

    #[tokio::test]
    async fn run_blocking_future_does_not_panic_inside_active_tokio_runtime() {
        let res = run_blocking_future(async { 42usize }).unwrap();
        assert_eq!(res, 42);
    }
}
