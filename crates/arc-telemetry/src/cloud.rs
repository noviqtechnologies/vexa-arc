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

    /// Resolve the Vexa Cloud API base URL (`override_url` -> `VEXA_API_URL` -> `VEXA_API_BASE_URL` -> default).
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

        let creds = StoredVexaCredentials {
            token: token.trim().to_string(),
            org_slug: org_slug.map(|s| s.to_string()),
            user_email: user_email.map(|s| s.to_string()),
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

/// Sanitize a reason string so raw secrets or multi-line outputs never leave the workstation.
pub fn sanitize_cloud_reason(raw: &str) -> String {
    let first_line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    if first_line.chars().count() <= 160 {
        first_line.to_string()
    } else {
        let prefix: String = first_line.chars().take(157).collect();
        format!("{prefix}...")
    }
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
        actor: event.actor.clone(),
        os: event.os.clone(),
        timestamp: event.timestamp.clone(),
    };

    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };

    rt.block_on(async move {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn credentials_roundtrip_and_cloud_event_post_succeeds() {
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
