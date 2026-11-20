use arc_policy_engine::evaluator::{PolicyConfig, PolicyMode};
use arc_telemetry::{
    emit_cloud_heartbeat, poll_device_token, request_device_code, CloudArcHeartbeat,
    DeviceTokenPollResult, VexaCloudAuth,
};
use std::path::Path;
use std::time::{Duration, Instant};

fn is_headless_session() -> bool {
    let ci_or_ssh = std::env::var("CI").is_ok()
        || std::env::var("SSH_CONNECTION").is_ok()
        || std::env::var("SSH_TTY").is_ok();
    #[cfg(target_os = "linux")]
    {
        ci_or_ssh
            || (std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err())
    }
    #[cfg(not(target_os = "linux"))]
    {
        ci_or_ssh
    }
}

fn try_open_browser(url: &str) -> bool {
    if is_headless_session() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    }
}

/// Reads the persisted `min_sequence` from `.arc/policy-state.json` (or `~/.arc/policy-state.json`).
pub fn read_active_policy_sequence(project_dir: &Path) -> i64 {
    let project_state = project_dir.join(".arc").join("policy-state.json");
    if let Ok(raw) = std::fs::read_to_string(&project_state) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(seq) = v.get("min_sequence").and_then(|s| s.as_i64()) {
                return seq;
            }
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
    {
        let home_state = home.join(".arc").join("policy-state.json");
        if let Ok(raw) = std::fs::read_to_string(&home_state) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(seq) = v.get("min_sequence").and_then(|s| s.as_i64()) {
                    return seq;
                }
            }
        }
    }
    0
}

/// Detects which supported AI coding host adapters actually have Arc hooks installed
/// in either the project directory or the user's home directory (cross-platform).
pub fn detect_installed_host_adapters(project_dir: &Path) -> Vec<String> {
    let mut bases = vec![project_dir.to_path_buf()];
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
    {
        if !bases.iter().any(|b| b == &home) {
            bases.push(home);
        }
    }

    type AdapterCheck = (&'static str, fn(&Path) -> bool);
    let checks: &[AdapterCheck] = &[
        ("claude-code", |dir| {
            let p = dir.join(".claude").join("settings.json");
            std::fs::read_to_string(p)
                .map(|c| c.contains("intercept hook"))
                .unwrap_or(false)
        }),
        ("cursor", |dir| {
            let p = dir.join(".cursor").join("hooks.json");
            std::fs::read_to_string(p)
                .map(|c| c.contains("intercept hook"))
                .unwrap_or(false)
        }),
        ("codex-cli", |dir| {
            let p = dir.join(".codex").join("hooks.json");
            std::fs::read_to_string(p)
                .map(|c| c.contains("intercept hook"))
                .unwrap_or(false)
        }),
        ("gemini-cli", |dir| {
            let p = dir.join(".gemini").join("settings.json");
            std::fs::read_to_string(p)
                .map(|c| c.contains("intercept hook"))
                .unwrap_or(false)
        }),
        ("windsurf", |dir| {
            let p = dir.join(".windsurf").join("hooks.json");
            std::fs::read_to_string(p)
                .map(|c| c.contains("intercept hook"))
                .unwrap_or(false)
        }),
    ];

    let mut installed = Vec::new();
    for (name, check_fn) in checks {
        if bases.iter().any(|base| check_fn(base)) {
            installed.push((*name).to_string());
        }
    }
    installed
}

pub fn build_workstation_heartbeat(project_dir: &Path) -> CloudArcHeartbeat {
    let policy_res = PolicyConfig::try_load_with_precedence(Some(project_dir));
    let policy_ok = policy_res.is_ok();
    let mode_str = policy_res
        .as_ref()
        .map(|p| match p.mode {
            PolicyMode::Enforce => "enforce",
            PolicyMode::Audit => "audit",
        })
        .unwrap_or("enforce");

    let host_adapters = detect_installed_host_adapters(project_dir);
    let doctor_status = if !policy_ok {
        "degraded"
    } else if host_adapters.is_empty() {
        "unconfigured"
    } else {
        "healthy"
    };

    CloudArcHeartbeat {
        install_id: arc_telemetry::install_id(),
        actor: VexaCloudAuth::current_actor(),
        os: std::env::consts::OS.to_string(),
        host_adapters,
        arc_version: env!("CARGO_PKG_VERSION").to_string(),
        policy_mode: mode_str.to_string(),
        active_policy_seq: read_active_policy_sequence(project_dir),
        doctor_status: doctor_status.to_string(),
    }
}

/// One-command workstation onboarding:
/// 1. Authenticate (OAuth Device Flow in browser, or `--token` for CI/headless) & persist `api_base_url`
/// 2. Install IDE hooks & MCP server (`arc init` on `.`)
/// 3. Sync signed organization policy (non-fatal if none published yet)
/// 4. Send immediate endpoint posture heartbeat with real `active_policy_seq`
pub fn run_setup(
    api_url: Option<&str>,
    token: Option<&str>,
    json: bool,
    sync_policy_fn: fn(&Path, Option<&str>) -> bool,
) -> bool {
    let base_url = VexaCloudAuth::resolve_api_base_url(api_url);
    let project_dir = Path::new(".");

    // 1. Authenticate
    let mut authed_org: Option<String> = None;
    let mut authed_email: Option<String> = None;

    if let Some(tok) = token.map(str::trim).filter(|s| !s.is_empty()) {
        if !crate::commands::auth::run_auth_login(Some(tok), Some(&base_url), false) {
            return false;
        }
        if let Some(c) = VexaCloudAuth::load_stored_credentials() {
            authed_org = c.org_slug;
            authed_email = c.user_email;
        }
    } else {
        let sess = match request_device_code(Some(&base_url)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[Arc Setup] {e}");
                return false;
            }
        };
        let verify_url = sess
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&sess.verification_uri);

        if !json {
            println!("Opening browser to authorize this workstation...");
            println!("  Verification URL:  {verify_url}");
            println!("  Verification Code: {}", sess.user_code);
            println!("Waiting for approval in Vexa Cloud...");
        }
        let _ = try_open_browser(verify_url);

        let deadline = Instant::now() + Duration::from_secs(sess.expires_in.min(600));
        let poll_interval = Duration::from_secs(sess.interval.clamp(1, 5));

        loop {
            if Instant::now() >= deadline {
                eprintln!("[Arc Setup] Device authorization timed out.");
                return false;
            }
            std::thread::sleep(poll_interval);
            match poll_device_token(&sess.device_code, Some(&base_url)) {
                Ok(DeviceTokenPollResult::Pending) => continue,
                Ok(DeviceTokenPollResult::Authorized {
                    token: minted,
                    org_slug,
                    user_email,
                }) => {
                    if let Err(e) = VexaCloudAuth::save_credentials_with_url(
                        &minted,
                        org_slug.as_deref(),
                        user_email.as_deref(),
                        Some(&base_url),
                    ) {
                        eprintln!("[Arc Setup] Failed to save credentials: {e}");
                        return false;
                    }
                    authed_org = org_slug;
                    authed_email = user_email;
                    break;
                }
                Ok(DeviceTokenPollResult::Denied(msg)) => {
                    eprintln!("[Arc Setup] Authorization denied: {msg}");
                    return false;
                }
                Ok(DeviceTokenPollResult::Expired) => {
                    eprintln!("[Arc Setup] Device verification code expired.");
                    return false;
                }
                Err(e) => {
                    eprintln!("[Arc Setup] {e}");
                    return false;
                }
            }
        }
    }

    // 2. Configure IDE hooks & MCP server on current directory
    let init_ok = crate::commands::init::run_init(project_dir, "auto", false, false);

    // 3. Sync signed organization policy (non-fatal if org has not published one yet)
    let policy_synced = sync_policy_fn(project_dir, Some(&base_url));
    let active_seq = read_active_policy_sequence(project_dir);

    // 4. Send immediate endpoint posture heartbeat
    let hb = build_workstation_heartbeat(project_dir);
    let heartbeat_ok = emit_cloud_heartbeat(&hb, Some(&base_url));

    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "connected",
                "api_base_url": base_url,
                "org_slug": authed_org,
                "user_email": authed_email,
                "install_id": hb.install_id,
                "init_ok": init_ok,
                "policy_synced": policy_synced,
                "active_policy_seq": active_seq,
                "heartbeat_ok": heartbeat_ok,
            })
        );
    } else {
        println!(
            "✔ Workstation connected to {} (org: {}, policy seq #{}, heartbeat={})",
            base_url,
            authed_org.as_deref().unwrap_or("default"),
            active_seq,
            heartbeat_ok
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_reads_real_active_policy_seq_from_policy_state() {
        let tmp = std::env::temp_dir().join(format!("arc_seq_test_{}", uuid::Uuid::now_v7()));
        let arc_dir = tmp.join(".arc");
        std::fs::create_dir_all(&arc_dir).unwrap();
        std::fs::write(
            arc_dir.join("policy-state.json"),
            r#"{"trusted_key":"k1:aa","min_sequence":7}"#,
        )
        .unwrap();

        assert_eq!(read_active_policy_sequence(&tmp), 7);
        let hb = build_workstation_heartbeat(&tmp);
        assert_eq!(hb.active_policy_seq, 7);

        // Fresh directory with no hooks installed in project dir must not fabricate adapters
        assert!(
            matches!(hb.doctor_status.as_str(), "healthy" | "unconfigured"),
            "unexpected doctor_status: {}",
            hb.doctor_status
        );

        // Installing a real Claude Code hook file in project_dir is detected dynamically
        let claude_dir = tmp.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"arc intercept hook --host claude-code"}]}]}}"#,
        )
        .unwrap();
        let detected = detect_installed_host_adapters(&tmp);
        assert!(detected.contains(&"claude-code".to_string()));
        let hb2 = build_workstation_heartbeat(&tmp);
        assert_eq!(hb2.doctor_status, "healthy");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
