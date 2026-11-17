use arc_policy_engine::evaluator::{PolicyConfig, PolicyException};
use std::path::Path;

pub fn run_allow(
    path: &Path,
    rule: &str,
    target: Option<&str>,
    reason: &str,
    ttl_hours: u64,
    json: bool,
) -> bool {
    let policy_path = path.join(".arc").join("policy.json");
    let mut cfg = if policy_path.exists() {
        match std::fs::read_to_string(&policy_path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<PolicyConfig>(&s).map_err(|e| e.to_string()))
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Arc Allow] Failed to read {}: {e}", policy_path.display());
                return false;
            }
        }
    } else {
        PolicyConfig::default()
    };

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ttl_ms = ttl_hours.saturating_mul(3600).saturating_mul(1000);
    let exc = PolicyException {
        id: format!("exc-{}", uuid::Uuid::now_v7()),
        session_id: None,
        rule_id: Some(rule.to_string()),
        target: target.map(|t| t.to_string()),
        destination: None,
        granted_by: "arc-cli-allow".to_string(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms.saturating_add(ttl_ms),
        reason: reason.to_string(),
    };

    cfg.active_exceptions.push(exc.clone());

    match cfg.save_to_dir(path) {
        Ok(saved_path) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "policy_path": saved_path.display().to_string(),
                        "exception": exc,
                    })
                );
            } else {
                println!(
                    "✔ Added allowlist exception '{}' for rule '{}'{} (TTL: {}h) in {}",
                    exc.id,
                    rule,
                    target
                        .map(|t| format!(" on target '{t}'"))
                        .unwrap_or_default(),
                    ttl_hours,
                    saved_path.display()
                );
            }
            true
        }
        Err(e) => {
            eprintln!("[Arc Allow] Failed to save policy: {e}");
            false
        }
    }
}
