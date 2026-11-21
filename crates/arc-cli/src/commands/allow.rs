use arc_policy_engine::evaluator::{PolicyConfig, PolicyException, PolicySource};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AllowCommandOptions<'a> {
    pub path: &'a Path,
    pub rule: Option<&'a str>,
    pub target: Option<&'a str>,
    pub server: Option<&'a str>,
    pub schema_fingerprint: Option<&'a str>,
    pub reason: &'a str,
    pub ttl_hours: u64,
    pub list: bool,
    pub explain_id: Option<&'a str>,
    pub revoke_id: Option<&'a str>,
    pub diff: bool,
    pub json: bool,
}

fn load_project_policy_file(path: &Path) -> Result<(PolicyConfig, bool), String> {
    let policy_path = path.join(".arc").join("policy.json");
    if policy_path.exists() {
        let raw = std::fs::read_to_string(&policy_path)
            .map_err(|e| format!("Failed to read {}: {e}", policy_path.display()))?;
        let mut cfg: PolicyConfig = serde_json::from_str(&raw)
            .map_err(|e| format!("Failed to parse {}: {e}", policy_path.display()))?;
        cfg.source = Some(PolicySource::ProjectLocal);
        for exc in &mut cfg.active_exceptions {
            if exc.source.is_none() {
                exc.source = Some(PolicySource::ProjectLocal);
            }
        }
        Ok((cfg, true))
    } else {
        let cfg = PolicyConfig {
            source: Some(PolicySource::ProjectLocal),
            ..Default::default()
        };
        Ok((cfg, false))
    }
}

#[cfg(test)]
pub fn run_allow(
    path: &Path,
    rule: &str,
    target: Option<&str>,
    reason: &str,
    ttl_hours: u64,
    json: bool,
) -> bool {
    run_allow_with_options(AllowCommandOptions {
        path,
        rule: Some(rule),
        target,
        server: None,
        schema_fingerprint: None,
        reason,
        ttl_hours,
        list: false,
        explain_id: None,
        revoke_id: None,
        diff: false,
        json,
    })
}

pub fn run_allow_with_options(opts: AllowCommandOptions<'_>) -> bool {
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let project_scope = opts
        .path
        .canonicalize()
        .unwrap_or_else(|_| opts.path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let (mut cfg, existed) = match load_project_policy_file(opts.path) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[Arc Allow] {e}");
            return false;
        }
    };

    // Check if a signed organization policy is present in this project
    let signed_org_path = opts.path.join(".arc").join("signed_policy.json");
    let effective_policy = PolicyConfig::try_load_with_precedence(Some(opts.path)).ok();
    let signed_org_active = signed_org_path.exists()
        || effective_policy.as_ref().and_then(|p| p.source)
            == Some(PolicySource::SignedOrganization);

    // 1. LIST operation
    if opts.list {
        let entries: Vec<serde_json::Value> = cfg
            .active_exceptions
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "rule_id": e.rule_id,
                    "server_name": e.server_name,
                    "target": e.target,
                    "schema_fingerprint": e.schema_fingerprint,
                    "project_scope": e.project_scope.clone().unwrap_or_else(|| project_scope.clone()),
                    "source": e.source.unwrap_or(PolicySource::ProjectLocal),
                    "active": e.is_active(now_ms),
                    "overridden_by_signed_org": signed_org_active,
                    "created_at_unix_ms": e.created_at_unix_ms,
                    "expires_at_unix_ms": e.expires_at_unix_ms,
                    "granted_by": e.granted_by,
                    "reason": e.reason,
                })
            })
            .collect();

        if opts.json {
            println!(
                "{}",
                serde_json::json!({
                    "policy_path": opts.path.join(".arc").join("policy.json").display().to_string(),
                    "policy_revision": cfg.revision_hash(),
                    "signed_organization_active": signed_org_active,
                    "exceptions": entries,
                })
            );
        } else {
            println!(
                "[Arc Allow] Active project-local exceptions ({}): {}",
                entries.len(),
                opts.path.join(".arc").join("policy.json").display()
            );
            if signed_org_active {
                println!(
                    "  [WARN] Signed organization policy is active; project-local exceptions cannot override it."
                );
            }
            for e in &cfg.active_exceptions {
                let status = if !e.is_active(now_ms) {
                    "EXPIRED"
                } else if signed_org_active {
                    "OVERRIDDEN_BY_ORG_POLICY"
                } else {
                    "ACTIVE"
                };
                println!(
                    "  - {} [{}] rule={} server={} tool/target={} expires_ms={} reason=\"{}\"",
                    e.id,
                    status,
                    e.rule_id.as_deref().unwrap_or("*"),
                    e.server_name.as_deref().unwrap_or("*"),
                    e.target.as_deref().unwrap_or("*"),
                    e.expires_at_unix_ms,
                    e.reason
                );
            }
        }
        return true;
    }

    // 2. EXPLAIN operation
    if let Some(explain_id) = opts.explain_id {
        let Some(exc) = cfg.active_exceptions.iter().find(|e| e.id == explain_id) else {
            eprintln!("[Arc Allow] Exception '{}' not found.", explain_id);
            return false;
        };
        let is_active = exc.is_active(now_ms);
        if opts.json {
            println!(
                "{}",
                serde_json::json!({
                    "found": true,
                    "id": exc.id,
                    "active": is_active && !signed_org_active,
                    "expired": !is_active,
                    "overridden_by_signed_org": signed_org_active,
                    "policy_source": exc.source.unwrap_or(PolicySource::ProjectLocal),
                    "project_scope": exc.project_scope.clone().unwrap_or_else(|| project_scope.clone()),
                    "exception": exc,
                })
            );
        } else {
            println!("Exception ID:       {}", exc.id);
            println!(
                "Rule ID:            {}",
                exc.rule_id.as_deref().unwrap_or("*")
            );
            println!(
                "Server Identity:    {}",
                exc.server_name.as_deref().unwrap_or("*")
            );
            println!(
                "Tool / Target:      {}",
                exc.target.as_deref().unwrap_or("*")
            );
            println!(
                "Schema Fingerprint: {}",
                exc.schema_fingerprint.as_deref().unwrap_or("unpinned")
            );
            println!(
                "Project Scope:      {}",
                exc.project_scope.as_deref().unwrap_or(&project_scope)
            );
            println!(
                "Policy Source:      {:?}",
                exc.source.unwrap_or(PolicySource::ProjectLocal)
            );
            println!("Granted By:         {}", exc.granted_by);
            println!(
                "Expires (unix ms):  {} (active={})",
                exc.expires_at_unix_ms, is_active
            );
            println!("Reason:             {}", exc.reason);
            if signed_org_active {
                println!(
                    "Precedence Note:    OVERRIDDEN — SignedOrganization policy is active and cannot be weakened by local exceptions."
                );
            }
        }
        return true;
    }

    // 3. REVOKE operation
    if let Some(revoke_id) = opts.revoke_id {
        let before_len = cfg.active_exceptions.len();
        cfg.active_exceptions.retain(|e| e.id != revoke_id);
        if cfg.active_exceptions.len() == before_len {
            eprintln!("[Arc Allow] Exception '{}' not found.", revoke_id);
            return false;
        }
        match cfg.save_to_dir(opts.path) {
            Ok(saved_path) => {
                if opts.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "success": true,
                            "revoked_id": revoke_id,
                            "policy_path": saved_path.display().to_string(),
                            "policy_revision": cfg.revision_hash(),
                        })
                    );
                } else {
                    println!(
                        "✔ Revoked exception '{}' from {}",
                        revoke_id,
                        saved_path.display()
                    );
                }
                return true;
            }
            Err(e) => {
                eprintln!("[Arc Allow] Failed to save policy after revoke: {e}");
                return false;
            }
        }
    }

    // 4. DIFF operation (compare project-local policy against built-in default / effective policy)
    if opts.diff {
        let default_cfg = PolicyConfig::default();
        let added_servers: Vec<String> = cfg
            .allowed_mcp_servers
            .difference(&default_cfg.allowed_mcp_servers)
            .cloned()
            .collect();
        let removed_servers: Vec<String> = default_cfg
            .allowed_mcp_servers
            .difference(&cfg.allowed_mcp_servers)
            .cloned()
            .collect();
        if opts.json {
            println!(
                "{}",
                serde_json::json!({
                    "policy_exists": existed,
                    "mode": cfg.mode.as_str(),
                    "default_mode": default_cfg.mode.as_str(),
                    "block_unapproved_mcp": cfg.block_unapproved_mcp,
                    "added_allowed_mcp_servers": added_servers,
                    "removed_allowed_mcp_servers": removed_servers,
                    "active_exceptions_count": cfg.active_exceptions.len(),
                    "active_exceptions": cfg.active_exceptions,
                    "policy_revision": cfg.revision_hash(),
                })
            );
        } else {
            println!(
                "[Arc Allow Diff] Policy diff against default baseline ({})",
                opts.path.join(".arc").join("policy.json").display()
            );
            println!(
                "  mode:                 {} (default: {})",
                cfg.mode.as_str(),
                default_cfg.mode.as_str()
            );
            println!(
                "  block_unapproved_mcp: {} (default: {})",
                cfg.block_unapproved_mcp, default_cfg.block_unapproved_mcp
            );
            println!("  added_mcp_servers:    {:?}", added_servers);
            println!("  removed_mcp_servers:  {:?}", removed_servers);
            println!("  active_exceptions:    {}", cfg.active_exceptions.len());
        }
        return true;
    }

    // 5. ADD exception operation
    let Some(rule) = opts.rule else {
        eprintln!("[Arc Allow] --rule is required when adding an exception (or pass --list, --explain, --revoke, --diff).");
        return false;
    };

    if rule == "ARC-EMG-001" {
        eprintln!(
            "[Arc Allow] Denied: Emergency Deny rule (ARC-EMG-001) cannot be bypassed by local exceptions."
        );
        return false;
    }

    if let Some(srv) = opts.server.or(opts.target) {
        if cfg.emergency_deny_servers.contains(srv)
            || effective_policy
                .as_ref()
                .map(|p| p.emergency_deny_servers.contains(srv))
                .unwrap_or(false)
        {
            eprintln!(
                "[Arc Allow] Denied: MCP server '{}' is in emergency_deny_servers and cannot be allowlisted locally.",
                srv
            );
            return false;
        }
    }

    if signed_org_active {
        eprintln!(
            "[Arc Allow] Denied: Signed organization policy (.arc/signed_policy.json) is active in this project and cannot be weakened by local exceptions."
        );
        return false;
    }

    let ttl_ms = opts.ttl_hours.saturating_mul(3600).saturating_mul(1000);
    let exc = PolicyException {
        id: format!("exc-{}", uuid::Uuid::now_v7()),
        session_id: None,
        rule_id: Some(rule.to_string()),
        target: opts.target.map(|t| t.to_string()),
        destination: None,
        server_name: opts.server.map(|s| s.to_string()),
        schema_fingerprint: opts.schema_fingerprint.map(|s| s.to_string()),
        project_scope: Some(project_scope.clone()),
        source: Some(PolicySource::ProjectLocal),
        granted_by: "arc-cli-allow".to_string(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms.saturating_add(ttl_ms),
        reason: opts.reason.to_string(),
    };

    cfg.active_exceptions.push(exc.clone());

    match cfg.save_to_dir(opts.path) {
        Ok(saved_path) => {
            if opts.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "policy_path": saved_path.display().to_string(),
                        "policy_revision": cfg.revision_hash(),
                        "policy_source": "project_local",
                        "project_scope": project_scope,
                        "exception": exc,
                    })
                );
            } else {
                println!(
                    "✔ Added allowlist exception '{}' for rule '{}'{} (server: {}, schema: {}, scope: {}, source: project_local, TTL: {}h) in {}",
                    exc.id,
                    rule,
                    opts.target
                        .map(|t| format!(" on target '{t}'"))
                        .unwrap_or_default(),
                    exc.server_name.as_deref().unwrap_or("*"),
                    exc.schema_fingerprint.as_deref().unwrap_or("unpinned"),
                    project_scope,
                    opts.ttl_hours,
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
