use arc_discover::scanner::DiscoveryScanner;
use arc_hooks::claude_code::ClaudeCodeAdapter;
use arc_hooks::cursor::CursorAdapter;
use arc_policy_engine::evaluator::{PolicyConfig, PolicyMode};
use std::path::Path;

pub fn run_init(path: &Path, host: &str, audit_mode: bool, json: bool) -> bool {
    if !path.exists() || !path.is_dir() {
        eprintln!(
            "[Arc Init] Target directory does not exist: {}",
            path.display()
        );
        return false;
    }

    // 1. Ensure .arc/policy.json exists (without clobbering existing user config)
    let policy_path = path.join(".arc").join("policy.json");
    let policy_created = if !policy_path.exists() {
        let mut cfg = PolicyConfig::default();
        if audit_mode {
            cfg.mode = PolicyMode::Audit;
        }
        cfg.require_approval_for_trifecta = true;
        if let Err(e) = cfg.save_to_dir(path) {
            eprintln!("[Arc Init] Failed to write {}: {e}", policy_path.display());
            return false;
        }
        true
    } else {
        false
    };

    // 2. Install IDE hooks
    let host_lower = host.to_lowercase();
    let has_claude = path.join(".claude").exists();
    let has_cursor = path.join(".cursor").exists();

    let (install_claude, install_cursor) = match host_lower.as_str() {
        "none" => (false, false),
        "claude-code" | "claude" => (true, false),
        "cursor" => (false, true),
        "all" => (true, true),
        _ => {
            // auto: install for detected hosts, or both if neither exists yet
            if !has_claude && !has_cursor {
                (true, true)
            } else {
                (has_claude, has_cursor)
            }
        }
    };

    let mut installed_hosts = Vec::new();
    let mut hook_warnings = Vec::new();

    if install_claude {
        match ClaudeCodeAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("claude-code");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Claude Code hook install failed: {e}");
            }
        }
    }
    if install_cursor {
        match CursorAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("cursor");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Cursor hook install failed: {e}");
            }
        }
    }

    // 3. Instant repository discovery + secret check
    let scanner = DiscoveryScanner::new();
    let audit_report = match scanner.audit_directory(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[Arc Init] Discovery scan failed: {e}");
            return false;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "path": path.display().to_string(),
                "policy_path": policy_path.display().to_string(),
                "policy_created": policy_created,
                "mode": if audit_mode { "audit" } else { "enforce" },
                "installed_hosts": installed_hosts,
                "warnings": hook_warnings,
                "discovery": {
                    "mcp_servers": audit_report.mcp_servers.len(),
                    "agent_skills": audit_report.agent_skills.len(),
                    "model_assets": audit_report.model_assets.len(),
                    "exposed_secrets": audit_report.exposed_secrets.len(),
                    "overall_risk_band": format!("{:?}", audit_report.overall_risk_band).to_lowercase(),
                    "scan_duration_ms": audit_report.scan_duration_ms,
                }
            })
        );
        return true;
    }

    println!("\n=======================================================");
    println!("               VEXA ARC INITIALIZED                    ");
    println!("=======================================================");
    println!(
        "Policy:          {} ({})",
        policy_path.display(),
        if policy_created {
            if audit_mode {
                "created in audit mode"
            } else {
                "created"
            }
        } else {
            "existing preserved"
        }
    );
    println!(
        "IDE Hooks:       {}",
        if installed_hosts.is_empty() {
            "none".to_string()
        } else {
            installed_hosts.join(", ")
        }
    );
    println!(
        "AI Assets:       {} MCP server(s), {} rule/skill file(s), {} model(s)",
        audit_report.mcp_servers.len(),
        audit_report.agent_skills.len(),
        audit_report.model_assets.len()
    );
    println!(
        "Exposed Secrets: {} finding(s) (scan took {} ms)",
        audit_report.exposed_secrets.len(),
        audit_report.scan_duration_ms
    );
    for w in &hook_warnings {
        println!("[WARN] {w}");
    }
    println!("\nNext steps:");
    println!("  • Run `arc audit` for full AI asset & MCP risk details");
    println!("  • Run `arc sca audit` to check dependencies for vulnerabilities");
    println!("  • Run `arc mcp-server` to expose Arc tools to any MCP-capable agent");
    println!("=======================================================\n");

    true
}
