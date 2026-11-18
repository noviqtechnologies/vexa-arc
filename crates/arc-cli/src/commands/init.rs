use arc_discover::scanner::DiscoveryScanner;
use arc_hooks::claude_code::ClaudeCodeAdapter;
use arc_hooks::codex_cli::CodexCliAdapter;
use arc_hooks::cursor::CursorAdapter;
use arc_hooks::gemini_cli::GeminiCliAdapter;
use arc_hooks::windsurf::WindsurfAdapter;
use arc_policy_engine::evaluator::{PolicyConfig, PolicyMode};
use std::path::Path;

const DIRECTIVE_MARKER: &str = "<!-- vexa-arc-security-directive -->";

const CURSOR_MDC_DIRECTIVE: &str = r#"---
description: Vexa Arc Secure-at-Inception AI Coding Guardrails
globs: ["**/*"]
alwaysApply: true
---
<!-- vexa-arc-security-directive -->
# Vexa Arc Security Directives

1. **Pre-Flight Package Verification:** Before installing or adding any new dependency in `package.json`, `requirements.txt`, `pyproject.toml`, or `Cargo.toml`, call the `arc_check_package` MCP tool to verify the package against typosquatting, slopsquatting, and OSV/KEV vulnerabilities.
2. **Zero-Secret Commits:** Never hardcode API keys, tokens, or private keys in source files. Call `arc_scan_secrets` on modified files if unsure.
3. **Dependency & AI Asset Audit:** When modifying dependency lockfiles or `.mcp.json` / agent skill files, call `arc_sca_audit` or `arc_audit_ai_assets` to verify compliance.
"#;

const MARKDOWN_AGENT_DIRECTIVE: &str = r#"
<!-- vexa-arc-security-directive -->
## Vexa Arc Security Directives (Secure-at-Inception)
- Before installing or adding any third-party package, invoke the `arc_check_package` MCP tool to check for slopsquatting and known vulnerabilities.
- Never write hardcoded credentials or tokens into source files; use environment variables and verify with `arc_scan_secrets`.
"#;

fn resolve_arc_exe_string() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| "arc".to_string())
}

/// Atomically upserts `mcpServers.vexa-arc` in an MCP JSON configuration file (`mcp.json` or `.cursor/mcp.json`)
/// while preserving all existing user-configured MCP servers and top-level keys.
pub fn upsert_mcp_server_config(mcp_json_path: &Path, arc_cmd: &str) -> Result<bool, String> {
    if let Some(parent) = mcp_json_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }

    let mut root: serde_json::Value = if mcp_json_path.exists() {
        let raw = std::fs::read_to_string(mcp_json_path)
            .map_err(|e| format!("Failed to read {}: {e}", mcp_json_path.display()))?;
        if raw.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&raw)
                .map_err(|e| format!("Invalid JSON in {}: {e}", mcp_json_path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let Some(obj) = root.as_object_mut() else {
        return Err(format!(
            "Expected JSON object at root of {}",
            mcp_json_path.display()
        ));
    };

    let servers = obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| serde_json::json!({}));

    let Some(servers_obj) = servers.as_object_mut() else {
        return Err(format!(
            "'mcpServers' in {} is not a JSON object",
            mcp_json_path.display()
        ));
    };

    let desired = serde_json::json!({
        "command": arc_cmd,
        "args": ["mcp-server"]
    });

    if servers_obj.get("vexa-arc") == Some(&desired) {
        return Ok(false);
    }

    servers_obj.insert("vexa-arc".to_string(), desired);
    let formatted = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize MCP config: {e}"))?;
    std::fs::write(mcp_json_path, formatted)
        .map_err(|e| format!("Failed to write {}: {e}", mcp_json_path.display()))?;
    Ok(true)
}

/// Ensures `.cursor/rules/vexa-arc-security.mdc` is installed and any existing `CLAUDE.md` or `.windsurfrules`
/// contains the idempotent Secure-at-Inception directive block.
pub fn install_secure_at_inception_directives(
    base_dir: &Path,
    install_claude: bool,
    install_cursor: bool,
    install_windsurf: bool,
) -> Vec<String> {
    let mut updated = Vec::new();

    if install_cursor {
        let rules_dir = base_dir.join(".cursor").join("rules");
        let mdc_path = rules_dir.join("vexa-arc-security.mdc");
        let needs_write = match std::fs::read_to_string(&mdc_path) {
            Ok(existing) => !existing.contains(DIRECTIVE_MARKER),
            Err(_) => true,
        };
        if needs_write
            && std::fs::create_dir_all(&rules_dir).is_ok()
            && std::fs::write(&mdc_path, CURSOR_MDC_DIRECTIVE).is_ok()
        {
            updated.push(".cursor/rules/vexa-arc-security.mdc".to_string());
        }
    }

    if install_claude {
        let claude_md = base_dir.join("CLAUDE.md");
        if claude_md.exists() {
            if let Ok(existing) = std::fs::read_to_string(&claude_md) {
                if !existing.contains(DIRECTIVE_MARKER) {
                    let mut combined = existing;
                    if !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(MARKDOWN_AGENT_DIRECTIVE);
                    if std::fs::write(&claude_md, combined).is_ok() {
                        updated.push("CLAUDE.md".to_string());
                    }
                }
            }
        }
    }

    if install_windsurf {
        let ws_rules = base_dir.join(".windsurfrules");
        if ws_rules.exists() {
            if let Ok(existing) = std::fs::read_to_string(&ws_rules) {
                if !existing.contains(DIRECTIVE_MARKER) {
                    let mut combined = existing;
                    if !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(MARKDOWN_AGENT_DIRECTIVE);
                    if std::fs::write(&ws_rules, combined).is_ok() {
                        updated.push(".windsurfrules".to_string());
                    }
                }
            }
        }
    }

    updated
}

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
    let has_codex = path.join(".codex").exists();
    let has_gemini = path.join(".gemini").exists();
    let has_windsurf = path.join(".windsurf").exists();

    let (install_claude, install_cursor, install_codex, install_gemini, install_windsurf) =
        match host_lower.as_str() {
            "none" => (false, false, false, false, false),
            "claude-code" | "claude" => (true, false, false, false, false),
            "cursor" => (false, true, false, false, false),
            "codex-cli" | "codex" => (false, false, true, false, false),
            "gemini-cli" | "gemini" => (false, false, false, true, false),
            "windsurf" => (false, false, false, false, true),
            "all" => (true, true, true, true, true),
            _ => {
                // auto: install for detected hosts, or Claude + Cursor if none exist yet
                if !has_claude && !has_cursor && !has_codex && !has_gemini && !has_windsurf {
                    (true, true, false, false, false)
                } else {
                    (has_claude, has_cursor, has_codex, has_gemini, has_windsurf)
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
    if install_codex {
        match CodexCliAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("codex-cli");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Codex CLI hook install failed: {e}");
            }
        }
    }
    if install_gemini {
        match GeminiCliAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("gemini-cli");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Gemini CLI hook install failed: {e}");
            }
        }
    }
    if install_windsurf {
        match WindsurfAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("windsurf");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Windsurf hook install failed: {e}");
            }
        }
    }

    // 2b. Register local MCP server & Secure-at-Inception directives ("Snyk Studio" flow)
    let arc_exe = resolve_arc_exe_string();
    let mut mcp_registered = Vec::new();
    if install_cursor {
        let cursor_mcp = path.join(".cursor").join("mcp.json");
        if upsert_mcp_server_config(&cursor_mcp, &arc_exe).is_ok() {
            mcp_registered.push(".cursor/mcp.json");
        }
    }
    if install_claude {
        let claude_mcp = path.join(".mcp.json");
        if upsert_mcp_server_config(&claude_mcp, &arc_exe).is_ok() {
            mcp_registered.push(".mcp.json");
        }
    }
    let directives_installed = install_secure_at_inception_directives(
        path,
        install_claude,
        install_cursor,
        install_windsurf,
    );

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
                "mcp_registered": mcp_registered,
                "directives_installed": directives_installed,
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
    if !mcp_registered.is_empty() {
        println!(
            "MCP Server:      registered in {}",
            mcp_registered.join(", ")
        );
    }
    if !directives_installed.is_empty() {
        println!("Directives:      {}", directives_installed.join(", "));
    }
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
    println!("  • Run `arc auth login --token <vexa_pat_...>` to stream events to Vexa Cloud");
    println!("=======================================================\n");

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_upsert_and_directives_are_idempotent_and_preserve_user_servers() {
        let dir = std::env::temp_dir().join(format!("arc_init_studio_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join(".cursor")).unwrap();
        let cursor_mcp = dir.join(".cursor").join("mcp.json");
        std::fs::write(
            &cursor_mcp,
            r#"{"mcpServers":{"existing":{"command":"node","args":["srv.js"]}}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "# Project Instructions\n").unwrap();

        assert!(upsert_mcp_server_config(&cursor_mcp, "/usr/local/bin/arc").unwrap());
        // Second call with identical command is a no-op
        assert!(!upsert_mcp_server_config(&cursor_mcp, "/usr/local/bin/arc").unwrap());

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cursor_mcp).unwrap()).unwrap();
        assert_eq!(parsed["mcpServers"]["existing"]["command"], "node");
        assert_eq!(
            parsed["mcpServers"]["vexa-arc"]["command"],
            "/usr/local/bin/arc"
        );
        assert_eq!(parsed["mcpServers"]["vexa-arc"]["args"][0], "mcp-server");

        let first_dirs = install_secure_at_inception_directives(&dir, true, true, false);
        assert_eq!(first_dirs.len(), 2);
        assert!(dir
            .join(".cursor")
            .join("rules")
            .join("vexa-arc-security.mdc")
            .exists());
        assert!(std::fs::read_to_string(dir.join("CLAUDE.md"))
            .unwrap()
            .contains(DIRECTIVE_MARKER));

        // Second call is idempotent
        let second_dirs = install_secure_at_inception_directives(&dir, true, true, false);
        assert!(second_dirs.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
