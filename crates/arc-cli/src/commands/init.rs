use arc_discover::scanner::{AuditReport, DiscoveryScanner};
use arc_hooks::claude_code::ClaudeCodeAdapter;
use arc_hooks::cline::ClineAdapter;
use arc_hooks::codex_cli::CodexCliAdapter;
use arc_hooks::cursor::CursorAdapter;
use arc_hooks::gemini_cli::GeminiCliAdapter;
use arc_hooks::github_copilot::GitHubCopilotAdapter;
use arc_hooks::kiro::KiroAdapter;
use arc_hooks::opencode::OpenCodeAdapter;
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

/// Structured result of `execute_init`, reused by both standalone `arc init` and `arc setup`
/// so composite onboarding commands can render a single unified summary without leaking
/// duplicate banners or corrupting `--json` stdout.
pub struct InitSummary {
    pub is_workstation_scope: bool,
    pub path: std::path::PathBuf,
    pub policy_path: std::path::PathBuf,
    pub policy_created: bool,
    pub audit_mode: bool,
    pub installed_hosts: Vec<&'static str>,
    pub mcp_registered: Vec<&'static str>,
    pub directives_installed: Vec<String>,
    pub hook_warnings: Vec<String>,
    pub mcp_servers: usize,
    pub agent_skills: usize,
    pub model_assets: usize,
    pub exposed_secrets: usize,
    pub files_scanned: usize,
    pub overall_risk_band: String,
    pub scan_duration_ms: u64,
    pub truncated: bool,
    pub audit_report: Option<Box<AuditReport>>,
}

pub fn execute_init(
    path: &Path,
    host: &str,
    audit_mode: bool,
    quiet: bool,
) -> Result<InitSummary, String> {
    if !path.exists() || !path.is_dir() {
        return Err(format!(
            "Target directory does not exist: {}",
            path.display()
        ));
    }

    // 1. Ensure .arc/policy.json exists (without clobbering existing user config)
    let policy_path = path.join(".arc").join("policy.json");
    let policy_created = if !policy_path.exists() {
        let mut cfg = PolicyConfig::default();
        if audit_mode {
            cfg.mode = PolicyMode::Audit;
        }
        cfg.block_unapproved_mcp = true;
        cfg.protect_sensitive_paths = true;
        cfg.protect_destructive_commands = true;
        cfg.require_approval_for_trifecta = true;
        cfg.require_approval_rules.insert("ARC-MCP-001".to_string());
        cfg.require_approval_rules.insert("ARC-FS-001".to_string());
        if let Err(e) = cfg.save_to_dir(path) {
            return Err(format!("Failed to write {}: {e}", policy_path.display()));
        }
        true
    } else {
        false
    };

    // 2. Install IDE hooks
    let host_lower = host.to_lowercase();
    let has_claude = path.join(".claude").exists();
    let has_cursor = path.join(".cursor").exists();
    let has_copilot = path.join(".github").join("hooks").exists()
        || path
            .join(".github")
            .join("copilot-instructions.md")
            .exists()
        || path.join(".vscode").exists();
    let has_codex = path.join(".codex").exists();
    let has_gemini = path.join(".gemini").exists();
    let has_windsurf = path.join(".windsurf").exists();
    let has_cline = path.join(".clinerules").exists() || path.join(".cline").exists();
    let has_kiro = path.join(".kiro").exists();
    let has_opencode = path.join(".opencode").exists() || path.join("opencode.json").exists();

    let (
        install_claude,
        install_cursor,
        install_copilot,
        install_codex,
        install_gemini,
        install_windsurf,
        install_cline,
        install_kiro,
        install_opencode,
    ) = match host_lower.as_str() {
        "none" => (
            false, false, false, false, false, false, false, false, false,
        ),
        "claude-code" | "claude" => (true, false, false, false, false, false, false, false, false),
        "cursor" => (false, true, false, false, false, false, false, false, false),
        "github-copilot" | "copilot" | "vscode-copilot" | "vscode" => {
            (false, false, true, false, false, false, false, false, false)
        }
        "codex-cli" | "codex" => (false, false, false, true, false, false, false, false, false),
        "gemini-cli" | "gemini" => (false, false, false, false, true, false, false, false, false),
        "windsurf" => (false, false, false, false, false, true, false, false, false),
        "cline" => (false, false, false, false, false, false, true, false, false),
        "kiro" | "aws-kiro" => (false, false, false, false, false, false, false, true, false),
        "opencode" => (false, false, false, false, false, false, false, false, true),
        "all" => (true, true, true, true, true, true, true, true, true),
        _ => {
            // auto: install for detected hosts, or Claude + Cursor if none exist yet
            if !has_claude
                && !has_cursor
                && !has_copilot
                && !has_codex
                && !has_gemini
                && !has_windsurf
                && !has_cline
                && !has_kiro
                && !has_opencode
            {
                (true, true, false, false, false, false, false, false, false)
            } else {
                (
                    has_claude,
                    has_cursor,
                    has_copilot,
                    has_codex,
                    has_gemini,
                    has_windsurf,
                    has_cline,
                    has_kiro,
                    has_opencode,
                )
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
    if install_copilot {
        match GitHubCopilotAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("github-copilot");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: GitHub Copilot hook install failed: {e}");
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
    if install_cline {
        match ClineAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("cline");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: Cline hook install failed: {e}");
            }
        }
    }
    if install_kiro {
        match KiroAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("kiro");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: AWS Kiro hook install failed: {e}");
            }
        }
    }
    if install_opencode {
        match OpenCodeAdapter::install_integration(path) {
            Ok(summary) => {
                installed_hosts.push("opencode");
                if let Some(w) = summary.volatile_warning {
                    hook_warnings.push(w);
                }
            }
            Err(e) => {
                eprintln!("[Arc Init] Warning: OpenCode plugin install failed: {e}");
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
    // Pin the built-in `vexa-arc` MCP server schema dynamically in `.arc/mcp-pins.lock` so
    // `arc mcp inventory` and `arc ci-report --fail-on-unpinned-mcp` do not flag Arc's own server.
    if !mcp_registered.is_empty() {
        if let Some(pin_hex) = crate::commands::mcp_server::builtin_tools_schema_hash() {
            let lock_path = path.join(".arc").join("mcp-pins.lock");
            let _ = arc_hooks::broker::save_mcp_pin_to_lockfile(&lock_path, "vexa-arc", &pin_hex);
        }
    }
    let directives_installed = install_secure_at_inception_directives(
        path,
        install_claude,
        install_cursor,
        install_windsurf,
    );

    // 3. Instant discovery + secret check (workstation-scoped if run in $HOME / root,
    //    bounded quick-scan if run in a project repository so `arc init` never hangs)
    let is_workstation_scope = vexa_core::fs_guard::is_unsafe_recursive_scan_root(path);
    let display_path = std::fs::canonicalize(path)
        .ok()
        .map(|p| {
            let s = p.display().to_string();
            s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
        })
        .unwrap_or_else(|| path.display().to_string());
    let scanner = DiscoveryScanner::new();
    let audit_report = if is_workstation_scope {
        if !quiet {
            eprintln!(
                "[Arc Init] Home/root directory detected ({}) — using workstation scope (known IDE/AI config roots only).",
                display_path
            );
            eprintln!(
                "[Arc Init] Tip: Run `arc init` inside a project repository for project-scoped policy & repo audit."
            );
        }
        scanner
            .audit_workstation()
            .map_err(|e| format!("Workstation discovery scan failed: {e}"))?
    } else {
        if !quiet {
            eprintln!("[Arc Init] Running quick discovery scan...");
        }
        // Use a deterministic sorted file cap (5,000 non-ignored files) with a generous
        // runaway safety timeout so repeated `arc init` runs always report identical counts.
        scanner
            .audit_directory_bounded(path, 5_000, std::time::Duration::from_secs(30))
            .map_err(|e| format!("Discovery scan failed: {e}"))?
    };

    // Exclude Vexa Arc's own self-managed MCP entry and directive file from the baseline
    // AI Assets summary so first and repeated `arc init` runs report identical project counts.
    let (mcp_server_count, agent_skill_count, model_asset_count) =
        summarize_project_discovery(&audit_report);

    Ok(InitSummary {
        is_workstation_scope,
        path: path.to_path_buf(),
        policy_path,
        policy_created,
        audit_mode,
        installed_hosts,
        mcp_registered,
        directives_installed,
        hook_warnings,
        mcp_servers: mcp_server_count,
        agent_skills: agent_skill_count,
        model_assets: model_asset_count,
        exposed_secrets: audit_report.exposed_secrets.len(),
        files_scanned: audit_report.files_scanned,
        overall_risk_band: format!("{:?}", audit_report.overall_risk_band).to_lowercase(),
        scan_duration_ms: audit_report.scan_duration_ms,
        truncated: audit_report.truncated,
        audit_report: Some(Box::new(audit_report)),
    })
}

pub fn run_init(path: &Path, host: &str, audit_mode: bool, json: bool) -> bool {
    let summary = match execute_init(path, host, audit_mode, json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[Arc Init] {e}");
            return false;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "scope": if summary.is_workstation_scope { "workstation" } else { "project" },
                "path": summary.path.display().to_string(),
                "policy_path": summary.policy_path.display().to_string(),
                "policy_created": summary.policy_created,
                "mode": if summary.audit_mode { "audit" } else { "enforce" },
                "installed_hosts": summary.installed_hosts,
                "mcp_registered": summary.mcp_registered,
                "directives_installed": summary.directives_installed,
                "warnings": summary.hook_warnings,
                "discovery": {
                    "mcp_servers": summary.mcp_servers,
                    "agent_skills": summary.agent_skills,
                    "model_assets": summary.model_assets,
                    "exposed_secrets": summary.exposed_secrets,
                    "files_scanned": summary.files_scanned,
                    "overall_risk_band": summary.overall_risk_band,
                    "scan_duration_ms": summary.scan_duration_ms,
                    "truncated": summary.truncated,
                }
            })
        );
        return true;
    }

    println!("\n=======================================================");
    println!("               VEXA ARC INITIALIZED                    ");
    println!("=======================================================");
    println!(
        "Scope:           {}",
        if summary.is_workstation_scope {
            "workstation (home/root directory detected)"
        } else {
            "project"
        }
    );
    println!(
        "Policy:          {} ({})",
        summary.policy_path.display(),
        if summary.policy_created {
            if summary.audit_mode {
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
        if summary.installed_hosts.is_empty() {
            "none".to_string()
        } else {
            summary.installed_hosts.join(", ")
        }
    );
    if !summary.mcp_registered.is_empty() {
        println!(
            "MCP Server:      registered in {}",
            summary.mcp_registered.join(", ")
        );
    }
    if !summary.directives_installed.is_empty() {
        println!(
            "Directives:      {}",
            summary.directives_installed.join(", ")
        );
    }
    println!(
        "AI Assets:       {} MCP server(s), {} rule/skill file(s), {} model(s)",
        summary.mcp_servers, summary.agent_skills, summary.model_assets
    );
    println!(
        "Exposed Secrets: {}",
        format_exposed_secrets_line(
            summary.exposed_secrets,
            summary.files_scanned,
            summary.scan_duration_ms,
            summary.truncated,
        )
    );
    for w in &summary.hook_warnings {
        println!("[WARN] {w}");
    }
    println!("\nNext steps:");
    println!("  • Run `arc audit` for full AI asset & MCP risk details");
    println!("  • Run `arc sca audit` to check dependencies for vulnerabilities");
    println!("  • Run `arc setup` to connect to Vexa Cloud via browser approval (pass `--api-url <URL>` for dev/self-hosted, or `--token <PAT>` for CI/headless)");
    println!("=======================================================\n");

    true
}

/// Counts discovered project AI assets excluding Vexa Arc's own self-managed MCP entry
/// (`vexa-arc`) and directive file (`vexa-arc-security.mdc`) so baseline counts stay
/// identical across repeated `arc init` runs.
fn summarize_project_discovery(report: &AuditReport) -> (usize, usize, usize) {
    let mcp_servers = report
        .mcp_servers
        .iter()
        .filter(|s| s.name != "vexa-arc")
        .count();
    let agent_skills = report
        .agent_skills
        .iter()
        .filter(|s| !s.name.eq_ignore_ascii_case("vexa-arc-security.mdc"))
        .count();
    let model_assets = report.model_assets.len();
    (mcp_servers, agent_skills, model_assets)
}

/// Formats the `Exposed Secrets:` summary line, rendering a lower-bound `N+` indicator
/// whenever a bounded quick-scan was capped so partial results are never mistaken for totals.
pub fn format_exposed_secrets_line(
    count: usize,
    files_scanned: usize,
    duration_ms: u64,
    truncated: bool,
) -> String {
    if truncated {
        format!(
            "{count}+ finding(s) (partial scan: {files_scanned} files in {duration_ms} ms; capped — run `arc audit` for full scan)"
        )
    } else {
        format!("{count} finding(s) (scanned {files_scanned} files in {duration_ms} ms)")
    }
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

    #[test]
    fn format_exposed_secrets_distinguishes_complete_and_truncated_scans() {
        let complete = format_exposed_secrets_line(4, 120, 45, false);
        assert_eq!(complete, "4 finding(s) (scanned 120 files in 45 ms)");

        let partial = format_exposed_secrets_line(9, 5000, 310, true);
        assert_eq!(
            partial,
            "9+ finding(s) (partial scan: 5000 files in 310 ms; capped — run `arc audit` for full scan)"
        );
    }

    #[test]
    fn summarize_project_discovery_excludes_vexa_arc_self_managed_entries() {
        let dir = std::env::temp_dir().join(format!("arc_init_baseline_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join(".cursor")).unwrap();
        std::fs::write(
            dir.join(".cursor").join("mcp.json"),
            r#"{"mcpServers":{"user-mcp":{"command":"node","args":["srv.js"]}}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "# Team Rules\n").unwrap();

        // Install Arc's own MCP server and directive file
        upsert_mcp_server_config(&dir.join(".cursor").join("mcp.json"), "arc").unwrap();
        upsert_mcp_server_config(&dir.join(".mcp.json"), "arc").unwrap();
        install_secure_at_inception_directives(&dir, true, true, false);

        let scanner = DiscoveryScanner::new();
        let report = scanner.audit_directory(&dir).unwrap();
        // Raw report sees user-mcp + 2 vexa-arc entries, and CLAUDE.md + vexa-arc-security.mdc
        assert_eq!(report.mcp_servers.len(), 3);
        assert_eq!(report.agent_skills.len(), 2);

        // Baseline summary for `arc init` excludes Arc's own managed entries
        let (mcps, skills, models) = summarize_project_discovery(&report);
        assert_eq!(mcps, 1);
        assert_eq!(skills, 1);
        assert_eq!(models, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
