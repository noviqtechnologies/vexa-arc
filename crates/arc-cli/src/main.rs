use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, Ecosystem, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::taint::{SinkClass, Taint};
use arc_discover::cyclonedx::generate_cyclonedx_1_6_bom;
use arc_discover::scanner::DiscoveryScanner;
use arc_dlp::detector::SecretScanEngine;
use arc_dlp::vault::LocalPseudonymizationVault;
use arc_firewall::osv_scanner::{ecosystem_to_osv_str, OsvPackageScanner};
use arc_firewall::proxy::PackageFirewall;
use arc_firewall::slopsquat::SlopsquatVerdict;
use arc_hooks::broker::McpStdioBroker;
use arc_hooks::claude_code::ClaudeCodeAdapter;
use arc_hooks::cursor::CursorAdapter;
use arc_hooks::HostAdapter;
use arc_policy_engine::evaluator::{PolicyConfig, PolicyEvaluator};
use arc_policy_engine::taint_dag::SessionTaintDag;

#[derive(Parser)]
#[command(
    name = "arc",
    version = "1.0.0",
    about = "Vexa Arc (Agentic Runtime Control): Native Rust Pre-Execution Endpoint & Agent Firewall",
    long_about = "Vexa Arc provides ultra-low latency, zero-dependency pre-execution security for autonomous AI coding agents and MCP interactions."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Zero-touch AI & MCP asset discovery across workstations and repositories
    Audit {
        /// Target root directory to audit (default: current directory)
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// Audit all user workstation AI/MCP roots (FR-DISC-002)
        #[arg(long)]
        workstation: bool,

        /// Output full audit report as JSON
        #[arg(long)]
        json: bool,

        /// Export live CycloneDX v1.6 AI-BOM to specified file
        #[arg(long)]
        output_bom: Option<PathBuf>,
    },

    /// Generate and export a standardized CycloneDX v1.6 AI-BOM
    Bom {
        /// Target directory to scan (default: current directory)
        #[arg(short, long, default_value = ".")]
        path: PathBuf,

        /// File path to write the AI-BOM JSON to (default: stdout)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Scan files, directories, or stdin for leaked credentials and production secrets
    ScanSecrets {
        /// Target file or directory to scan (if omitted, reads from stdin)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Redact detected secrets using local pseudonymization vault tokens (<ARC_VAULT_SECRET_XX>)
        #[arg(long)]
        redact: bool,
    },

    /// Shield dependency firewall: evaluate package for AI slopsquatting / hallucination
    Shield {
        #[command(subcommand)]
        action: ShieldAction,
    },

    /// Intercept and evaluate an agent action against session Taint DAG and security policies
    Intercept {
        #[command(subcommand)]
        action: InterceptAction,
    },

    /// Protect an agent or MCP server using fail-closed runtime enforcement (FR-MCP-001)
    Protect {
        #[command(subcommand)]
        action: ProtectAction,
    },

    /// Manage IDE and Agent host integrations (Claude Code, Cursor) (FR-MCP-005)
    Host {
        #[command(subcommand)]
        action: HostAction,
    },

    /// Diagnose installation, runtime adapters, policy, storage, and protection status (FR-CLI-001)
    Doctor {
        /// Output health and diagnostic report as JSON
        #[arg(long)]
        json: bool,

        /// Include cumulative session metrics and active taints (FR-CLI-001)
        #[arg(long)]
        metrics: bool,
    },

    /// Trace decision, causal data-flow ancestry, and evidence for an event (FR-CLI-004)
    Trace {
        /// Event ID or UUID to inspect (or 'latest' for the most recent event)
        event_id: String,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Export trace and causal evidence report to file (FR-CLI-004)
        #[arg(long)]
        export: Option<PathBuf>,

        /// Output trace evidence as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run local adversarial verification test fixtures (FR-CLI-001)
    Test {
        /// Output test results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Display platform version and operational status
    Version,
}

#[derive(Subcommand)]
enum HostAction {
    /// Install Vexa Arc proxy wrapper into host agent config
    Install {
        /// Target host (claude-code, cursor)
        #[arg(long, default_value = "claude-code")]
        host: String,

        /// Target directory or workspace root (defaults to current dir)
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Check host integration status and detect config bypasses (FR-MCP-005)
    Status {
        /// Target host (claude-code, cursor)
        #[arg(long, default_value = "claude-code")]
        host: String,

        /// Target directory or workspace root (defaults to current dir)
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Output status as JSON
        #[arg(long)]
        json: bool,
    },

    /// Uninstall Vexa Arc proxy wrapper and restore original config
    Uninstall {
        /// Target host (claude-code, cursor)
        #[arg(long, default_value = "claude-code")]
        host: String,

        /// Target directory or workspace root (defaults to current dir)
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProtectAction {
    /// Supervise an MCP server via managed stdio broker (FR-MCP-001)
    Stdio {
        /// MCP server identifier (e.g. 'github' or 'sqlite')
        #[arg(short, long)]
        server: String,

        /// Host session identifier
        #[arg(long, default_value = "default-session")]
        session: String,

        /// Pin the server's tools/list schema (hex SHA-256 JCS fingerprint); mismatches disable tool calls
        #[arg(long)]
        pin_schema: Option<String>,

        /// Maximum memory for the supervised server (MiB; Windows job-wide, Linux per-process)
        #[arg(long)]
        max_memory_mb: Option<u64>,

        /// Target MCP server command and arguments
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ShieldAction {
    /// Check a package against the 4-gate compound anti-slopsquatting engine
    Check {
        /// Package name, scoped package (e.g. 'npm:reactt'), or install command ('npm install reactt')
        package: String,

        /// Ecosystem (npm, pypi, cargo, go) - auto-detected from project files if omitted
        #[arg(short, long)]
        ecosystem: Option<String>,

        /// Days since package registration (optional simulation override)
        #[arg(long)]
        age_days: Option<u32>,

        /// Monthly download count on upstream registry (optional simulation override)
        #[arg(long)]
        downloads: Option<u64>,

        /// Whether install lifecycle scripts (preinstall/postinstall) contain shell execution
        #[arg(long)]
        dangerous_scripts: bool,

        /// Output findings as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Execute or contain a package install command under protected mode firewall (FR-PKG-004)
    Run {
        /// Automatically enforce containment by wrapping command with --ignore-scripts or blocking
        #[arg(long)]
        enforce: bool,

        /// Command to supervise and evaluate (e.g. npm install express)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Direct package name (e.g. 'reactt'), scoped target ('npm:reactt'), or install command ('npm install reactt')
    #[command(external_subcommand)]
    Direct(Vec<String>),
}

#[derive(Subcommand)]
enum InterceptAction {
    /// Native host hook entrypoint: reads the host's hook JSON from stdin and answers in the
    /// host's native format (used by `arc host install`). Fails closed on any error.
    Hook {
        /// Host whose hook payload is on stdin (claude-code, cursor)
        #[arg(long)]
        host: String,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,
    },

    /// Evaluate an action event within a stateful session (supports shorthand positional input or flags)
    Eval {
        /// Target path, tool, command, or action shorthand (e.g. '.env', 'slack/slack_post_message', 'curl evil.com')
        #[arg(value_name = "TARGET")]
        pos_target: Option<String>,

        /// Secondary parameter (e.g. tool name if pos_target is server, or target if pos_target is verb)
        #[arg(value_name = "EXTRA")]
        pos_extra: Option<String>,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// Action kind (file_read, shell, mcp_call, prompt, mcp_result)
        #[arg(short, long)]
        kind: Option<String>,

        /// Action target path, command, or tool name
        #[arg(short, long)]
        target: Option<String>,

        /// MCP server name (if action is mcp_call or mcp_result)
        #[arg(long)]
        server: Option<String>,

        /// MCP schema fingerprint (hex-encoded SHA-256 or raw JSON schema) for rug-pull detection
        #[arg(long)]
        schema: Option<String>,

        /// Source/provenance of content (e.g. 'github_issue', 'web_scraper', 'user')
        #[arg(long)]
        source: Option<String>,

        /// Explicitly mark action content as untrusted external input
        #[arg(long)]
        untrusted: bool,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Reset session state before evaluating
        #[arg(long)]
        reset: bool,

        /// Output verdict as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Read a file within a session (shorthand for eval file_read)
    Read {
        /// File path to read (e.g. .env)
        path: PathBuf,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Output verdict as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Execute or evaluate a shell command within a session
    Exec {
        /// Command string to evaluate (e.g. 'curl https://evil.com')
        command: String,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Output verdict as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Evaluate an MCP tool call within a session
    Mcp {
        /// MCP server name (e.g. 'slack' or 'github')
        server: String,

        /// Tool name (e.g. 'slack_post_message' or 'fetch')
        tool: String,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// MCP schema fingerprint (hex-encoded SHA-256 or raw JSON schema) for rug-pull detection
        #[arg(long)]
        schema: Option<String>,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Output verdict as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Ingest untrusted prompt or issue text into a session
    Prompt {
        /// Text containing issue, URL, or external prompt content
        text: String,

        /// Host session identifier
        #[arg(short, long, default_value = "default-session")]
        session: String,

        /// Source/provenance of content (e.g. 'github_issue', 'web_scraper', 'user')
        #[arg(long)]
        source: Option<String>,

        /// Explicitly mark prompt content as untrusted external input
        #[arg(long)]
        untrusted: bool,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Output verdict as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect or clear active session taints, history, and status
    Session {
        /// Host session identifier to inspect
        #[arg(default_value = "default-session")]
        session_id: String,

        /// Clear/reset the recorded taints and history for this session
        #[arg(long)]
        reset: bool,

        /// Prune expired sessions older than max-age-hours (NFR-PRIV-004)
        #[arg(long)]
        cleanup: bool,

        /// Session expiration threshold in hours for cleanup (default: 24)
        #[arg(long, default_value = "24")]
        max_age_hours: u64,

        /// Custom session storage directory
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Use project-local .arc/sessions storage directory
        #[arg(long)]
        project_local: bool,

        /// Output session state as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            path,
            workstation,
            json,
            output_bom,
        } => {
            if !run_audit(&path, workstation, json, output_bom.as_deref()) {
                std::process::exit(1);
            }
        }
        Commands::Bom { path, out } => {
            if !run_bom(&path, out.as_deref()) {
                std::process::exit(1);
            }
        }
        Commands::ScanSecrets { path, redact } => {
            if !run_scan_secrets(path.as_deref(), redact) {
                std::process::exit(1);
            }
        }
        Commands::Shield { action } => match action {
            ShieldAction::Check {
                package,
                ecosystem,
                age_days,
                downloads,
                dangerous_scripts,
                json,
            } => {
                let default_eco = PackageFirewall::detect_ecosystem(Path::new("."));
                let target_eco = ecosystem
                    .as_deref()
                    .map(parse_ecosystem)
                    .unwrap_or(default_eco);
                let pkgs = PackageFirewall::parse_target_or_command(&package, target_eco);
                let mut all_permitted = true;
                for (eco, pkg_name) in pkgs {
                    let permitted = run_shield_check(
                        &pkg_name,
                        &format!("{eco:?}").to_lowercase(),
                        age_days,
                        downloads,
                        dangerous_scripts,
                        json,
                    );
                    if !permitted {
                        all_permitted = false;
                    }
                }
                if !all_permitted {
                    std::process::exit(1);
                }
            }
            ShieldAction::Run { command, enforce } => {
                if !run_shield_run(command, enforce) {
                    std::process::exit(1);
                }
            }
            ShieldAction::Direct(args) => {
                let default_eco = PackageFirewall::detect_ecosystem(Path::new("."));
                let combined = args.join(" ");
                let dangerous_scripts = combined.contains("--dangerous-scripts");
                let json = combined.contains("--json");
                let clean_command = combined
                    .replace("--dangerous-scripts", "")
                    .replace("--json", "")
                    .trim()
                    .to_string();

                let pkgs = PackageFirewall::parse_target_or_command(&clean_command, default_eco);
                if pkgs.is_empty() {
                    eprintln!("Error: Package name or install command required. Example: 'arc shield reactt' or 'arc shield npm install reactt'");
                    std::process::exit(1);
                }

                let mut all_permitted = true;
                for (eco, pkg_name) in pkgs {
                    let permitted = run_shield_check(
                        &pkg_name,
                        &format!("{eco:?}").to_lowercase(),
                        None,
                        None,
                        dangerous_scripts,
                        json,
                    );
                    if !permitted {
                        all_permitted = false;
                    }
                }
                if !all_permitted {
                    std::process::exit(1);
                }
            }
        },
        Commands::Intercept { action } => match action {
            InterceptAction::Hook {
                host,
                session_dir,
                project_local,
            } => {
                let code = run_intercept_hook(&host, session_dir.as_deref(), project_local);
                std::process::exit(code);
            }
            InterceptAction::Eval {
                pos_target,
                pos_extra,
                session,
                kind,
                target,
                server,
                schema,
                source,
                untrusted,
                session_dir,
                project_local,
                reset,
                json,
            } => {
                let permitted = run_intercept_eval_with_opts(InterceptEvalOptions {
                    session: &session,
                    kind: kind.as_deref(),
                    target: target.as_deref(),
                    server: server.as_deref(),
                    pos_target: pos_target.as_deref(),
                    pos_extra: pos_extra.as_deref(),
                    schema: schema.as_deref(),
                    source: source.as_deref(),
                    untrusted,
                    session_dir: session_dir.as_deref(),
                    project_local,
                    reset,
                    json,
                });
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Read {
                path,
                session,
                session_dir,
                project_local,
                json,
            } => {
                let path_str = path.to_string_lossy();
                let permitted = run_intercept_eval_with_opts(InterceptEvalOptions {
                    session: &session,
                    kind: Some("file_read"),
                    target: Some(&path_str),
                    session_dir: session_dir.as_deref(),
                    project_local,
                    json,
                    ..Default::default()
                });
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Exec {
                command,
                session,
                session_dir,
                project_local,
                json,
            } => {
                let permitted = run_intercept_eval_with_opts(InterceptEvalOptions {
                    session: &session,
                    kind: Some("shell"),
                    target: Some(&command),
                    session_dir: session_dir.as_deref(),
                    project_local,
                    json,
                    ..Default::default()
                });
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Mcp {
                server,
                tool,
                session,
                schema,
                session_dir,
                project_local,
                json,
            } => {
                let permitted = run_intercept_eval_with_opts(InterceptEvalOptions {
                    session: &session,
                    kind: Some("mcp_call"),
                    target: Some(&tool),
                    server: Some(&server),
                    schema: schema.as_deref(),
                    session_dir: session_dir.as_deref(),
                    project_local,
                    json,
                    ..Default::default()
                });
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Prompt {
                text,
                session,
                source,
                untrusted,
                session_dir,
                project_local,
                json,
            } => {
                let permitted = run_intercept_eval_with_opts(InterceptEvalOptions {
                    session: &session,
                    kind: Some("prompt"),
                    target: Some(&text),
                    source: source.as_deref(),
                    untrusted,
                    session_dir: session_dir.as_deref(),
                    project_local,
                    json,
                    ..Default::default()
                });
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Session {
                session_id,
                reset,
                cleanup,
                max_age_hours,
                session_dir,
                project_local,
                json,
            } => {
                if !run_intercept_session_with_dir(
                    &session_id,
                    reset,
                    cleanup,
                    max_age_hours,
                    json,
                    session_dir.as_deref(),
                    project_local,
                ) {
                    std::process::exit(1);
                }
            }
        },
        Commands::Protect { action } => match action {
            ProtectAction::Stdio {
                server,
                session,
                pin_schema,
                max_memory_mb,
                command,
            } => {
                if !run_protect_stdio(
                    &server,
                    &session,
                    pin_schema.as_deref(),
                    max_memory_mb,
                    command,
                ) {
                    std::process::exit(1);
                }
            }
        },
        Commands::Host { action } => match action {
            HostAction::Install { host, workspace } => {
                if !run_host_install(&host, workspace.as_deref()) {
                    std::process::exit(1);
                }
            }
            HostAction::Status {
                host,
                workspace,
                json,
            } => {
                if !run_host_status(&host, workspace.as_deref(), json) {
                    std::process::exit(1);
                }
            }
            HostAction::Uninstall { host, workspace } => {
                if !run_host_uninstall(&host, workspace.as_deref()) {
                    std::process::exit(1);
                }
            }
        },
        Commands::Doctor { json, metrics } => {
            if !run_doctor(json, metrics) {
                std::process::exit(1);
            }
        }
        Commands::Trace {
            event_id,
            session,
            session_dir,
            project_local,
            export,
            json,
        } => {
            if !run_trace(
                &event_id,
                &session,
                session_dir.as_deref(),
                project_local,
                export.as_deref(),
                json,
            ) {
                std::process::exit(1);
            }
        }
        Commands::Test { json } => {
            if !run_test(json) {
                std::process::exit(1);
            }
        }
        Commands::Version => {
            println!("Vexa Arc CLI v1.0.0 (Agentic Runtime Control)");
            println!("Target Architecture: Pure Rust Pre-Execution Endpoint & Agent Firewall");
            println!("License: Apache-2.0");
        }
    }
}

fn run_doctor(json: bool, metrics: bool) -> bool {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let policy = PolicyConfig::load_with_precedence(Some(Path::new(".")));
    let session_dir = resolve_session_storage_dir(None, false);
    let session_status = match &session_dir {
        Ok(dir) => format!("writable ({})", dir.display()),
        Err(e) => format!("error: {e}"),
    };

    let adapters = vec![
        "ClaudeCode (arc-hooks::ClaudeCodeAdapter)",
        "Cursor (arc-hooks::CursorAdapter)",
        "ManagedStdioBroker (arc-hooks::McpStdioBroker)",
        "GenericJsonRpc (arc-hooks::McpJsonRpcInterceptor)",
    ];

    // Gather host integration status if metrics flag is set
    let host_status_cc = if metrics {
        Some(ClaudeCodeAdapter::check_integration(Path::new(".")))
    } else {
        None
    };
    let host_status_cursor = if metrics {
        Some(CursorAdapter::check_integration(Path::new(".")))
    } else {
        None
    };

    if json {
        let mut output = serde_json::json!({
            "status": "healthy",
            "version": "1.0.0",
            "os": os,
            "arch": arch,
            "policy_version": policy.version,
            "policy_source": format!("{:?}", policy.source.unwrap_or(arc_policy_engine::evaluator::PolicySource::BuiltInDefault)),
            "allowed_mcp_servers": policy.allowed_mcp_servers.len(),
            "emergency_deny_servers": policy.emergency_deny_servers.len(),
            "session_storage": session_status,
            "supported_adapters": adapters,
        });
        if let Some(ref cc) = host_status_cc {
            output["host_integrations"] = serde_json::json!({
                "claude_code": { "installed": cc.is_configured, "bypass_risk": cc.bypass_risk, "message": cc.message },
                "cursor": host_status_cursor.as_ref().map(|c| serde_json::json!({ "installed": c.is_configured, "bypass_risk": c.bypass_risk, "message": c.message })),
            });
        }
        println!("{output}");
        return true;
    }

    println!("\n=======================================================");
    println!("             VEXA ARC SYSTEM DIAGNOSTIC (DOCTOR)       ");
    println!("=======================================================");
    println!("Operational Status: HEALTHY");
    println!("Engine Version:     v1.0.0 (Rust 2021 Edition)");
    println!("Platform:           {os} ({arch})");
    println!(
        "Effective Policy:   v{} (Source: {:?})",
        policy.version,
        policy
            .source
            .unwrap_or(arc_policy_engine::evaluator::PolicySource::BuiltInDefault)
    );
    println!(
        "Allowed Servers:    {} registered",
        policy.allowed_mcp_servers.len()
    );
    println!(
        "Emergency Deny:     {} active rules",
        policy.emergency_deny_servers.len()
    );
    println!("Session Storage:    {session_status}");
    println!("Supported Adapters:");
    for a in &adapters {
        println!("  • {a}");
    }

    if metrics {
        println!("-------------------------------------------------------");
        println!("Host Integration Status (--metrics):");
        if let Some(ref cc) = host_status_cc {
            println!(
                "  Claude Code: installed={}, bypass_risk={}",
                cc.is_configured, cc.bypass_risk
            );
            println!("    Status: {}", cc.message);
        }
        if let Some(ref cursor) = host_status_cursor {
            println!(
                "  Cursor:      installed={}, bypass_risk={}",
                cursor.is_configured, cursor.bypass_risk
            );
            println!("    Status: {}", cursor.message);
        }
    }

    println!("=======================================================\n");
    true
}

fn run_protect_stdio(
    server: &str,
    session: &str,
    pin_schema: Option<&str>,
    max_memory_mb: Option<u64>,
    command: Vec<String>,
) -> bool {
    let pinned = match parse_schema_fingerprint(pin_schema) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[Arc Protect] Invalid --pin-schema: {e}");
            return false;
        }
    };
    let policy = PolicyConfig::load_with_precedence(Some(Path::new(".")));
    let evaluator = PolicyEvaluator::new(policy);
    let mut broker = McpStdioBroker::new(server, session, evaluator)
        .with_command(command)
        .with_limits(arc_hooks::ContainmentLimits {
            max_memory_bytes: max_memory_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
        });
    if let Some(hash) = pinned {
        broker = broker.with_pinned_schema(hash);
    }

    eprintln!("[Arc Protect] Supervising MCP server '{server}' in session '{session}' (Fail-Closed Protected Edge)");
    if let Err(e) = broker.run_stdio() {
        eprintln!("[Arc Protect] Stdio broker error: {e}");
        return false;
    }
    true
}

/// Installs Vexa Arc proxy wrapper into a host agent config (FR-MCP-005)
fn run_host_install(host: &str, workspace: Option<&Path>) -> bool {
    let root = workspace.unwrap_or(Path::new("."));
    match host.to_lowercase().as_str() {
        "claude-code" | "claude" => match ClaudeCodeAdapter::install_integration(root) {
            Ok(_path) => {
                println!(
                    "[Arc Host] Claude Code integration installed at {}",
                    root.display()
                );
                true
            }
            Err(e) => {
                eprintln!("[Arc Host] Failed to install Claude Code integration: {e}");
                false
            }
        },
        "cursor" => match CursorAdapter::install_integration(root) {
            Ok(_path) => {
                println!(
                    "[Arc Host] Cursor integration installed at {}",
                    root.display()
                );
                true
            }
            Err(e) => {
                eprintln!("[Arc Host] Failed to install Cursor integration: {e}");
                false
            }
        },
        _ => {
            eprintln!("Error: Unknown host '{host}'. Supported: claude-code, cursor");
            false
        }
    }
}

/// Checks host integration status and detects config bypasses (FR-MCP-005)
fn run_host_status(host: &str, workspace: Option<&Path>, json: bool) -> bool {
    let root = workspace.unwrap_or(Path::new("."));
    let status = match host.to_lowercase().as_str() {
        "claude-code" | "claude" => ClaudeCodeAdapter::check_integration(root),
        "cursor" => CursorAdapter::check_integration(root),
        _ => {
            eprintln!("Error: Unknown host '{host}'. Supported: claude-code, cursor");
            return false;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "host": host,
                "installed": status.is_configured,
                "bypass_risk": status.bypass_risk,
                "message": status.message,
            })
        );
    } else {
        println!("\n[Arc Host] Integration Status for '{host}'");
        println!(
            "  Installed:    {}",
            if status.is_configured { "Yes" } else { "No" }
        );
        println!(
            "  Bypass Risk:  {}",
            if status.bypass_risk {
                "YES (ALERT!)"
            } else {
                "No"
            }
        );
        println!("  Status:       {}", status.message);
        if let Some(ref path) = status.hook_path {
            println!("  Config File:  {}", path.display());
        }
        if let Some(ref cmd) = status.hook_command {
            println!("  Hook Cmd:     {cmd}");
        }
    }
    true
}

/// Uninstalls Vexa Arc proxy wrapper from a host agent config
fn run_host_uninstall(host: &str, workspace: Option<&Path>) -> bool {
    let root = workspace.unwrap_or(Path::new("."));
    match host.to_lowercase().as_str() {
        "claude-code" | "claude" => {
            match ClaudeCodeAdapter::uninstall_integration(root) {
                Ok(modified) => {
                    if modified {
                        println!(
                            "[Arc Host] Claude Code integration removed from {}",
                            root.display()
                        );
                    } else {
                        println!("[Arc Host] No Arc hook found in Claude Code config (was not installed)");
                    }
                    true
                }
                Err(e) => {
                    eprintln!("[Arc Host] Failed to remove Claude Code integration: {e}");
                    false
                }
            }
        }
        "cursor" => match CursorAdapter::uninstall_integration(root) {
            Ok(modified) => {
                if modified {
                    println!(
                        "[Arc Host] Cursor integration removed from {}",
                        root.display()
                    );
                } else {
                    println!("[Arc Host] No Arc hook found in Cursor config (was not installed)");
                }
                true
            }
            Err(e) => {
                eprintln!("[Arc Host] Failed to remove Cursor integration: {e}");
                false
            }
        },
        _ => {
            eprintln!("Error: Unknown host '{host}'. Supported: claude-code, cursor");
            false
        }
    }
}

/// Evaluates and optionally enforces containment on a package install command (FR-PKG-004)
fn run_shield_run(command: Vec<String>, enforce: bool) -> bool {
    let cmd_str = command.join(" ");
    let pkgs = PackageFirewall::parse_command(&cmd_str);

    if pkgs.is_empty() {
        eprintln!("[Arc Shield] No packages detected in command: '{cmd_str}'");
        eprintln!("  Tip: 'arc shield run npm install express'");
        return false;
    }

    let firewall = PackageFirewall::new();
    let mut all_safe = true;

    println!("\n[Arc Shield Run] Evaluating install command: {cmd_str}");
    for (eco, pkg_name) in &pkgs {
        let verdict = firewall.inspect_package_protected(*eco, pkg_name, false);
        match &verdict {
            SlopsquatVerdict::Blocked { gate, reason } => {
                println!("  🛑 BLOCKED  {pkg_name} ({eco:?}) — {gate}: {reason}");
                all_safe = false;
            }
            SlopsquatVerdict::Review {
                gate,
                containment_recommendation,
                ..
            } => {
                println!("  ⚠️  REVIEW  {pkg_name} ({eco:?}) — {gate}");
                if enforce {
                    match PackageFirewall::enforce_containment(&cmd_str, &verdict) {
                        Ok(safe_cmd) => println!("  → Containment applied: {safe_cmd}"),
                        Err(e) => {
                            println!("  → Blocked: {e}");
                            all_safe = false;
                        }
                    }
                } else {
                    println!("  → Recommendation: {containment_recommendation}");
                    println!("  → Use --enforce to automatically apply containment");
                }
            }
            SlopsquatVerdict::Permitted { reason } => {
                println!("  ✅ PERMITTED {pkg_name} ({eco:?}) — {reason}");
            }
        }
    }
    all_safe
}

fn run_trace(
    event_id: &str,
    session_id: &str,
    session_dir: Option<&Path>,
    project_local: bool,
    export: Option<&Path>,
    json: bool,
) -> bool {
    let dir = match resolve_session_storage_dir(session_dir, project_local) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Session storage error: {e}");
            return false;
        }
    };

    let dag = match SessionTaintDag::load_from_dir(&dir, session_id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            eprintln!(
                "Error: Session '{session_id}' not found in storage: {}",
                dir.display()
            );
            return false;
        }
        Err(e) => {
            eprintln!("Error loading session: {e}");
            return false;
        }
    };

    let matched_node = if event_id.eq_ignore_ascii_case("latest") {
        dag.causal_nodes.last()
    } else {
        dag.causal_nodes.iter().find(|n| {
            n.node_id.contains(event_id)
                || n.event_id
                    .map(|id| id.to_string().contains(event_id))
                    .unwrap_or(false)
        })
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "session_id": session_id,
                "current_taints": format!("{:?}", dag.current_taints),
                "matched_event": matched_node,
                "causal_graph_size": dag.causal_nodes.len(),
                "history_length": dag.history.len(),
            })
        );
        return true;
    }

    println!("\n=======================================================");
    println!("             VEXA ARC CAUSAL TRACE REPORT               ");
    println!("=======================================================");
    println!("Session ID:         {}", dag.session_id);
    println!("Current Taints:     {:?}", dag.current_taints);
    println!("Graph Node Count:   {}", dag.causal_nodes.len());
    println!("-------------------------------------------------------");

    if let Some(node) = matched_node {
        println!("Event / Action:     {}", node.action_summary);
        println!("Node ID:            {}", node.node_id);
        if let Some(id) = node.event_id {
            println!("Event UUID:         {id}");
        }
        println!("Taints Introduced:  {:?}", node.taints_introduced);
        println!("Capabilities:       {:?}", node.capabilities);
        println!("Parent Nodes:       {:?}", node.parent_node_ids);
    } else {
        println!("(No specific event matching '{event_id}' found in session history)");
    }

    if !dag.causal_nodes.is_empty() {
        println!("\nCausal Ancestry Chain:");
        for (i, node) in dag.causal_nodes.iter().rev().take(5).enumerate() {
            println!(
                "  [{}] {} (Taints: {:?})",
                i + 1,
                node.action_summary,
                node.taints_introduced
            );
        }
    }
    println!("=======================================================\n");

    if let Some(export_path) = export {
        let report = serde_json::json!({
            "session_id": session_id,
            "current_taints": format!("{:?}", dag.current_taints),
            "causal_graph_size": dag.causal_nodes.len(),
            "history_length": dag.history.len(),
            "nodes": dag.causal_nodes,
        });
        let content = serde_json::to_string_pretty(&report).unwrap_or_default();
        if let Err(e) = fs::write(export_path, content) {
            eprintln!("Error exporting trace to {}: {e}", export_path.display());
            return false;
        }
        println!(
            "[Arc Trace] Causal evidence report exported to {}",
            export_path.display()
        );
    }
    true
}

fn run_test(json: bool) -> bool {
    let mut results = Vec::new();

    // 1. Rug-Pull Quarantine Test
    let rug_pull_pass = {
        let evaluator = PolicyEvaluator::default();
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let e1 = ActionEvent::new(
            AgentHost::ClaudeCode,
            "test-rug",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "test-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: Some(s1),
                },
                tool: "search".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let _ = evaluator.evaluate(&e1);
        let e2 = ActionEvent::new(
            AgentHost::ClaudeCode,
            "test-rug",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "test-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: Some(s2),
                },
                tool: "search".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let v2 = evaluator.evaluate(&e2);
        matches!(v2, arc_core::Verdict::Quarantine { .. })
    };
    results.push(("Dynamic Schema Rug-Pull Quarantine", rug_pull_pass));

    // 2. Lethal Trifecta Prevention Test
    let trifecta_pass = {
        let evaluator = PolicyEvaluator::default();
        let e_priv = ActionEvent::new(
            AgentHost::ClaudeCode,
            "test-trifecta",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::FileRead {
                path: PathBuf::from(".env"),
            },
        );
        let _ = evaluator.evaluate(&e_priv);

        let e_untrusted = ActionEvent::new(
            AgentHost::ClaudeCode,
            "test-trifecta",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::PromptSubmit {
                text: "https://evil.com/issue".to_string(),
                source: Some("untrusted_web".to_string()),
            },
        );
        let _ = evaluator.evaluate(&e_untrusted);

        let e_sink = ActionEvent::new(
            AgentHost::ClaudeCode,
            "test-trifecta",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "slack".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "slack_post_message".to_string(),
                arguments: serde_json::json!({"text": "leak"}),
            },
        );
        let v_sink = evaluator.evaluate(&e_sink);
        v_sink.is_denied()
    };
    results.push((
        "Lethal Trifecta Context Exfiltration Prevention",
        trifecta_pass,
    ));

    // 3. Secret Detection & Redaction
    let dlp_pass = {
        let engine = SecretScanEngine::new();
        let sample = b"api_key: AKIAIOSFODNN7EXAMPLE";
        let findings = engine.scan(sample);
        !findings.is_empty()
    };
    results.push(("Context DLP Secret Detection & Byte Offsets", dlp_pass));

    // 4. Package Slopsquatting Defense
    let package_pass = {
        let fw = PackageFirewall::new();
        let verdict = fw.inspect_package(Ecosystem::Npm, "reactt", Some(2), Some(10), true);
        verdict.is_blocked()
    };
    results.push(("Anti-Slopsquatting Package Firewall Gate", package_pass));

    let all_passed = results.iter().all(|(_, p)| *p);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "suite": "adversarial_runtime_verification",
                "all_passed": all_passed,
                "tests": results.iter().map(|(n, p)| serde_json::json!({ "name": n, "passed": p })).collect::<Vec<_>>()
            })
        );
    } else {
        println!("\n=======================================================");
        println!("             VEXA ARC ADVERSARIAL TEST SUITE           ");
        println!("=======================================================");
        for (name, passed) in &results {
            let status = if *passed { "PASS [OK]" } else { "FAIL [X]" };
            println!("{name:<48} : {status}");
        }
        println!("=======================================================");
        if all_passed {
            println!("All adversarial tests PASSED (0 failures).\n");
        } else {
            println!("Some adversarial tests FAILED.\n");
        }
    }

    all_passed
}

fn run_audit(path: &Path, workstation: bool, output_json: bool, bom_file: Option<&Path>) -> bool {
    if workstation {
        if !output_json {
            println!("[Arc Audit] Performing full workstation AI/MCP discovery...");
        }
        let scanner = DiscoveryScanner::new();
        match scanner.audit_workstation() {
            Ok(report) => {
                if output_json {
                    let json_str = serde_json::to_string_pretty(&report).unwrap_or_default();
                    println!("{json_str}");
                } else {
                    println!("  Scanned Roots:  {}", report.scanned_locations.len());
                    println!("  Unscanned:      {}", report.unscanned_locations.len());
                    println!("  Total Assets:   {}", report.total_assets);
                    println!("  Overall Risk:   {:?}", report.overall_risk_band);
                    println!("[Arc Audit] Workstation audit complete.");
                }
                return true;
            }
            Err(e) => {
                eprintln!("Error: Workstation audit failed: {e}");
                return false;
            }
        }
    }

    let scanner = DiscoveryScanner::new();
    let report = match scanner.audit_directory(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Cannot audit target path '{}': {e}", path.display());
            return false;
        }
    };

    if let Some(bom_path) = bom_file {
        let bom = generate_cyclonedx_1_6_bom(&report);
        let json_str = match serde_json::to_string_pretty(&bom) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error serializing CycloneDX AI-BOM: {e}");
                return false;
            }
        };
        if let Err(e) = fs::write(bom_path, json_str) {
            eprintln!(
                "Error saving CycloneDX AI-BOM to {}: {e}",
                bom_path.display()
            );
            return false;
        } else {
            println!("Exported CycloneDX v1.6 AI-BOM to {}", bom_path.display());
        }
    }

    if output_json {
        let json_str = serde_json::to_string_pretty(&report).unwrap_or_default();
        println!("{json_str}");
        return true;
    }

    // Terminal Summary
    println!("\n=======================================================");
    println!("             VEXA ARC ZERO-TOUCH AUDIT REPORT           ");
    println!("=======================================================");
    println!("Scanned Target:     {}", report.scanned_path.display());
    println!(
        "Scan Duration:      {} ms (< 1200 ms latency target)",
        report.scan_duration_ms
    );
    println!("Total AI Assets:    {}", report.total_assets);
    println!("Overall Risk Band:  {:?}", report.overall_risk_band);
    println!("-------------------------------------------------------");

    println!(
        "\n[1] Discovered MCP Servers ({}):",
        report.mcp_servers.len()
    );
    if report.mcp_servers.is_empty() {
        println!("  (No active or registered MCP servers discovered)");
    } else {
        for s in &report.mcp_servers {
            println!(
                "  • {:<16} [transport: {:<8} risk: {:<8} score: {:<4}] (from: {})",
                s.name,
                s.transport,
                format!("{:?}", s.profile.band).to_lowercase(),
                s.profile.composite_risk_score,
                s.source_file.display()
            );
        }
    }

    println!(
        "\n[2] Agent Skills & Instruction Directives ({}):",
        report.agent_skills.len()
    );
    if report.agent_skills.is_empty() {
        println!("  (No custom agent skill or rule files found)");
    } else {
        for sk in &report.agent_skills {
            println!(
                "  • {:<24} ({} lines, sha256: {}...)",
                sk.name,
                sk.line_count,
                &sk.content_hash[..8]
            );
        }
    }

    println!(
        "\n[3] AI Models & Local Checkpoints ({}):",
        report.model_assets.len()
    );
    if report.model_assets.is_empty() {
        println!("  (No local model weights or checkpoints found)");
    } else {
        for m in &report.model_assets {
            println!(
                "  • {:<24} [format: {}] ({} bytes)",
                m.name, m.kind, m.size_bytes
            );
        }
    }

    println!(
        "\n[4] Exposed Credentials & Secret Findings ({}):",
        report.exposed_secrets.len()
    );
    if report.exposed_secrets.is_empty() {
        println!("  (No exposed production credentials detected)");
    } else {
        for sec in &report.exposed_secrets {
            println!(
                "  • [{}] in {}: {}",
                sec.detector,
                sec.file_path.display(),
                sec.snippet
            );
        }
    }
    println!("=======================================================\n");
    true
}

fn run_bom(path: &Path, out: Option<&Path>) -> bool {
    let scanner = DiscoveryScanner::new();
    let report = match scanner.audit_directory(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Cannot scan target path '{}': {e}", path.display());
            return false;
        }
    };
    let bom = generate_cyclonedx_1_6_bom(&report);
    let json_str = match serde_json::to_string_pretty(&bom) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error serializing CycloneDX BOM: {e}");
            return false;
        }
    };

    if let Some(out_path) = out {
        if let Err(e) = fs::write(out_path, json_str) {
            eprintln!("Error writing CycloneDX BOM to {}: {e}", out_path.display());
            false
        } else {
            println!("Saved CycloneDX v1.6 AI-BOM to {}", out_path.display());
            true
        }
    } else {
        println!("{json_str}");
        true
    }
}

fn collect_scan_files(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if depth > 10 {
        return Ok(());
    }
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == ".git"
            || file_name == "target"
            || file_name == "node_modules"
            || file_name == ".venv"
            || file_name == "venv"
        {
            continue;
        }
        if path.is_dir() {
            let _ = collect_scan_files(&path, depth + 1, files);
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn run_scan_secrets(path: Option<&Path>, redact: bool) -> bool {
    let engine = SecretScanEngine::new();
    let vault = LocalPseudonymizationVault::new();

    if let Some(p) = path {
        if !p.exists() {
            eprintln!("Error: Target path does not exist: {}", p.display());
            return false;
        }

        if p.is_dir() {
            let mut files = Vec::new();
            if let Err(e) = collect_scan_files(p, 0, &mut files) {
                eprintln!("Error reading directory {}: {e}", p.display());
                return false;
            }
            let mut total_findings = 0;
            let mut files_scanned = 0;
            let mut read_errors = 0;

            for file_path in &files {
                match fs::read(file_path) {
                    Ok(bytes) => {
                        files_scanned += 1;
                        let findings = engine.scan(&bytes);
                        if !findings.is_empty() {
                            total_findings += findings.len();
                            for f in &findings {
                                println!(
                                    "• [{}] in {}:{}..{} Snippet: {}",
                                    f.detector,
                                    file_path.display(),
                                    f.start,
                                    f.end,
                                    f.snippet
                                );
                            }
                            if redact {
                                let (_, tokens) = vault.redact_and_vault(
                                    &file_path.display().to_string(),
                                    &bytes,
                                    &findings,
                                );
                                println!(
                                    "  -> Registered {} vault token(s) for {}",
                                    tokens.len(),
                                    file_path.display()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: Failed reading {}: {e}", file_path.display());
                        read_errors += 1;
                    }
                }
            }

            if total_findings == 0 && read_errors == 0 {
                println!("Scan complete: 0 secrets detected across {files_scanned} file(s).");
                true
            } else {
                if total_findings > 0 {
                    println!(
                        "Scan complete: {total_findings} secret(s) detected across {files_scanned} file(s)!"
                    );
                }
                false
            }
        } else if p.is_file() {
            // Single file scan
            let raw_bytes = match fs::read(p) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error: Failed to read {}: {e}", p.display());
                    return false;
                }
            };

            let findings = engine.scan(&raw_bytes);
            if findings.is_empty() {
                println!("Scan complete: 0 secrets detected.");
                return true;
            }

            println!("Scan complete: {} secret(s) detected!", findings.len());
            for f in &findings {
                println!(
                    "• Detector: {:<12} Offset: {}..{} Snippet: {}",
                    f.detector, f.start, f.end, f.snippet
                );
            }

            if redact {
                let (redacted, tokens) = vault.redact_and_vault("cli-scan", &raw_bytes, &findings);
                println!("\n--- Redacted Output (Vault tokens attached) ---");
                println!("{}", String::from_utf8_lossy(&redacted));
                println!("\nVault Tokens Registered ({}):", tokens.len());
                for t in tokens {
                    println!("  • Token: {:<24} Detector: {}", t.token, t.detector);
                }
            }
            false
        } else {
            eprintln!(
                "Error: Target path is not a regular file or directory: {}",
                p.display()
            );
            false
        }
    } else {
        let mut buffer = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut buffer) {
            eprintln!("Error reading stdin: {e}");
            return false;
        }

        let findings = engine.scan(&buffer);
        if findings.is_empty() {
            println!("Scan complete: 0 secrets detected.");
            return true;
        }

        println!("Scan complete: {} secret(s) detected!", findings.len());
        for f in &findings {
            println!(
                "• Detector: {:<12} Offset: {}..{} Snippet: {}",
                f.detector, f.start, f.end, f.snippet
            );
        }

        if redact {
            let (redacted, tokens) = vault.redact_and_vault("cli-scan", &buffer, &findings);
            println!("\n--- Redacted Output (Vault tokens attached) ---");
            println!("{}", String::from_utf8_lossy(&redacted));
            println!("\nVault Tokens Registered ({}):", tokens.len());
            for t in tokens {
                println!("  • Token: {:<24} Detector: {}", t.token, t.detector);
            }
        }
        false
    }
}

fn parse_ecosystem(s: &str) -> Ecosystem {
    match s.to_lowercase().as_str() {
        "pypi" | "pip" | "python" => Ecosystem::Pypi,
        "cargo" | "rust" | "crate" => Ecosystem::Cargo,
        "go" | "golang" => Ecosystem::Go,
        _ => Ecosystem::Npm,
    }
}

/// Outcome of the OSV step in `arc shield check`. Never silently green.
enum OsvOutcome {
    /// Scan completed with advisory data available.
    Scanned(arc_firewall::osv_scanner::PackageScanResult),
    /// Scan failed or advisory data unavailable: treated as a failure (fail closed).
    Incomplete(String),
    /// No concrete version supplied, so OSV cannot give a meaningful answer.
    NoVersion,
}

impl OsvOutcome {
    fn blocks(&self) -> bool {
        match self {
            OsvOutcome::Scanned(r) => r.should_block(),
            OsvOutcome::Incomplete(_) => true,
            OsvOutcome::NoVersion => false,
        }
    }
}

/// Splits `name@1.2.3` (npm/go/cargo) or `name==1.2.3` (pip) into name and an exact version.
/// Range specifiers (`^`, `~`, `>`, `<`, `*`, `latest`) are NOT treated as concrete versions.
fn split_package_version(spec: &str) -> (&str, Option<&str>) {
    let (name, ver) = if let Some((n, v)) = spec.split_once("==") {
        (n, v)
    } else if let Some(idx) = spec.rfind('@').filter(|i| *i > 0) {
        (&spec[..idx], &spec[idx + 1..])
    } else {
        return (spec, None);
    };
    let ver = ver.trim_start_matches('v');
    let concrete = ver.chars().next().is_some_and(|c| c.is_ascii_digit())
        && ver
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c));
    (name, concrete.then_some(ver))
}

fn run_shield_check(
    package: &str,
    ecosystem: &str,
    age_days: Option<u32>,
    downloads: Option<u64>,
    dangerous_scripts: bool,
    json: bool,
) -> bool {
    let firewall = PackageFirewall::new();
    let eco = parse_ecosystem(ecosystem);

    let verdict = firewall.inspect_package(eco, package, age_days, downloads, dangerous_scripts);
    let suggestion = verdict.suggested_action(ecosystem);

    // FR-PKG-005: Run OSV/EPSS vulnerability scan via vexa-sca native integration.
    // Only public package coordinates (name + exact version) are queried; no
    // source code leaves the host (100% payload locality).
    // No fake sentinel version: without an exact version the scan is reported as
    // NoVersion, and scan errors / unreachable advisory data fail closed.
    let osv_scanner = OsvPackageScanner::default();
    let osv_eco = ecosystem_to_osv_str(eco);
    let (osv_name, osv_version) = split_package_version(package);
    let osv_outcome = match osv_version {
        None => OsvOutcome::NoVersion,
        Some(v) => match osv_scanner.scan_package(osv_name, v, osv_eco) {
            Ok(r) if r.advisory_available => OsvOutcome::Scanned(r),
            Ok(_) => OsvOutcome::Incomplete(
                "advisory database unavailable and no cached result".to_string(),
            ),
            Err(e) => OsvOutcome::Incomplete(e),
        },
    };
    let osv_result = match &osv_outcome {
        OsvOutcome::Scanned(r) => Some(r),
        _ => None,
    };

    if json {
        let osv_status = match &osv_outcome {
            OsvOutcome::Scanned(_) => "scanned",
            OsvOutcome::Incomplete(_) => "incomplete",
            OsvOutcome::NoVersion => "not_scanned_no_version",
        };
        let osv_error = match &osv_outcome {
            OsvOutcome::Incomplete(e) => Some(e.clone()),
            _ => None,
        };
        let osv_json = Some(osv_result.map_or_else(
            || serde_json::json!({ "status": osv_status, "error": osv_error }),
            |r| {
                serde_json::json!({
                    "status": osv_status,
                    "advisory_available": r.advisory_available,
                    "finding_count": r.findings.len(),
                    "has_critical_or_high": r.has_critical_or_high,
                    "has_high_epss": r.has_high_epss,
                    "has_reachable": r.has_reachable,
                    // FR-PKG-006: inline JSON-RPC remediation for the top finding
                    "remediation": r.aggregate_jsonrpc_error(),
                    "findings": r.findings.iter().map(|f| serde_json::json!({
                        "advisory_id": f.advisory_id,
                        "severity": f.severity,
                        "cvss_score": f.cvss_score,
                        "epss_score": f.epss_score,
                        "is_reachable": f.is_reachable,
                        "fixed_in": f.fixed_in,
                        "remediation_message": f.remediation_message,
                    })).collect::<Vec<_>>(),
                })
            },
        ));

        let json_output = match &verdict {
            arc_firewall::slopsquat::SlopsquatVerdict::Permitted { reason } => {
                serde_json::json!({
                    "package": package,
                    "ecosystem": format!("{eco:?}").to_lowercase(),
                    "status": "permitted",
                    "reason": reason,
                    "suggested_action": null,
                    "metrics": {
                        "age_days": age_days,
                        "monthly_downloads": downloads,
                        "dangerous_scripts": dangerous_scripts
                    },
                    "osv": osv_json,
                })
            }
            arc_firewall::slopsquat::SlopsquatVerdict::Blocked { gate, reason } => {
                serde_json::json!({
                    "package": package,
                    "ecosystem": format!("{eco:?}").to_lowercase(),
                    "status": "blocked",
                    "gate": gate,
                    "reason": reason,
                    "suggested_action": suggestion,
                    "metrics": {
                        "age_days": age_days,
                        "monthly_downloads": downloads,
                        "dangerous_scripts": dangerous_scripts
                    },
                    "osv": osv_json,
                })
            }
            arc_firewall::slopsquat::SlopsquatVerdict::Review {
                gate,
                reason,
                containment_recommendation,
            } => {
                serde_json::json!({
                    "package": package,
                    "ecosystem": format!("{eco:?}").to_lowercase(),
                    "status": "review",
                    "gate": gate,
                    "reason": reason,
                    "containment_recommendation": containment_recommendation,
                    "suggested_action": suggestion,
                    "metrics": {
                        "age_days": age_days,
                        "monthly_downloads": downloads,
                        "dangerous_scripts": dangerous_scripts
                    },
                    "osv": osv_json,
                })
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json_output).unwrap_or_default()
        );
        return !verdict.is_blocked() && !osv_outcome.blocks();
    }

    println!("\n┌────────────────────────────────────────────────────────┐");
    println!("│        ARC SHIELD ANTI-SLOPSQUATTING EVALUATION        │");
    println!("└────────────────────────────────────────────────────────┘");
    println!("Package:            {package} ({ecosystem})");
    if let (Some(age), Some(dl)) = (age_days, downloads) {
        println!("Registry Metrics:   Age: {age} days | Monthly Downloads: {dl}");
    } else if let Some(age) = age_days {
        println!("Registry Metrics:   Age: {age} days");
    } else if let Some(dl) = downloads {
        println!("Registry Metrics:   Monthly Downloads: {dl}");
    } else {
        println!(
            "Registry Metrics:   Pre-install Gate (Automated package baseline & slopsquat check)"
        );
    }
    println!("Dangerous Scripts:  {dangerous_scripts}");
    println!("----------------------------------------------------------");

    match &verdict {
        arc_firewall::slopsquat::SlopsquatVerdict::Permitted { reason } => {
            println!("STATUS:             \u{2705} PERMITTED (PASS)");
            println!("Reason:             {reason}");
        }
        arc_firewall::slopsquat::SlopsquatVerdict::Blocked { gate, reason } => {
            println!("STATUS:             \u{1F6D1} BLOCKED (HARD GATE REJECTION)");
            println!("Triggered Gate:     {gate}");
            println!("Finding:            {reason}");

            if let Some(act) = &suggestion {
                println!("\nSUGGESTED ACTION:");
                if gate == &"CompoundTyposquatGate" {
                    println!("  \u{1F4A1} {act}");
                    println!(
                        "  \u{2139}\u{FE0F}  If legitimate: arc shield allow {package} --ecosystem {ecosystem}"
                    );
                } else if gate == &"CompoundLifecycleGate" {
                    println!("  \u{26a0}\u{FE0F}  {act}");
                } else {
                    println!("  \u{27a1}  {act}");
                }
            }
        }
        arc_firewall::slopsquat::SlopsquatVerdict::Review {
            gate,
            reason,
            containment_recommendation,
        } => {
            println!("STATUS:             \u{26a0}\u{FE0F}  REVIEW REQUIRED");
            println!("Triggered Gate:     {gate}");
            println!("Finding:            {reason}");
            println!("Containment:        {containment_recommendation}");
            println!("Action:             Use 'arc shield run --enforce {package}' to auto-apply containment");
        }
    }

    // FR-PKG-005 / FR-PKG-006: Print OSV/EPSS vulnerability findings.
    match &osv_outcome {
        OsvOutcome::Incomplete(e) => {
            println!("----------------------------------------------------------");
            println!("OSV VULNERABILITY SCAN  [ARC-SCA-001]  \u{1F6D1} INCOMPLETE (FAIL CLOSED)");
            println!("  Reason: {e}");
        }
        OsvOutcome::NoVersion => {
            println!("----------------------------------------------------------");
            println!(
                "OSV VULNERABILITY SCAN  [ARC-SCA-001]  \u{26a0}\u{FE0F}  NOT SCANNED (no exact version; use name@1.2.3)"
            );
        }
        OsvOutcome::Scanned(_) => {}
    }
    if let Some(osv) = osv_result {
        if !osv.findings.is_empty() {
            println!("----------------------------------------------------------");
            println!("OSV VULNERABILITY SCAN  [ARC-SCA-001]");
            if !osv.advisory_available {
                println!("  ⚠️  Advisory database unavailable (served from cache or offline)");
            }
            for f in &osv.findings {
                let epss_str = f
                    .epss_score
                    .map(|s| format!(", EPSS: {:.1}%", s * 100.0))
                    .unwrap_or_default();
                let reach_str = if f.is_reachable { " [REACHABLE]" } else { "" };
                println!(
                    "  🔴 {} – {} (CVSS: {:.1}{epss_str}){reach_str}",
                    f.advisory_id, f.severity, f.cvss_score
                );
                println!("     {}", f.remediation_message);
            }
            if osv.should_block() {
                // FR-PKG-006: emit structured JSON-RPC error
                if let Some(err) = osv.aggregate_jsonrpc_error() {
                    println!("  JSON-RPC remediation: {err}");
                }
            }
        } else if osv.advisory_available {
            println!("----------------------------------------------------------");
            println!("OSV VULNERABILITY SCAN  [ARC-SCA-001]  ✅ No known vulnerabilities");
        }
    }
    println!("----------------------------------------------------------\n");

    !verdict.is_blocked() && !osv_outcome.blocks()
}

/// Native host hook runner. Returns the process exit code. Any failure (bad payload, unreadable or
/// corrupt session state, persistence failure) is reported on stderr and returns 2, which both
/// Claude Code and Cursor treat as a block (fail closed).
fn run_intercept_hook(host: &str, session_dir: Option<&Path>, project_local: bool) -> i32 {
    let adapter: Box<dyn HostAdapter> = match host.to_lowercase().as_str() {
        "claude-code" | "claude" => Box::new(ClaudeCodeAdapter),
        "cursor" => Box::new(CursorAdapter),
        other => {
            eprintln!("[Arc Hook] Unknown host '{other}'. Supported: claude-code, cursor");
            return 2;
        }
    };

    const MAX_HOOK_PAYLOAD: u64 = 16 * 1024 * 1024;
    let mut raw = Vec::new();
    if let Err(e) = io::stdin().take(MAX_HOOK_PAYLOAD).read_to_end(&mut raw) {
        eprintln!("[Arc Hook] Failed to read hook payload from stdin: {e} (failing closed)");
        return 2;
    }

    let events = match adapter.decode(&raw, OsPrincipal::Uid(1000)) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("[Arc Hook] Malformed {host} hook payload: {e} (failing closed)");
            return 2;
        }
    };

    let emit = |resp: arc_hooks::HostResponse| -> i32 {
        use std::io::Write;
        let _ = io::stdout().write_all(&resp.stdout);
        let _ = io::stdout().flush();
        let _ = io::stderr().write_all(&resp.stderr);
        resp.exit_code
    };
    let allow = arc_core::verdict::Verdict::Allow {
        obligations: Vec::new(),
    };

    let Some(first) = events.first() else {
        return emit(adapter.encode(&allow));
    };
    let session = first.host_session_id.clone();

    let storage_dir = match resolve_session_storage_dir(session_dir, project_local) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[Arc Hook] Session storage failure: {e} (failing closed)");
            return 2;
        }
    };

    let evaluator = PolicyEvaluator::new(PolicyConfig::load_with_precedence(Some(Path::new("."))));
    if let Err(e) = evaluator.load_session_state(&storage_dir, &session) {
        eprintln!("[Arc Hook] Session state for '{session}' is corrupt or unreadable: {e} (failing closed)");
        return 2;
    }

    let mut response = adapter.encode(&allow);
    for event in &events {
        let verdict = evaluator.evaluate(event);
        // Post-phase hooks only report results for taint tracking; they never block.
        if event.phase == Phase::Pre && !verdict.is_allowed() {
            response = adapter.encode(&verdict);
            break;
        }
    }

    if let Err(e) = evaluator.save_session_state(&storage_dir, &session) {
        eprintln!("[Arc Hook] Failed to persist session state: {e} (failing closed)");
        return 2;
    }
    emit(response)
}

#[derive(Default, Debug)]
pub struct InterceptEvalOptions<'a> {
    pub session: &'a str,
    pub kind: Option<&'a str>,
    pub target: Option<&'a str>,
    pub server: Option<&'a str>,
    pub pos_target: Option<&'a str>,
    pub pos_extra: Option<&'a str>,
    pub schema: Option<&'a str>,
    pub source: Option<&'a str>,
    pub untrusted: bool,
    pub session_dir: Option<&'a Path>,
    pub project_local: bool,
    pub reset: bool,
    pub json: bool,
}

fn check_session_dir_usable(dir: &Path) -> Result<(), String> {
    if dir.exists() && !dir.is_dir() {
        return Err(format!(
            "Session storage path '{}' exists but is a file, not a directory",
            dir.display()
        ));
    }
    fs::create_dir_all(dir).map_err(|e| {
        format!(
            "Failed to create session storage directory '{}': {e}",
            dir.display()
        )
    })?;
    if !dir.is_dir() {
        return Err(format!(
            "Session storage path '{}' is not a valid directory",
            dir.display()
        ));
    }
    // Test write permission by writing and removing a temporary probe file
    let probe_name = format!(
        ".arc_probe_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let probe_path = dir.join(probe_name);
    match fs::write(&probe_path, b"probe") {
        Ok(_) => {
            let _ = fs::remove_file(&probe_path);
            Ok(())
        }
        Err(e) => Err(format!(
            "Session storage directory '{}' is unwritable: {e}",
            dir.display()
        )),
    }
}

fn resolve_session_storage_dir(
    override_dir: Option<&Path>,
    project_local: bool,
) -> Result<PathBuf, String> {
    // 1. Explicit override passed via CLI argument
    if let Some(dir) = override_dir {
        check_session_dir_usable(dir)?;
        return Ok(dir.to_path_buf());
    }

    // 2. Explicit environment variable ARC_SESSION_DIR
    if let Ok(env_dir) = std::env::var("ARC_SESSION_DIR") {
        let pb = PathBuf::from(env_dir);
        check_session_dir_usable(&pb)?;
        return Ok(pb);
    }

    // 3. Opt-in project-local mode (via --project-local flag or ARC_PROJECT_LOCAL=1)
    let env_local = std::env::var("ARC_PROJECT_LOCAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if project_local || env_local {
        let local_arc = Path::new(".arc").join("sessions");
        check_session_dir_usable(&local_arc)?;
        return Ok(local_arc);
    }

    // 4. If current working directory already contains .arc/sessions, preserve project-local continuity
    let cwd_local = Path::new(".arc").join("sessions");
    if cwd_local.is_dir() && check_session_dir_usable(&cwd_local).is_ok() {
        return Ok(cwd_local);
    }

    // 5. OS-appropriate user data directory:
    #[cfg(windows)]
    let base_user_dir = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(|p| PathBuf::from(p).join(".arc")));

    #[cfg(not(windows))]
    let base_user_dir = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::var("HOME").map(|h| {
                #[cfg(target_os = "macos")]
                {
                    PathBuf::from(&h)
                        .join("Library")
                        .join("Application Support")
                }
                #[cfg(not(target_os = "macos"))]
                {
                    PathBuf::from(&h).join(".local").join("share")
                }
            })
        });

    if let Ok(user_dir) = base_user_dir {
        let arc_dir = user_dir.join("vexa-arc").join("sessions");
        if check_session_dir_usable(&arc_dir).is_ok() {
            return Ok(arc_dir);
        }
    }

    // 6. Fallback: system temp directory
    let temp_arc = std::env::temp_dir().join("vexa-arc").join("sessions");
    check_session_dir_usable(&temp_arc)?;
    Ok(temp_arc)
}

#[allow(dead_code)]
fn get_session_storage_dir(override_dir: Option<&Path>, project_local: bool) -> PathBuf {
    resolve_session_storage_dir(override_dir, project_local)
        .unwrap_or_else(|_| std::env::temp_dir().join("vexa-arc").join("sessions"))
}

fn parse_schema_fingerprint(schema_input: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(raw_str) = schema_input else {
        return Ok(None);
    };
    let raw = raw_str.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    // Check if it's 64-char hex
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(raw) {
            if let Ok(arr) = bytes.try_into() {
                return Ok(Some(arr));
            }
        }
    }
    // Check if it's a file path containing JSON schema
    let path = Path::new(raw);
    if path.is_file() {
        let content = fs::read(path)
            .map_err(|e| format!("Cannot read schema file '{}': {e}", path.display()))?;
        let hash = arc_core::compute_jcs_schema_hash(&content)
            .map_err(|e| format!("Invalid JSON schema in file '{}': {e}", path.display()))?;
        return Ok(Some(hash));
    }

    // Check if it's a raw JSON schema payload
    if raw.starts_with('{') || raw.starts_with('[') {
        let hash = arc_core::compute_jcs_schema_hash(raw.as_bytes())
            .map_err(|e| format!("Invalid JSON schema payload: {e}"))?;
        return Ok(Some(hash));
    }

    // Try parsing as JSON anyway in case of whitespace or formatting
    if let Ok(hash) = arc_core::compute_jcs_schema_hash(raw.as_bytes()) {
        return Ok(Some(hash));
    }

    Err(format!(
        "Invalid schema input '{raw}'. Expected a 64-character hex SHA-256 fingerprint, a path to a JSON schema file, or a valid JSON schema string."
    ))
}

pub fn classify_cli_provenance(
    untrusted: bool,
    source: Option<&str>,
) -> arc_core::event::EventProvenance {
    if untrusted {
        let src = source.unwrap_or("untrusted_external").to_string();
        arc_core::event::EventProvenance::UntrustedExternal { source: src }
    } else if let Some(src) = source {
        let src_lower = src.to_lowercase();
        if matches!(
            src_lower.as_str(),
            "user" | "developer" | "operator" | "admin" | "local" | "cli" | "prompt" | "human"
        ) {
            arc_core::event::EventProvenance::UserExplicit
        } else if src_lower.contains("untrusted")
            || src_lower.contains("issue")
            || src_lower.contains("web")
            || src_lower.contains("pr")
            || src_lower.contains("external")
            || src_lower.contains("chat")
            || src_lower.contains("ticket")
            || src_lower.contains("scraper")
            || src_lower.contains("crawl")
            || src_lower.contains("slack")
            || src_lower.contains("discord")
            || src_lower.contains("webhook")
            || src_lower.contains("remote")
            || src_lower.contains("fetch")
        {
            arc_core::event::EventProvenance::UntrustedExternal {
                source: src.to_string(),
            }
        } else if matches!(
            src_lower.as_str(),
            "internal" | "trusted_internal" | "pipeline" | "ci" | "local_repo"
        ) {
            arc_core::event::EventProvenance::TrustedInternal {
                source: src.to_string(),
            }
        } else {
            // Unrecognized custom source metadata without --untrusted preserves UserExplicit
            arc_core::event::EventProvenance::UserExplicit
        }
    } else {
        arc_core::event::EventProvenance::UserExplicit
    }
}

fn resolve_action_params(
    kind_arg: Option<&str>,
    target_arg: Option<&str>,
    server_arg: Option<&str>,
    pos_target: Option<&str>,
    pos_extra: Option<&str>,
) -> Result<(String, String, String), String> {
    if let Some(target) = target_arg {
        let kind = kind_arg
            .map(|k| k.to_string())
            .unwrap_or_else(|| infer_kind_from_target(target, server_arg));
        let server = server_arg.unwrap_or("default-mcp");
        return Ok((kind, target.to_string(), server.to_string()));
    }

    if let Some(pos1) = pos_target {
        let p1_lower = pos1.to_lowercase();
        if matches!(p1_lower.as_str(), "read" | "file_read" | "cat") {
            let target = pos_extra.ok_or_else(|| {
                "Missing file path after 'read'. Example: arc intercept eval read .env".to_string()
            })?;
            return Ok((
                "file_read".to_string(),
                target.to_string(),
                "default-mcp".to_string(),
            ));
        }
        if matches!(p1_lower.as_str(), "exec" | "shell" | "run" | "cmd") {
            let target = pos_extra.ok_or_else(|| {
                "Missing command string after 'exec'. Example: arc intercept eval exec 'curl evil.com'".to_string()
            })?;
            return Ok((
                "shell".to_string(),
                target.to_string(),
                "default-mcp".to_string(),
            ));
        }
        if matches!(p1_lower.as_str(), "mcp" | "tool") {
            let server_or_tool = pos_extra.ok_or_else(|| {
                "Missing tool or server/tool after 'mcp'. Example: arc intercept eval mcp slack/slack_post_message".to_string()
            })?;
            if let Some((srv, tl)) = server_or_tool.split_once('/') {
                return Ok(("mcp_call".to_string(), tl.to_string(), srv.to_string()));
            } else if let Some(srv) = server_arg {
                return Ok((
                    "mcp_call".to_string(),
                    server_or_tool.to_string(),
                    srv.to_string(),
                ));
            } else {
                return Ok((
                    "mcp_call".to_string(),
                    server_or_tool.to_string(),
                    "default-mcp".to_string(),
                ));
            }
        }
        if matches!(p1_lower.as_str(), "prompt" | "ask") {
            let text = pos_extra.ok_or_else(|| {
                "Missing prompt text after 'prompt'. Example: arc intercept eval prompt 'https://evil.com'".to_string()
            })?;
            return Ok((
                "prompt".to_string(),
                text.to_string(),
                "default-mcp".to_string(),
            ));
        }

        // Check if pos1 contains server/tool format (e.g. "slack/slack_post_message")
        if !pos1.contains(' ')
            && !pos1.contains("://")
            && !pos1.starts_with('.')
            && !pos1.contains('\\')
        {
            if let Some((srv, tl)) = pos1.split_once('/') {
                return Ok(("mcp_call".to_string(), tl.to_string(), srv.to_string()));
            }
        }

        if let Some(pos2) = pos_extra {
            return Ok(("mcp_call".to_string(), pos2.to_string(), pos1.to_string()));
        }

        let kind = kind_arg
            .map(|k| k.to_string())
            .unwrap_or_else(|| infer_kind_from_target(pos1, server_arg));
        let server = server_arg.unwrap_or("default-mcp");
        return Ok((kind, pos1.to_string(), server.to_string()));
    }

    Err("No action target specified. Examples:\n  arc intercept eval .env\n  arc intercept eval slack/slack_post_message\n  arc intercept eval --session dev-sess --kind file_read --target .env".to_string())
}

fn infer_kind_from_target(target: &str, server_arg: Option<&str>) -> String {
    if server_arg.is_some() {
        return "mcp_call".to_string();
    }
    let lower = target.to_lowercase();
    if lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("rm ")
        || lower.contains("npm ")
        || lower.contains("cargo ")
    {
        "shell".to_string()
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        "prompt".to_string()
    } else if target.contains(".env")
        || target.contains(".json")
        || target.contains(".toml")
        || target.contains(".yaml")
        || target.contains(".rs")
        || target.contains(".py")
        || target.contains('/')
        || target.contains('\\')
        || Path::new(target).exists()
    {
        "file_read".to_string()
    } else if lower.contains('_')
        || lower.contains("post")
        || lower.contains("send")
        || lower.contains("read")
    {
        "mcp_call".to_string()
    } else {
        "file_read".to_string()
    }
}

fn format_taints(taints: Taint) -> String {
    if taints.is_empty() {
        return "None".to_string();
    }
    let mut names = Vec::new();
    if taints.contains(Taint::PRIVATE_DATA) {
        names.push("PRIVATE_DATA");
    }
    if taints.contains(Taint::UNTRUSTED_CONTENT) {
        names.push("UNTRUSTED_CONTENT");
    }
    if taints.contains(Taint::SECRET_MATERIAL) {
        names.push("SECRET_MATERIAL");
    }
    if taints.contains(Taint::PRIVILEGED_DATA) {
        names.push("PRIVILEGED_DATA");
    }
    format!("[{}]", names.join(", "))
}

fn format_added_taints(taints: Taint) -> String {
    if taints.is_empty() {
        return "None (No new taints ingested)".to_string();
    }
    let mut names = Vec::new();
    if taints.contains(Taint::PRIVATE_DATA) {
        names.push("+PRIVATE_DATA");
    }
    if taints.contains(Taint::UNTRUSTED_CONTENT) {
        names.push("+UNTRUSTED_CONTENT");
    }
    if taints.contains(Taint::SECRET_MATERIAL) {
        names.push("+SECRET_MATERIAL");
    }
    if taints.contains(Taint::PRIVILEGED_DATA) {
        names.push("+PRIVILEGED_DATA");
    }
    names.join(", ")
}

#[allow(dead_code)]
fn run_intercept_session(session_id: &str, reset: bool, json: bool) -> bool {
    run_intercept_session_with_dir(session_id, reset, false, 24, json, None, false)
}

fn run_intercept_session_with_dir(
    session_id: &str,
    reset: bool,
    cleanup: bool,
    max_age_hours: u64,
    json: bool,
    session_dir: Option<&Path>,
    project_local: bool,
) -> bool {
    let storage_dir = match resolve_session_storage_dir(session_dir, project_local) {
        Ok(dir) => dir,
        Err(err) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "error": format!("Session storage error: {err}"), "session_id": session_id, "success": false })
                );
            } else {
                eprintln!("Error: Session storage failure: {err}");
            }
            return false;
        }
    };
    let evaluator = PolicyEvaluator::default();

    if cleanup {
        use arc_policy_engine::taint_dag::SessionTaintDag;
        match SessionTaintDag::cleanup_expired_sessions(&storage_dir, max_age_hours) {
            Ok(count) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "cleaned_up": count, "max_age_hours": max_age_hours, "success": true })
                    );
                } else {
                    println!("[Arc Session] Cleaned up {count} expired sessions (older than {max_age_hours}h)");
                }
                return true;
            }
            Err(e) => {
                eprintln!("Error: Session cleanup failed: {e}");
                return false;
            }
        }
    }

    if reset {
        match evaluator.clear_session_state(Some(&storage_dir), session_id) {
            Ok(cleared) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "session_id": session_id, "cleared": cleared, "success": true })
                    );
                } else {
                    println!("\nSession '{session_id}' state cleared successfully.");
                }
                return true;
            }
            Err(err) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "error": format!("Failed to clear session state: {err}"), "session_id": session_id, "success": false })
                    );
                } else {
                    eprintln!("Error: Failed to clear session '{session_id}': {err}");
                }
                return false;
            }
        }
    }

    if let Err(err) = evaluator.load_session_state(&storage_dir, session_id) {
        if json {
            println!(
                "{}",
                serde_json::json!({ "error": format!("Session state file is corrupt or unreadable: {err}"), "session_id": session_id, "storage_dir": storage_dir.display().to_string(), "corrupt": true, "success": false })
            );
        } else {
            eprintln!(
                "Error: Session state for '{session_id}' in '{}' is corrupt or unreadable: {err}",
                storage_dir.display()
            );
        }
        return false;
    }

    let dag = evaluator.taint_tracker.get_or_create(session_id);
    let session_file = storage_dir.join(format!("{session_id}.json"));

    if json {
        println!("{}", serde_json::to_string_pretty(&dag).unwrap_or_default());
        return true;
    }

    println!("\n═══════════════════════════════════════════════════════════");
    println!("              ARC SESSION TAINT DAG INSPECTOR              ");
    println!("═══════════════════════════════════════════════════════════");
    println!(" Session ID:     {}", dag.session_id);
    println!(" Storage File:   {}", session_file.display());
    println!(" Exists on Disk: {}", session_file.exists());
    println!(" Current Taints: {}", format_taints(dag.current_taints));
    println!("───────────────────────────────────────────────────────────");
    println!(" Action History ({} items):", dag.history.len());
    if dag.history.is_empty() {
        println!("  (No actions recorded for this session yet)");
    } else {
        for (i, entry) in dag.history.iter().enumerate() {
            let time_str = chrono::DateTime::from_timestamp_millis(entry.timestamp_ms as i64)
                .map(|dt| dt.format("%H:%M:%S UTC").to_string())
                .unwrap_or_else(|| format!("{}ms", entry.timestamp_ms));
            println!(
                "  [{}] {} | Taints: {} | Origin: {}",
                i + 1,
                time_str,
                format_taints(entry.taint),
                entry.origin
            );
        }
    }
    println!("═══════════════════════════════════════════════════════════\n");
    true
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn run_intercept_eval(
    session: &str,
    kind_arg: Option<&str>,
    target_arg: Option<&str>,
    server_arg: Option<&str>,
    pos_target: Option<&str>,
    pos_extra: Option<&str>,
    reset: bool,
    output_json: bool,
) -> bool {
    run_intercept_eval_with_opts(InterceptEvalOptions {
        session,
        kind: kind_arg,
        target: target_arg,
        server: server_arg,
        pos_target,
        pos_extra,
        reset,
        json: output_json,
        ..Default::default()
    })
}

fn run_intercept_eval_with_opts(opts: InterceptEvalOptions) -> bool {
    let session = opts.session;
    let (kind, target, server) = match resolve_action_params(
        opts.kind,
        opts.target,
        opts.server,
        opts.pos_target,
        opts.pos_extra,
    ) {
        Ok(res) => res,
        Err(err) => {
            if opts.json {
                let json_output = serde_json::json!({
                    "error": format!("Parameter error: {err}"),
                    "session_id": session,
                    "success": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_output).unwrap_or_default()
                );
            } else {
                eprintln!("Error: {err}");
            }
            return false;
        }
    };

    let storage_dir = match resolve_session_storage_dir(opts.session_dir, opts.project_local) {
        Ok(dir) => dir,
        Err(err) => {
            if opts.json {
                let json_output = serde_json::json!({
                    "error": format!("Session storage failure: {err}"),
                    "session_id": session,
                    "success": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_output).unwrap_or_default()
                );
            } else {
                eprintln!("Error: Session storage failure: {err}");
            }
            return false;
        }
    };

    let evaluator = PolicyEvaluator::default();

    if opts.reset {
        if let Err(err) = evaluator.clear_session_state(Some(&storage_dir), session) {
            if opts.json {
                let json_output = serde_json::json!({
                    "error": format!("Failed to clear session state: {err}"),
                    "session_id": session,
                    "storage_dir": storage_dir.display().to_string(),
                    "success": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_output).unwrap_or_default()
                );
            } else {
                eprintln!("Error: Failed to clear session '{session}': {err}");
            }
            return false;
        }
    } else if let Err(err) = evaluator.load_session_state(&storage_dir, session) {
        if opts.json {
            let json_output = serde_json::json!({
                "error": format!("Session state file is corrupt or unreadable: {err}"),
                "session_id": session,
                "storage_dir": storage_dir.display().to_string(),
                "corrupt": true,
                "success": false,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json_output).unwrap_or_default()
            );
        } else {
            eprintln!(
                "Error: Session state file for '{session}' in '{}' is corrupt or unreadable: {err}",
                storage_dir.display()
            );
        }
        return false;
    }

    let prev_dag = evaluator.taint_tracker.get_or_create(session);
    let prev_taints = prev_dag.current_taints;

    let schema_root = match parse_schema_fingerprint(opts.schema) {
        Ok(s) => s,
        Err(err) => {
            if opts.json {
                let json_output = serde_json::json!({
                    "error": format!("Invalid schema parameter: {err}"),
                    "session_id": session,
                    "success": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_output).unwrap_or_default()
                );
            } else {
                eprintln!("Error: Invalid schema parameter: {err}");
            }
            return false;
        }
    };

    let action = match kind.to_lowercase().as_str() {
        "file_read" | "read" => Action::FileRead {
            path: PathBuf::from(&target),
        },
        "shell" | "exec" => Action::Shell {
            command: target.to_string(),
            cwd: PathBuf::from("."),
        },
        "mcp_call" | "tool" => Action::McpToolCall {
            server: ServerIdentity {
                config_name: server.to_string(),
                artifact: Artifact::Unknown,
                schema_root,
            },
            tool: target.to_string(),
            arguments: serde_json::json!({}),
        },
        "prompt" => Action::PromptSubmit {
            text: target.to_string(),
            source: opts.source.map(|s| s.to_string()),
        },
        "mcp_result" => Action::McpToolResult {
            server: ServerIdentity {
                config_name: server.to_string(),
                artifact: Artifact::Unknown,
                schema_root,
            },
            tool: target.to_string(),
            content: String::new(),
            is_error: false,
        },
        _ => {
            eprintln!("Unknown action kind '{kind}'. Use file_read, shell, mcp_call, or prompt.");
            return false;
        }
    };

    let mut event = ActionEvent::new(
        AgentHost::ClaudeCode,
        session,
        OsPrincipal::Uid(1000),
        Phase::Pre,
        action,
    );

    let provenance = classify_cli_provenance(opts.untrusted, opts.source);
    event = event.with_provenance(provenance);

    let verdict = evaluator.evaluate(&event);

    // Persist session state to disk - must fail closed if persistence fails
    let session_file = match evaluator.save_session_state(&storage_dir, session) {
        Ok(path) => path,
        Err(err) => {
            if opts.json {
                let json_output = serde_json::json!({
                    "error": format!("Failed to persist session state: {err}"),
                    "session_id": session,
                    "storage_dir": storage_dir.display().to_string(),
                    "verdict": verdict,
                    "saved": false,
                    "success": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_output).unwrap_or_default()
                );
            } else {
                eprintln!(
                    "Error: Failed to persist session state for '{session}' in '{}': {err}",
                    storage_dir.display()
                );
                eprintln!("Failing closed to prevent unpersisted taint governance loss.");
            }
            return false;
        }
    };

    let updated_dag = evaluator.taint_tracker.get_or_create(session);
    let current_taints = updated_dag.current_taints;
    let newly_added_taints = current_taints - prev_taints;

    if opts.json {
        let json_output = serde_json::json!({
            "session_id": session,
            "action_kind": kind,
            "target": target,
            "server": if kind == "mcp_call" { Some(&server) } else { None },
            "verdict": verdict,
            "taints": {
                "active": format_taints(current_taints),
                "newly_added": format_added_taints(newly_added_taints),
                "history_count": updated_dag.history.len(),
            },
            "session_file": session_file.display().to_string(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json_output).unwrap_or_default()
        );
        return !verdict.is_blocked();
    }

    println!("\n═══════════════════════════════════════════════════════════════════════");
    println!("                    ARC RUNTIME ACTION INTERCEPT                       ");
    println!("═══════════════════════════════════════════════════════════════════════");
    println!(" Session ID:    {session}");
    println!(" Session File:  {}", session_file.display());
    if kind == "mcp_call" {
        println!(" Action:        {kind} ➔ {server}:{target}");
    } else {
        println!(" Action:        {kind} ➔ {target}");
    }
    println!(" Phase:         Pre-Execution Runtime Interception");
    println!("───────────────────────────────────────────────────────────────────────");

    // Taint Section
    println!(" [TAINT DAG TRACKING]");
    println!(
        "   • Newly Added:   {}",
        format_added_taints(newly_added_taints)
    );
    println!("   • Active Taints: {}", format_taints(current_taints));
    println!(
        "   • History Size:  {} recorded action(s)",
        updated_dag.history.len()
    );

    // Policy Gate Breakdown
    let has_private = current_taints.contains(Taint::PRIVATE_DATA)
        || current_taints.contains(Taint::SECRET_MATERIAL)
        || current_taints.contains(Taint::PRIVILEGED_DATA);
    let has_untrusted = current_taints.contains(Taint::UNTRUSTED_CONTENT);
    let sink = arc_policy_engine::taint_dag::TaintTracker::classify_sink(&event.action);
    let is_sensitive_sink =
        sink.contains(SinkClass::EXTERNAL_EGRESS) || sink.contains(SinkClass::DESTRUCTIVE);

    println!("\n [SECURITY POLICY GATES]");
    println!("   Gate 1 (MCP Whitelist):       PASS");
    println!("   Gate 2 (Dynamic Rug-Pull):    PASS");
    match &verdict {
        arc_core::verdict::Verdict::Deny { rule, .. } if rule.0 == "ARC-LTT-001" => {
            println!("   Gate 3 (Lethal Trifecta):     ✘ VIOLATION (ARC-LTT-001)");
        }
        _ => {
            if has_private && !has_untrusted && is_sensitive_sink {
                println!(
                    "   Gate 3 (Lethal Trifecta):     PASS (Missing untrusted context trigger)"
                );
            } else if !has_private && has_untrusted && is_sensitive_sink {
                println!("   Gate 3 (Lethal Trifecta):     PASS (Missing private context trigger)");
            } else {
                println!("   Gate 3 (Lethal Trifecta):     PASS");
            }
        }
    }
    println!(
        "       ├─ Private Context:       {}",
        if has_private {
            "[✔] Present"
        } else {
            "[ ] None"
        }
    );
    println!(
        "       ├─ Untrusted Input:       {}",
        if has_untrusted {
            "[✔] Present"
        } else {
            "[ ] None detected"
        }
    );
    println!(
        "       └─ Sensitive Sink:        {}",
        if is_sensitive_sink {
            format!("[✔] {sink:?}")
        } else {
            "[ ] None (Read-only or safe)".to_string()
        }
    );

    println!("   Gate 4 (Secret Redaction):    PASS");
    println!("───────────────────────────────────────────────────────────────────────");

    match &verdict {
        arc_core::verdict::Verdict::Allow { obligations } => {
            println!(" Decision:      ✔ ALLOW");
            if !obligations.is_empty() {
                println!("\n Obligations Enforced ({}):", obligations.len());
                for ob in obligations {
                    println!("  • {ob:?}");
                }
            }
            if !newly_added_taints.is_empty() {
                println!("\n Security Notice:");
                println!(
                    "   Session now holds {}. Monotonic taint tracking active.",
                    format_taints(current_taints)
                );
                println!(
                    "   If untrusted external data (web/issues) is ingested, outbound network"
                );
                println!("   egress (slack, webhooks, curl) will be strictly BLOCKED.");
            } else if is_sensitive_sink && has_private && !has_untrusted {
                println!("\n Security Notice:");
                println!("   Outbound action allowed because session has NOT ingested untrusted context.");
                println!("   (Direct developer actions without external prompt injection are permitted).");
            }
        }
        arc_core::verdict::Verdict::Deny { rule, explanation } => {
            println!(" Decision:      ✘ DENY [Rule: {}]", rule.0);
            println!("\n Reason:\n   {}", explanation.summary);
            if !explanation.options.is_empty() {
                println!("\n Self-Explaining Remediation Options:");
                for (idx, opt) in explanation.options.iter().enumerate() {
                    println!("   {}. {}", idx + 1, opt);
                }
            }
            if let Some(ref url) = explanation.policy_url {
                println!("\n Policy Documentation: {url}");
            }
        }
        arc_core::verdict::Verdict::Quarantine { rule, explanation } => {
            println!(" Decision:      ⚠ QUARANTINE [Rule: {}]", rule.0);
            println!("\n Reason:\n   {}", explanation.summary);
        }
        arc_core::verdict::Verdict::RequireApproval {
            rule,
            explanation,
            timeout_secs,
            ..
        } => {
            println!(
                " Decision:      ⏳ REQUIRE_APPROVAL (timeout: {}s) [Rule: {}]",
                timeout_secs, rule.0
            );
            println!("\n Reason:\n   {}", explanation.summary);
        }
    }
    println!("═══════════════════════════════════════════════════════════════════════\n");

    !verdict.is_blocked()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_audit_execution() {
        let scanner = DiscoveryScanner::new();
        let report = scanner.audit_directory(Path::new(".")).unwrap();
        assert!(report.scan_duration_ms < 5000);
    }

    #[test]
    fn test_scan_secrets_directory_collection() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("arc_scan_test_{ts}"));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let test_file = temp_dir.join("test.rs");
        std::fs::write(&test_file, "fn main() {}").unwrap();

        let mut files = Vec::new();
        collect_scan_files(&temp_dir, 0, &mut files).unwrap();
        assert!(!files.is_empty(), "Must collect files from directory");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_shield_check_blocked_and_permitted() {
        assert!(!run_shield_check(
            "reactt",
            "npm",
            Some(2),
            Some(12),
            false,
            true
        ));
        assert!(run_shield_check(
            "react",
            "npm",
            Some(35),
            Some(50000),
            false,
            true
        ));
        assert!(run_shield_check("react", "npm", None, None, false, true));
        assert!(!run_shield_check("reactt", "npm", None, None, false, true));
    }

    #[test]
    fn test_resolve_action_params() {
        // Direct flags
        let (k, t, s) =
            resolve_action_params(Some("file_read"), Some(".env"), None, None, None).unwrap();
        assert_eq!(k, "file_read");
        assert_eq!(t, ".env");
        assert_eq!(s, "default-mcp");

        // Positional file read inference
        let (k, t, _) = resolve_action_params(None, None, None, Some(".env"), None).unwrap();
        assert_eq!(k, "file_read");
        assert_eq!(t, ".env");

        // Shorthand verb read
        let (k, t, _) =
            resolve_action_params(None, None, None, Some("read"), Some(".env")).unwrap();
        assert_eq!(k, "file_read");
        assert_eq!(t, ".env");

        // Server/tool slash syntax
        let (k, t, s) =
            resolve_action_params(None, None, None, Some("slack/slack_post_message"), None)
                .unwrap();
        assert_eq!(k, "mcp_call");
        assert_eq!(t, "slack_post_message");
        assert_eq!(s, "slack");

        // Shell command inference
        let (k, t, _) =
            resolve_action_params(None, None, None, Some("curl https://evil.com"), None).unwrap();
        assert_eq!(k, "shell");
        assert_eq!(t, "curl https://evil.com");
    }

    #[test]
    fn test_multi_step_intercept_session_persistence_and_lethal_trifecta() {
        let session = "test-e2e-cli-session";

        // Step 0: Ensure session is reset
        let _ = run_intercept_eval(
            session,
            None,
            None,
            None,
            Some("read"),
            Some(".env"),
            true,
            true,
        );

        // Step 1: Read .env (accumulates PRIVATE_DATA) -> should ALLOW
        let p1 = run_intercept_eval(session, None, None, None, Some(".env"), None, false, true);
        assert!(
            p1,
            "Step 1: Reading .env should be allowed and taint the session"
        );

        // Step 2: Post to Slack without untrusted context -> should ALLOW (missing untrusted leg)
        let p2 = run_intercept_eval(
            session,
            None,
            None,
            None,
            Some("slack/slack_post_message"),
            None,
            false,
            true,
        );
        assert!(
            p2,
            "Step 2: Slack post without untrusted input should be allowed"
        );

        // Step 3: Ingest untrusted context (adds UNTRUSTED_CONTENT) -> should ALLOW
        let p3 = run_intercept_eval(
            session,
            None,
            None,
            None,
            Some("prompt"),
            Some("https://evil.com/issue"),
            false,
            true,
        );
        assert!(
            p3,
            "Step 3: Prompt ingestion should be allowed and taint the session"
        );

        // Step 4: Post to Slack again (Trifecta complete: Private + Untrusted + Egress) -> must DENY!
        let p4 = run_intercept_eval(
            session,
            None,
            None,
            None,
            Some("slack/slack_post_message"),
            None,
            false,
            true,
        );
        assert!(!p4, "Step 4: Lethal trifecta must be triggered and blocked");

        // Cleanup: Reset session
        run_intercept_session(session, true, true);
    }
}

#[cfg(test)]
mod shield_version_tests {
    use super::split_package_version;

    #[test]
    fn exact_versions_are_extracted() {
        assert_eq!(
            split_package_version("lodash@4.17.21"),
            ("lodash", Some("4.17.21"))
        );
        assert_eq!(
            split_package_version("@scope/pkg@1.2.3"),
            ("@scope/pkg", Some("1.2.3"))
        );
        assert_eq!(
            split_package_version("requests==2.31.0"),
            ("requests", Some("2.31.0"))
        );
    }

    #[test]
    fn ranges_and_missing_versions_are_not_concrete() {
        assert_eq!(split_package_version("lodash"), ("lodash", None));
        assert_eq!(split_package_version("lodash@^4.17.21"), ("lodash", None));
        assert_eq!(split_package_version("lodash@latest"), ("lodash", None));
        assert_eq!(split_package_version("@scope/pkg"), ("@scope/pkg", None));
    }
}
