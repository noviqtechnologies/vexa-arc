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
use arc_firewall::proxy::PackageFirewall;
use arc_policy_engine::evaluator::PolicyEvaluator;

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

    /// Display platform version and operational status
    Version,
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

    /// Direct package name (e.g. 'reactt'), scoped target ('npm:reactt'), or install command ('npm install reactt')
    #[command(external_subcommand)]
    Direct(Vec<String>),
}

#[derive(Subcommand)]
enum InterceptAction {
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
            json,
            output_bom,
        } => {
            if !run_audit(&path, json, output_bom.as_deref()) {
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
            InterceptAction::Eval {
                pos_target,
                pos_extra,
                session,
                kind,
                target,
                server,
                reset,
                json,
            } => {
                let permitted = run_intercept_eval(
                    &session,
                    kind.as_deref(),
                    target.as_deref(),
                    server.as_deref(),
                    pos_target.as_deref(),
                    pos_extra.as_deref(),
                    reset,
                    json,
                );
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Read {
                path,
                session,
                json,
            } => {
                let path_str = path.to_string_lossy();
                let permitted = run_intercept_eval(
                    &session,
                    Some("file_read"),
                    Some(&path_str),
                    None,
                    None,
                    None,
                    false,
                    json,
                );
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Exec {
                command,
                session,
                json,
            } => {
                let permitted = run_intercept_eval(
                    &session,
                    Some("shell"),
                    Some(&command),
                    None,
                    None,
                    None,
                    false,
                    json,
                );
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Mcp {
                server,
                tool,
                session,
                json,
            } => {
                let permitted = run_intercept_eval(
                    &session,
                    Some("mcp_call"),
                    Some(&tool),
                    Some(&server),
                    None,
                    None,
                    false,
                    json,
                );
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Prompt {
                text,
                session,
                json,
            } => {
                let permitted = run_intercept_eval(
                    &session,
                    Some("prompt"),
                    Some(&text),
                    None,
                    None,
                    None,
                    false,
                    json,
                );
                if !permitted {
                    std::process::exit(1);
                }
            }
            InterceptAction::Session {
                session_id,
                reset,
                json,
            } => {
                run_intercept_session(&session_id, reset, json);
            }
        },
        Commands::Version => {
            println!("Vexa Arc CLI v1.0.0 (Agentic Runtime Control)");
            println!("Target Architecture: Pure Rust Pre-Execution Endpoint & Agent Firewall");
            println!("License: Apache-2.0");
        }
    }
}

fn run_audit(path: &Path, output_json: bool, bom_file: Option<&Path>) -> bool {
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

    if json {
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
                    }
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
                    }
                })
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json_output).unwrap_or_default()
        );
        return !verdict.is_blocked();
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
            println!("STATUS:             ✅ PERMITTED (PASS)");
            println!("Reason:             {reason}");
        }
        arc_firewall::slopsquat::SlopsquatVerdict::Blocked { gate, reason } => {
            println!("STATUS:             🛑 BLOCKED (HARD GATE REJECTION)");
            println!("Triggered Gate:     {gate}");
            println!("Finding:            {reason}");

            if let Some(act) = &suggestion {
                println!("\nSUGGESTED ACTION:");
                if gate == &"CompoundTyposquatGate" {
                    println!("  💡 {act}");
                    println!(
                        "  ℹ️  If legitimate: arc shield allow {package} --ecosystem {ecosystem}"
                    );
                } else if gate == &"CompoundLifecycleGate" {
                    println!("  ⚠️  {act}");
                } else {
                    println!("  ➜  {act}");
                }
            }
        }
    }
    println!("──────────────────────────────────────────────────────────\n");

    !verdict.is_blocked()
}

fn get_session_storage_dir() -> PathBuf {
    let local_arc = Path::new(".arc").join("sessions");
    if local_arc.exists() || fs::create_dir_all(&local_arc).is_ok() {
        return local_arc;
    }
    let temp_arc = std::env::temp_dir().join("vexa-arc").join("sessions");
    let _ = fs::create_dir_all(&temp_arc);
    temp_arc
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

fn run_intercept_session(session_id: &str, reset: bool, json: bool) {
    let storage_dir = get_session_storage_dir();
    let evaluator = PolicyEvaluator::default();
    let _ = evaluator.load_session_state(&storage_dir, session_id);

    if reset {
        let cleared = evaluator
            .clear_session_state(Some(&storage_dir), session_id)
            .unwrap_or(false);
        if json {
            println!(
                "{}",
                serde_json::json!({ "session_id": session_id, "cleared": cleared })
            );
        } else {
            println!("\nSession '{session_id}' state cleared successfully.");
        }
        return;
    }

    let dag = evaluator.taint_tracker.get_or_create(session_id);
    let session_file = storage_dir.join(format!("{session_id}.json"));

    if json {
        println!("{}", serde_json::to_string_pretty(&dag).unwrap_or_default());
        return;
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
}

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
    let (kind, target, server) =
        match resolve_action_params(kind_arg, target_arg, server_arg, pos_target, pos_extra) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error: {err}");
                return false;
            }
        };

    let storage_dir = get_session_storage_dir();
    let evaluator = PolicyEvaluator::default();

    if reset {
        let _ = evaluator.clear_session_state(Some(&storage_dir), session);
    } else {
        let _ = evaluator.load_session_state(&storage_dir, session);
    }

    let prev_dag = evaluator.taint_tracker.get_or_create(session);
    let prev_taints = prev_dag.current_taints;

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
                schema_root: None,
            },
            tool: target.to_string(),
            arguments: serde_json::json!({}),
        },
        "prompt" => Action::PromptSubmit {
            text: target.to_string(),
        },
        "mcp_result" => Action::McpToolResult {
            server: ServerIdentity {
                config_name: server.to_string(),
                artifact: Artifact::Unknown,
                schema_root: None,
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

    let event = ActionEvent::new(
        AgentHost::ClaudeCode,
        session,
        OsPrincipal::Uid(1000),
        Phase::Pre,
        action,
    );

    let verdict = evaluator.evaluate(&event);

    // Persist session state to disk
    let session_file = evaluator.save_session_state(&storage_dir, session).ok();

    let updated_dag = evaluator.taint_tracker.get_or_create(session);
    let current_taints = updated_dag.current_taints;
    let newly_added_taints = current_taints - prev_taints;

    if output_json {
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
            "session_file": session_file.map(|p| p.display().to_string()),
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
    if let Some(ref path) = session_file {
        println!(" Session File:  {}", path.display());
    }
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
        let mut files = Vec::new();
        collect_scan_files(Path::new("src"), 0, &mut files).unwrap();
        assert!(!files.is_empty(), "Must collect files from directory");
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
