use arc_core::event::{
    Action, ActionEvent, AgentHost, Artifact, OsPrincipal, Phase, ServerIdentity,
};
use arc_core::verdict::Verdict;
use arc_discover::scanner::DiscoveryScanner;
use arc_hooks::broker::{
    load_mcp_pin_from_lockfile, ClientMessageOutcome, McpStdioBroker, ServerMessageOutcome,
};
use arc_policy_engine::evaluator::{
    PolicyConfig, PolicyEvaluator, PolicyException, PolicyMode, PolicyOutcomeKind, PolicySource,
};
use arc_policy_engine::taint_dag::SessionAuditRecord;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::commands::setup::detect_installed_host_adapters;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCoverageContract {
    pub integration: String,
    pub event_types: Vec<String>,
    pub interception_point: String,
    pub known_bypasses: Vec<String>,
    pub required_config: String,
    pub coverage_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpInventoryItem {
    pub server_name: String,
    pub source_config: String,
    pub transport: String,
    pub command_identity: String,
    pub schema_pin_status: String,
    pub schema_hash: Option<String>,
    pub policy_source: String,
    pub arc_in_path: bool,
    pub coverage_status: String,
    pub last_seen_unix_secs: Option<u64>,
    pub observed_tools: Vec<String>,
}

fn default_session_dirs(project_dir: &Path, explicit_session_dir: Option<&Path>) -> Vec<PathBuf> {
    if let Some(d) = explicit_session_dir {
        return vec![d.to_path_buf()];
    }
    let mut dirs = vec![project_dir.join(".arc").join("sessions")];
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
    {
        let global_dir = home.join(".arc").join("sessions");
        if !dirs.iter().any(|d| d == &global_dir) {
            dirs.push(global_dir);
        }
    }
    dirs
}

fn collect_all_audit_records(
    project_dir: &Path,
    explicit_session_dir: Option<&Path>,
) -> Vec<SessionAuditRecord> {
    let mut out = Vec::new();
    for dir in default_session_dirs(project_dir, explicit_session_dir) {
        if let Ok(by_sess) = SessionAuditRecord::read_all_sessions_from_dir(&dir) {
            for (_, recs) in by_sess {
                out.extend(recs);
            }
        }
    }
    out
}

pub fn build_host_coverage_contracts(project_dir: &Path) -> Vec<HostCoverageContract> {
    let installed = detect_installed_host_adapters(project_dir);
    let policy = PolicyConfig::load_with_precedence(Some(project_dir));
    let active_status = if policy.mode.is_preview() {
        "observe-only"
    } else {
        "enforced"
    };

    vec![
        HostCoverageContract {
            integration: "claude-code".to_string(),
            event_types: vec![
                "PreToolUse".to_string(),
                "PostToolUse".to_string(),
                "UserPromptSubmit".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct terminal shell commands outside Claude Code".to_string(),
                "Hooks disabled via user settings override".to_string(),
            ],
            required_config: ".claude/settings.json (`arc intercept hook --host claude-code`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "claude-code") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "cursor".to_string(),
            event_types: vec![
                "beforeShellExecution".to_string(),
                "beforeMCPExecution".to_string(),
                "beforeReadFile".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct IDE file edits outside agent hooks".to_string(),
                "Unwrapped MCP servers if Cursor hooks are disabled".to_string(),
            ],
            required_config: ".cursor/hooks.json (`arc intercept hook --host cursor`)".to_string(),
            coverage_status: if installed.iter().any(|h| h == "cursor") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "windsurf".to_string(),
            event_types: vec![
                "pre_run_command".to_string(),
                "pre_read_code".to_string(),
                "pre_write_code".to_string(),
                "pre_mcp_tool_use".to_string(),
                "post_mcp_tool_use".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct terminal shell commands outside Windsurf hooks".to_string(),
                "Unwrapped MCP servers if Windsurf hooks are disabled".to_string(),
            ],
            required_config: ".windsurf/hooks.json (`arc init --host windsurf` or `arc host install --host windsurf`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "windsurf") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "codex-cli".to_string(),
            event_types: vec!["PreToolUse".to_string(), "PostToolUse".to_string()],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct terminal shell commands outside Codex CLI".to_string(),
                "Hooks disabled via user settings override".to_string(),
            ],
            required_config: ".codex/hooks.json (`arc init --host codex-cli` or `arc host install --host codex-cli`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "codex-cli") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "gemini-cli".to_string(),
            event_types: vec![
                "BeforeTool".to_string(),
                "AfterTool".to_string(),
                "BeforeAgent".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct terminal shell commands outside Gemini CLI".to_string(),
                "Hooks disabled via user settings override".to_string(),
            ],
            required_config: ".gemini/settings.json (`arc init --host gemini-cli` or `arc host install --host gemini-cli`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "gemini-cli") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "github-copilot".to_string(),
            event_types: vec![
                "preToolUse".to_string(),
                "postToolUse".to_string(),
                "userPromptSubmitted".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Inline editor ghost-text completions outside Copilot Agent Mode".to_string(),
                "Direct terminal shell commands outside Copilot".to_string(),
            ],
            required_config: ".github/hooks/vexa-arc.json (`arc init --host github-copilot` or `arc host install --host github-copilot`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "github-copilot") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "cline".to_string(),
            event_types: vec![
                "PreToolUse".to_string(),
                "PostToolUse".to_string(),
                "UserPromptSubmit".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct editor writes outside Cline hooks".to_string(),
                "Unwrapped MCP servers if Cline hooks are disabled".to_string(),
            ],
            required_config: ".clinerules/hooks/PreToolUse(.ps1) (`arc init --host cline` or `arc host install --host cline`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "cline") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "kiro".to_string(),
            event_types: vec![
                "PreToolUse".to_string(),
                "PostToolUse".to_string(),
                "UserPromptSubmit".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct editor writes outside Kiro hooks".to_string(),
                "Unwrapped MCP servers if Kiro hooks are disabled".to_string(),
            ],
            required_config: ".kiro/hooks/vexa-arc.json (`arc init --host kiro` or `arc host install --host kiro`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "kiro") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "opencode".to_string(),
            event_types: vec![
                "tool.execute.before".to_string(),
                "tool.execute.after".to_string(),
            ],
            interception_point: "pre_and_post_hook".to_string(),
            known_bypasses: vec![
                "Direct terminal shell commands outside OpenCode".to_string(),
                "Unwrapped MCP servers if OpenCode plugin is disabled".to_string(),
            ],
            required_config: ".opencode/plugins/vexa-arc.js (`arc init --host opencode` or `arc host install --host opencode`)"
                .to_string(),
            coverage_status: if installed.iter().any(|h| h == "opencode") {
                active_status.to_string()
            } else {
                "unknown".to_string()
            },
        },
        HostCoverageContract {
            integration: "mcp-stdio-broker".to_string(),
            event_types: vec!["tools/list".to_string(), "tools/call".to_string()],
            interception_point: "pre_and_post_jsonrpc_stdio".to_string(),
            known_bypasses: vec![
                "MCP servers launched directly without `arc protect stdio` wrapper".to_string(),
                "Out-of-band network calls made directly by the child MCP process".to_string(),
            ],
            required_config:
                "Wrap MCP server command with `arc protect stdio --server <name> -- <cmd>`"
                    .to_string(),
            coverage_status: active_status.to_string(),
        },
    ]
}

pub fn run_mcp_inventory(path: &Path, workstation: bool, json: bool) -> bool {
    if !workstation && (!path.exists() || !path.is_dir()) {
        eprintln!(
            "[Arc MCP Inventory] Target directory does not exist: {}",
            path.display()
        );
        return false;
    }

    let scanner = DiscoveryScanner::new();
    let audit = if workstation {
        scanner.audit_workstation()
    } else {
        scanner.audit_directory(path)
    };
    let Ok(audit) = audit else {
        eprintln!("[Arc MCP Inventory] Discovery scan failed.");
        return false;
    };

    let policy = PolicyConfig::load_with_precedence(Some(path));
    let policy_source_str = format!(
        "{:?}",
        policy.source.unwrap_or(PolicySource::BuiltInDefault)
    )
    .to_lowercase();
    let lockfile_path = path.join(".arc").join("mcp-pins.lock");
    let installed_hosts = detect_installed_host_adapters(path);
    let records = collect_all_audit_records(path, None);

    let mut items = Vec::new();
    for srv in &audit.mcp_servers {
        let cmd_str = srv.command.clone().unwrap_or_default();
        let full_cmd = if srv.args.is_empty() {
            cmd_str.clone()
        } else {
            format!("{} {}", cmd_str, srv.args.join(" "))
        };
        let wrapped_by_broker = full_cmd.contains("arc protect") || srv.name == "vexa-arc";
        let arc_in_path = wrapped_by_broker || !installed_hosts.is_empty();

        let org_pin = policy.mcp_schema_pins.get(&srv.name).cloned();
        let lock_pin = load_mcp_pin_from_lockfile(&lockfile_path, &srv.name);
        let (schema_pin_status, schema_hash) = if let Some(h) = org_pin {
            ("pinned_signed_org".to_string(), Some(h))
        } else if let Some(h) = lock_pin {
            ("pinned_lockfile".to_string(), Some(h))
        } else if let Some(ref h) = srv.schema_hash {
            ("pinned_inline".to_string(), Some(h.clone()))
        } else {
            ("unpinned".to_string(), None)
        };

        let mut last_seen: Option<u64> = None;
        let mut tools_set = BTreeSet::new();
        for rec in &records {
            let matches_srv = rec
                .server_name
                .as_deref()
                .map(|s| s == srv.name)
                .unwrap_or(false)
                || rec.tool.starts_with(&format!("mcp__{}__", srv.name));
            if matches_srv {
                last_seen = Some(last_seen.map_or(rec.timestamp, |prev| prev.max(rec.timestamp)));
                tools_set.insert(rec.tool.clone());
            }
        }

        let coverage_status = if !matches!(
            srv.transport.as_str(),
            "stdio" | "http" | "sse" | "http/sse"
        ) {
            "unsupported".to_string()
        } else if wrapped_by_broker || !installed_hosts.is_empty() {
            if policy.mode.is_preview() {
                "observe-only".to_string()
            } else {
                "enforced".to_string()
            }
        } else {
            "unknown".to_string()
        };

        items.push(McpInventoryItem {
            server_name: srv.name.clone(),
            source_config: srv.source_file.display().to_string(),
            transport: srv.transport.clone(),
            command_identity: full_cmd,
            schema_pin_status,
            schema_hash,
            policy_source: policy_source_str.clone(),
            arc_in_path,
            coverage_status,
            last_seen_unix_secs: last_seen,
            observed_tools: tools_set.into_iter().collect(),
        });
    }

    let contracts = build_host_coverage_contracts(path);
    let scope_notice = "Local endpoint/repository inventory only. Vexa Arc mediates configured host hooks and explicitly wrapped MCP servers; it does not provide org-wide shadow-AI discovery.";

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "scope_notice": scope_notice,
                "scanned_path": path.display().to_string(),
                "policy_mode": policy.mode.as_str(),
                "policy_source": policy_source_str,
                "policy_revision": policy.revision_hash(),
                "installed_host_adapters": installed_hosts,
                "mcp_servers_total": items.len(),
                "mcp_servers": items,
                "coverage_contracts": contracts,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("\n┌──────────────────────────────────────────────────────────────┐");
        println!("│              VEXA ARC — LOCAL MCP INVENTORY                  │");
        println!("└──────────────────────────────────────────────────────────────┘");
        println!("Notice:          {scope_notice}");
        println!("Scanned Path:    {}", path.display());
        println!(
            "Policy Mode:     {} (source: {}, rev: {:.12})",
            policy.mode.as_str(),
            policy_source_str,
            policy.revision_hash()
        );
        println!("Installed Hooks: {:?}", installed_hosts);
        println!("----------------------------------------------------------------");
        if items.is_empty() {
            println!("No local MCP server configurations discovered in scanned path.");
        } else {
            for item in &items {
                println!(
                    "• Server '{}' [coverage: {}] (pin: {}, arc_in_path: {}, last_seen: {:?})",
                    item.server_name,
                    item.coverage_status,
                    item.schema_pin_status,
                    item.arc_in_path,
                    item.last_seen_unix_secs
                );
                println!("    Config:  {}", item.source_config);
                println!("    Command: {}", item.command_identity);
                if !item.observed_tools.is_empty() {
                    println!("    Tools:   {:?}", item.observed_tools);
                }
            }
        }
    }
    true
}

pub fn run_mcp_rollout_report(
    path: &Path,
    session_dir: Option<&Path>,
    stage_transition: Option<&str>,
    server_filter: Option<&str>,
    json: bool,
) -> bool {
    let mut policy = PolicyConfig::load_with_precedence(Some(path));

    // Handle explicit human staged rollout transition: observe -> review -> enforce
    if let Some(stage) = stage_transition {
        let stage_lower = stage.to_ascii_lowercase();
        if matches!(
            policy.source,
            Some(PolicySource::SignedOrganization | PolicySource::EmergencyDeny)
        ) && stage_lower != "enforce"
        {
            eprintln!(
                "[Arc MCP Rollout] Denied: SignedOrganization / EmergencyDeny policy cannot be downgraded to '{}'.",
                stage
            );
            return false;
        }
        let policy_path = path.join(".arc").join("policy.json");
        let mut local_cfg = if policy_path.exists() {
            std::fs::read_to_string(&policy_path)
                .ok()
                .and_then(|s| serde_json::from_str::<PolicyConfig>(&s).ok())
                .unwrap_or_default()
        } else {
            PolicyConfig::default()
        };
        match stage_lower.as_str() {
            "observe" | "review" => {
                local_cfg.mode = PolicyMode::Observe;
            }
            "enforce" => {
                local_cfg.mode = PolicyMode::Enforce;
                local_cfg.block_unapproved_mcp = true;
            }
            other => {
                eprintln!(
                    "[Arc MCP Rollout] Invalid stage '{}'. Expected 'observe', 'review', or 'enforce'.",
                    other
                );
                return false;
            }
        }
        if let Some(srv) = server_filter {
            if stage_lower == "enforce" {
                local_cfg.allowed_mcp_servers.insert(srv.to_string());
            }
        }
        if let Err(e) = local_cfg.save_to_dir(path) {
            eprintln!("[Arc MCP Rollout] Failed to save staged policy transition: {e}");
            return false;
        }
        policy = PolicyConfig::load_with_precedence(Some(path));
    }

    let records = collect_all_audit_records(path, session_dir);
    let scanner = DiscoveryScanner::new();
    let discovered = scanner
        .audit_directory(path)
        .map(|a| a.mcp_servers)
        .unwrap_or_default();
    let lockfile_path = path.join(".arc").join("mcp-pins.lock");
    let installed_hosts = detect_installed_host_adapters(path);

    let mut servers_seen = BTreeSet::new();
    let mut tools_seen = BTreeSet::new();
    let mut would_allow_count = 0usize;
    let mut would_deny_count = 0usize;
    let mut would_require_approval_count = 0usize;
    let mut would_quarantine_count = 0usize;
    let mut enforced_deny_count = 0usize;
    let mut evaluation_error_count = 0usize;
    let mut rule_triggers: BTreeMap<String, usize> = BTreeMap::new();
    let mut observed_schemas_by_server: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for rec in &records {
        if let Some(filter) = server_filter {
            if rec.server_name.as_deref() != Some(filter) {
                continue;
            }
        }
        if let Some(ref srv) = rec.server_name {
            servers_seen.insert(srv.clone());
            if let Some(ref fp) = rec.schema_fingerprint {
                observed_schemas_by_server
                    .entry(srv.clone())
                    .or_default()
                    .insert(fp.clone());
            }
        }
        tools_seen.insert(rec.tool.clone());
        if let Some(ref rule) = rec.rule_id {
            *rule_triggers.entry(rule.clone()).or_insert(0) += 1;
        }
        match rec.outcome.as_deref().unwrap_or(rec.verdict.as_str()) {
            "would_allow" => would_allow_count += 1,
            "would_deny" => would_deny_count += 1,
            "would_require_approval" => would_require_approval_count += 1,
            "would_quarantine" => would_quarantine_count += 1,
            "deny" | "quarantine" => enforced_deny_count += 1,
            "evaluation_error" => evaluation_error_count += 1,
            _ => {}
        }
    }

    let mut unknown_coverage_servers = Vec::new();
    let mut unpinned_servers = Vec::new();
    let mut schema_drift_servers = Vec::new();
    for srv in &discovered {
        if let Some(filter) = server_filter {
            if srv.name != filter {
                continue;
            }
        }
        let full_cmd = format!(
            "{} {}",
            srv.command.clone().unwrap_or_default(),
            srv.args.join(" ")
        );
        let wrapped = full_cmd.contains("arc protect") || srv.name == "vexa-arc";
        if !wrapped && installed_hosts.is_empty() {
            unknown_coverage_servers.push(srv.name.clone());
        }
        let pinned = policy.mcp_schema_pins.contains_key(&srv.name)
            || load_mcp_pin_from_lockfile(&lockfile_path, &srv.name).is_some()
            || srv.schema_hash.is_some();
        if !pinned {
            unpinned_servers.push(srv.name.clone());
        }
    }

    for (srv, hashes) in &observed_schemas_by_server {
        if hashes.len() > 1 {
            schema_drift_servers.push(serde_json::json!({
                "server_name": srv,
                "observed_schema_fingerprints": hashes,
                "review_required": true,
                "reason": "Multiple schema fingerprints observed for server; review schema diff before pinning or enforcing."
            }));
        }
    }

    let mut remediation_steps = Vec::new();
    for rule in rule_triggers.keys() {
        match rule.as_str() {
            "ARC-MCP-001" => remediation_steps.push(
                "Add approved MCP server to .arc/policy.json `allowed_mcp_servers` or grant a scoped exception with `arc allow --rule ARC-MCP-001 --server <server> --target <tool> --ttl-hours 168`.".to_string()
            ),
            "ARC-MCP-003" => remediation_steps.push(
                "Pin the verified MCP tool schema hash in `.arc/mcp-pins.lock` or signed organization policy (`--pin-schema <sha256>`).".to_string()
            ),
            "ARC-LTT-001" => remediation_steps.push(
                "Separate untrusted ingestion from private-credential sessions, or require human approval (`require_approval_for_trifecta: true`).".to_string()
            ),
            other => remediation_steps.push(format!(
                "Review rule '{other}' triggers and scope exceptions with `arc allow --rule {other} --target <tool>` if authorized."
            )),
        }
    }
    if !unpinned_servers.is_empty() {
        remediation_steps.push(format!(
            "Pin unpinned MCP servers {:?} before transitioning from observe to enforce.",
            unpinned_servers
        ));
    }
    if !unknown_coverage_servers.is_empty() {
        remediation_steps.push(format!(
            "Install host hooks (`arc init`) or wrap servers {:?} with `arc protect stdio` to eliminate unknown coverage.",
            unknown_coverage_servers
        ));
    }

    let verdict_notice = "Absence of observed policy blocks does NOT mean unmonitored or unpinned MCP servers are safe. Only mediated calls in configured hooks/brokers are observed.";

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policy_mode": policy.mode.as_str(),
                "policy_source": policy.source.unwrap_or(PolicySource::BuiltInDefault),
                "policy_revision": policy.revision_hash(),
                "stage_transition_applied": stage_transition,
                "total_observed_events": records.len(),
                "servers_seen": servers_seen,
                "tools_seen": tools_seen,
                "preview_outcomes": {
                    "would_allow": would_allow_count,
                    "would_deny": would_deny_count,
                    "would_require_approval": would_require_approval_count,
                    "would_quarantine": would_quarantine_count,
                },
                "enforced_outcomes": {
                    "denied_or_quarantined": enforced_deny_count,
                    "evaluation_errors": evaluation_error_count,
                },
                "rule_triggers": rule_triggers,
                "unknown_coverage_servers": unknown_coverage_servers,
                "unpinned_servers": unpinned_servers,
                "schema_changes_requiring_review": schema_drift_servers,
                "remediation_steps": remediation_steps,
                "verdict_notice": verdict_notice,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("\n┌──────────────────────────────────────────────────────────────┐");
        println!("│             VEXA ARC — MCP SAFE ROLLOUT REPORT               │");
        println!("└──────────────────────────────────────────────────────────────┘");
        println!(
            "Policy Mode:        {} (rev: {:.12})",
            policy.mode.as_str(),
            policy.revision_hash()
        );
        if let Some(st) = stage_transition {
            println!("Stage Transition:   Applied -> {st}");
        }
        println!("Observed Events:    {}", records.len());
        println!("Servers Seen:       {:?}", servers_seen);
        println!("Tools Seen:         {:?}", tools_seen);
        println!(
            "Preview Impact:     would_allow={} | would_deny={} | would_require_approval={} | would_quarantine={}",
            would_allow_count, would_deny_count, would_require_approval_count, would_quarantine_count
        );
        println!("Rule Triggers:      {:?}", rule_triggers);
        println!("Unknown Coverage:   {:?}", unknown_coverage_servers);
        println!("Unpinned Servers:   {:?}", unpinned_servers);
        if !remediation_steps.is_empty() {
            println!("\nRecommended Actions Before Enforcing:");
            for (idx, step) in remediation_steps.iter().enumerate() {
                println!("  {}. {}", idx + 1, step);
            }
        }
        println!("\nNotice: {verdict_notice}");
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTestSummary {
    pub all_passed: bool,
    pub fixture_count: usize,
    pub failed_fixtures: Vec<String>,
    pub policy_revision: String,
}

/// Evaluates the 10 deterministic checked-in policy & MCP rollout fixtures and returns structured results.
pub fn evaluate_policy_tests(
    path: &Path,
) -> (PolicyTestSummary, Vec<(&'static str, bool, &'static str)>) {
    let active_policy = PolicyConfig::load_with_precedence(Some(path));
    let policy_revision = active_policy.revision_hash();
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

    let mut fixtures = Vec::new();

    // Fixture 1: allowed_call
    let f1 = {
        let cfg = PolicyConfig {
            block_unapproved_mcp: true,
            ..Default::default()
        };
        let ev = PolicyEvaluator::new(cfg.clone());
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-1",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "github".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "list_issues".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let obs = ev.evaluate_with_observation(&event);
        let mut broker =
            McpStdioBroker::new("github", "fix-1", PolicyEvaluator::new(cfg)).allow_schema_tofu();
        let broker_out = broker.handle_client_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}"#,
        );
        obs.outcome == PolicyOutcomeKind::Allow
            && matches!(broker_out, ClientMessageOutcome::Forward(_))
    };
    fixtures.push(("allowed_call", f1, "allow"));

    // Fixture 2: denied_call
    let f2 = {
        let cfg = PolicyConfig {
            block_unapproved_mcp: true,
            ..Default::default()
        };
        let ev = PolicyEvaluator::new(cfg.clone());
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-2",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "unapproved-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "exec".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let obs = ev.evaluate_with_observation(&event);
        let mut broker = McpStdioBroker::new("unapproved-mcp", "fix-2", PolicyEvaluator::new(cfg))
            .allow_schema_tofu();
        let broker_out = broker.handle_client_message(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{}}}"#,
        );
        obs.outcome == PolicyOutcomeKind::Deny
            && matches!(broker_out, ClientMessageOutcome::RespondLocally(_))
    };
    fixtures.push(("denied_call", f2, "deny"));

    // Fixture 3: approval_required_call
    let f3 = {
        let mut cfg = PolicyConfig {
            block_unapproved_mcp: true,
            ..Default::default()
        };
        cfg.require_approval_servers
            .insert("staging-db".to_string());
        let ev = PolicyEvaluator::new(cfg);
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-3",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "staging-db".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "run_migration".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let obs = ev.evaluate_with_observation(&event);
        obs.outcome == PolicyOutcomeKind::RequireApproval
            && matches!(obs.hypothetical_verdict, Verdict::RequireApproval { .. })
    };
    fixtures.push(("approval_required_call", f3, "require_approval"));

    // Fixture 4: sensitive_argument_dlp
    let f4 = {
        let cfg = PolicyConfig {
            redact_secrets: true,
            ..Default::default()
        };
        let ev = PolicyEvaluator::new(cfg.clone());
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-4",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "github".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "create_comment".to_string(),
                arguments: serde_json::json!({"text": concat!("key ", "AKIA", "IOSFODNN7EXAMPLE")}),
            },
        );
        let obs = ev.evaluate_with_observation(&event);
        let mut broker =
            McpStdioBroker::new("github", "fix-4", PolicyEvaluator::new(cfg)).allow_schema_tofu();
        let fake_aws = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let raw_msg = format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"create_comment","arguments":{{"text":"key {fake_aws}"}}}}}}"#
        );
        let broker_out = broker.handle_client_message(&raw_msg);
        let redacted_ok = match broker_out {
            ClientMessageOutcome::Forward(s) => !s.contains(fake_aws),
            _ => false,
        };
        obs.outcome == PolicyOutcomeKind::RedactOrTransform && redacted_ok
    };
    fixtures.push(("sensitive_argument_dlp", f4, "redact_or_transform"));

    // Fixture 5: changed_schema_rug_pull
    let f5 = {
        let mut broker =
            McpStdioBroker::new("github", "fix-5", PolicyEvaluator::default()).allow_schema_tofu();
        let s1 = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"Search repos"}]}}"#;
        let call1 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{}}}"#;
        let s2 = r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"search","description":"Changed schema mid-session"}]}}"#;
        let call2 = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search","arguments":{}}}"#;
        let out1 = broker.handle_server_message(s1);
        let c1 = broker.handle_client_message(call1);
        let out2 = broker.handle_server_message(s2);
        let c2 = broker.handle_client_message(call2);
        matches!(out1, ServerMessageOutcome::CapturedSchema { .. })
            && matches!(c1, ClientMessageOutcome::Forward(_))
            && matches!(out2, ServerMessageOutcome::CapturedSchema { .. })
            && matches!(c2, ClientMessageOutcome::RespondLocally(ref v) if v.to_string().contains("ARC-RUG-001"))
    };
    fixtures.push(("changed_schema_rug_pull", f5, "quarantine"));

    // Fixture 6: unpinned_server_block
    let f6 = {
        let mut broker = McpStdioBroker::new("unpinned-srv", "fix-6", PolicyEvaluator::default())
            .require_schema_pin();
        let out = broker.handle_client_message(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ping","arguments":{}}}"#,
        );
        matches!(out, ClientMessageOutcome::RespondLocally(ref v) if v.to_string().contains("ARC-MCP-003"))
    };
    fixtures.push(("unpinned_server_block", f6, "deny"));

    // Fixture 7: malformed_jsonrpc_rejection
    let f7 = {
        let mut broker =
            McpStdioBroker::new("github", "fix-7", PolicyEvaluator::default()).allow_schema_tofu();
        let out = broker.handle_client_message("{malformed_jsonrpc");
        matches!(out, ClientMessageOutcome::ProtocolError(_))
    };
    fixtures.push(("malformed_jsonrpc_rejection", f7, "protocol_error"));

    // Fixture 8: oversized_payload_rejection
    let f8 = {
        let mut broker =
            McpStdioBroker::new("github", "fix-8", PolicyEvaluator::default()).with_max_payload(64);
        let oversized = "x".repeat(128);
        let out = broker.handle_client_message(&oversized);
        matches!(out, ClientMessageOutcome::ProtocolError(_))
    };
    fixtures.push(("oversized_payload_rejection", f8, "protocol_error"));

    // Fixture 9: evaluator_error_fail_closed
    let f9 = {
        let ev = PolicyEvaluator::default();
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-9",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "github".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "list_issues".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        let obs = ev.evaluate_with_mode_override(
            &event,
            None,
            Some("simulated session storage lock failure".to_string()),
        );
        obs.outcome == PolicyOutcomeKind::EvaluationError && obs.effective_verdict.is_denied()
    };
    fixtures.push(("evaluator_error_fail_closed", f9, "evaluation_error"));

    // Fixture 10: policy_conflict_signed_org_vs_local_exception
    let f10 = {
        let mut local = PolicyConfig {
            source: Some(PolicySource::ProjectLocal),
            active_exceptions: vec![PolicyException {
                id: "local-override".to_string(),
                rule_id: Some("ARC-MCP-001".to_string()),
                target: Some("*".to_string()),
                source: Some(PolicySource::ProjectLocal),
                granted_by: "dev".to_string(),
                created_at_unix_ms: now_ms,
                expires_at_unix_ms: now_ms + 60_000,
                reason: "local override".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let signed_org = PolicyConfig {
            source: Some(PolicySource::SignedOrganization),
            block_unapproved_mcp: true,
            allowed_mcp_servers: HashSet::from(["github".to_string()]),
            ..Default::default()
        };
        local.merge_lower_precedence(signed_org);
        let ev = PolicyEvaluator::new(local);
        let event = ActionEvent::new(
            AgentHost::ClaudeCode,
            "fix-10",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: "rogue-mcp".to_string(),
                    artifact: Artifact::Unknown,
                    schema_root: None,
                },
                tool: "dump".to_string(),
                arguments: serde_json::json!({}),
            },
        );
        ev.evaluate(&event).is_denied()
    };
    fixtures.push(("policy_conflict_signed_org_vs_local_exception", f10, "deny"));

    let all_passed = fixtures.iter().all(|(_, passed, _)| *passed);
    let failed_fixtures: Vec<String> = fixtures
        .iter()
        .filter(|(_, passed, _)| !*passed)
        .map(|(name, _, _)| (*name).to_string())
        .collect();
    let summary = PolicyTestSummary {
        all_passed,
        fixture_count: fixtures.len(),
        failed_fixtures,
        policy_revision,
    };
    (summary, fixtures)
}

/// Runs the 10 deterministic checked-in policy & MCP rollout fixtures across PolicyEvaluator and McpStdioBroker.
pub fn run_policy_test(path: &Path, json: bool) -> bool {
    let (summary, fixtures) = evaluate_policy_tests(path);
    let all_passed = summary.all_passed;
    let policy_revision = summary.policy_revision;

    if json {
        let list: Vec<serde_json::Value> = fixtures
            .iter()
            .map(|(name, passed, expected_outcome)| {
                serde_json::json!({
                    "fixture": name,
                    "passed": passed,
                    "expected_outcome": expected_outcome,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "all_passed": all_passed,
                "fixture_count": fixtures.len(),
                "policy_revision": policy_revision,
                "fixtures": list,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "\n[Arc Policy Test] Running {} deterministic policy & broker fixtures (policy_rev: {:.12})",
            fixtures.len(),
            policy_revision
        );
        for (name, passed, expected) in &fixtures {
            let icon = if *passed { "✔ PASS" } else { "✘ FAIL" };
            println!("  {icon}  {name:<48} (expected: {expected})");
        }
    }

    all_passed
}

/// Phase 3 Item 4: Simulates the active policy against captured session audit metadata ONLY.
/// Never replays real tool calls or executes MCP server commands.
pub fn run_policy_simulate(path: &Path, session_dir: Option<&Path>, json: bool) -> bool {
    let policy = PolicyConfig::load_with_precedence(Some(path));
    let evaluator = PolicyEvaluator::new(policy.clone());
    let records = collect_all_audit_records(path, session_dir);

    let mut simulated = Vec::new();
    let mut would_allow = 0usize;
    let mut would_deny = 0usize;
    let mut would_require_approval = 0usize;

    for rec in &records {
        let server_name = rec
            .server_name
            .clone()
            .unwrap_or_else(|| "unknown-mcp".to_string());
        let schema_root = rec
            .schema_fingerprint
            .as_deref()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| b.try_into().ok());

        let synthetic_event = ActionEvent::new(
            AgentHost::CustomMcpClient,
            "policy-simulation",
            OsPrincipal::Uid(1000),
            Phase::Pre,
            Action::McpToolCall {
                server: ServerIdentity {
                    config_name: server_name.clone(),
                    artifact: Artifact::Unknown,
                    schema_root,
                },
                tool: rec.tool.clone(),
                arguments: serde_json::json!({}),
            },
        );
        let obs = evaluator.evaluate_with_mode_override(
            &synthetic_event,
            Some(PolicyMode::Observe),
            None,
        );
        match obs.outcome {
            PolicyOutcomeKind::WouldAllow => would_allow += 1,
            PolicyOutcomeKind::WouldDeny | PolicyOutcomeKind::WouldQuarantine => would_deny += 1,
            PolicyOutcomeKind::WouldRequireApproval => would_require_approval += 1,
            _ => {}
        }
        simulated.push(serde_json::json!({
            "event_id": rec.event_id,
            "server_name": server_name,
            "tool": rec.tool,
            "previous_outcome": rec.outcome.as_deref().unwrap_or(rec.verdict.as_str()),
            "simulated_outcome": obs.outcome.as_str(),
        }));
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "simulation_mode": "metadata_only_no_tool_execution",
                "policy_revision": policy.revision_hash(),
                "events_simulated": simulated.len(),
                "would_allow": would_allow,
                "would_deny": would_deny,
                "would_require_approval": would_require_approval,
                "results": simulated,
            }))
            .unwrap_or_default()
        );
    } else {
        println!(
            "[Arc Policy Simulate] Metadata-only simulation complete ({} captured events, 0 tool executions, rev {:.12})",
            simulated.len(),
            policy.revision_hash()
        );
        println!(
            "  would_allow={} | would_deny={} | would_require_approval={}",
            would_allow, would_deny, would_require_approval
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_policy_fixtures_pass_deterministically() {
        let temp_dir =
            std::env::temp_dir().join(format!("arc_policy_fixtures_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        assert!(run_policy_test(&temp_dir, true));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
