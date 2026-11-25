use crate::commands::rollout::{evaluate_policy_tests, PolicyTestSummary};
use arc_discover::scanner::DiscoveryScanner;
use arc_dlp::detector::SecretScanEngine;
use arc_dlp::sanitizer::sanitize_inbound_text;
use arc_firewall::remediation::{run_sca_audit, ScaAuditOptions, ScaAuditResult};
use arc_hooks::broker::load_mcp_pin_from_lockfile;
use arc_telemetry::VexaCloudAuth;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeAnomaly {
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSummary {
    pub file_path: String,
    pub detector: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CiReport {
    pub path: String,
    pub secrets: Vec<SecretSummary>,
    pub unicode_anomalies: Vec<UnicodeAnomaly>,
    pub mcp_servers_total: usize,
    pub unpinned_mcp_servers: Vec<String>,
    pub agent_skills_count: usize,
    pub sca: Option<ScaAuditResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_test: Option<PolicyTestSummary>,
    pub checks_enforced: Vec<String>,
    pub advisory_warnings: Vec<String>,
    pub passed: bool,
    pub failure_reasons: Vec<String>,
    #[serde(skip_serializing)]
    pub audit_report: Option<Box<arc_discover::scanner::AuditReport>>,
}

fn collect_repo_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 10 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if matches!(
            name,
            ".git" | "target" | "node_modules" | ".venv" | "venv" | ".sca-cache"
        ) {
            continue;
        }
        if path.is_dir() {
            collect_repo_files(&path, depth + 1, out);
        } else if path.is_file() {
            let lower = name.to_ascii_lowercase();
            let is_generated_report = matches!(
                lower.as_str(),
                "sbom-cyclonedx.json"
                    | "sca-report.html"
                    | "sca-report.json"
                    | "sca-report.sarif"
                    | "ai-bom.json"
                    | "vexa-ai-bom.json"
            );
            if !is_generated_report {
                out.push(path);
            }
        }
    }
}

fn is_agent_instruction_file(path: &Path) -> bool {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "claude.md"
            | ".cursorrules"
            | ".windsurfrules"
            | "copilot-instructions.md"
            | "agent.md"
            | "agents.md"
            | "skill.md"
    ) || lower.ends_with(".mdc")
        || lower.ends_with(".prompt.md")
}

#[cfg(test)]
pub fn generate_ci_report(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
    fail_on_unpinned_mcp: bool,
) -> Result<CiReport, String> {
    generate_ci_report_with_options(
        path,
        run_sca,
        fail_on,
        fail_on_secrets,
        fail_on_unpinned_mcp,
        false,
    )
}

pub fn generate_ci_report_with_options(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
    fail_on_unpinned_mcp: bool,
    run_policy_test: bool,
) -> Result<CiReport, String> {
    if !path.exists() || !path.is_dir() {
        return Err(format!(
            "Target directory does not exist: {}",
            path.display()
        ));
    }

    let scanner = DiscoveryScanner::new();
    let audit = scanner
        .audit_directory(path)
        .map_err(|e| format!("Discovery audit failed: {e}"))?;

    let lockfile_path = path.join(".arc").join("mcp-pins.lock");
    let mut unpinned_mcp_servers = Vec::new();
    for srv in &audit.mcp_servers {
        let pinned_in_lock = load_mcp_pin_from_lockfile(&lockfile_path, &srv.name).is_some();
        if srv.schema_hash.is_none() && !pinned_in_lock {
            unpinned_mcp_servers.push(srv.name.clone());
        }
    }

    let mut files = Vec::new();
    collect_repo_files(path, 0, &mut files);

    let secret_engine = SecretScanEngine::new();
    let mut secrets = Vec::new();
    let mut unicode_anomalies = Vec::new();

    for file in &files {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        if bytes.len() > 2 * 1024 * 1024 {
            continue;
        }
        let rel = file
            .strip_prefix(path)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");

        for f in secret_engine.scan(&bytes) {
            secrets.push(SecretSummary {
                file_path: rel.clone(),
                detector: f.detector.to_string(),
                snippet: f.snippet,
            });
        }

        if is_agent_instruction_file(file) {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if sanitize_inbound_text(text) != text {
                    unicode_anomalies.push(UnicodeAnomaly { file_path: rel });
                }
            }
        }
    }

    let sca = if run_sca {
        let opts = ScaAuditOptions {
            dev: true,
            reachable_only: false,
            allow_unavailable: true,
            sarif_out: None,
            sanitize_locations: false,
            fail_on: fail_on.map(|s| s.to_string()),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;
        rt.block_on(run_sca_audit(path, &opts)).ok()
    } else {
        None
    };

    let policy_test = if run_policy_test {
        let (summary, _) = evaluate_policy_tests(path);
        Some(summary)
    } else {
        None
    };

    let mut checks_enforced = vec!["unicode_anomalies".to_string()];
    if fail_on_secrets {
        checks_enforced.push("secrets".to_string());
    }
    if fail_on_unpinned_mcp {
        checks_enforced.push("unpinned_mcp_servers".to_string());
    }
    if run_sca {
        checks_enforced.push(format!("sca(fail_on={})", fail_on.unwrap_or("high")));
    }
    if run_policy_test {
        checks_enforced.push("policy_fixtures".to_string());
    }

    let mut failure_reasons = Vec::new();
    let mut advisory_warnings = Vec::new();
    if fail_on_secrets && !secrets.is_empty() {
        failure_reasons.push(format!("Detected {} leaked secret(s)", secrets.len()));
    } else if !secrets.is_empty() {
        advisory_warnings.push(format!(
            "Detected {} leaked secret(s) (not gated: --fail-on-secrets=false)",
            secrets.len()
        ));
    }
    if !unicode_anomalies.is_empty() {
        failure_reasons.push(format!(
            "Detected hidden/Trojan-Source Unicode in {} agent instruction file(s)",
            unicode_anomalies.len()
        ));
    }
    if !unpinned_mcp_servers.is_empty() {
        if fail_on_unpinned_mcp {
            failure_reasons.push(format!(
                "Detected {} unpinned MCP server(s): {}",
                unpinned_mcp_servers.len(),
                unpinned_mcp_servers.join(", ")
            ));
        } else {
            advisory_warnings.push(format!(
                "{} unpinned MCP server(s) detected (advisory only; pass --fail-on-unpinned-mcp to gate): {}",
                unpinned_mcp_servers.len(),
                unpinned_mcp_servers.join(", ")
            ));
        }
    }
    if let Some(ref sca_res) = sca {
        if sca_res.should_fail {
            failure_reasons.push(
                sca_res
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| "SCA threshold exceeded".to_string()),
            );
        }
    }
    if let Some(ref pt) = policy_test {
        if !pt.all_passed {
            failure_reasons.push(format!(
                "Policy fixture verification failed ({} of {} failed): {}",
                pt.failed_fixtures.len(),
                pt.fixture_count,
                pt.failed_fixtures.join(", ")
            ));
        }
    }

    let passed = failure_reasons.is_empty();

    Ok(CiReport {
        path: path.display().to_string(),
        secrets,
        unicode_anomalies,
        mcp_servers_total: audit.mcp_servers.len(),
        unpinned_mcp_servers,
        agent_skills_count: audit.agent_skills.len(),
        sca,
        policy_test,
        checks_enforced,
        advisory_warnings,
        passed,
        failure_reasons,
        audit_report: Some(Box::new(audit)),
    })
}

/// Builds a Zero-Code-Retention `VexaFactsPayload` JSON object compatible with `vexa-sca-cloud` (`POST /v1/facts/sync`).
pub fn build_vexa_facts_payload(path: &Path, report: &CiReport) -> serde_json::Value {
    let project_name = std::env::var("VEXA_PROJECT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REPOSITORY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            path.canonicalize()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        })
        .unwrap_or_else(|| "workspace".to_string());

    let mut code_findings = Vec::new();

    for s in &report.secrets {
        let masked_sink: String = s.snippet.chars().take(64).collect();
        code_findings.push(serde_json::json!({
            "rule_id": s.detector,
            "category": "SECRET",
            "severity": "CRITICAL",
            "title": format!("Exposed credential detected ({})", s.detector),
            "cwe": "CWE-798",
            "file_path": s.file_path,
            "line": 1,
            "matched_sink": masked_sink,
            "remediation": "Revoke this credential immediately and load secrets from environment variables or a secret manager."
        }));
    }

    for u in &report.unicode_anomalies {
        code_findings.push(serde_json::json!({
            "rule_id": "ARC-UNI-001",
            "category": "SUPPLY_CHAIN",
            "severity": "CRITICAL",
            "title": "Hidden Trojan-Source / Prompt-Injection Unicode in Agent Instruction File",
            "cwe": "CWE-1036",
            "file_path": u.file_path,
            "line": 1,
            "matched_sink": "hidden_bidi_or_zero_width_unicode",
            "remediation": "Strip invisible zero-width and bidirectional override characters from agent rule and skill files."
        }));
    }

    for srv in &report.unpinned_mcp_servers {
        let sink: String = srv.chars().take(64).collect();
        code_findings.push(serde_json::json!({
            "rule_id": "ARC-MCP-001",
            "category": "SUPPLY_CHAIN",
            "severity": "HIGH",
            "title": format!("Unpinned MCP Server '{}' (missing .arc/mcp-pins.lock entry)", srv),
            "cwe": "CWE-829",
            "file_path": ".arc/mcp-pins.lock",
            "line": 1,
            "matched_sink": sink,
            "remediation": "Pin the MCP server schema hash in .arc/mcp-pins.lock via `arc protect`."
        }));
    }

    let (total_vulns, reachable_vulns, ecosystem) = match &report.sca {
        Some(sca) => (
            sca.total_vulnerabilities,
            sca.reachable_count,
            sca.manifest_type.clone(),
        ),
        None => (0, 0, "AI-Workspace".to_string()),
    };

    let branch = std::env::var("GITHUB_HEAD_REF")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REF_NAME")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "main".to_string());

    let commit_sha = std::env::var("GITHUB_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty());

    serde_json::json!({
        "version": 2,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "project_name": project_name,
        "project_version": "1.0.0",
        "ecosystem": ecosystem,
        "total_packages": 0,
        "direct_dependencies": 0,
        "transitive_dependencies": 0,
        "packages": [],
        "reachable_vulnerabilities": reachable_vulns,
        "unreachable_vulnerabilities": 0,
        "unknown_reachability_vulnerabilities": total_vulns.saturating_sub(reachable_vulns),
        "total_vulnerabilities": total_vulns,
        "findings": [],
        "code_findings": code_findings,
        "components": [
            {
                "id": "vexa-arc-engine",
                "name": "Vexa Arc AI & Secret Security Engine",
                "status": "COMPLETED",
                "findings_count": code_findings.len()
            }
        ],
        "branch": branch,
        "commit_sha": commit_sha,
    })
}

/// Builds a zero-code-retention AI-BOM inventory payload for `POST /arc/inventory`
/// directly from an `AuditReport` (used by `arc audit`, `arc setup`, and `arc ci-report`).
pub fn build_arc_inventory_payload_from_audit(
    path: &Path,
    report: &arc_discover::scanner::AuditReport,
    is_workstation: bool,
    unicode_anomalies_count: usize,
) -> serde_json::Value {
    let source_type = if is_workstation {
        "workstation"
    } else {
        "repo"
    };

    let source_name = if is_workstation {
        let actor = arc_telemetry::sanitize_cloud_actor(&VexaCloudAuth::current_actor());
        format!("workstation:{actor}")
    } else {
        std::env::var("VEXA_PROJECT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("GITHUB_REPOSITORY")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
            .or_else(|| {
                path.canonicalize()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            })
            .unwrap_or_else(|| "workspace".to_string())
    };

    let lockfile_path = path.join(".arc").join("mcp-pins.lock");
    let mut seen_mcp = std::collections::HashSet::new();
    let mut mcp_servers = Vec::new();
    let mut unpinned_mcp_count = 0usize;

    for srv in &report.mcp_servers {
        let key = (srv.name.clone(), srv.transport.clone());
        if !seen_mcp.insert(key) {
            continue;
        }
        let lock_pin = if !is_workstation {
            load_mcp_pin_from_lockfile(&lockfile_path, &srv.name)
        } else {
            None
        };
        let schema_hash = srv.schema_hash.clone().or(lock_pin);
        let pinned = schema_hash.is_some();
        if !pinned {
            unpinned_mcp_count += 1;
        }
        let mut entry = serde_json::json!({
            "name": srv.name,
            "transport": srv.transport,
            "risk_band": format!("{:?}", srv.profile.band).to_lowercase(),
            "risk_score": srv.profile.composite_risk_score,
            "pinned": pinned,
        });
        if let Some(hash) = schema_hash {
            entry["schema_hash"] = serde_json::Value::String(hash);
        }
        mcp_servers.push(entry);
    }

    let agent_skills: Vec<serde_json::Value> = report
        .agent_skills
        .iter()
        .map(|sk| {
            serde_json::json!({
                "name": sk.name,
                "content_hash": sk.content_hash,
                "line_count": sk.line_count,
            })
        })
        .collect();

    let model_assets: Vec<serde_json::Value> = report
        .model_assets
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "kind": m.kind,
                "size_bytes": m.size_bytes,
            })
        })
        .collect();

    let risk_band = if !report.exposed_secrets.is_empty() || unicode_anomalies_count > 0 {
        "CRITICAL"
    } else if unpinned_mcp_count > 0 {
        "HIGH"
    } else {
        match report.overall_risk_band {
            arc_core::mcp_profile::RiskBand::Critical => "CRITICAL",
            arc_core::mcp_profile::RiskBand::High => "HIGH",
            arc_core::mcp_profile::RiskBand::Medium => "MEDIUM",
            arc_core::mcp_profile::RiskBand::Low => "LOW",
        }
    };

    serde_json::json!({
        "source_type": source_type,
        "source_name": source_name,
        "install_id": arc_telemetry::install_id(),
        "overall_risk_band": risk_band,
        "mcp_servers": mcp_servers,
        "agent_skills": agent_skills,
        "model_assets": model_assets,
        "exposed_secrets_count": report.exposed_secrets.len(),
        "unicode_anomalies_count": unicode_anomalies_count,
        "unpinned_mcp_count": unpinned_mcp_count,
    })
}

pub fn build_arc_inventory_payload(path: &Path, report: &CiReport) -> serde_json::Value {
    if let Some(ref audit) = report.audit_report {
        let mut payload = build_arc_inventory_payload_from_audit(
            path,
            audit,
            false,
            report.unicode_anomalies.len(),
        );
        payload["exposed_secrets_count"] = serde_json::json!(report.secrets.len());
        payload["unpinned_mcp_count"] = serde_json::json!(report.unpinned_mcp_servers.len());
        let risk_band = if !report.secrets.is_empty() || !report.unicode_anomalies.is_empty() {
            "CRITICAL"
        } else if !report.unpinned_mcp_servers.is_empty() {
            "HIGH"
        } else {
            "LOW"
        };
        payload["overall_risk_band"] = serde_json::json!(risk_band);
        return payload;
    }

    let project_name = std::env::var("VEXA_PROJECT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REPOSITORY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            path.canonicalize()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        })
        .unwrap_or_else(|| "workspace".to_string());

    let risk_band = if !report.secrets.is_empty() || !report.unicode_anomalies.is_empty() {
        "CRITICAL"
    } else if !report.unpinned_mcp_servers.is_empty() {
        "HIGH"
    } else {
        "LOW"
    };

    let mcp_servers: Vec<serde_json::Value> = report
        .unpinned_mcp_servers
        .iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "transport": "stdio",
            })
        })
        .collect();

    serde_json::json!({
        "source_type": "repo",
        "source_name": project_name,
        "install_id": arc_telemetry::install_id(),
        "overall_risk_band": risk_band,
        "mcp_servers": mcp_servers,
        "agent_skills": [],
        "model_assets": [],
        "exposed_secrets_count": report.secrets.len(),
        "unicode_anomalies_count": report.unicode_anomalies.len(),
        "unpinned_mcp_count": report.unpinned_mcp_servers.len(),
    })
}

pub fn upload_ci_report_to_cloud(
    path: &Path,
    report: &CiReport,
    api_url: Option<&str>,
) -> Result<String, String> {
    if VexaCloudAuth::is_offline() {
        return Err("Cloud upload skipped: offline mode is active".to_string());
    }
    let token = VexaCloudAuth::get_token().ok_or_else(|| {
        "Authentication required for `--upload`. Run `arc auth login --token <vexa_pat_...>` or set `VEXA_TOKEN`.".to_string()
    })?;
    let base_url = VexaCloudAuth::resolve_api_base_url(api_url);

    // 1. Always upload Arc AI-workspace inventory to dedicated /arc/inventory
    let inv_payload = build_arc_inventory_payload(path, report);
    let inv_res = arc_telemetry::upload_arc_inventory(&inv_payload, api_url)?;
    let mut result_url = inv_res
        .get("snapshot_id")
        .and_then(|s| s.as_str())
        .map(|id| format!("{base_url}/arc/inventory/{id}"))
        .unwrap_or_else(|| base_url.clone());

    // 2. Only upload to SCA /facts/sync when actual SCA scan data is present
    if report.sca.is_some() {
        let sync_url = format!("{}/facts/sync", base_url.trim_end_matches('/'));
        let org_slug = VexaCloudAuth::get_org_slug();
        let payload = build_vexa_facts_payload(path, report);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;

        result_url = rt.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
            let mut req = client
                .post(&sync_url)
                .header("Authorization", format!("Bearer {}", token.trim()));
            if let Some(org) = org_slug {
                req = req.header("X-Vexa-Org", org);
            }
            let resp = req
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("Failed to connect to Vexa Cloud ({sync_url}): {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("Cloud upload failed ({status}): {text}"));
            }
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let dash = body
                .get("dashboard_url")
                .and_then(|d| d.as_str())
                .unwrap_or(&base_url);
            Ok(dash.to_string())
        })?;
    }

    Ok(result_url)
}

fn escape_md_cell(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "'")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(['\r', '\n'], " ")
}

pub fn render_markdown_report(report: &CiReport) -> String {
    let mut md = String::new();
    md.push_str("<!-- vexa-arc-pr-report -->\n");

    let secrets_gated = report.checks_enforced.iter().any(|c| c == "secrets");
    let mcp_gated = report
        .checks_enforced
        .iter()
        .any(|c| c == "unpinned_mcp_servers");

    let sec_crit = report.secrets.len();
    let uni_crit = report.unicode_anomalies.len();
    let mcp_high = report.unpinned_mcp_servers.len();

    let (sca_crit, sca_high, sca_med, sca_low, sca_total) = match &report.sca {
        Some(s) => (
            s.critical_count,
            s.high_count,
            s.medium_count,
            s.low_count,
            s.total_vulnerabilities,
        ),
        None => (0, 0, 0, 0, 0),
    };

    let (lic_high, lic_med, lic_low, lic_total, has_licenses) =
        match report.sca.as_ref().and_then(|s| s.licenses.as_ref()) {
            Some(l) => (
                l.strong_copyleft,
                l.weak_copyleft,
                l.unknown,
                l.strong_copyleft + l.weak_copyleft + l.unknown,
                true,
            ),
            None => (0, 0, 0, 0, false),
        };

    let policy_failed_count = report
        .policy_test
        .as_ref()
        .map(|p| p.failed_fixtures.len())
        .unwrap_or(0);

    let total_issues = sec_crit + uni_crit + mcp_high + sca_total + lic_total + policy_failed_count;

    if report.passed && total_issues == 0 {
        md.push_str("### ✅ Vexa Arc checks have passed. No issues have been found so far.\n\n");
    } else if report.passed {
        md.push_str(&format!(
            "### ✅ Vexa Arc checks have passed ({total_issues} advisory/ungated finding(s)).\n\n"
        ));
    } else {
        md.push_str(&format!(
            "### ❌ Vexa Arc checks failed ({total_issues} total issue(s) found).\n\n"
        ));
    }

    md.push_str(&format!(
        "| Status | Scan Engine | Critical | High | Medium | Low | Total ({total_issues}) |\n"
    ));
    md.push_str("| :---: | :--- | :---: | :---: | :---: | :---: | :---: |\n");

    let sec_status = if sec_crit > 0 && secrets_gated {
        "❌"
    } else if sec_crit > 0 {
        "⚠️"
    } else {
        "✅"
    };
    md.push_str(&format!(
        "| {sec_status} | **Secret Detection (DLP)** | {sec_crit} | 0 | 0 | 0 | {sec_crit} issues |\n"
    ));

    let uni_status = if uni_crit > 0 { "❌" } else { "✅" };
    md.push_str(&format!(
        "| {uni_status} | **Agent Prompt / Unicode Integrity** | {uni_crit} | 0 | 0 | 0 | {uni_crit} issues |\n"
    ));

    let mcp_status = if mcp_high > 0 && mcp_gated {
        "❌"
    } else if mcp_high > 0 {
        "⚠️"
    } else {
        "✅"
    };
    let mcp_total_cell = if report.mcp_servers_total > 0 {
        format!("{mcp_high} unpinned ({} total)", report.mcp_servers_total)
    } else {
        format!("{mcp_high} issues")
    };
    md.push_str(&format!(
        "| {mcp_status} | **MCP Supply Chain & Pinning** | 0 | {mcp_high} | 0 | 0 | {mcp_total_cell} |\n"
    ));

    if let Some(ref sca) = report.sca {
        let sca_status = if sca.should_fail {
            "❌"
        } else if sca_total > 0 {
            "⚠️"
        } else {
            "✅"
        };
        let sca_total_cell = if sca_total > 0 && sca.reachable_count > 0 {
            format!("{sca_total} issues ({} reachable)", sca.reachable_count)
        } else {
            format!("{sca_total} issues")
        };
        md.push_str(&format!(
            "| {sca_status} | **Open Source Security (SCA)** | {sca_crit} | {sca_high} | {sca_med} | {sca_low} | {sca_total_cell} |\n"
        ));
    } else {
        md.push_str("| ⏭️ | **Open Source Security (SCA)** | — | — | — | — | skipped |\n");
    }

    if has_licenses {
        let lic_status = if lic_total > 0 { "⚠️" } else { "✅" };
        md.push_str(&format!(
            "| {lic_status} | **Licenses** | 0 | {lic_high} | {lic_med} | {lic_low} | {lic_total} issues |\n"
        ));
    } else {
        md.push_str("| ⏭️ | **Licenses** | — | — | — | — | skipped |\n");
    }

    if let Some(ref pt) = report.policy_test {
        let pt_status = if pt.all_passed { "✅" } else { "❌" };
        let passed_count = pt.fixture_count.saturating_sub(policy_failed_count);
        md.push_str(&format!(
            "| {pt_status} | **Policy Fixtures** | 0 | {policy_failed_count} | 0 | 0 | {policy_failed_count} failed ({passed_count}/{} passed) |\n",
            pt.fixture_count
        ));
    } else {
        md.push_str("| ⏭️ | **Policy Fixtures** | — | — | — | — | skipped |\n");
    }

    md.push_str(&format!(
        "\n**Inventory:** {} MCP server(s) • {} agent rule/skill file(s) | **Enforced Gate Checks:** `{}`\n",
        report.mcp_servers_total,
        report.agent_skills_count,
        report.checks_enforced.join("`, `")
    ));

    if !report.secrets.is_empty() {
        md.push_str(&format!(
            "\n<details>\n<summary>🔑 <b>Secrets Detected ({} finding(s))</b></summary>\n\n",
            report.secrets.len()
        ));
        md.push_str("| Detector | File | Sanitized Match |\n| :--- | :--- | :--- |\n");
        for s in report.secrets.iter().take(20) {
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` |\n",
                escape_md_cell(&s.detector),
                escape_md_cell(&s.file_path),
                escape_md_cell(&s.snippet)
            ));
        }
        if report.secrets.len() > 20 {
            md.push_str(&format!(
                "\n*...and {} more secret finding(s).*\n",
                report.secrets.len() - 20
            ));
        }
        md.push_str("\n</details>\n");
    }

    if !report.unicode_anomalies.is_empty() {
        md.push_str(&format!(
            "\n<details>\n<summary>🧬 <b>Hidden Unicode / Trojan Source in Agent Rules ({} file(s))</b></summary>\n\n",
            report.unicode_anomalies.len()
        ));
        for u in report.unicode_anomalies.iter().take(20) {
            md.push_str(&format!(
                "- `{}` contains invisible or bidi-override characters\n",
                escape_md_cell(&u.file_path)
            ));
        }
        md.push_str("\n</details>\n");
    }

    if !report.unpinned_mcp_servers.is_empty() {
        let label = if mcp_gated { "Gated" } else { "Advisory" };
        md.push_str(&format!(
            "\n<details>\n<summary>🔌 <b>Unpinned MCP Servers ({label} — {} server(s))</b></summary>\n\n",
            report.unpinned_mcp_servers.len()
        ));
        let escaped: Vec<String> = report
            .unpinned_mcp_servers
            .iter()
            .map(|s| escape_md_cell(s))
            .collect();
        md.push_str(&format!(
            "- Servers without `.arc/mcp-pins.lock` entries: `{}`\n",
            escaped.join("`, `")
        ));
        md.push_str("\n</details>\n");
    }

    if let Some(ref pt) = report.policy_test {
        if !pt.failed_fixtures.is_empty() {
            md.push_str(&format!(
                "\n<details>\n<summary>🧪 <b>Failed Policy Fixtures ({} failed)</b></summary>\n\n",
                pt.failed_fixtures.len()
            ));
            for f in &pt.failed_fixtures {
                md.push_str(&format!("- `{}`\n", escape_md_cell(f)));
            }
            md.push_str("\n</details>\n");
        }
    }

    if !report.advisory_warnings.is_empty() {
        md.push_str("\n#### ⚠️ Advisory Warnings (Not Gated)\n");
        for w in &report.advisory_warnings {
            md.push_str(&format!("- {}\n", escape_md_cell(w)));
        }
    }
    if !report.failure_reasons.is_empty() {
        md.push_str("\n#### 🚦 Gate Failures\n");
        for r in &report.failure_reasons {
            md.push_str(&format!("- {}\n", escape_md_cell(r)));
        }
    }

    md.push_str("\n💻 Catch issues earlier locally with `npx @vexasec/arc init` (Claude Code, Cursor, GitHub Copilot, Codex CLI, Gemini CLI, Windsurf, Cline, Kiro, OpenCode).\n");
    md
}

#[allow(clippy::too_many_arguments)]
pub fn run_ci_report(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
    fail_on_unpinned_mcp: bool,
    run_policy_test: bool,
    markdown_out: Option<&Path>,
    json_out: Option<&Path>,
    json: bool,
    upload: bool,
    api_url: Option<&str>,
) -> bool {
    let report = match generate_ci_report_with_options(
        path,
        run_sca,
        fail_on,
        fail_on_secrets,
        fail_on_unpinned_mcp,
        run_policy_test,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[Arc CI] {e}");
            return false;
        }
    };

    let md = render_markdown_report(&report);
    if let Some(md_path) = markdown_out {
        if let Some(parent) = md_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(md_path, md.as_bytes()) {
            eprintln!("[Arc CI] Failed to write {}: {e}", md_path.display());
            return false;
        }
    }

    if let Some(j_path) = json_out {
        if let Some(parent) = j_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(parent);
        }
        let body = serde_json::to_string_pretty(&report).unwrap_or_default();
        if let Err(e) = std::fs::write(j_path, body.as_bytes()) {
            eprintln!("[Arc CI] Failed to write {}: {e}", j_path.display());
            return false;
        }
    }

    if upload {
        match upload_ci_report_to_cloud(path, &report, api_url) {
            Ok(dash_url) => {
                eprintln!("[Arc CI] Synced scan facts to Vexa Cloud: {dash_url}");
            }
            Err(e) => {
                eprintln!("[Arc CI] Warning: Cloud upload failed: {e}");
            }
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!("{md}");
    }

    report.passed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_report_passes_on_clean_dir_and_flags_secrets_and_unicode() {
        let dir = std::env::temp_dir().join(format!("arc_ci_report_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("README.md"), "clean repo\n").unwrap();

        let clean = generate_ci_report(&dir, false, None, true, false).unwrap();
        assert!(clean.passed);
        assert!(clean.secrets.is_empty());
        assert!(clean.unicode_anomalies.is_empty());
        assert!(clean.advisory_warnings.is_empty());

        let fake_aws = concat!("AKIA", "IOSFODNN7EXAMPLE");
        std::fs::write(dir.join(".env"), format!("AWS_KEY={fake_aws}\n")).unwrap();
        std::fs::write(
            dir.join(".cursorrules"),
            "Always follow rules\u{202E}hidden\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mcp.json"),
            r#"{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}}"#,
        )
        .unwrap();

        let dirty = generate_ci_report(&dir, false, None, true, false).unwrap();
        assert!(!dirty.passed);
        assert_eq!(dirty.secrets.len(), 1);
        assert_eq!(dirty.unicode_anomalies.len(), 1);
        assert_eq!(dirty.unpinned_mcp_servers, vec!["github".to_string()]);
        assert!(
            dirty
                .advisory_warnings
                .iter()
                .any(|w| w.contains("unpinned MCP")),
            "Advisory warning must explicitly call out unpinned MCP servers when not gated"
        );

        // Now test strict --fail-on-unpinned-mcp on a directory with ONLY an unpinned MCP server
        let _ = std::fs::remove_file(dir.join(".env"));
        let _ = std::fs::remove_file(dir.join(".cursorrules"));
        let gated_mcp = generate_ci_report(&dir, false, None, true, true).unwrap();
        assert!(!gated_mcp.passed);
        assert!(gated_mcp
            .checks_enforced
            .contains(&"unpinned_mcp_servers".to_string()));
        assert!(gated_mcp
            .failure_reasons
            .iter()
            .any(|r| r.contains("unpinned MCP server")));

        let md = render_markdown_report(&dirty);
        assert!(md.contains("<!-- vexa-arc-pr-report -->"));
        assert!(md.contains("SEC-AWS-001"));
        assert!(md.contains(".cursorrules"));

        let facts = build_vexa_facts_payload(&dir, &dirty);
        let code_findings = facts["code_findings"].as_array().unwrap();
        assert_eq!(code_findings.len(), 3);
        assert!(code_findings.iter().any(|f| f["category"] == "SECRET"));
        assert!(code_findings.iter().any(|f| f["rule_id"] == "ARC-UNI-001"));
        assert!(code_findings.iter().any(|f| f["rule_id"] == "ARC-MCP-001"));

        let inv = build_arc_inventory_payload(&dir, &dirty);
        assert_eq!(inv["source_type"], "repo");
        assert_eq!(inv["exposed_secrets_count"], 1);
        assert_eq!(inv["unicode_anomalies_count"], 1);
        assert_eq!(inv["unpinned_mcp_count"], 1);
        assert_eq!(inv["mcp_servers"].as_array().unwrap().len(), 1);
        assert_eq!(inv["mcp_servers"][0]["name"], "github");
        assert_eq!(inv["mcp_servers"][0]["pinned"], false);
        assert_eq!(inv["agent_skills"].as_array().unwrap().len(), 1);
        assert_eq!(inv["agent_skills"][0]["name"], ".cursorrules");
        // Zero-code-retention: never leak raw secret values or file paths
        let inv_str = inv.to_string();
        assert!(!inv_str.contains(fake_aws));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_markdown_report_emits_severity_matrix_policy_and_licenses() {
        let dir = std::env::temp_dir().join(format!("arc_ci_matrix_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("README.md"), "clean\n").unwrap();

        let mut report = generate_ci_report_with_options(&dir, false, None, true, false, true)
            .expect("generate clean report with policy tests");
        assert!(report.passed);
        assert!(report.policy_test.as_ref().unwrap().all_passed);

        let clean_md = render_markdown_report(&report);
        assert!(clean_md.contains("Vexa Arc checks have passed. No issues have been found so far."));
        assert!(clean_md
            .contains("| Status | Scan Engine | Critical | High | Medium | Low | Total (0) |"));
        assert!(clean_md
            .contains("| ✅ | **Policy Fixtures** | 0 | 0 | 0 | 0 | 0 failed (10/10 passed) |"));
        assert!(
            clean_md.contains("| ⏭️ | **Open Source Security (SCA)** | — | — | — | — | skipped |")
        );
        assert!(clean_md.contains("npx @vexasec/arc init"));

        // Attach SCA + License summary and ensure all 4 severities + licenses render
        report.sca = Some(arc_firewall::remediation::ScaAuditResult {
            project_dir: ".".to_string(),
            manifest_file: "Cargo.lock".to_string(),
            manifest_type: "CargoLock".to_string(),
            total_vulnerabilities: 4,
            reachable_count: 1,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            low_count: 1,
            licenses: Some(arc_firewall::remediation::ScaLicenseSummary {
                total: 5,
                permissive: 3,
                weak_copyleft: 1,
                strong_copyleft: 1,
                unknown: 0,
            }),
            sarif_path: None,
            should_fail: true,
            failure_reason: Some("SCA threshold exceeded".to_string()),
        });
        report.passed = false;
        let full_md = render_markdown_report(&report);
        assert!(full_md.contains(
            "| ❌ | **Open Source Security (SCA)** | 1 | 1 | 1 | 1 | 4 issues (1 reachable) |"
        ));
        assert!(full_md.contains("| ⚠️ | **Licenses** | 0 | 1 | 1 | 0 | 2 issues |"));
        assert!(full_md.contains("Total (6)"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
