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
    pub passed: bool,
    pub failure_reasons: Vec<String>,
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
            out.push(path);
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

pub fn generate_ci_report(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
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

    let mut failure_reasons = Vec::new();
    if fail_on_secrets && !secrets.is_empty() {
        failure_reasons.push(format!("Detected {} leaked secret(s)", secrets.len()));
    }
    if !unicode_anomalies.is_empty() {
        failure_reasons.push(format!(
            "Detected hidden/Trojan-Source Unicode in {} agent instruction file(s)",
            unicode_anomalies.len()
        ));
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

    let passed = failure_reasons.is_empty();

    Ok(CiReport {
        path: path.display().to_string(),
        secrets,
        unicode_anomalies,
        mcp_servers_total: audit.mcp_servers.len(),
        unpinned_mcp_servers,
        agent_skills_count: audit.agent_skills.len(),
        sca,
        passed,
        failure_reasons,
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
    let sync_url = format!("{}/facts/sync", base_url.trim_end_matches('/'));
    let org_slug = VexaCloudAuth::get_org_slug();
    let payload = build_vexa_facts_payload(path, report);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to initialize async runtime: {e}"))?;

    rt.block_on(async move {
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
    })
}

pub fn render_markdown_report(report: &CiReport) -> String {
    let status_badge = if report.passed {
        "✅ **PASSED**"
    } else {
        "❌ **FAILED**"
    };
    let mut md = String::new();
    md.push_str("<!-- vexa-arc-pr-report -->\n");
    md.push_str(&format!(
        "## 🛡️ Vexa Arc Security Report — {status_badge}\n\n"
    ));

    md.push_str("| Check | Result |\n| :--- | :--- |\n");
    md.push_str(&format!(
        "| **Leaked Secrets** | {} finding(s) |\n",
        report.secrets.len()
    ));
    md.push_str(&format!(
        "| **Hidden Unicode / Injection** | {} file(s) |\n",
        report.unicode_anomalies.len()
    ));
    md.push_str(&format!(
        "| **MCP Servers** | {} discovered ({} unpinned) |\n",
        report.mcp_servers_total,
        report.unpinned_mcp_servers.len()
    ));
    md.push_str(&format!(
        "| **Agent Rules / Skills** | {} file(s) |\n",
        report.agent_skills_count
    ));

    if let Some(ref sca) = report.sca {
        md.push_str(&format!(
            "| **Dependencies (SCA)** | {} total ({} critical, {} high, {} reachable) |\n",
            sca.total_vulnerabilities, sca.critical_count, sca.high_count, sca.reachable_count
        ));
    } else {
        md.push_str("| **Dependencies (SCA)** | skipped / no supported manifest |\n");
    }

    if !report.secrets.is_empty() {
        md.push_str("\n### Secrets Detected\n");
        for s in report.secrets.iter().take(15) {
            md.push_str(&format!(
                "- `{}` in `{}` (`{}`)\n",
                s.detector, s.file_path, s.snippet
            ));
        }
    }

    if !report.unicode_anomalies.is_empty() {
        md.push_str("\n### Hidden Unicode / Trojan Source in Agent Rules\n");
        for u in &report.unicode_anomalies {
            md.push_str(&format!(
                "- `{}` contains invisible or bidi-override characters\n",
                u.file_path
            ));
        }
    }

    if !report.unpinned_mcp_servers.is_empty() {
        md.push_str("\n### Unpinned MCP Servers (Advisory)\n");
        md.push_str(&format!(
            "- Servers without `.arc/mcp-pins.lock` entries: `{}`\n",
            report.unpinned_mcp_servers.join("`, `")
        ));
    }

    if !report.failure_reasons.is_empty() {
        md.push_str("\n### Gate Failures\n");
        for r in &report.failure_reasons {
            md.push_str(&format!("- {r}\n"));
        }
    }

    md.push_str("\n<sub>Generated by Vexa Arc (`arc ci-report`)</sub>\n");
    md
}

#[allow(clippy::too_many_arguments)]
pub fn run_ci_report(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
    markdown_out: Option<&Path>,
    json_out: Option<&Path>,
    json: bool,
    upload: bool,
    api_url: Option<&str>,
) -> bool {
    let report = match generate_ci_report(path, run_sca, fail_on, fail_on_secrets) {
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

        let clean = generate_ci_report(&dir, false, None, true).unwrap();
        assert!(clean.passed);
        assert!(clean.secrets.is_empty());
        assert!(clean.unicode_anomalies.is_empty());

        std::fs::write(dir.join(".env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
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

        let dirty = generate_ci_report(&dir, false, None, true).unwrap();
        assert!(!dirty.passed);
        assert_eq!(dirty.secrets.len(), 1);
        assert_eq!(dirty.unicode_anomalies.len(), 1);
        assert_eq!(dirty.unpinned_mcp_servers, vec!["github".to_string()]);

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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
