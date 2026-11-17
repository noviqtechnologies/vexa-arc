use arc_discover::scanner::DiscoveryScanner;
use arc_dlp::detector::SecretScanEngine;
use arc_dlp::sanitizer::sanitize_inbound_text;
use arc_firewall::remediation::{run_sca_audit, ScaAuditOptions, ScaAuditResult};
use arc_hooks::broker::load_mcp_pin_from_lockfile;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct UnicodeAnomaly {
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize)]
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
        "claude.md" | ".cursorrules" | ".windsurfrules" | "copilot-instructions.md" | "agent.md"
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

pub fn run_ci_report(
    path: &Path,
    run_sca: bool,
    fail_on: Option<&str>,
    fail_on_secrets: bool,
    markdown_out: Option<&Path>,
    json_out: Option<&Path>,
    json: bool,
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
