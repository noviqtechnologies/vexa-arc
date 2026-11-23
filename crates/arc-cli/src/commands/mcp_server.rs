use arc_core::event::Ecosystem;
use arc_discover::scanner::DiscoveryScanner;
use arc_dlp::detector::SecretScanEngine;
use arc_firewall::osv_scanner::{ecosystem_to_osv_str, OsvPackageScanner};
use arc_firewall::proxy::PackageFirewall;
use arc_firewall::remediation::{run_sca_audit, ScaAuditOptions};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

fn parse_ecosystem(s: &str) -> Ecosystem {
    match s.to_lowercase().as_str() {
        "pypi" | "pip" | "python" => Ecosystem::Pypi,
        "cargo" | "rust" | "crate" => Ecosystem::Cargo,
        "go" | "golang" => Ecosystem::Go,
        _ => Ecosystem::Npm,
    }
}

fn tool_definitions() -> Value {
    json!({
        "tools": [
            {
                "name": "scan_secrets",
                "description": "Scan a file, directory, or raw text snippet for leaked credentials and production secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File or directory path to scan" },
                        "content": { "type": "string", "description": "Raw text content to scan if path is omitted" }
                    }
                }
            },
            {
                "name": "check_package",
                "description": "Check a package name (or name@version) for slopsquatting heuristics and known OSV advisories.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package": { "type": "string", "description": "Package name or name@version (e.g. 'lodash@4.17.21' or 'reactt')" },
                        "ecosystem": { "type": "string", "description": "Ecosystem: npm, pypi, cargo, go" }
                    },
                    "required": ["package"]
                }
            },
            {
                "name": "sca_audit",
                "description": "Scan project lockfiles/manifests for known dependency vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Project directory (default: '.')" },
                        "reachable_only": { "type": "boolean", "description": "Only report reachable vulnerabilities" }
                    }
                }
            },
            {
                "name": "audit_ai_assets",
                "description": "Discover MCP servers, agent instruction files (CLAUDE.md, .cursorrules), local models, and exposed .env secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Project directory (default: '.')" }
                    }
                }
            }
        ]
    })
}

/// Computes the canonical RFC 8785 JCS SHA-256 schema hash of the built-in `vexa-arc` MCP server's
/// `tools/list` definitions dynamically so lockfiles and tests never hardcode stale hashes.
pub fn builtin_tools_schema_hash() -> Option<String> {
    let defs = tool_definitions();
    let tools = defs.get("tools")?;
    let bytes = serde_json::to_vec(tools).ok()?;
    let hash = arc_core::compute_jcs_schema_hash(&bytes).ok()?;
    Some(hex::encode(hash))
}

fn ok_tool_result(payload: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
            }
        ],
        "isError": false
    })
}

fn err_tool_result(msg: impl Into<String>) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": msg.into()
            }
        ],
        "isError": true
    })
}

fn handle_tool_call(name: &str, args: &Value, default_root: &Path) -> Value {
    match name {
        "scan_secrets" => {
            let engine = SecretScanEngine::new();
            if let Some(content) = args.get("content").and_then(|v| v.as_str()) {
                let findings = engine.scan(content.as_bytes());
                return ok_tool_result(json!({
                    "finding_count": findings.len(),
                    "findings": findings,
                }));
            }
            let target = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());
            if target.is_file() {
                match std::fs::read(&target) {
                    Ok(bytes) => {
                        let findings = engine.scan(&bytes);
                        ok_tool_result(json!({
                            "path": target.display().to_string(),
                            "finding_count": findings.len(),
                            "findings": findings,
                        }))
                    }
                    Err(e) => err_tool_result(format!("Failed to read {}: {e}", target.display())),
                }
            } else if target.is_dir() {
                let scanner = DiscoveryScanner::new();
                match scanner.audit_directory(&target) {
                    Ok(report) => ok_tool_result(json!({
                        "path": target.display().to_string(),
                        "exposed_secrets": report.exposed_secrets,
                    })),
                    Err(e) => err_tool_result(format!("Failed to scan {}: {e}", target.display())),
                }
            } else {
                err_tool_result(format!("Path does not exist: {}", target.display()))
            }
        }
        "check_package" => {
            let Some(pkg) = args.get("package").and_then(|v| v.as_str()) else {
                return err_tool_result("Missing required argument 'package'");
            };
            let eco = args
                .get("ecosystem")
                .and_then(|v| v.as_str())
                .map(parse_ecosystem)
                .unwrap_or_else(|| PackageFirewall::detect_ecosystem(default_root));
            let fw = PackageFirewall::new();
            let (name, ver) = crate::split_package_version(pkg);
            let insp = fw.inspect_package_live(eco, name, false);
            let provenance_source = match insp.source {
                arc_firewall::registry::RegistryMetadataSource::Live => "live",
                arc_firewall::registry::RegistryMetadataSource::Cache => "cache",
                arc_firewall::registry::RegistryMetadataSource::HeuristicFallback => {
                    "heuristic_fallback"
                }
            };
            let verdict = insp.verdict;
            let (osv_json, osv_blocks) = match ver {
                Some(v) => {
                    let scanner = OsvPackageScanner::default();
                    match scanner.scan_package(name, v, ecosystem_to_osv_str(eco)) {
                        Ok(r) => {
                            let blocks = !r.advisory_available || r.should_block();
                            (serde_json::to_value(&r).unwrap_or(Value::Null), blocks)
                        }
                        Err(e) => (
                            json!({
                                "status": "incomplete",
                                "advisory_available": false,
                                "error": e
                            }),
                            true,
                        ),
                    }
                }
                None => (
                    json!({
                        "status": "not_scanned_no_version",
                        "advisory_available": false,
                        "error": null
                    }),
                    false,
                ),
            };
            let status = if verdict.is_blocked() || osv_blocks {
                "blocked"
            } else if matches!(
                verdict,
                arc_firewall::slopsquat::SlopsquatVerdict::Review { .. }
            ) {
                "review"
            } else {
                "permitted"
            };
            ok_tool_result(json!({
                "package": pkg,
                "ecosystem": format!("{eco:?}").to_lowercase(),
                "status": status,
                "provenance": {
                    "source": provenance_source,
                    "cache_age_secs": insp.cache_age_secs,
                    "confidence": if insp.confidence_known { "known" } else { "unknown" },
                },
                "verdict": verdict,
                "osv": osv_json,
            }))
        }
        "sca_audit" => {
            let target = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());
            let reachable_only = args
                .get("reachable_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let opts = ScaAuditOptions {
                reachable_only,
                allow_unavailable: true,
                ..Default::default()
            };
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => return err_tool_result(format!("Runtime init failed: {e}")),
            };
            match rt.block_on(run_sca_audit(&target, &opts)) {
                Ok(res) => ok_tool_result(serde_json::to_value(res).unwrap_or(Value::Null)),
                Err(e) => err_tool_result(format!("SCA audit failed: {e}")),
            }
        }
        "audit_ai_assets" => {
            let target = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());
            let scanner = DiscoveryScanner::new();
            match scanner.audit_directory(&target) {
                Ok(report) => ok_tool_result(serde_json::to_value(report).unwrap_or(Value::Null)),
                Err(e) => err_tool_result(format!("Audit failed: {e}")),
            }
        }
        other => err_tool_result(format!("Unknown tool: {other}")),
    }
}

pub fn handle_jsonrpc_line(line: &str, default_root: &Path) -> Option<Value> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let req: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32700, "message": format!("Parse error: {e}") }
            }));
        }
    };

    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned();

    // JSON-RPC notifications (no id) require no response
    let req_id = id?;

    let resp = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "vexa-arc",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "ping" => json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": tool_definitions()
        }),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let result = handle_tool_call(tool_name, &args, default_root);
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": { "code": -32601, "message": format!("Method not found: {method}") }
        }),
    };

    Some(resp)
}

pub fn run_mcp_server(path: &Path) -> bool {
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let Ok(line) = line else {
            break;
        };
        if let Some(resp) = handle_jsonrpc_line(&line, path) {
            if writeln!(stdout, "{resp}").is_err() || stdout.flush().is_err() {
                break;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_server_initialize_and_tools_list() {
        let init = handle_jsonrpc_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            Path::new("."),
        )
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "vexa-arc");

        let list = handle_jsonrpc_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            Path::new("."),
        )
        .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn mcp_server_scan_secrets_tool_detects_key_without_leaking_raw_value() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_secrets",
                "arguments": { "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" }
            }
        })
        .to_string();
        let resp = handle_jsonrpc_line(&req, Path::new(".")).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("SEC-AWS-001"));
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
