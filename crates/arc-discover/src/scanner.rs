use arc_core::mcp_profile::{compute_jcs_schema_hash, Mcp3DCapabilityProfile, RiskBand};
use arc_dlp::detector::SecretScanEngine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMcpServer {
    pub name: String,
    pub source_file: PathBuf,
    pub transport: String, // stdio or http/sse
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub schema_hash: Option<String>,
    pub profile: Mcp3DCapabilityProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgentSkill {
    pub name: String,
    pub file_path: PathBuf,
    pub content_hash: String,
    pub line_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredModelAsset {
    pub name: String,
    pub file_path: PathBuf,
    pub kind: String, // gguf, safetensors, ollama
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedSecretFinding {
    pub file_path: PathBuf,
    pub detector: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub scanned_path: PathBuf,
    pub scan_duration_ms: u64,
    pub mcp_servers: Vec<DiscoveredMcpServer>,
    pub agent_skills: Vec<DiscoveredAgentSkill>,
    pub model_assets: Vec<DiscoveredModelAsset>,
    pub exposed_secrets: Vec<ExposedSecretFinding>,
    pub overall_risk_band: RiskBand,
    pub total_assets: usize,
}

pub struct DiscoveryScanner {
    dlp_engine: SecretScanEngine,
}

impl Default for DiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryScanner {
    pub fn new() -> Self {
        Self {
            dlp_engine: SecretScanEngine::new(),
        }
    }

    /// Performs zero-touch discovery of all AI assets, MCP servers, skills, and secrets.
    pub fn audit_directory(&self, root: &Path) -> io::Result<AuditReport> {
        if !root.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Target path does not exist: {}", root.display()),
            ));
        }
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Target path is not a directory: {}", root.display()),
            ));
        }
        // Verify read permissions on root directory
        let _ = fs::read_dir(root)?;

        let start = std::time::Instant::now();
        let mut mcp_servers = Vec::new();
        let mut agent_skills = Vec::new();
        let mut model_assets = Vec::new();
        let mut exposed_secrets = Vec::new();

        self.scan_recursive(
            root,
            0,
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
        );

        let elapsed = start.elapsed().as_millis() as u64;

        // Determine overall risk band: highest band among MCP servers or High if secrets found
        let mut highest_band = RiskBand::Low;
        for s in &mcp_servers {
            if s.profile.band > highest_band {
                highest_band = s.profile.band;
            }
        }
        if !exposed_secrets.is_empty() && highest_band < RiskBand::High {
            highest_band = RiskBand::High;
        }

        let total_assets = mcp_servers.len() + agent_skills.len() + model_assets.len();

        Ok(AuditReport {
            scanned_path: root.to_path_buf(),
            scan_duration_ms: elapsed,
            mcp_servers,
            agent_skills,
            model_assets,
            exposed_secrets,
            overall_risk_band: highest_band,
            total_assets,
        })
    }

    fn scan_recursive(
        &self,
        current: &Path,
        depth: usize,
        mcp_servers: &mut Vec<DiscoveredMcpServer>,
        agent_skills: &mut Vec<DiscoveredAgentSkill>,
        model_assets: &mut Vec<DiscoveredModelAsset>,
        exposed_secrets: &mut Vec<ExposedSecretFinding>,
    ) {
        if depth > 10 {
            return;
        }

        let entries = match fs::read_dir(current) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Skip heavy build / source-control directories
            if file_name == ".git"
                || file_name == "target"
                || file_name == "node_modules"
                || file_name == ".venv"
                || file_name == "venv"
            {
                continue;
            }

            if path.is_dir() {
                self.scan_recursive(
                    &path,
                    depth + 1,
                    mcp_servers,
                    agent_skills,
                    model_assets,
                    exposed_secrets,
                );
            } else if path.is_file() {
                self.inspect_file(
                    &path,
                    file_name,
                    mcp_servers,
                    agent_skills,
                    model_assets,
                    exposed_secrets,
                );
            }
        }
    }

    fn inspect_file(
        &self,
        path: &Path,
        file_name: &str,
        mcp_servers: &mut Vec<DiscoveredMcpServer>,
        agent_skills: &mut Vec<DiscoveredAgentSkill>,
        model_assets: &mut Vec<DiscoveredModelAsset>,
        exposed_secrets: &mut Vec<ExposedSecretFinding>,
    ) {
        let lower = file_name.to_lowercase();

        // 1. MCP Configuration files
        if lower == "mcp.json"
            || lower == ".mcp.json"
            || lower == "mcp_config.json"
            || lower.ends_with(".claude.json")
            || lower.ends_with("claude_desktop_config.json")
            || (lower.contains("windsurf") && lower.ends_with(".json"))
        {
            if let Ok(content) = fs::read_to_string(path) {
                self.parse_mcp_config(path, &content, mcp_servers);
            }
        }

        // 2. Agent Skills and System Instructions
        if lower == "claude.md"
            || lower == ".cursorrules"
            || lower == ".windsurfrules"
            || lower == "copilot-instructions.md"
            || lower.ends_with(".prompt.md")
            || lower.ends_with(".mdc")
            || lower == "agent.md"
        {
            if let Ok(bytes) = fs::read(path) {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hash = hex::encode(hasher.finalize());
                let lines = bytes.iter().filter(|&&b| b == b'\n').count() + 1;

                agent_skills.push(DiscoveredAgentSkill {
                    name: file_name.to_string(),
                    file_path: path.to_path_buf(),
                    content_hash: hash,
                    line_count: lines,
                });
            }
        }

        // 3. AI Models and Weights
        if lower.ends_with(".safetensors")
            || lower.ends_with(".gguf")
            || lower.ends_with(".onnx")
            || lower.ends_with(".pt")
            || lower.ends_with(".bin")
        {
            let metadata = fs::metadata(path).ok();
            let size = metadata.map(|m| m.len()).unwrap_or(0);
            let kind = if lower.ends_with(".gguf") {
                "gguf"
            } else if lower.ends_with(".safetensors") {
                "safetensors"
            } else if lower.ends_with(".onnx") {
                "onnx"
            } else if lower.ends_with(".pt") {
                "pytorch"
            } else {
                "binary-weights"
            };

            model_assets.push(DiscoveredModelAsset {
                name: file_name.to_string(),
                file_path: path.to_path_buf(),
                kind: kind.to_string(),
                size_bytes: size,
            });
        }

        // 4. Exposed Secrets Scan (.env*, credentials.json, id_rsa, etc.)
        if lower.starts_with(".env")
            || lower.contains("credential")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower == "id_rsa"
            || lower == "id_ed25519"
            || lower == "id_ecdsa"
            || lower == "id_dsa"
        {
            if let Ok(bytes) = fs::read(path) {
                let findings = self.dlp_engine.scan(&bytes);
                for f in findings {
                    exposed_secrets.push(ExposedSecretFinding {
                        file_path: path.to_path_buf(),
                        detector: f.detector.to_string(),
                        snippet: f.snippet,
                    });
                }
            }
        }
    }

    fn parse_mcp_config(
        &self,
        source_path: &Path,
        content: &str,
        mcp_servers: &mut Vec<DiscoveredMcpServer>,
    ) {
        let value: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return,
        };

        let servers_obj = value
            .get("mcpServers")
            .or_else(|| value.get("servers"))
            .and_then(|v| v.as_object());

        if let Some(servers) = servers_obj {
            for (name, sval) in servers {
                let command = sval
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());
                let transport = if command.is_some() {
                    "stdio".to_string()
                } else if sval.get("url").is_some() {
                    "http/sse".to_string()
                } else {
                    "unknown".to_string()
                };

                let args = sval
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let env_keys: Vec<String> = sval
                    .get("env")
                    .and_then(|e| e.as_object())
                    .map(|obj| obj.keys().cloned().collect())
                    .unwrap_or_default();

                // Compute canonical schema hash if tools are included
                let schema_hash = if let Some(tools) = sval.get("tools") {
                    let tools_bytes = serde_json::to_vec(tools).unwrap_or_default();
                    compute_jcs_schema_hash(&tools_bytes).ok().map(hex::encode)
                } else {
                    None
                };

                // Profile 3D capabilities based on heuristics
                let name_lower = name.to_lowercase();
                let is_destructive = name_lower.contains("exec")
                    || name_lower.contains("shell")
                    || name_lower.contains("delete")
                    || name_lower.contains("write");
                let is_untrusted = name_lower.contains("fetch")
                    || name_lower.contains("web")
                    || name_lower.contains("scrape")
                    || name_lower.contains("github")
                    || name_lower.contains("slack");
                let is_private = name_lower.contains("file")
                    || name_lower.contains("db")
                    || name_lower.contains("sql")
                    || !env_keys.is_empty();

                let p_score = if is_private { 600 } else { 100 };
                let u_score = if is_untrusted { 700 } else { 100 };
                let d_score = if is_destructive { 800 } else { 150 };

                let hash_bytes = schema_hash
                    .as_ref()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|v| v.try_into().ok())
                    .unwrap_or([0u8; 32]);

                let profile =
                    Mcp3DCapabilityProfile::calculate(p_score, u_score, d_score, hash_bytes);

                mcp_servers.push(DiscoveredMcpServer {
                    name: name.clone(),
                    source_file: source_path.to_path_buf(),
                    transport,
                    command,
                    args,
                    env_keys,
                    schema_hash,
                    profile,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_config_discovery() {
        let scanner = DiscoveryScanner::new();
        let sample_json = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": { "GITHUB_TOKEN": "demo" }
                },
                "remote-agent": {
                    "url": "https://mcp.internal.corp/sse"
                }
            }
        }"#;

        let mut servers = Vec::new();
        scanner.parse_mcp_config(Path::new("c:/fake/mcp.json"), sample_json, &mut servers);

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "github");
        assert_eq!(servers[0].transport, "stdio");
        assert_eq!(servers[1].name, "remote-agent");
        assert_eq!(servers[1].transport, "http/sse");
    }

    #[test]
    fn test_agent_skill_and_model_asset_discovery() {
        let scanner = DiscoveryScanner::new();
        let mut mcp_servers = Vec::new();
        let mut agent_skills = Vec::new();
        let mut model_assets = Vec::new();
        let mut exposed_secrets = Vec::new();

        let temp_skill = std::env::temp_dir().join("test_security.mdc");
        std::fs::write(&temp_skill, "# Cursor Agent Rule\nApply security gates").unwrap();

        scanner.inspect_file(
            &temp_skill,
            "test_security.mdc",
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
        );

        assert_eq!(agent_skills.len(), 1);
        assert_eq!(agent_skills[0].name, "test_security.mdc");
        let _ = std::fs::remove_file(&temp_skill);

        scanner.inspect_file(
            Path::new("models/model.onnx"),
            "model.onnx",
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
        );

        assert_eq!(model_assets.len(), 1);
        assert_eq!(model_assets[0].kind, "onnx");
    }

    #[test]
    fn test_audit_directory_validation() {
        let scanner = DiscoveryScanner::new();

        // 1. Nonexistent directory
        let non_existent = Path::new("target").join("non_existent_dir_qa_12345");
        let err = scanner.audit_directory(&non_existent).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // 2. Path is a file, not a directory
        let temp_file = std::env::temp_dir().join("test_not_a_dir.txt");
        let _ = fs::write(&temp_file, "content").unwrap();
        let err2 = scanner.audit_directory(&temp_file).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_file(&temp_file);

        // 3. Valid directory
        let res = scanner.audit_directory(Path::new("."));
        assert!(res.is_ok());
    }
}
