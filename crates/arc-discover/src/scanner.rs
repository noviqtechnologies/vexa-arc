use arc_core::mcp_profile::{compute_jcs_schema_hash, Mcp3DCapabilityProfile, RiskBand};
use arc_dlp::detector::SecretScanEngine;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScope {
    Production,
    TestOrDoc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedSecretFinding {
    pub file_path: PathBuf,
    pub detector: String,
    pub snippet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SecretScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainSignal {
    pub rule_id: String,
    pub signal_name: String,
    pub severity: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub scanned_path: PathBuf,
    pub scan_duration_ms: u64,
    pub mcp_servers: Vec<DiscoveredMcpServer>,
    pub agent_skills: Vec<DiscoveredAgentSkill>,
    pub model_assets: Vec<DiscoveredModelAsset>,
    pub exposed_secrets: Vec<ExposedSecretFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_or_doc_secrets: Vec<ExposedSecretFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supply_chain_signals: Vec<SupplyChainSignal>,
    pub overall_risk_band: RiskBand,
    pub total_assets: usize,
    #[serde(default)]
    pub scanned_locations: Vec<PathBuf>,
    #[serde(default)]
    pub not_installed_locations: Vec<PathBuf>,
    #[serde(default)]
    pub unscanned_locations: Vec<PathBuf>,
    #[serde(default)]
    pub excluded_paths: Vec<PathBuf>,
    #[serde(default)]
    pub permission_errors: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub files_scanned: usize,
}

#[derive(Default)]
struct ScanBudget {
    max_files: Option<usize>,
    deadline: Option<std::time::Instant>,
    files_scanned: usize,
    truncated: bool,
}

impl ScanBudget {
    fn unbounded() -> Self {
        Self::default()
    }

    fn bounded(max_files: usize, max_duration: std::time::Duration) -> Self {
        Self {
            max_files: Some(max_files),
            deadline: Some(std::time::Instant::now() + max_duration),
            files_scanned: 0,
            truncated: false,
        }
    }

    fn is_exhausted(&mut self) -> bool {
        if self.truncated {
            return true;
        }
        if let Some(limit) = self.max_files {
            if self.files_scanned >= limit {
                self.truncated = true;
                return true;
            }
        }
        if let Some(deadline) = self.deadline {
            if std::time::Instant::now() >= deadline {
                self.truncated = true;
                return true;
            }
        }
        false
    }
}

pub struct DiscoveryScanner {
    dlp_engine: SecretScanEngine,
}

impl Default for DiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns known OS-specific roots for workstation AI configuration audit (FR-DISC-002)
pub fn get_workstation_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            roots.push(appdata.join("Claude"));
            roots.push(appdata.join("Cursor"));
            roots.push(appdata.join("Code").join("User"));
            roots.push(appdata.join("Windsurf"));
        }
        if let Some(userprofile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            roots.push(userprofile.join(".cursor"));
            roots.push(userprofile.join(".claude"));
            roots.push(userprofile.join(".vscode"));
            roots.push(userprofile.join(".windsurf"));
            roots.push(userprofile.join(".codex"));
            roots.push(userprofile.join(".gemini"));
            roots.push(userprofile.join(".cline"));
            roots.push(userprofile.join(".kiro"));
            roots.push(userprofile.join(".opencode"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            #[cfg(target_os = "macos")]
            {
                let app_support = home.join("Library").join("Application Support");
                roots.push(app_support.join("Claude"));
                roots.push(app_support.join("Cursor"));
                roots.push(app_support.join("Code").join("User"));
                roots.push(app_support.join("Windsurf"));
            }
            #[cfg(not(target_os = "macos"))]
            {
                let config = home.join(".config");
                roots.push(config.join("Claude"));
                roots.push(config.join("Cursor"));
                roots.push(config.join("Code").join("User"));
                roots.push(config.join("Windsurf"));
                roots.push(config.join("opencode"));
            }
            roots.push(home.join(".cursor"));
            roots.push(home.join(".claude"));
            roots.push(home.join(".vscode"));
            roots.push(home.join(".windsurf"));
            roots.push(home.join(".codex"));
            roots.push(home.join(".gemini"));
            roots.push(home.join(".cline"));
            roots.push(home.join(".kiro"));
            roots.push(home.join(".opencode"));
        }
    }

    roots
}

impl DiscoveryScanner {
    pub fn new() -> Self {
        Self {
            dlp_engine: SecretScanEngine::new(),
        }
    }

    /// Performs zero-touch discovery of all AI assets, MCP servers, skills, and secrets.
    pub fn audit_directory(&self, root: &Path) -> io::Result<AuditReport> {
        self.audit_directory_with_budget(root, ScanBudget::unbounded())
    }

    /// Performs bounded zero-touch discovery capped by file count and wall-clock duration
    /// (used by `arc init` to guarantee sub-second / bounded onboarding even in large monorepos).
    pub fn audit_directory_bounded(
        &self,
        root: &Path,
        max_files: usize,
        max_duration: std::time::Duration,
    ) -> io::Result<AuditReport> {
        self.audit_directory_with_budget(root, ScanBudget::bounded(max_files, max_duration))
    }

    fn audit_directory_with_budget(
        &self,
        root: &Path,
        mut budget: ScanBudget,
    ) -> io::Result<AuditReport> {
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
        let mut test_or_doc_secrets = Vec::new();
        let mut scanned_locations = Vec::new();
        let mut unscanned_locations = Vec::new();
        let mut excluded_paths = Vec::new();
        let mut permission_errors = Vec::new();

        scanned_locations.push(root.to_path_buf());

        let candidate_files = self.collect_candidate_files(
            root,
            &mut budget,
            &mut scanned_locations,
            &mut unscanned_locations,
            &mut excluded_paths,
            &mut permission_errors,
        );

        let inspect_timed_out = self.inspect_files_parallel(
            &candidate_files,
            budget.deadline,
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
            &mut test_or_doc_secrets,
        );
        if inspect_timed_out {
            budget.truncated = true;
        }

        // Delegate targeted AI/MCP/workflow supply-chain checks to vexa-sca's LocalSupplyChainAnalyzer
        let mut supply_chain_signals = if !budget.truncated {
            collect_vexa_sca_supply_chain_signals(root)
        } else {
            Vec::new()
        };
        supply_chain_signals.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then(a.file_path.cmp(&b.file_path))
                .then(a.line.cmp(&b.line))
        });

        sort_report_vectors(
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
            &mut test_or_doc_secrets,
            &mut scanned_locations,
            &mut unscanned_locations,
            &mut excluded_paths,
            &mut permission_errors,
        );

        let elapsed = start.elapsed().as_millis() as u64;

        // Determine overall risk band: highest band among MCP servers or High if actionable production secrets found
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
            test_or_doc_secrets,
            supply_chain_signals,
            overall_risk_band: highest_band,
            total_assets,
            scanned_locations,
            not_installed_locations: Vec::new(),
            unscanned_locations,
            excluded_paths,
            permission_errors,
            truncated: budget.truncated,
            files_scanned: budget.files_scanned,
        })
    }

    /// Opt-in workstation audit mode scanning known host roots across Windows, macOS, and Linux (FR-DISC-002)
    pub fn audit_workstation(&self) -> io::Result<AuditReport> {
        let start = std::time::Instant::now();
        let overall_deadline = start + std::time::Duration::from_secs(20);
        let mut mcp_servers = Vec::new();
        let mut agent_skills = Vec::new();
        let mut model_assets = Vec::new();
        let mut exposed_secrets = Vec::new();
        let mut test_or_doc_secrets = Vec::new();
        let mut scanned_locations = Vec::new();
        let mut not_installed_locations = Vec::new();
        let mut unscanned_locations = Vec::new();
        let mut excluded_paths = Vec::new();
        let mut permission_errors = Vec::new();

        let roots = get_workstation_roots();
        let mut all_candidate_files = Vec::new();
        let mut total_files_scanned = 0usize;
        let mut any_truncated = false;

        // Fair per-root budget (2,500 files / 3s per root) so a single noisy host directory
        // (e.g. IDE caches or plugin temp trees) can never starve later roots like `.gemini` or `.cline`.
        for root in roots {
            if std::time::Instant::now() >= overall_deadline {
                any_truncated = true;
                unscanned_locations.push(root);
                continue;
            }
            if root.exists() && root.is_dir() {
                scanned_locations.push(root.clone());
                let remaining = overall_deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(std::time::Duration::from_secs(3));
                let mut root_budget = ScanBudget::bounded(2_500, remaining);
                let mut files = self.collect_candidate_files(
                    &root,
                    &mut root_budget,
                    &mut scanned_locations,
                    &mut unscanned_locations,
                    &mut excluded_paths,
                    &mut permission_errors,
                );
                total_files_scanned += root_budget.files_scanned;
                if root_budget.truncated {
                    any_truncated = true;
                }
                all_candidate_files.append(&mut files);
            } else {
                not_installed_locations.push(root);
            }
        }

        let inspect_timed_out = self.inspect_files_parallel(
            &all_candidate_files,
            Some(overall_deadline),
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
            &mut test_or_doc_secrets,
        );
        if inspect_timed_out {
            any_truncated = true;
        }

        sort_report_vectors(
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
            &mut test_or_doc_secrets,
            &mut scanned_locations,
            &mut unscanned_locations,
            &mut excluded_paths,
            &mut permission_errors,
        );

        let elapsed = start.elapsed().as_millis() as u64;
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
            scanned_path: PathBuf::from("workstation://"),
            scan_duration_ms: elapsed,
            mcp_servers,
            agent_skills,
            model_assets,
            exposed_secrets,
            test_or_doc_secrets,
            supply_chain_signals: Vec::new(),
            overall_risk_band: highest_band,
            total_assets,
            scanned_locations,
            not_installed_locations,
            unscanned_locations,
            excluded_paths,
            permission_errors,
            truncated: any_truncated,
            files_scanned: total_files_scanned,
        })
    }

    /// Walks `root` deterministically using `.gitignore` / `.arcignore` + OS-heavy directory
    /// exclusions, then ensures high-signal security/AI config files (such as gitignored `.env`
    /// files and IDE MCP configs) are still included without duplication.
    fn collect_candidate_files(
        &self,
        root: &Path,
        budget: &mut ScanBudget,
        scanned_locations: &mut Vec<PathBuf>,
        unscanned_locations: &mut Vec<PathBuf>,
        excluded_paths: &mut Vec<PathBuf>,
        permission_errors: &mut Vec<String>,
    ) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let excluded_shared: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
        let excluded_for_filter = Arc::clone(&excluded_shared);

        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false) // Discover dotfiles (.cursor, .mcp.json, .env, .cursorrules, etc.)
            .git_ignore(true)
            .git_global(false) // Keep scans reproducible across machines
            .git_exclude(true)
            .require_git(false) // Honor .gitignore even outside a .git repository
            .add_custom_ignore_filename(".arcignore")
            .max_depth(Some(11))
            .follow_links(false)
            .sort_by_file_name(Ord::cmp)
            .filter_entry(move |entry| {
                // Never filter out the scan root itself
                if entry.depth() == 0 {
                    return true;
                }

                let path = entry.path();
                if is_entry_symlink_or_reparse(entry) {
                    if let Ok(mut ex) = excluded_for_filter.lock() {
                        ex.push(path.to_path_buf());
                    }
                    return false;
                }

                let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                if is_dir {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name == ".git"
                        || name.eq_ignore_ascii_case(".sca-cache")
                        || is_ephemeral_cache_dir(name)
                        || is_vendored_or_generated_dir(name)
                        || vexa_core::fs_guard::is_os_heavy_dir(name)
                    {
                        if let Ok(mut ex) = excluded_for_filter.lock() {
                            ex.push(path.to_path_buf());
                        }
                        return false;
                    }
                }

                true
            });

        for result in builder.build() {
            if budget.is_exhausted() {
                if let Ok(entry) = result {
                    unscanned_locations.push(entry.into_path());
                }
                break;
            }

            let entry = match result {
                Ok(e) => e,
                Err(err) => {
                    if let Some(io_err) = err.io_error() {
                        if io_err.kind() == io::ErrorKind::PermissionDenied {
                            permission_errors.push(format!("Permission denied: {err}"));
                        }
                    }
                    continue;
                }
            };

            if entry.depth() == 0 {
                continue;
            }

            let Some(ft) = entry.file_type() else {
                continue;
            };

            let path = entry.into_path();
            if ft.is_dir() {
                scanned_locations.push(path);
            } else if ft.is_file() {
                budget.files_scanned += 1;
                seen.insert(path.clone());
                files.push(path);
            }
        }

        if let Ok(mut ex) = excluded_shared.lock() {
            excluded_paths.append(&mut *ex);
        }

        // Security invariant: high-signal local files (.env*, IDE MCP configs, agent rules)
        // are commonly listed in .gitignore, so we still inspect them explicitly unless the
        // scan budget has already been exhausted.
        if !budget.is_exhausted() {
            collect_high_signal_gitignored_files(root, &mut seen, &mut files, budget);
        }

        files
    }

    /// Inspects collected candidate files across available CPU cores using scoped threads.
    /// Returns `true` if a bounded `deadline` was exceeded before all files were inspected.
    #[allow(clippy::too_many_arguments)]
    fn inspect_files_parallel(
        &self,
        files: &[PathBuf],
        deadline: Option<std::time::Instant>,
        mcp_servers: &mut Vec<DiscoveredMcpServer>,
        agent_skills: &mut Vec<DiscoveredAgentSkill>,
        model_assets: &mut Vec<DiscoveredModelAsset>,
        exposed_secrets: &mut Vec<ExposedSecretFinding>,
        test_or_doc_secrets: &mut Vec<ExposedSecretFinding>,
    ) -> bool {
        if files.is_empty() {
            return false;
        }

        let thread_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(files.len())
            .max(1);

        if thread_count <= 1 || files.len() < 32 {
            for path in files {
                if let Some(dl) = deadline {
                    if std::time::Instant::now() >= dl {
                        return true;
                    }
                }
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                self.inspect_file(
                    path,
                    file_name,
                    mcp_servers,
                    agent_skills,
                    model_assets,
                    exposed_secrets,
                    test_or_doc_secrets,
                );
            }
            return false;
        }

        let timed_out = AtomicBool::new(false);
        let chunk_size = files.len().div_ceil(thread_count);
        let partial_results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = files
                .chunks(chunk_size)
                .map(|chunk| {
                    let timed_out_ref = &timed_out;
                    scope.spawn(move || {
                        let mut local_mcp = Vec::new();
                        let mut local_skills = Vec::new();
                        let mut local_models = Vec::new();
                        let mut local_secrets = Vec::new();
                        let mut local_test_secrets = Vec::new();
                        for path in chunk {
                            if let Some(dl) = deadline {
                                if timed_out_ref.load(Ordering::Relaxed)
                                    || std::time::Instant::now() >= dl
                                {
                                    timed_out_ref.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                            self.inspect_file(
                                path,
                                file_name,
                                &mut local_mcp,
                                &mut local_skills,
                                &mut local_models,
                                &mut local_secrets,
                                &mut local_test_secrets,
                            );
                        }
                        (
                            local_mcp,
                            local_skills,
                            local_models,
                            local_secrets,
                            local_test_secrets,
                        )
                    })
                })
                .collect();

            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });

        for (mut m, mut s, mut mo, mut sec, mut test_sec) in partial_results {
            mcp_servers.append(&mut m);
            agent_skills.append(&mut s);
            model_assets.append(&mut mo);
            exposed_secrets.append(&mut sec);
            test_or_doc_secrets.append(&mut test_sec);
        }

        timed_out.load(Ordering::Relaxed)
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_file(
        &self,
        path: &Path,
        file_name: &str,
        mcp_servers: &mut Vec<DiscoveredMcpServer>,
        agent_skills: &mut Vec<DiscoveredAgentSkill>,
        model_assets: &mut Vec<DiscoveredModelAsset>,
        exposed_secrets: &mut Vec<ExposedSecretFinding>,
        test_or_doc_secrets: &mut Vec<ExposedSecretFinding>,
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

        // 4. Exposed Secrets Scan across all non-binary repository files (up to 2 MB)
        //    so `arc audit`, `audit_ai_assets`, `arc ci-report`, and `arc scan-secrets` agree.
        const MAX_SECRET_SCAN_BYTES: u64 = 2 * 1024 * 1024;
        let is_binary_ext = matches!(
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .as_deref(),
            Some(
                "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "webp"
                    | "ico"
                    | "pdf"
                    | "zip"
                    | "tar"
                    | "gz"
                    | "tgz"
                    | "7z"
                    | "rar"
                    | "exe"
                    | "dll"
                    | "so"
                    | "dylib"
                    | "wasm"
                    | "o"
                    | "a"
                    | "rlib"
                    | "class"
                    | "jar"
                    | "pyc"
                    | "pyo"
                    | "safetensors"
                    | "gguf"
                    | "onnx"
                    | "pt"
                    | "bin"
                    | "mp3"
                    | "mp4"
                    | "mov"
                    | "avi"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "otf"
                    | "db"
                    | "sqlite"
                    | "sqlite3"
            )
        );
        let is_generated_report = matches!(
            lower.as_str(),
            "sbom-cyclonedx.json"
                | "sca-report.html"
                | "sca-report.json"
                | "sca-report.sarif"
                | "ai-bom.json"
                | "vexa-ai-bom.json"
        );
        if !is_binary_ext && !is_generated_report && !is_lockfile(&lower) {
            let within_size = fs::metadata(path)
                .map(|m| m.len() <= MAX_SECRET_SCAN_BYTES)
                .unwrap_or(false);
            if within_size {
                if let Ok(bytes) = fs::read(path) {
                    if !bytes.contains(&0) {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            let findings = self.dlp_engine.scan(&bytes);
                            if !findings.is_empty() {
                                let path_is_test_or_doc = is_test_or_doc_path(path);
                                let cfg_test_offset = if lower.ends_with(".rs") {
                                    rust_cfg_test_byte_offset(text)
                                } else {
                                    None
                                };
                                let mut seen_in_file: HashSet<(usize, &'static str)> =
                                    HashSet::new();

                                for f in findings {
                                    let raw_match = text.get(f.start..f.end).unwrap_or("");
                                    let (line_no, line_text) = byte_offset_to_line(text, f.start);

                                    // Skip developer-suppressed lines, pure comments, regex literals,
                                    // and canonical documentation/placeholder/local-dev values.
                                    if is_inline_suppressed(line_text)
                                        || is_comment_or_regex_line(line_text)
                                        || is_canonical_placeholder(f.detector, raw_match)
                                    {
                                        continue;
                                    }

                                    // Deduplicate multiple hits of the same detector on the same line
                                    if !seen_in_file.insert((line_no, f.detector)) {
                                        continue;
                                    }

                                    let in_cfg_test =
                                        cfg_test_offset.map(|off| f.start >= off).unwrap_or(false);
                                    let scope = if path_is_test_or_doc || in_cfg_test {
                                        SecretScope::TestOrDoc
                                    } else {
                                        SecretScope::Production
                                    };

                                    let entry = ExposedSecretFinding {
                                        file_path: path.to_path_buf(),
                                        detector: f.detector.to_string(),
                                        snippet: f.snippet,
                                        line: Some(line_no),
                                        scope: Some(scope),
                                    };
                                    match scope {
                                        SecretScope::Production => exposed_secrets.push(entry),
                                        SecretScope::TestOrDoc => test_or_doc_secrets.push(entry),
                                    }
                                }
                            }
                        }
                    }
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

/// Cross-platform check for symlinks and Windows NTFS reparse points (junctions/mount points).
fn is_entry_symlink_or_reparse(entry: &ignore::DirEntry) -> bool {
    #[cfg(windows)]
    {
        if entry.path_is_symlink() {
            return true;
        }
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        entry
            .metadata()
            .map(|meta| (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        entry.path_is_symlink()
    }
}

fn is_path_symlink_or_reparse(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// High-signal local secret and AI/IDE config files that are frequently listed in `.gitignore`.
/// Checking these explicitly ensures `.gitignore`-aware walking stays fast without blinding
/// secret/MCP discovery to local `.env` or `.cursor/mcp.json` files.
fn collect_high_signal_gitignored_files(
    root: &Path,
    seen: &mut HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
    budget: &mut ScanBudget,
) {
    const RELATIVE_CANDIDATES: &[&str] = &[
        ".env",
        ".env.local",
        ".env.development",
        ".env.development.local",
        ".env.production",
        ".env.production.local",
        ".env.staging",
        ".env.test",
        ".env.test.local",
        ".mcp.json",
        "mcp.json",
        "mcp_config.json",
        ".claude.json",
        "claude_desktop_config.json",
        ".cursorrules",
        ".windsurfrules",
        "CLAUDE.md",
        "AGENT.md",
        ".cursor/mcp.json",
        ".cursor/.env",
        ".claude/mcp.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".github/copilot-instructions.md",
    ];

    for rel in RELATIVE_CANDIDATES {
        if budget.is_exhausted() {
            return;
        }
        let candidate = root.join(rel);
        if seen.contains(&candidate) || is_path_symlink_or_reparse(&candidate) {
            continue;
        }
        if candidate.is_file() {
            budget.files_scanned += 1;
            seen.insert(candidate.clone());
            files.push(candidate);
        }
    }

    // Also inspect `.cursor/rules/*.mdc` if `.cursor/` is gitignored
    let cursor_rules_dir = root.join(".cursor").join("rules");
    if cursor_rules_dir.is_dir() && !is_path_symlink_or_reparse(&cursor_rules_dir) {
        if let Ok(entries) = fs::read_dir(&cursor_rules_dir) {
            let mut rule_paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("mdc"))
                        .unwrap_or(false)
                })
                .collect();
            rule_paths.sort();
            for p in rule_paths {
                if budget.is_exhausted() {
                    return;
                }
                if seen.contains(&p) || is_path_symlink_or_reparse(&p) || !p.is_file() {
                    continue;
                }
                budget.files_scanned += 1;
                seen.insert(p.clone());
                files.push(p);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn sort_report_vectors(
    mcp_servers: &mut [DiscoveredMcpServer],
    agent_skills: &mut [DiscoveredAgentSkill],
    model_assets: &mut [DiscoveredModelAsset],
    exposed_secrets: &mut [ExposedSecretFinding],
    test_or_doc_secrets: &mut [ExposedSecretFinding],
    scanned_locations: &mut [PathBuf],
    unscanned_locations: &mut [PathBuf],
    excluded_paths: &mut [PathBuf],
    permission_errors: &mut [String],
) {
    mcp_servers.sort_by(|a, b| a.source_file.cmp(&b.source_file).then(a.name.cmp(&b.name)));
    agent_skills.sort_by(|a, b| a.file_path.cmp(&b.file_path).then(a.name.cmp(&b.name)));
    model_assets.sort_by(|a, b| a.file_path.cmp(&b.file_path).then(a.name.cmp(&b.name)));
    let secret_cmp = |a: &ExposedSecretFinding, b: &ExposedSecretFinding| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line.cmp(&b.line))
            .then(a.detector.cmp(&b.detector))
            .then(a.snippet.cmp(&b.snippet))
    };
    exposed_secrets.sort_by(secret_cmp);
    test_or_doc_secrets.sort_by(secret_cmp);
    scanned_locations.sort();
    unscanned_locations.sort();
    excluded_paths.sort();
    permission_errors.sort();
}

/// Returns true for third-party vendored or build-output directories that are never
/// first-party source code and should be excluded from workspace audits.
fn is_vendored_or_generated_dir(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "vendor"
            | "third_party"
            | "3rdparty"
            | "dist"
            | "build"
            | "out"
            | "coverage"
            | ".next"
            | ".nuxt"
            | ".svelte-kit"
            | ".turbo"
            | "bower_components"
            | "jspm_packages"
            | "pods"
            | ".terraform"
            | ".serverless"
    )
}

/// Returns true for dependency lockfiles and scanner metadata files that contain
/// package hashes rather than user-authored secrets.
fn is_lockfile(lower_file_name: &str) -> bool {
    lower_file_name.ends_with(".lock")
        || matches!(
            lower_file_name,
            "package-lock.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "cargo.lock"
                | "go.sum"
                | "poetry.lock"
                | "uv.lock"
                | "pipfile.lock"
                | "gemfile.lock"
                | "composer.lock"
                | "flake.lock"
                | ".vexa.facts.json"
        )
}

/// Cross-platform check (using `Path::components()`) for test, benchmark, fixture,
/// documentation, or template/example files. Matches in these files are classified as
/// `SecretScope::TestOrDoc` rather than elevating production risk.
fn is_test_or_doc_path(path: &Path) -> bool {
    for comp in path.components() {
        let std::path::Component::Normal(os_str) = comp else {
            continue;
        };
        let Some(seg) = os_str.to_str() else {
            continue;
        };
        let lower = seg.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "test"
                | "tests"
                | "__tests__"
                | "testdata"
                | "fixtures"
                | "fixture"
                | "mock"
                | "mocks"
                | "bench"
                | "benches"
                | "benchmarks"
                | "example"
                | "examples"
                | "sample"
                | "samples"
                | "docs"
                | "doc"
                | "e2e"
                | "cypress"
                | "spec"
                | "specs"
        ) {
            return true;
        }
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    file_name.ends_with(".example")
        || file_name.ends_with(".sample")
        || file_name.ends_with(".template")
        || file_name.ends_with(".md")
        || file_name.ends_with(".rst")
        || file_name.ends_with(".adoc")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_tests.rs")
        || file_name.ends_with("_test.go")
        || file_name.ends_with("_test.py")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.tsx")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".test.jsx")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.tsx")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.jsx")
        || file_name.starts_with("test_")
        || file_name == "tests.rs"
        || file_name.starts_with("benchmark")
}

/// Returns the byte offset of the first `#[cfg(test)]` attribute in a Rust source file.
fn rust_cfg_test_byte_offset(text: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" || trimmed.starts_with("#[cfg(test)]") {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

/// Converts a byte offset in `text` to a 1-based line number and the full line slice.
fn byte_offset_to_line(text: &str, byte_offset: usize) -> (usize, &str) {
    let clamped = byte_offset.min(text.len());
    let prefix = text.get(..clamped).unwrap_or("");
    let line_no = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text
        .get(line_start..)
        .and_then(|s| s.find('\n').map(|i| line_start + i))
        .unwrap_or(text.len());
    let line_text = text
        .get(line_start..line_end)
        .unwrap_or("")
        .trim_end_matches('\r');
    (line_no, line_text)
}

/// Returns true if the line carries an explicit inline suppression directive.
fn is_inline_suppressed(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("arc:ignore")
        || lower.contains("vexa:ignore")
        || lower.contains("gitleaks:allow")
        || lower.contains("nosec")
}

/// Returns true for pure comment lines or regex pattern definitions.
fn is_comment_or_regex_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
        || trimmed.starts_with("--")
        || trimmed.starts_with("<!--")
    {
        return true;
    }
    trimmed.contains("Regex::new(")
        || trimmed.contains("RegExp(")
        || trimmed.contains("= /")
        || trimmed.contains(": /")
}

/// Value-level filter for canonical documentation placeholders, local-dev DB URIs,
/// truncated/stub PEM blocks, and low-entropy sequential dummy tokens.
/// Applied only in `WorkspaceAudit` mode; runtime DLP (`arc-dlp`) remains strict.
fn is_canonical_placeholder(detector: &str, raw_match: &str) -> bool {
    let upper = raw_match.to_ascii_uppercase();
    match detector {
        "SEC-AWS-001" | "SEC-AWS-003" => {
            raw_match == "AKIAIOSFODNN7EXAMPLE"
                || upper.ends_with("EXAMPLE")
                || upper.ends_with("DUMMY")
                || upper.ends_with("ANOTHER")
                || upper.ends_with("ABCDEF")
                || upper.ends_with("123456")
                || upper.ends_with("000000")
                || upper.contains("EXAMPLE")
                || upper.contains("FAKE")
                || upper.contains("TEST")
                || upper.contains("PLACEHOLDER")
        }
        "SEC-AWS-002" => {
            raw_match == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                || upper.contains("EXAMPLEKEY")
                || upper.contains("EXAMPLE")
                || upper.contains("DUMMY")
                || upper.contains("PLACEHOLDER")
        }
        "SEC-URI-001" => is_placeholder_or_local_db_uri(raw_match),
        "SEC-PRV-001" => is_stub_private_key(raw_match),
        _ => {
            let lower = raw_match.to_ascii_lowercase();
            if lower.contains("example")
                || lower.contains("placeholder")
                || lower.contains("dummy")
                || lower.contains("fake")
                || lower.contains("12345678")
                || lower.contains("abcdefgh")
                || lower.contains("11112222")
                || lower.contains("00000000")
                || lower.contains("aaaaaaaa")
                || lower.ends_with("1234")
                || lower.ends_with("3456")
                || lower.ends_with("stuv")
            {
                return true;
            }
            // Strip common prefix to measure entropy of the secret payload itself
            let payload = raw_match
                .split_once('_')
                .map(|(_, r)| r)
                .or_else(|| raw_match.split_once('-').map(|(_, r)| r))
                .unwrap_or(raw_match);
            arc_dlp::entropy::shannon_entropy(payload.as_bytes()) < 3.0
        }
    }
}

fn is_placeholder_or_local_db_uri(uri: &str) -> bool {
    let Some((_, rest)) = uri.split_once("://") else {
        return false;
    };
    let Some((userinfo, host_part)) = rest.split_once('@') else {
        return false;
    };
    let host = host_part
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_local_or_example_host = matches!(
        host.as_str(),
        "localhost"
            | "127.0.0.1"
            | "::1"
            | "0.0.0.0"
            | "db"
            | "postgres"
            | "postgresql"
            | "mysql"
            | "redis"
            | "mongo"
            | "mongodb"
            | "host"
            | "hostname"
            | "myhost"
            | "example.com"
            | "db.example.com"
            | "postgres.example.com"
    ) || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".example")
        || host.ends_with(".example.com")
        || host.starts_with("${")
        || host.starts_with('<');

    let password = userinfo
        .split_once(':')
        .map(|(_, p)| p)
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_dummy_password = matches!(
        password.as_str(),
        "" | "pass"
            | "password"
            | "passwd"
            | "pwd"
            | "postgres"
            | "root"
            | "admin"
            | "secret"
            | "changeme"
            | "test"
            | "testing"
            | "dev"
            | "local"
            | "example"
            | "dummy"
            | "your_password"
            | "your-password"
            | "mysecretpassword"
            | "supersecret"
            | "***"
            | "..."
    ) || password.starts_with("${")
        || password.starts_with('<')
        || password.contains("example")
        || password.contains("placeholder");

    is_local_or_example_host || is_dummy_password
}

fn is_stub_private_key(pem: &str) -> bool {
    let upper = pem.to_ascii_uppercase();
    if upper.contains("...")
        || upper.contains("EXAMPLE")
        || upper.contains("REDACTED")
        || upper.contains("DUMMY")
        || upper.contains("PLACEHOLDER")
        || upper.contains("YOUR_KEY")
        || upper.contains("YOUR PRIVATE KEY")
    {
        return true;
    }
    let body_b64_len: usize = pem
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("-----BEGIN ") && !t.starts_with("-----END ")
        })
        .map(|l| {
            l.bytes()
                .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
                .count()
        })
        .sum();
    body_b64_len < 64
}

/// Delegates targeted workspace supply-chain checks (GitHub Actions pinning, MCP config
/// hygiene, and AI instruction file prompt-injection/Unicode checks) to `vexa-sca`.
fn collect_vexa_sca_supply_chain_signals(root: &Path) -> Vec<SupplyChainSignal> {
    let mut raw = Vec::new();
    vexa_sca::supply_chain::local_analyzer::LocalSupplyChainAnalyzer::scan_github_workflows(
        root, &mut raw,
    );
    vexa_sca::supply_chain::local_analyzer::LocalSupplyChainAnalyzer::scan_mcp_configs(
        root, &mut raw,
    );
    vexa_sca::supply_chain::local_analyzer::LocalSupplyChainAnalyzer::scan_ai_instruction_files(
        root, &mut raw,
    );

    let mut seen = HashSet::new();
    let mut signals = Vec::new();
    for f in raw {
        let key = (f.rule_id.clone(), f.file_path.clone(), f.line);
        if !seen.insert(key) {
            continue;
        }
        signals.push(SupplyChainSignal {
            rule_id: f.rule_id,
            signal_name: f.signal_name,
            severity: f.severity.as_str().to_string(),
            message: f.message,
            file_path: f.file_path,
            line: f.line,
        });
    }
    signals
}

/// Returns true for ephemeral IDE/browser/plugin cache or temp directories that never hold
/// authoritative MCP configs, agent rules, or source code, preventing workstation scans from
/// starving other host roots across Windows, macOS, and Linux.
fn is_ephemeral_cache_dir(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        ".tmp"
            | "tmp"
            | "cacheddata"
            | "code cache"
            | "gpucache"
            | "dawngpucache"
            | "dawngraphitecache"
            | "crashpad"
            | "logs"
            | "blob_storage"
            | "session storage"
            | "indexeddb"
            | "local storage"
    )
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
        let mut test_or_doc_secrets = Vec::new();

        let temp_skill = std::env::temp_dir().join("test_security.mdc");
        std::fs::write(&temp_skill, "# Cursor Agent Rule\nApply security gates").unwrap();

        scanner.inspect_file(
            &temp_skill,
            "test_security.mdc",
            &mut mcp_servers,
            &mut agent_skills,
            &mut model_assets,
            &mut exposed_secrets,
            &mut test_or_doc_secrets,
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
            &mut test_or_doc_secrets,
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
        fs::write(&temp_file, "content").unwrap();
        let err2 = scanner.audit_directory(&temp_file).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_file(&temp_file);

        // 3. Valid directory with an excluded folder
        let temp_test_dir =
            std::env::temp_dir().join(format!("vexa_arc_audit_val_{}", uuid::Uuid::now_v7()));
        let _ = fs::create_dir_all(temp_test_dir.join("target"));
        let _ = fs::create_dir_all(temp_test_dir.join("src"));
        let res = scanner.audit_directory(&temp_test_dir);
        assert!(res.is_ok());
        let rep = res.unwrap();
        assert!(!rep.scanned_locations.is_empty());
        assert!(
            !rep.excluded_paths.is_empty(),
            "Should exclude target/node_modules/.git"
        );
        let _ = fs::remove_dir_all(&temp_test_dir);
    }

    #[test]
    fn test_workstation_audit_and_coverage_reporting() {
        let scanner = DiscoveryScanner::new();
        let report = scanner
            .audit_workstation()
            .expect("Workstation audit must succeed");
        assert_eq!(report.scanned_path, Path::new("workstation://"));
        // Workstation audit should report roots (scanned, not-installed, or unscanned)
        let total_reported_locations = report.scanned_locations.len()
            + report.not_installed_locations.len()
            + report.unscanned_locations.len();
        assert!(
            total_reported_locations > 0,
            "Must report inspected workstation roots"
        );
    }

    #[test]
    fn test_bounded_scan_and_os_heavy_dir_exclusion() {
        let scanner = DiscoveryScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_bounded_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(temp_dir.join("AppData").join("Roaming")).unwrap();
        fs::create_dir_all(temp_dir.join("Library")).unwrap();
        fs::create_dir_all(temp_dir.join("src")).unwrap();
        fs::write(
            temp_dir.join("AppData").join("Roaming").join("skip.mdc"),
            "# should never be scanned",
        )
        .unwrap();
        for i in 0..10 {
            fs::write(temp_dir.join("src").join(format!("file_{i}.txt")), "hello").unwrap();
        }

        // Verify OS-heavy directories are excluded regardless of filesystem read_dir order.
        let exclusion_rep = scanner
            .audit_directory_bounded(&temp_dir, 100, std::time::Duration::from_secs(5))
            .expect("Bounded scan must succeed");
        assert!(
            exclusion_rep.agent_skills.is_empty(),
            "AppData should be excluded from discovery"
        );
        assert!(
            exclusion_rep
                .excluded_paths
                .iter()
                .any(|p| p.ends_with("AppData")),
            "AppData must appear in excluded_paths"
        );
        assert!(
            exclusion_rep
                .excluded_paths
                .iter()
                .any(|p| p.ends_with("Library")),
            "Library must appear in excluded_paths"
        );

        // Verify bounded scan stops and reports truncation when max_files is reached.
        let bounded_rep = scanner
            .audit_directory_bounded(&temp_dir.join("src"), 3, std::time::Duration::from_secs(5))
            .expect("Bounded scan must succeed");
        assert!(
            bounded_rep.truncated,
            "Should report truncation when file cap hit"
        );
        assert_eq!(bounded_rep.files_scanned, 3);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_gitignore_arcignore_and_high_signal_env_preserved() {
        let scanner = DiscoveryScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_gitignore_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(temp_dir.join("dist")).unwrap();
        fs::create_dir_all(temp_dir.join("custom_ignored")).unwrap();
        fs::create_dir_all(temp_dir.join("src")).unwrap();
        fs::create_dir_all(temp_dir.join(".cursor")).unwrap();

        let fake_aws = format!("{}9X8W7V6U5T4S3R2Q", "AKIA");
        let fake_gh = format!("{}{}", "ghp_", "K9mN3pQ7rS2tU5vW8xY1zA4bC6dE0fG2hJ9k");

        // .gitignore ignores dist/, .env, and .cursor/
        fs::write(temp_dir.join(".gitignore"), "dist/\n.env\n.cursor/\n").unwrap();
        // .arcignore ignores custom_ignored/
        fs::write(temp_dir.join(".arcignore"), "custom_ignored/\n").unwrap();

        // Ignored build/custom files should NOT be scanned
        fs::write(
            temp_dir.join("dist").join("bundle.js"),
            format!("const k = '{fake_aws}';"),
        )
        .unwrap();
        fs::write(
            temp_dir.join("custom_ignored").join("dump.txt"),
            format!("token={fake_gh}"),
        )
        .unwrap();

        // Gitignored .env and .cursor/mcp.json MUST still be discovered (security invariant)
        fs::write(temp_dir.join(".env"), format!("AWS_KEY={fake_aws}\n")).unwrap();
        fs::write(
            temp_dir.join(".cursor").join("mcp.json"),
            r#"{"mcpServers":{"demo":{"command":"node","args":["srv.js"]}}}"#,
        )
        .unwrap();

        // Regular tracked source file
        fs::write(
            temp_dir.join("src").join("app.rs"),
            format!("const GH: &str = \"{fake_gh}\";"),
        )
        .unwrap();

        let report = scanner
            .audit_directory(&temp_dir)
            .expect("Gitignore-aware audit must succeed");

        // dist/ and custom_ignored/ must be skipped
        assert!(
            !report
                .exposed_secrets
                .iter()
                .any(|f| f.file_path.to_string_lossy().contains("dist")),
            "dist/ must be ignored via .gitignore"
        );
        assert!(
            !report
                .exposed_secrets
                .iter()
                .any(|f| f.file_path.to_string_lossy().contains("custom_ignored")),
            "custom_ignored/ must be ignored via .arcignore"
        );

        // Both .env (gitignored high-signal) and src/app.rs must be detected, with no duplicates
        assert_eq!(report.exposed_secrets.len(), 2);
        assert!(report
            .exposed_secrets
            .iter()
            .any(|f| f.file_path.ends_with(".env")));
        assert!(report
            .exposed_secrets
            .iter()
            .any(|f| f.file_path.ends_with("app.rs")));

        // Gitignored .cursor/mcp.json must still be discovered
        assert_eq!(report.mcp_servers.len(), 1);
        assert_eq!(report.mcp_servers[0].name, "demo");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_bounded_and_parallel_scan_determinism() {
        let scanner = DiscoveryScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_determ_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(temp_dir.join("src")).unwrap();

        let fake_aws = format!("{}9X8W7V6U5T4S3R2Q", "AKIA");
        // Create 50 files (>32 threshold so parallel inspection runs) with secrets in deterministic slots
        for i in 0..50 {
            let content = if i % 5 == 0 {
                format!("key_{i}={fake_aws}\n")
            } else {
                format!("// clean file {i}\n")
            };
            fs::write(temp_dir.join("src").join(format!("f_{i:02}.txt")), content).unwrap();
        }

        // Full parallel scan: two consecutive runs must match identically
        let full_1 = scanner.audit_directory(&temp_dir).unwrap();
        let full_2 = scanner.audit_directory(&temp_dir).unwrap();
        assert_eq!(full_1.files_scanned, 50);
        assert_eq!(full_1.files_scanned, full_2.files_scanned);
        assert_eq!(full_1.exposed_secrets.len(), 10);
        assert_eq!(
            full_1
                .exposed_secrets
                .iter()
                .map(|s| &s.file_path)
                .collect::<Vec<_>>(),
            full_2
                .exposed_secrets
                .iter()
                .map(|s| &s.file_path)
                .collect::<Vec<_>>()
        );

        // Bounded scan with file cap: two consecutive runs must report the exact same count and paths
        let cap_1 = scanner
            .audit_directory_bounded(&temp_dir, 20, std::time::Duration::from_secs(30))
            .unwrap();
        let cap_2 = scanner
            .audit_directory_bounded(&temp_dir, 20, std::time::Duration::from_secs(30))
            .unwrap();
        assert!(cap_1.truncated);
        assert!(cap_2.truncated);
        assert_eq!(cap_1.files_scanned, 20);
        assert_eq!(cap_1.files_scanned, cap_2.files_scanned);
        assert_eq!(cap_1.exposed_secrets.len(), cap_2.exposed_secrets.len());
        assert_eq!(
            cap_1
                .exposed_secrets
                .iter()
                .map(|s| &s.file_path)
                .collect::<Vec<_>>(),
            cap_2
                .exposed_secrets
                .iter()
                .map(|s| &s.file_path)
                .collect::<Vec<_>>()
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_excludes_sca_cache_and_generated_reports_from_secret_scan() {
        let scanner = DiscoveryScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_noise_excl_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(temp_dir.join(".sca-cache").join("advisories")).unwrap();

        let fake_aws = format!("{}9X8W7V6U5T4S3R2Q", "AKIA");
        // Cache advisory and generated reports containing example credentials must be ignored
        fs::write(
            temp_dir
                .join(".sca-cache")
                .join("advisories")
                .join("GHSA-test.json"),
            format!(r#"{{"example":"{fake_aws}"}}"#),
        )
        .unwrap();
        fs::write(
            temp_dir.join("sbom-cyclonedx.json"),
            format!(r#"{{"token":"{fake_aws}"}}"#),
        )
        .unwrap();
        fs::write(
            temp_dir.join("sca-report.html"),
            format!("<p>{fake_aws}</p>"),
        )
        .unwrap();
        // Real repo file with secret must still be caught
        fs::write(temp_dir.join("app.env"), format!("AWS_KEY={fake_aws}\n")).unwrap();
        // Ephemeral IDE/plugin temp/cache directories must be skipped
        fs::create_dir_all(temp_dir.join(".tmp").join("plugins")).unwrap();
        fs::write(
            temp_dir.join(".tmp").join("plugins").join("cached.txt"),
            format!("KEY={fake_aws}\n"),
        )
        .unwrap();
        fs::create_dir_all(temp_dir.join("GPUCache")).unwrap();
        fs::write(
            temp_dir.join("GPUCache").join("index.txt"),
            format!("KEY={fake_aws}\n"),
        )
        .unwrap();

        let report = scanner.audit_directory(&temp_dir).unwrap();
        assert_eq!(report.exposed_secrets.len(), 1);
        assert!(
            report.exposed_secrets[0].file_path.ends_with("app.env"),
            "unexpected secret path: {:?}",
            report.exposed_secrets[0].file_path
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_workspace_audit_filters_vendor_placeholders_and_classifies_tests_and_cfg_test() {
        let scanner = DiscoveryScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_ws_audit_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(temp_dir.join("vendor").join("github.com").join("lib")).unwrap();
        fs::create_dir_all(temp_dir.join("tests")).unwrap();
        fs::create_dir_all(temp_dir.join("docs")).unwrap();
        fs::create_dir_all(temp_dir.join("src")).unwrap();

        let real_like_aws = format!("{}9X8W7V6U5T4S3R2Q", "AKIA");
        let placeholder_aws = format!("{}IOSFODNN7EXAMPLE", "AKIA");
        let placeholder_secret = format!(
            "AWS_SECRET_ACCESS_KEY={}{}",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"
        );

        // 1. Vendored code must be completely excluded
        fs::write(
            temp_dir
                .join("vendor")
                .join("github.com")
                .join("lib")
                .join("config.go"),
            format!("const key = \"{real_like_aws}\"\n"),
        )
        .unwrap();

        // 2. Canonical doc placeholders, local DB URIs, comments, and inline arc:ignore must be filtered
        fs::write(
            temp_dir.join("src").join("examples.rs"),
            format!(
                "// {real_like_aws}\n\
                 let doc_key = \"{placeholder_aws}\";\n\
                 let doc_sec = \"{placeholder_secret}\";\n\
                 let local_db = \"postgres://postgres:postgres@localhost:5432/app\";\n\
                 let suppressed = \"{real_like_aws}\"; // arc:ignore\n"
            ),
        )
        .unwrap();

        // 3. Real-looking key in tests/ and inside #[cfg(test)] -> classified as TestOrDoc (not Production)
        fs::write(
            temp_dir.join("tests").join("auth_test.rs"),
            format!("const TEST_KEY: &str = \"{real_like_aws}\";\n"),
        )
        .unwrap();
        fs::write(
            temp_dir.join("src").join("service.rs"),
            format!(
                "pub fn prod() {{}}\n\n#[cfg(test)]\nmod tests {{\n    const K: &str = \"{real_like_aws}\";\n}}\n"
            ),
        )
        .unwrap();

        let clean_prod_report = scanner.audit_directory(&temp_dir).unwrap();
        assert!(
            clean_prod_report.exposed_secrets.is_empty(),
            "No production secrets should be reported: {:?}",
            clean_prod_report.exposed_secrets
        );
        assert_eq!(
            clean_prod_report.overall_risk_band,
            RiskBand::Low,
            "Test/doc secrets must not elevate overall risk band to High"
        );
        assert_eq!(
            clean_prod_report.test_or_doc_secrets.len(),
            2,
            "Real-looking keys in tests/ and #[cfg(test)] must be captured in test_or_doc_secrets"
        );
        assert!(clean_prod_report
            .test_or_doc_secrets
            .iter()
            .all(|f| f.scope == Some(SecretScope::TestOrDoc) && f.line.is_some()));

        // 4. Real-looking key in production source -> Production finding with exact line number + High risk
        fs::write(
            temp_dir.join("src").join("prod.rs"),
            format!("pub fn init() {{\n    let k = \"{real_like_aws}\";\n}}\n"),
        )
        .unwrap();
        let prod_report = scanner.audit_directory(&temp_dir).unwrap();
        assert_eq!(prod_report.exposed_secrets.len(), 1);
        assert_eq!(prod_report.exposed_secrets[0].line, Some(2));
        assert_eq!(
            prod_report.exposed_secrets[0].scope,
            Some(SecretScope::Production)
        );
        assert_eq!(prod_report.overall_risk_band, RiskBand::High);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
