//! # Consensual, Disposable-Worktree SCA Remediation — Pillar 4
//!
//! Provides enterprise-grade, non-contaminating SCA scanning and automated remediation:
//! - **Scoped SCA Audit with SARIF (`arc sca audit`):** Invokes `vexa_sca::scan_project`,
//!   generates standard OASIS SARIF v2.1.0, supports location sanitization (`--sanitize-locations`),
//!   and supports policy-driven failure thresholds (`--fail-on <severity>`).
//! - **Dry-Run Scratch Diff Proposal (`arc sca fix --dry-run`):** Performs manifest isolation into
//!   a temporary scratch copy in OS temp, applies fixes, and generates a non-destructive unified diff
//!   without mutating active developer working trees.
//! - **Isolated Disposable Git Worktree (`arc sca fix --open-pr`):**
//!   - Distinguishes Git refs (`refs/remotes/origin/<base>`) from GitHub PR base branch names (`<base>`).
//!   - Fetches and validates remote refs.
//!   - Fails closed on divergence between local HEAD and remote origin unless `--force-remote-base` is passed.
//!   - Spawns detached worktree (`git worktree add --detach`) with `.arc-worktree-marker.json`.
//!   - Delegates single-branch creation, commit, push, and PR opening to `vexa_sca::patcher::PrCreator`.
//!   - Enforces best-effort RAII `Drop` cleanup and 5-point stale worktree safety pruning.
//!   - Enforces opt-in test execution via `--run-tests`.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

use vexa_sca::parsers::detector::ManifestType;
use vexa_sca::patcher::{apply_fixes, PrCreator, PrResult};
use vexa_sca::reporters::sarif::format_sarif_report;
use vexa_sca::types::SeverityLevel;
use vexa_sca::{scan_project, ScanOptions};

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ScaRemediationError {
    #[error("Git command execution failed: {0}")]
    GitError(String),

    #[error("SCA scan error: {0}")]
    ScanError(String),

    #[error("Manifest patching error: {0}")]
    PatchError(String),

    #[error("Pull Request creation error: {0}")]
    PrError(String),

    #[error("I/O error during remediation: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Local branch diverged from remote base: {base} has {ahead} unpushed and {behind} unpulled commits.\n\
To proceed, either:\n  1. Push or synchronize your local branch with origin.\n  2. Explicitly bypass local state: arc sca fix --open-pr --base {base} --force-remote-base")]
    DivergedFromRemote {
        base: String,
        ahead: usize,
        behind: usize,
    },

    #[error("Remote ref '{0}' does not exist or could not be validated on origin.")]
    RemoteRefNotFound(String),

    #[error("Worktree safety validation failed: {0}")]
    SafetyViolation(String),

    #[error("Test execution failed in worktree: {0}")]
    TestsFailed(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// 1. Scoped SCA Audit with SARIF & Location Sanitization
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ScaAuditOptions {
    pub dev: bool,
    pub reachable_only: bool,
    pub allow_unavailable: bool,
    pub sarif_out: Option<PathBuf>,
    pub sanitize_locations: bool,
    pub fail_on: Option<String>,
}

impl Default for ScaAuditOptions {
    fn default() -> Self {
        Self {
            dev: true,
            reachable_only: false,
            allow_unavailable: false,
            sarif_out: None,
            sanitize_locations: false,
            fail_on: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaAuditResult {
    pub project_dir: String,
    pub manifest_file: String,
    pub manifest_type: String,
    pub total_vulnerabilities: usize,
    pub reachable_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub sarif_path: Option<String>,
    pub should_fail: bool,
    pub failure_reason: Option<String>,
}

/// Runs a scoped SCA audit on the target project directory, produces structured
/// vulnerability results, exports standard/sanitized SARIF, and checks policy thresholds.
pub async fn run_sca_audit(
    project_dir: &Path,
    options: &ScaAuditOptions,
) -> Result<ScaAuditResult, ScaRemediationError> {
    let scan_opts = ScanOptions {
        dev: options.dev,
        reachable_only: options.reachable_only,
        allow_unavailable: options.allow_unavailable,
        ..Default::default()
    };

    let scan_out = scan_project(project_dir, scan_opts)
        .await
        .map_err(ScaRemediationError::ScanError)?;

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut reachable_count = 0;

    for vuln in &scan_out.scan_result.vulnerabilities {
        match vuln.severity.level {
            SeverityLevel::Critical => critical_count += 1,
            SeverityLevel::High => high_count += 1,
            SeverityLevel::Medium => medium_count += 1,
            SeverityLevel::Low | SeverityLevel::Unknown => low_count += 1,
        }
        if vuln
            .reachability
            .as_ref()
            .map(|r| r.status == vexa_sca::types::ReachabilityStatus::Reachable)
            .unwrap_or(false)
        {
            reachable_count += 1;
        }
    }

    let total_vulnerabilities = scan_out.scan_result.vulnerabilities.len();

    // Check policy failure gate (--fail-on)
    let (should_fail, failure_reason) = if let Some(ref threshold) = options.fail_on {
        let th_lower = threshold.to_lowercase();
        let matched = match th_lower.as_str() {
            "critical" => critical_count > 0,
            "high" => critical_count > 0 || high_count > 0,
            "medium" => critical_count > 0 || high_count > 0 || medium_count > 0,
            "low" => total_vulnerabilities > 0,
            _ => false,
        };
        if matched {
            (
                true,
                Some(format!(
                    "Vulnerability count meets or exceeds fail threshold '{threshold}'"
                )),
            )
        } else {
            (false, None)
        }
    } else {
        (false, None)
    };

    // Generate SARIF report if requested
    let sarif_path = if let Some(ref path) = options.sarif_out {
        let raw_sarif = format_sarif_report(
            &scan_out.scan_result,
            &scan_out.remediations,
            Some(&scan_out.manifest_file),
        );

        let final_sarif = if options.sanitize_locations {
            sanitize_sarif_locations(&raw_sarif)?
        } else {
            raw_sarif
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, final_sarif.as_bytes())?;
        Some(path.display().to_string())
    } else {
        None
    };

    Ok(ScaAuditResult {
        project_dir: project_dir.display().to_string(),
        manifest_file: scan_out.manifest_file.display().to_string(),
        manifest_type: format!("{:?}", scan_out.manifest_type),
        total_vulnerabilities,
        reachable_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        sarif_path,
        should_fail,
        failure_reason,
    })
}

/// Sanitizes an OASIS SARIF v2.1.0 document:
/// - Removes call-site source code snippets (`region.snippet`).
/// - Suppresses line and column numbers.
/// - Pseudonymizes physical file URIs with deterministic SHA-256 digests.
/// - Retains all vulnerability IDs, advisory names, package versions, and CVSS scores.
pub fn sanitize_sarif_locations(sarif_raw: &str) -> Result<String, ScaRemediationError> {
    let mut root: serde_json::Value =
        serde_json::from_str(sarif_raw).map_err(ScaRemediationError::JsonError)?;

    if let Some(runs) = root.get_mut("runs").and_then(|r| r.as_array_mut()) {
        for run in runs {
            if let Some(results) = run.get_mut("results").and_then(|res| res.as_array_mut()) {
                for result in results {
                    if let Some(locations) =
                        result.get_mut("locations").and_then(|l| l.as_array_mut())
                    {
                        for loc in locations {
                            if let Some(phys) = loc.get_mut("physicalLocation") {
                                // Pseudonymize file URI
                                if let Some(artifact) = phys.get_mut("artifactLocation") {
                                    if let Some(uri_val) =
                                        artifact.get("uri").and_then(|u| u.as_str())
                                    {
                                        let mut hasher = Sha256::new();
                                        hasher.update(uri_val.as_bytes());
                                        let digest = hex::encode(hasher.finalize());
                                        let pseudo_uri =
                                            format!("sanitized/{}.source", &digest[..16]);
                                        artifact["uri"] = serde_json::Value::String(pseudo_uri);
                                    }
                                }

                                // Strip code snippet and suppress exact line/col coordinates
                                if let Some(region) = phys.get_mut("region") {
                                    if let Some(obj) = region.as_object_mut() {
                                        obj.remove("snippet");
                                        obj.remove("startLine");
                                        obj.remove("startColumn");
                                        obj.remove("endLine");
                                        obj.remove("endColumn");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    serde_json::to_string_pretty(&root).map_err(ScaRemediationError::JsonError)
}

// ---------------------------------------------------------------------------
// 2. Dry-Run Scratch Diff Proposal (`arc sca fix --dry-run`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScratchDiffResult {
    pub manifest_type: String,
    pub remediations_count: usize,
    pub patched_files: Vec<String>,
    pub diff: String,
}

/// Executes a dry-run scratch patch: copies manifests into an ephemeral directory in
/// OS temp, applies in-place fixes, generates unified git diff output, and cleans up immediately.
pub async fn run_scratch_diff(
    project_dir: &Path,
) -> Result<ScratchDiffResult, ScaRemediationError> {
    let scan_opts = ScanOptions::default();
    let scan_out = scan_project(project_dir, scan_opts)
        .await
        .map_err(ScaRemediationError::ScanError)?;

    if scan_out.remediations.is_empty() {
        return Ok(ScratchDiffResult {
            manifest_type: format!("{:?}", scan_out.manifest_type),
            remediations_count: 0,
            patched_files: Vec::new(),
            diff: "No vulnerable packages require automated patching.".to_string(),
        });
    }

    let scratch_id = format!("arc-scratch-{}", Uuid::new_v4());
    let scratch_dir = std::env::temp_dir().join(scratch_id);
    fs::create_dir_all(&scratch_dir)?;

    // Candidates for manifest context
    let candidate_manifests = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.toml",
        "Cargo.lock",
        "requirements.txt",
    ];

    let mut copied_files = Vec::new();
    for file in &candidate_manifests {
        let src = project_dir.join(file);
        if src.is_file() {
            let dst = scratch_dir.join(file);
            fs::copy(&src, &dst)?;
            copied_files.push(file.to_string());
        }
    }

    // For Cargo workspaces, copy member crate manifests to preserve dependency tree
    let root_cargo = project_dir.join("Cargo.toml");
    if root_cargo.is_file() {
        if let Ok(content) = fs::read_to_string(&root_cargo) {
            if content.contains("[workspace]") {
                copy_cargo_workspace_skeleton(project_dir, &scratch_dir)?;
            }
        }
    }

    // Apply fixes in the isolated scratch directory
    let _patch_result = apply_fixes(
        &scratch_dir,
        &scan_out.manifest_type,
        &scan_out.remediations,
        false,
    )
    .map_err(ScaRemediationError::PatchError)?;

    // Compute diff between original and scratch
    let mut full_diff = String::new();
    let mut patched_files = Vec::new();

    for file in &copied_files {
        let orig_file = project_dir.join(file);
        let sc_file = scratch_dir.join(file);

        if orig_file.is_file() && sc_file.is_file() {
            let orig_content = fs::read_to_string(&orig_file).unwrap_or_default();
            let sc_content = fs::read_to_string(&sc_file).unwrap_or_default();

            if orig_content != sc_content {
                patched_files.push(file.clone());
                let diff_text = generate_unified_diff(file, &orig_content, &sc_content);
                full_diff.push_str(&diff_text);
                full_diff.push('\n');
            }
        }
    }

    // Clean up scratch directory immediately
    let _ = fs::remove_dir_all(&scratch_dir);

    Ok(ScratchDiffResult {
        manifest_type: format!("{:?}", scan_out.manifest_type),
        remediations_count: scan_out.remediations.len(),
        patched_files,
        diff: if full_diff.is_empty() {
            "Manifest already satisfied or no direct lockfile modifications required.".to_string()
        } else {
            full_diff
        },
    })
}

fn copy_cargo_workspace_skeleton(src_dir: &Path, dst_dir: &Path) -> std::io::Result<()> {
    if let Ok(entries) = fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dirname = path.file_name().unwrap_or_default();
                let dir_str = dirname.to_string_lossy();
                if dir_str.starts_with('.') || dir_str == "target" {
                    continue;
                }
                let member_cargo = path.join("Cargo.toml");
                if member_cargo.is_file() {
                    let target_subdir = dst_dir.join(dirname);
                    fs::create_dir_all(&target_subdir)?;
                    fs::copy(&member_cargo, target_subdir.join("Cargo.toml"))?;
                }
            }
        }
    }
    Ok(())
}

fn generate_unified_diff(filename: &str, old_text: &str, new_text: &str) -> String {
    let mut out = format!("--- a/{filename}\n+++ b/{filename}\n");
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let mut i = 0;
    let mut j = 0;

    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            i += 1;
            j += 1;
        } else {
            let start_i = i;
            let start_j = j;
            while i < old_lines.len() && (j >= new_lines.len() || old_lines[i] != new_lines[j]) {
                out.push_str(&format!("-{}\n", old_lines[i]));
                i += 1;
            }
            while j < new_lines.len()
                && (start_i >= old_lines.len() || old_lines[start_i] != new_lines[j])
            {
                out.push_str(&format!("+{}\n", new_lines[j]));
                j += 1;
            }
            if start_i == i && start_j == j {
                break;
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// 3. Remote Base Validation & Divergence Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceCheckResult {
    pub base_branch: String,
    pub remote_ref: String,
    pub behind_count: usize,
    pub ahead_count: usize,
    pub is_diverged: bool,
    pub forced_override: bool,
}

/// Evaluates synchronization between local checkout and remote base ref.
/// Distinguishes Git ref (`refs/remotes/origin/<base>`) from GitHub PR base (`<base>`).
/// Fails closed by default if unpushed or unpulled commits exist, unless `force_remote_base` is true.
pub fn check_remote_base_divergence(
    repo_dir: &Path,
    base_branch: &str,
    force_remote_base: bool,
) -> Result<DivergenceCheckResult, ScaRemediationError> {
    // 1. Fetch remote ref from origin
    let fetch_out = Command::new("git")
        .args(["fetch", "origin", base_branch, "--quiet"])
        .current_dir(repo_dir)
        .output();

    let remote_ref = format!("refs/remotes/origin/{base_branch}");

    // Verify remote ref exists locally
    let verify_ref = Command::new("git")
        .args(["rev-parse", "--verify", &remote_ref])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| ScaRemediationError::GitError(format!("git rev-parse failed: {e}")))?;

    if !verify_ref.status.success() {
        return Err(ScaRemediationError::RemoteRefNotFound(format!(
            "{} (fetch output: {})",
            remote_ref,
            fetch_out
                .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                .unwrap_or_default()
        )));
    }

    // 2. Count divergence between remote ref and HEAD
    let rev_list = Command::new("git")
        .args([
            "rev-list",
            "--left-right",
            "--count",
            &format!("{remote_ref}...HEAD"),
        ])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| ScaRemediationError::GitError(format!("git rev-list failed: {e}")))?;

    if !rev_list.status.success() {
        return Err(ScaRemediationError::GitError(format!(
            "Failed to evaluate commit divergence: {}",
            String::from_utf8_lossy(&rev_list.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&rev_list.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    let (behind, ahead) = if parts.len() == 2 {
        (
            parts[0].parse::<usize>().unwrap_or(0),
            parts[1].parse::<usize>().unwrap_or(0),
        )
    } else {
        (0, 0)
    };

    let is_diverged = ahead > 0 || behind > 0;

    if is_diverged && !force_remote_base {
        return Err(ScaRemediationError::DivergedFromRemote {
            base: base_branch.to_string(),
            ahead,
            behind,
        });
    }

    Ok(DivergenceCheckResult {
        base_branch: base_branch.to_string(),
        remote_ref,
        behind_count: behind,
        ahead_count: ahead,
        is_diverged,
        forced_override: force_remote_base && is_diverged,
    })
}

// ---------------------------------------------------------------------------
// 4. Isolated Disposable Git Worktree (`DisposableWorktree`) & RAII Cleanup
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeMarker {
    pub marker_version: u32,
    pub created_at_unix_ms: u64,
    pub pid: u32,
    pub repo_root_hash: String,
    pub target_ref: String,
    pub worktree_uuid: String,
}

pub struct DisposableWorktree {
    pub worktree_dir: PathBuf,
    pub repo_dir: PathBuf,
    pub target_ref: String,
    pub uuid: Uuid,
    marker_path: PathBuf,
    cleaned: bool,
}

impl DisposableWorktree {
    /// Creates a detached Git worktree attached directly to the validated remote ref.
    /// In detached HEAD mode, no branch named `vexa-sca/fix-...` exists yet, leaving
    /// branch creation entirely to `PrCreator`.
    pub fn create(repo_dir: &Path, target_ref: &str) -> Result<Self, ScaRemediationError> {
        let uuid = Uuid::new_v4();
        let folder_name = format!("arc-remediation-{uuid}");
        let worktree_dir = std::env::temp_dir().join(folder_name);

        let add_out = Command::new("git")
            .args([
                "worktree",
                "add",
                "--detach",
                worktree_dir.to_str().unwrap(),
                target_ref,
            ])
            .current_dir(repo_dir)
            .output()
            .map_err(|e| ScaRemediationError::GitError(format!("git worktree add failed: {e}")))?;

        if !add_out.status.success() {
            return Err(ScaRemediationError::GitError(format!(
                "Failed to spawn detached git worktree: {}",
                String::from_utf8_lossy(&add_out.stderr)
            )));
        }

        // Compute repo root canonical hash
        let mut hasher = Sha256::new();
        let canon_repo = repo_dir
            .canonicalize()
            .unwrap_or_else(|_| repo_dir.to_path_buf());
        hasher.update(canon_repo.display().to_string().as_bytes());
        let repo_root_hash = hex::encode(hasher.finalize());

        let marker = WorktreeMarker {
            marker_version: 1,
            created_at_unix_ms: Utc::now().timestamp_millis().max(0) as u64,
            pid: std::process::id(),
            repo_root_hash,
            target_ref: target_ref.to_string(),
            worktree_uuid: uuid.to_string(),
        };

        let marker_path = worktree_dir.join(".arc-worktree-marker.json");
        let marker_bytes = serde_json::to_vec_pretty(&marker)?;
        fs::write(&marker_path, marker_bytes)?;

        Ok(Self {
            worktree_dir,
            repo_dir: repo_dir.to_path_buf(),
            target_ref: target_ref.to_string(),
            uuid,
            marker_path,
            cleaned: false,
        })
    }

    /// Returns a reference to the worktree directory path.
    pub fn path(&self) -> &Path {
        &self.worktree_dir
    }

    /// Explicit cleanup of worktree and Git administrative metadata.
    pub fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;

        let _ = fs::remove_file(&self.marker_path);

        let _ = Command::new("git")
            .args([
                "worktree",
                "remove",
                "--force",
                self.worktree_dir.to_str().unwrap(),
            ])
            .current_dir(&self.repo_dir)
            .output();

        let _ = Command::new("git")
            .args(["worktree", "prune"])
            .current_dir(&self.repo_dir)
            .output();

        let _ = fs::remove_dir_all(&self.worktree_dir);
    }
}

impl Drop for DisposableWorktree {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---------------------------------------------------------------------------
// 5. 5-Point Stale Pruning Safety Contract
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PruneReport {
    pub scanned_directories: usize,
    pub pruned_directories: usize,
    pub skipped_directories: usize,
    pub pruned_paths: Vec<String>,
}

/// Scans OS temp for abandoned `arc-remediation-<uuid>` worktrees older than threshold,
/// enforcing all 5 safety checks before deleting:
/// 1. Canonical Path Containment: Must reside inside temp_dir().canonicalize().
/// 2. Strict Basename Format: ^arc-remediation-[0-9a-fA-F\-]{36}$
/// 3. Worktree & Project Marker: Contains .git and .arc-worktree-marker.json.
/// 4. Filesystem Ownership Check: Owned by current user / process.
/// 5. PID Liveness Check: Creating PID is dead.
pub fn prune_stale_remediation_worktrees(
    repo_dir: Option<&Path>,
    max_age_secs: u64,
) -> Result<PruneReport, ScaRemediationError> {
    let temp_dir = std::env::temp_dir();
    let canon_temp = temp_dir.canonicalize().unwrap_or_else(|_| temp_dir.clone());
    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let max_age_ms = max_age_secs.saturating_mul(1000);

    let mut report = PruneReport::default();

    let entries = match fs::read_dir(&canon_temp) {
        Ok(e) => e,
        Err(_) => return Ok(report),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let folder_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Check 2: Strict Basename Format (^arc-remediation-<uuid>$)
        let is_valid_uuid = folder_name
            .strip_prefix("arc-remediation-")
            .is_some_and(|uuid_str| Uuid::parse_str(uuid_str).is_ok());

        if !is_valid_uuid {
            continue;
        }

        report.scanned_directories += 1;

        // Check 1: Canonical Path Containment (Reject symlinks outside temp)
        let canon_path = match path.canonicalize() {
            Ok(cp) => cp,
            Err(_) => {
                report.skipped_directories += 1;
                continue;
            }
        };

        if !canon_path.starts_with(&canon_temp) {
            report.skipped_directories += 1;
            continue;
        }

        // Check 3: Worktree & Project Marker
        let marker_file = path.join(".arc-worktree-marker.json");
        let git_file = path.join(".git");

        if !marker_file.is_file() || !git_file.exists() {
            report.skipped_directories += 1;
            continue;
        }

        let marker_content = match fs::read_to_string(&marker_file) {
            Ok(c) => c,
            Err(_) => {
                report.skipped_directories += 1;
                continue;
            }
        };

        let marker: WorktreeMarker = match serde_json::from_str(&marker_content) {
            Ok(m) => m,
            Err(_) => {
                report.skipped_directories += 1;
                continue;
            }
        };

        // Check age: must be older than threshold
        if now_ms.saturating_sub(marker.created_at_unix_ms) < max_age_ms {
            report.skipped_directories += 1;
            continue;
        }

        // Optional matching repository hash check
        if let Some(r) = repo_dir {
            let mut hasher = Sha256::new();
            let canon_repo = r.canonicalize().unwrap_or_else(|_| r.to_path_buf());
            hasher.update(canon_repo.display().to_string().as_bytes());
            let expected_hash = hex::encode(hasher.finalize());
            if marker.repo_root_hash != expected_hash {
                report.skipped_directories += 1;
                continue;
            }
        }

        // Check 4: Filesystem Ownership Check
        if !is_owned_by_current_user(&path) {
            report.skipped_directories += 1;
            continue;
        }

        // Check 5: PID Liveness Check (Creator PID must be dead)
        if is_process_running(marker.pid) {
            report.skipped_directories += 1;
            continue;
        }

        // Enforce cleanup
        let _ = fs::remove_file(&marker_file);
        if let Some(r) = repo_dir {
            let _ = Command::new("git")
                .args(["worktree", "remove", "--force", path.to_str().unwrap()])
                .current_dir(r)
                .output();
            let _ = Command::new("git")
                .args(["worktree", "prune"])
                .current_dir(r)
                .output();
        }
        let _ = fs::remove_dir_all(&path);

        report.pruned_directories += 1;
        report.pruned_paths.push(path.display().to_string());
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// 6. Cross-Platform Process & Ownership Utilities
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
pub fn is_process_running(pid: u32) -> bool {
    type HANDLE = *mut std::ffi::c_void;
    type DWORD = u32;
    type BOOL = i32;

    const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
    const STILL_ACTIVE: DWORD = 259;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
        fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: DWORD = 0;
        let res = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        res != 0 && exit_code == STILL_ACTIVE
    }
}

#[cfg(unix)]
pub fn is_process_running(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(any(windows, unix)))]
pub fn is_process_running(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
pub fn is_owned_by_current_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = path.metadata() {
        meta.uid() == unsafe { libc::geteuid() }
    } else {
        false
    }
}

#[cfg(not(unix))]
pub fn is_owned_by_current_user(path: &Path) -> bool {
    if let Ok(meta) = path.metadata() {
        !meta.permissions().readonly()
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// 7. Full Disposable Worktree PR Creation Workflow (`run_worktree_pr_creation`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct WorktreePrOptions {
    pub base_branch: Option<String>,
    pub branch_name: Option<String>,
    pub target_repo: Option<String>,
    pub token: Option<String>,
    pub force_remote_base: bool,
    pub run_tests: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreePrResult {
    pub base_branch: String,
    pub branch_name: String,
    pub pr_url: Option<String>,
    pub pr_number: Option<u64>,
    pub committed: bool,
    pub pushed: bool,
    pub message: String,
    pub remediations_applied: usize,
}

/// Orchestrates the complete Pillar 4 consensual, disposable worktree PR creation flow:
/// 1. Divergence check between local HEAD and remote origin.
/// 2. Scans project for security remediations.
/// 3. Spawns detached worktree from validated remote ref.
/// 4. Applies in-place fixes into the worktree.
/// 5. Runs opt-in test suite if requested.
/// 6. Delegates single-branch creation, commit, push, and PR opening to `PrCreator`.
/// 7. Automatically cleans up worktree via RAII Drop.
pub async fn run_worktree_pr_creation(
    repo_dir: &Path,
    options: &WorktreePrOptions,
) -> Result<WorktreePrResult, ScaRemediationError> {
    // 1. Resolve base branch
    let base_branch = if let Some(ref b) = options.base_branch {
        b.clone()
    } else {
        let repo_info = PrCreator::detect_repo_info(repo_dir).ok();
        repo_info
            .map(|i| i.current_branch)
            .unwrap_or_else(|| "main".to_string())
    };

    // 2. Validate remote ref and divergence
    let divergence =
        check_remote_base_divergence(repo_dir, &base_branch, options.force_remote_base)?;

    // 3. Scan project for remediations
    let scan_opts = ScanOptions::default();
    let scan_out = scan_project(repo_dir, scan_opts)
        .await
        .map_err(ScaRemediationError::ScanError)?;

    if scan_out.remediations.is_empty() {
        return Ok(WorktreePrResult {
            base_branch: divergence.base_branch,
            branch_name: String::new(),
            pr_url: None,
            pr_number: None,
            committed: false,
            pushed: false,
            message: "No vulnerable packages require remediation; worktree creation skipped."
                .to_string(),
            remediations_applied: 0,
        });
    }

    // 4. Create detached worktree
    let mut worktree = DisposableWorktree::create(repo_dir, &divergence.remote_ref)?;

    // 5. Apply fixes in the isolated worktree
    let patch_res = apply_fixes(
        &worktree.worktree_dir,
        &scan_out.manifest_type,
        &scan_out.remediations,
        false,
    )
    .map_err(ScaRemediationError::PatchError)?;

    // 6. Optional test execution
    if options.run_tests {
        let test_cmd = match scan_out.manifest_type {
            ManifestType::RustCargoLock => Some(("cargo", vec!["test"])),
            ManifestType::NpmPackageLock | ManifestType::YarnLock | ManifestType::PnpmLock => {
                Some(("npm", vec!["test"]))
            }
            _ => None,
        };

        if let Some((exe, args)) = test_cmd {
            let test_out = Command::new(exe)
                .args(&args)
                .current_dir(&worktree.worktree_dir)
                .output()
                .map_err(|e| ScaRemediationError::TestsFailed(e.to_string()))?;

            if !test_out.status.success() {
                return Err(ScaRemediationError::TestsFailed(format!(
                    "Tests failed in remediation worktree: {}",
                    String::from_utf8_lossy(&test_out.stderr)
                )));
            }
        }
    }

    // 7. Delegate PR creation to PrCreator
    let pr_res: PrResult = PrCreator::create_and_open_pr(
        &worktree.worktree_dir,
        &patch_res,
        options.target_repo.clone(),
        options.branch_name.clone(),
        Some(divergence.base_branch.clone()),
        options.token.clone(),
        options.dry_run,
    )
    .await
    .map_err(ScaRemediationError::PrError)?;

    // 8. Explicit cleanup
    worktree.cleanup();

    Ok(WorktreePrResult {
        base_branch: divergence.base_branch,
        branch_name: pr_res.branch,
        pr_url: pr_res.pr_url,
        pr_number: pr_res.pr_number,
        committed: pr_res.committed,
        pushed: pr_res.pushed,
        message: pr_res.message,
        remediations_applied: scan_out.remediations.len(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_location_sanitization() {
        let sample_sarif = r#"{
          "version": "2.1.0",
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "runs": [
            {
              "tool": { "driver": { "name": "Vexa SCA" } },
              "results": [
                {
                  "ruleId": "GHSA-1234",
                  "message": { "text": "Vulnerable lodash dependency" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "src/auth/jwt_handler.ts" },
                        "region": {
                          "startLine": 42,
                          "startColumn": 12,
                          "endLine": 42,
                          "endColumn": 30,
                          "snippet": { "text": "import lodash from 'lodash';" }
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }"#;

        let sanitized = sanitize_sarif_locations(sample_sarif).expect("Sanitization must succeed");
        assert!(
            !sanitized.contains("jwt_handler.ts"),
            "Physical path must be pseudonymized"
        );
        assert!(
            !sanitized.contains("import lodash from"),
            "Source code snippet must be stripped"
        );
        assert!(
            !sanitized.contains("\"startLine\": 42"),
            "Line numbers must be suppressed"
        );
        assert!(
            sanitized.contains("GHSA-1234"),
            "Vulnerability rule ID must be preserved"
        );
        assert!(
            sanitized.contains("sanitized/"),
            "Pseudonymized prefix must be present"
        );
    }

    #[test]
    fn test_process_liveness_current_process() {
        let current_pid = std::process::id();
        assert!(
            is_process_running(current_pid),
            "Current process must be running"
        );
        assert!(
            !is_process_running(999_999_999),
            "Non-existent PID must not be running"
        );
    }

    #[test]
    fn test_unified_diff_generation() {
        let old = "name = \"app\"\nversion = \"1.0.0\"\nlodash = \"4.17.15\"\n";
        let new = "name = \"app\"\nversion = \"1.0.0\"\nlodash = \"4.17.21\"\n";
        let diff = generate_unified_diff("Cargo.toml", old, new);

        assert!(diff.contains("--- a/Cargo.toml"));
        assert!(diff.contains("+++ b/Cargo.toml"));
        assert!(diff.contains("-lodash = \"4.17.15\""));
        assert!(diff.contains("+lodash = \"4.17.21\""));
    }

    #[test]
    fn test_stale_worktree_safety_pruning_contract() {
        let temp_dir = std::env::temp_dir();
        let uuid = Uuid::new_v4();
        let valid_name = format!("arc-remediation-{uuid}");
        let candidate_dir = temp_dir.join(&valid_name);
        fs::create_dir_all(&candidate_dir).unwrap();

        // Write marker and fake .git
        fs::write(candidate_dir.join(".git"), b"gitdir: /fake/path").unwrap();
        let marker = WorktreeMarker {
            marker_version: 1,
            created_at_unix_ms: 1000, // Old timestamp
            pid: 999_999_999,         // Dead PID
            repo_root_hash: "dummy_hash".to_string(),
            target_ref: "refs/remotes/origin/main".to_string(),
            worktree_uuid: uuid.to_string(),
        };
        fs::write(
            candidate_dir.join(".arc-worktree-marker.json"),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        // Prune worktrees older than 10 seconds
        let report = prune_stale_remediation_worktrees(None, 10).unwrap();
        assert!(report.pruned_directories >= 1);
        assert!(
            !candidate_dir.exists(),
            "Stale orphaned worktree must be safely deleted"
        );
    }
}
