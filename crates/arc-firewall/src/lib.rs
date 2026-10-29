pub mod osv_scanner;
pub mod proxy;
pub mod remediation;
pub mod slopsquat;

pub use osv_scanner::{
    ecosystem_to_osv_str, OsvPackageScanner, PackageScanResult, PackageVulnFinding,
    EPSS_ALERT_THRESHOLD, RULE_ID,
};
pub use proxy::PackageFirewall;
pub use remediation::{
    check_remote_base_divergence, prune_stale_remediation_worktrees, run_sca_audit,
    run_scratch_diff, run_worktree_pr_creation, sanitize_sarif_locations, DisposableWorktree,
    DivergenceCheckResult, PruneReport, ScaAuditOptions, ScaAuditResult, ScaRemediationError,
    ScratchDiffResult, WorktreeMarker, WorktreePrOptions, WorktreePrResult,
};
pub use slopsquat::{CompoundAntiSlopsquatEngine, PackageRegistryMetadata, SlopsquatVerdict};
