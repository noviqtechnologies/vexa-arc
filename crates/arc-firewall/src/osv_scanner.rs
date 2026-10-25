//! # OSV/EPSS Vulnerability Scanner Integration — FR-PKG-005 & FR-PKG-006
//!
//! Provides [`OsvPackageScanner`] which wraps `vexa_sca::VulnScanner` to deliver:
//! - **FR-PKG-005 (P0):** OSV batch-query + EPSS scoring with 24-hour `.sca-cache` fallback
//!   (air-gapped safe; only public package coordinates are queried).
//! - **FR-PKG-006 (P1):** Structured JSON-RPC-style inline remediation:
//!   `{"error": "Vulnerable package {name}@{version}; update constraint to >={safe}"}`.
//!
//! ## Cross-platform notes
//! The `.sca-cache` directory is created relative to the current working directory on all
//! platforms (Windows, Linux, macOS) and requires no OS-specific code.

use serde::Serialize;
use std::path::Path;
use vexa_sca::core::dep_graph::{DepGraph, PkgManagerInfo};
use vexa_sca::scanner::cache::VulnCache;
use vexa_sca::scanner::vuln_scanner::VulnScanner;
use vexa_sca::types::{PkgInfo, RemediationAction, SeverityLevel, VulnerabilityFinding};

/// Rule identifier for OSV/EPSS vulnerability findings.
pub const RULE_ID: &str = "ARC-SCA-001";

/// The minimum EPSS percentile (0-1.0) above which a vulnerability is considered
/// actively exploited. Matches the PRD NFR gate for EPSS filtering.
pub const EPSS_ALERT_THRESHOLD: f64 = 0.7;

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/// Severity-level bridge: maps `vexa_sca::SeverityLevel` to a simple `&str`
/// without introducing a trait dependency in callers.
fn severity_str(level: SeverityLevel) -> &'static str {
    match level {
        SeverityLevel::Critical => "CRITICAL",
        SeverityLevel::High => "HIGH",
        SeverityLevel::Medium => "MEDIUM",
        SeverityLevel::Low => "LOW",
        SeverityLevel::Unknown => "UNKNOWN",
    }
}

/// A single vulnerability finding with structured remediation advice.
///
/// This is the outer type returned to `arc-firewall` callers; it mirrors
/// `vexa_sca::VulnerabilityFinding` but is decoupled from it so that the
/// rest of `arc-firewall` does not need `vexa-sca` imports.
#[derive(Debug, Clone, Serialize)]
pub struct PackageVulnFinding {
    /// OSV advisory ID (e.g. `GHSA-xxxx-xxxx-xxxx`).
    pub advisory_id: String,
    /// Package name.
    pub package: String,
    /// Installed version.
    pub version: String,
    /// Ecosystem (e.g. `npm`, `PyPI`, `crates.io`).
    pub ecosystem: String,
    /// Human-readable severity label.
    pub severity: &'static str,
    /// CVSS base score.
    pub cvss_score: f64,
    /// EPSS probability score (0.0-1.0), if available.
    pub epss_score: Option<f64>,
    /// Whether the vulnerable code path is reachable from project entry points.
    pub is_reachable: bool,
    /// Fixed-in version strings from OSV.
    pub fixed_in: Vec<String>,
    /// Structured inline remediation message for JSON-RPC error responses.
    /// Format: `"Vulnerable package {name}@{version}; update constraint to >={safe}"`.
    pub remediation_message: String,
    /// JSON-RPC-formatted error payload (FR-PKG-006).
    pub jsonrpc_error: String,
}

impl PackageVulnFinding {
    pub(crate) fn build(
        finding: &VulnerabilityFinding,
        remediation: Option<&RemediationAction>,
    ) -> Self {
        let severity = severity_str(finding.severity.level);
        let epss_score = finding.epss.as_ref().map(|e| e.score);

        let is_reachable = finding
            .reachability
            .as_ref()
            .map(|r| r.status == vexa_sca::types::ReachabilityStatus::Reachable)
            .unwrap_or(false);

        // Build the remediation message (FR-PKG-006)
        let safe_version = remediation
            .and_then(|r| r.target_version.as_deref())
            .or_else(|| finding.fixed_in.last().map(|s| s.as_str()))
            .unwrap_or("a patched version");

        let remediation_message = format!(
            "Vulnerable package {}@{}; update constraint to >={}",
            finding.package, finding.version, safe_version
        );

        let jsonrpc_error = serde_json::json!({
            "error": remediation_message,
            "rule_id": RULE_ID,
            "advisory": finding.id,
            "severity": severity,
            "epss_score": epss_score,
            "is_reachable": is_reachable,
        })
        .to_string();

        PackageVulnFinding {
            advisory_id: finding.id.clone(),
            package: finding.package.clone(),
            version: finding.version.clone(),
            ecosystem: finding.ecosystem.clone(),
            severity,
            cvss_score: finding.severity.score,
            epss_score,
            is_reachable,
            fixed_in: finding.fixed_in.clone(),
            remediation_message,
            jsonrpc_error,
        }
    }
}

/// Result of a single-package OSV scan, as returned by [`OsvPackageScanner::scan_package`].
#[derive(Debug, Clone, Serialize)]
pub struct PackageScanResult {
    /// Package that was scanned.
    pub package: String,
    /// Version that was scanned.
    pub version: String,
    /// Whether the advisory database was reachable (or served from cache).
    pub advisory_available: bool,
    /// All vulnerability findings for this package, sorted by severity (highest first).
    pub findings: Vec<PackageVulnFinding>,
    /// True if any finding is CRITICAL or HIGH severity.
    pub has_critical_or_high: bool,
    /// True if any finding exceeds the EPSS alert threshold.
    pub has_high_epss: bool,
    /// True if any finding is reachable from project entry points.
    pub has_reachable: bool,
}

impl PackageScanResult {
    /// Returns `true` when the scan result should block a package installation
    /// (i.e., any CRITICAL/HIGH severity or high-EPSS finding is present).
    pub fn should_block(&self) -> bool {
        self.has_critical_or_high || self.has_high_epss
    }

    /// Returns a single aggregated JSON-RPC error payload for all findings,
    /// formatted for inline agent remediation (FR-PKG-006).
    pub fn aggregate_jsonrpc_error(&self) -> Option<String> {
        if self.findings.is_empty() {
            return None;
        }
        // Use the first (highest severity) finding as the primary signal.
        Some(self.findings[0].jsonrpc_error.clone())
    }
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Cross-platform OSV/EPSS vulnerability scanner for single packages.
///
/// Internally uses `vexa_sca::VulnScanner` with a `.sca-cache` directory
/// for 24-hour air-gapped caching.  Only public package coordinates
/// (name + version + ecosystem) are sent to OSV; no source code leaves
/// the host (100% payload locality).
pub struct OsvPackageScanner {
    scanner: VulnScanner,
}

impl Default for OsvPackageScanner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl OsvPackageScanner {
    /// Creates a new scanner with the given cache directory.
    ///
    /// If `cache_dir` is `None` the default `.sca-cache` in the current
    /// working directory is used, enabling air-gapped / offline operation
    /// after the first successful query.
    pub fn new(cache_dir: Option<&Path>) -> Self {
        let cache = match cache_dir {
            Some(dir) => VulnCache::new(dir),
            None => VulnCache::default(),
        };
        Self {
            scanner: VulnScanner::new(Some(cache)),
        }
    }

    /// Scans a single package by name + version + ecosystem.
    ///
    /// This is a synchronous wrapper that spawns a one-shot Tokio runtime
    /// so that `arc-firewall`'s synchronous `PackageFirewall` path can call it
    /// without itself needing to be async.
    ///
    /// # Errors
    /// Returns `Err(String)` when the Tokio runtime cannot be created.
    pub fn scan_package(
        &self,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<PackageScanResult, String> {
        let pkg = PkgInfo::new(name, version, ecosystem);
        let mgr = PkgManagerInfo {
            name: ecosystem.to_string(),
            version: "0".to_string(),
        };
        let mut graph = DepGraph::new(pkg.clone(), mgr);
        graph.add_pkg(pkg);

        // Build a minimal single-threaded Tokio runtime for the async scan.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create Tokio runtime: {e}"))?;

        let scan_result = rt
            .block_on(self.scanner.scan_graph(&graph))
            .map_err(|e| format!("OSV scan error: {e}"))?;

        // Generate remediations for matched vulnerabilities.
        let remediations = vexa_sca::scanner::remediator::Remediator::generate_remediation(
            &scan_result.vulnerabilities,
        );

        let advisory_available = !scan_result.advisory_status.is_service_unavailable();

        let mut findings: Vec<PackageVulnFinding> = scan_result
            .vulnerabilities
            .iter()
            .map(|v| {
                let rem = remediations.iter().find(|r| r.package == v.package);
                PackageVulnFinding::build(v, rem)
            })
            .collect();

        // Sort highest severity first (CVSS descending).
        findings.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let has_critical_or_high = findings
            .iter()
            .any(|f| matches!(f.severity, "CRITICAL" | "HIGH"));
        let has_high_epss = findings
            .iter()
            .any(|f| f.epss_score.unwrap_or(0.0) >= EPSS_ALERT_THRESHOLD);
        let has_reachable = findings.iter().any(|f| f.is_reachable);

        Ok(PackageScanResult {
            package: name.to_string(),
            version: version.to_string(),
            advisory_available,
            findings,
            has_critical_or_high,
            has_high_epss,
            has_reachable,
        })
    }

    /// Convenience method: scan a package and return the aggregated JSON-RPC
    /// error string if any blocking vulnerability is found.
    ///
    /// Returns `None` only when the package was scanned with advisory data and is clean.
    /// Scan errors or an unavailable advisory database yield an error string (fail closed).
    pub fn blocking_error(&self, name: &str, version: &str, ecosystem: &str) -> Option<String> {
        match self.scan_package(name, version, ecosystem) {
            Ok(result) if !result.advisory_available => Some(format!(
                "OSV scan incomplete for {name}@{version}: advisory database unavailable"
            )),
            Ok(result) if result.should_block() => result.aggregate_jsonrpc_error(),
            Ok(_) => None,
            Err(e) => Some(format!("OSV scan failed for {name}@{version}: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Ecosystem bridging helper (arc-core Ecosystem -> vexa-sca ecosystem string)
// ---------------------------------------------------------------------------

/// Maps an `arc_core::event::Ecosystem` to the OSV ecosystem string expected
/// by `vexa-sca`.
pub fn ecosystem_to_osv_str(eco: arc_core::event::Ecosystem) -> &'static str {
    match eco {
        arc_core::event::Ecosystem::Npm => "npm",
        arc_core::event::Ecosystem::Pypi => "PyPI",
        arc_core::event::Ecosystem::Cargo => "crates.io",
        arc_core::event::Ecosystem::Go => "Go",
    }
}

// ---------------------------------------------------------------------------
// Unit tests (FR-PKG-005 & FR-PKG-006)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_cache_dir() -> PathBuf {
        // Use a temp sub-folder so tests don't pollute the project's .sca-cache.
        std::env::temp_dir().join("arc-firewall-test-sca-cache")
    }

    fn scanner() -> OsvPackageScanner {
        OsvPackageScanner::new(Some(&test_cache_dir()))
    }

    /// FR-PKG-005: A clean package returns no blocking findings.
    #[test]
    fn test_clean_package_no_block() {
        let sc = scanner();
        // Unknown package with no OSV entries should not block.
        let result = sc
            .scan_package("made-up-clean-package", "9.9.9", "npm")
            .expect("scan should not panic");
        assert!(
            !result.should_block(),
            "Unknown package with no OSV hits should not block"
        );
    }

    /// FR-PKG-006: `aggregate_jsonrpc_error` produces a valid JSON string when
    /// findings are injected directly (unit-level, no network needed).
    #[test]
    fn test_jsonrpc_error_format() {
        let finding = VulnerabilityFinding {
            id: "GHSA-test-0001-xxxx".to_string(),
            title: "Test XSS".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: vexa_sca::types::SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            fixed_in: vec!["4.17.21".to_string()],
            ..Default::default()
        };

        let pv = PackageVulnFinding::build(&finding, None);

        assert_eq!(pv.severity, "HIGH");
        assert!(
            pv.remediation_message.contains("lodash@4.17.15"),
            "Message must contain package@version: {}",
            pv.remediation_message
        );
        assert!(
            pv.remediation_message.contains(">=4.17.21"),
            "Message must contain safe version constraint: {}",
            pv.remediation_message
        );

        // Must be valid JSON with an "error" field.
        let parsed: serde_json::Value =
            serde_json::from_str(&pv.jsonrpc_error).expect("jsonrpc_error must be valid JSON");
        assert!(
            parsed["error"].is_string(),
            "jsonrpc_error must have an 'error' string field"
        );
        assert_eq!(parsed["rule_id"], RULE_ID);
        assert_eq!(parsed["severity"], "HIGH");
    }

    /// FR-PKG-005: ecosystem_to_osv_str covers all arc-core ecosystems.
    #[test]
    fn test_ecosystem_to_osv_str() {
        assert_eq!(ecosystem_to_osv_str(arc_core::event::Ecosystem::Npm), "npm");
        assert_eq!(
            ecosystem_to_osv_str(arc_core::event::Ecosystem::Pypi),
            "PyPI"
        );
        assert_eq!(
            ecosystem_to_osv_str(arc_core::event::Ecosystem::Cargo),
            "crates.io"
        );
        assert_eq!(ecosystem_to_osv_str(arc_core::event::Ecosystem::Go), "Go");
    }

    /// FR-PKG-006: `PackageScanResult::aggregate_jsonrpc_error` returns None for
    /// a clean scan and Some for a scan with findings.
    #[test]
    fn test_aggregate_jsonrpc_error_empty() {
        let clean = PackageScanResult {
            package: "clean".to_string(),
            version: "1.0.0".to_string(),
            advisory_available: true,
            findings: vec![],
            has_critical_or_high: false,
            has_high_epss: false,
            has_reachable: false,
        };
        assert!(clean.aggregate_jsonrpc_error().is_none());
        assert!(!clean.should_block());
    }

    /// Integration smoke-test: scan a well-known safe modern package.
    /// Skipped silently when OSV is unreachable (advisory_available == false).
    #[test]
    fn test_scan_tokio_latest_smoke() {
        let sc = scanner();
        let result = sc
            .scan_package("tokio", "1.45.0", "crates.io")
            .expect("scan should not return Err");
        if result.advisory_available {
            assert!(
                !result.has_critical_or_high,
                "tokio 1.45.0 should have no CRITICAL/HIGH findings; got: {:?}",
                result
                    .findings
                    .iter()
                    .map(|f| &f.advisory_id)
                    .collect::<Vec<_>>()
            );
        }
        assert!(!result.should_block(), "tokio 1.45.0 should not block");
    }
}
