use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRegistryMetadata {
    pub name: String,
    pub ecosystem: String,
    pub age_days: u32,
    pub monthly_downloads: u64,
    pub has_verified_repository_link: bool,
    pub repository_stars: u32,
    pub repository_commits: u32,
    pub has_slsa_provenance: bool,
    pub has_dangerous_lifecycle_scripts: bool,
    pub recent_registry_404: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SlopsquatVerdict {
    Permitted {
        reason: &'static str,
    },
    Review {
        gate: &'static str,
        reason: String,
        containment_recommendation: String,
    },
    Blocked {
        gate: &'static str,
        reason: String,
    },
}

impl SlopsquatVerdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, SlopsquatVerdict::Blocked { .. })
    }

    pub fn requires_review(&self) -> bool {
        matches!(self, SlopsquatVerdict::Review { .. })
    }

    pub fn is_permitted(&self) -> bool {
        matches!(self, SlopsquatVerdict::Permitted { .. })
    }

    /// Provides actionable remediation guidance based on the evaluation verdict and package ecosystem.
    pub fn suggested_action(&self, ecosystem: &str) -> Option<String> {
        match self {
            SlopsquatVerdict::Permitted { .. } => None,
            SlopsquatVerdict::Review { containment_recommendation, .. } => {
                Some(containment_recommendation.clone())
            }
            SlopsquatVerdict::Blocked { gate, reason } => match *gate {
                "CompoundTyposquatGate" => {
                    if let Some(target) = reason.split("of '").nth(1).and_then(|s| s.split('\'').next()) {
                        let install_cmd = match ecosystem.to_lowercase().as_str() {
                            "pypi" | "pip" => format!("pip install {target}"),
                            "cargo" | "rust" => format!("cargo add {target}"),
                            "go" => format!("go get {target}"),
                            _ => format!("npm install {target}"),
                        };
                        Some(format!("Did you mean: '{target}'? Run: {install_cmd}"))
                    } else {
                        Some("Verify spelling against official registry package listings.".to_string())
                    }
                }
                "CompoundLifecycleGate" => Some(
                    "Inspect package lifecycle scripts (preinstall/postinstall/setup.py). Run with --ignore-scripts if safe."
                        .to_string(),
                ),
                "CompoundPhantomGate" => Some(
                    "Verify dependency name; package matches hallucination/phantom watchlist with recent 404 records."
                        .to_string(),
                ),
                "CompoundProvenanceGate" => Some(
                    "Verify author source repository, commits, and SLSA provenance before allowing install."
                        .to_string(),
                ),
                _ => Some("Review package safety and registry provenance before proceeding.".to_string()),
            },
        }
    }
}

pub struct CompoundAntiSlopsquatEngine {
    popular_packages: Vec<String>,
}

impl Default for CompoundAntiSlopsquatEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CompoundAntiSlopsquatEngine {
    pub fn new() -> Self {
        // Representative seed list of highly targeted packages across npm, pypi, cargo
        let popular = vec![
            "react",
            "react-dom",
            "lodash",
            "express",
            "axios",
            "request",
            "next",
            "vue",
            "angular",
            "typescript",
            "chalk",
            "commander",
            "webpack",
            "babel",
            "eslint",
            "prettier",
            "jest",
            "mocha",
            "socket.io",
            "async",
            "requests",
            "numpy",
            "pandas",
            "scipy",
            "flask",
            "django",
            "urllib3",
            "cryptography",
            "pytest",
            "boto3",
            "torch",
            "tensorflow",
            "pydantic",
            "serde",
            "tokio",
            "syn",
            "quote",
            "rand",
            "regex",
            "clap",
            "anyhow",
        ];

        Self {
            popular_packages: popular.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn with_popular_packages(packages: Vec<String>) -> Self {
        Self {
            popular_packages: packages,
        }
    }

    /// Checks if a package name is in the known standard popular package baseline
    pub fn is_popular_package(&self, name: &str) -> bool {
        self.popular_packages
            .iter()
            .any(|p| p.eq_ignore_ascii_case(name))
    }

    /// Evaluates candidate package metadata using the 4-gate compound anti-slopsquatting engine.
    pub fn evaluate(&self, metadata: &PackageRegistryMetadata) -> SlopsquatVerdict {
        // Fast Path (< 1.5 ms): Curated standard popular packages pass immediately unless dangerous scripts detected
        if self.is_popular_package(&metadata.name) && !metadata.has_dangerous_lifecycle_scripts {
            return SlopsquatVerdict::Permitted {
                reason: "Verified standard package from official popular dependency baseline",
            };
        }

        // Fast Path (< 1.5 ms): Established package names with proven history pass immediately
        if metadata.age_days > 30
            && metadata.monthly_downloads > 1_000
            && metadata.has_verified_repository_link
        {
            return SlopsquatVerdict::Permitted {
                reason: "Established package with proven registry history and verified provenance",
            };
        }

        // Compound Block Gate: Newly registered package name (< 14 days AND < 500 downloads)
        // AND triggers at least one high-risk compound indicator:
        if metadata.age_days < 14 && metadata.monthly_downloads < 500 {
            // Indicator 1: Dangerous Install Lifecycle Scripts (preinstall/postinstall/setup.py shell exec)
            if metadata.has_dangerous_lifecycle_scripts {
                return SlopsquatVerdict::Blocked {
                    gate: "CompoundLifecycleGate",
                    reason: format!(
                        "New package '{}' attempts arbitrary shell/network execution in install lifecycle scripts",
                        metadata.name
                    ),
                };
            }

            // Indicator 2: Phantom Registry Watchlist
            if metadata.recent_registry_404 {
                return SlopsquatVerdict::Blocked {
                    gate: "CompoundPhantomGate",
                    reason: format!(
                        "Package '{}' matches known phantom package name returning recent 404 / LLM hallucination watchlist",
                        metadata.name
                    ),
                };
            }

            // Indicator 3: Hallucination / Typosquat Distance (Levenshtein <= 2 or Jaro-Winkler >= 0.92)
            for popular in &self.popular_packages {
                if &metadata.name != popular {
                    let jw = strsim::jaro_winkler(&metadata.name, popular);
                    let lev = strsim::levenshtein(&metadata.name, popular);
                    if jw >= 0.92 || lev <= 2 {
                        return SlopsquatVerdict::Blocked {
                            gate: "CompoundTyposquatGate",
                            reason: format!(
                                "Package '{}' is a suspected hallucination/typosquat of '{}' (similarity: {:.2}, edit_distance: {}, age: {}d, downloads: {})",
                                metadata.name, popular, jw, lev, metadata.age_days, metadata.monthly_downloads
                            ),
                        };
                    }
                }
            }

            // Indicator 4: Missing or Spoofed Source Provenance
            if !metadata.has_verified_repository_link
                || (metadata.repository_stars == 0 && metadata.repository_commits == 0)
            {
                return SlopsquatVerdict::Blocked {
                    gate: "CompoundProvenanceGate",
                    reason: format!(
                        "New package '{}' lacks verified source repository provenance (0 stars, 0 commits, unverified repo link)",
                        metadata.name
                    ),
                };
            }
        }

        SlopsquatVerdict::Permitted {
            reason: "Passed all anti-slopsquatting compound security gates",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_established_package_fast_path() {
        let engine = CompoundAntiSlopsquatEngine::new();
        let meta = PackageRegistryMetadata {
            name: "react".to_string(),
            ecosystem: "npm".to_string(),
            age_days: 3000,
            monthly_downloads: 50_000_000,
            has_verified_repository_link: true,
            repository_stars: 200_000,
            repository_commits: 15_000,
            has_slsa_provenance: true,
            has_dangerous_lifecycle_scripts: false,
            recent_registry_404: false,
        };

        let verdict = engine.evaluate(&meta);
        assert!(!verdict.is_blocked());
    }

    #[test]
    fn test_slopsquat_typosquat_blocked() {
        let engine = CompoundAntiSlopsquatEngine::new();
        // Candidate: 'reactt' (Levenshtein 1 from 'react')
        let meta = PackageRegistryMetadata {
            name: "reactt".to_string(),
            ecosystem: "npm".to_string(),
            age_days: 2,
            monthly_downloads: 12,
            has_verified_repository_link: true,
            repository_stars: 1,
            repository_commits: 1,
            has_slsa_provenance: false,
            has_dangerous_lifecycle_scripts: false,
            recent_registry_404: false,
        };

        let verdict = engine.evaluate(&meta);
        assert!(verdict.is_blocked());
        if let SlopsquatVerdict::Blocked { gate, reason } = verdict {
            assert_eq!(gate, "CompoundTyposquatGate");
            assert!(reason.contains("reactt"));
            assert!(reason.contains("react"));
        }
    }

    #[test]
    fn test_slopsquat_lifecycle_blocked() {
        let engine = CompoundAntiSlopsquatEngine::new();
        let meta = PackageRegistryMetadata {
            name: "super-niche-unique-lib".to_string(),
            ecosystem: "npm".to_string(),
            age_days: 3,
            monthly_downloads: 5,
            has_verified_repository_link: true,
            repository_stars: 10,
            repository_commits: 5,
            has_slsa_provenance: false,
            has_dangerous_lifecycle_scripts: true,
            recent_registry_404: false,
        };

        let verdict = engine.evaluate(&meta);
        assert!(verdict.is_blocked());
        if let SlopsquatVerdict::Blocked { gate, .. } = verdict {
            assert_eq!(gate, "CompoundLifecycleGate");
        }
    }

    #[test]
    fn test_slopsquat_phantom_404_blocked() {
        let engine = CompoundAntiSlopsquatEngine::new();
        let meta = PackageRegistryMetadata {
            name: "color-diff-ts".to_string(),
            ecosystem: "npm".to_string(),
            age_days: 1,
            monthly_downloads: 2,
            has_verified_repository_link: true,
            repository_stars: 10,
            repository_commits: 5,
            has_slsa_provenance: false,
            has_dangerous_lifecycle_scripts: false,
            recent_registry_404: true,
        };

        let verdict = engine.evaluate(&meta);
        assert!(verdict.is_blocked());
        if let SlopsquatVerdict::Blocked { gate, .. } = verdict {
            assert_eq!(gate, "CompoundPhantomGate");
        }
    }

    #[test]
    fn test_suggested_action_typosquat_and_lifecycle() {
        let typo = SlopsquatVerdict::Blocked {
            gate: "CompoundTyposquatGate",
            reason: "Package 'reactt' is a suspected hallucination/typosquat of 'react' (similarity: 0.97, edit_distance: 1, age: 2d, downloads: 12)".to_string(),
        };
        let act = typo.suggested_action("npm");
        assert!(act.is_some());
        assert!(act.unwrap().contains("npm install react"));

        let lifecycle = SlopsquatVerdict::Blocked {
            gate: "CompoundLifecycleGate",
            reason: "New package 'evil-pkg' attempts arbitrary shell/network execution".to_string(),
        };
        let act_life = lifecycle.suggested_action("pypi");
        assert!(act_life.is_some());
        assert!(act_life.unwrap().contains("--ignore-scripts"));

        let permitted = SlopsquatVerdict::Permitted { reason: "Passed" };
        assert!(permitted.suggested_action("npm").is_none());
    }
}
