use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::entropy::shannon_entropy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub detector: &'static str,
    pub start: usize,
    pub end: usize,
    pub confidence: u8, // 0 - 100
    pub snippet: String,
}

pub struct SecretScanEngine {
    ac: AhoCorasick,
    regex_aws_key: Regex,
    regex_aws_secret: Regex,
    regex_github_pat: Regex,
    regex_github_fine: Regex,
    regex_anthropic: Regex,
    regex_openai: Regex,
    regex_slack: Regex,
    regex_private_key: Regex,
    regex_jwt: Regex,
}

impl Default for SecretScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretScanEngine {
    pub fn new() -> Self {
        let patterns = vec![
            "AKIA",
            "ghp_",
            "github_pat_",
            "sk-ant-api",
            "sk-proj-",
            "xoxb-",
            "-----BEGIN ",
            "eyJ",
        ];

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        Self {
            ac,
            regex_aws_key: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            regex_aws_secret: Regex::new(r#"(?i)(?:aws_secret_access_key|secret_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
            regex_github_pat: Regex::new(r"\bghp_[0-9a-zA-Z]{36}\b").unwrap(),
            regex_github_fine: Regex::new(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b").unwrap(),
            regex_anthropic: Regex::new(r"\bsk-ant-api[0-9a-zA-Z_-]{40,}\b").unwrap(),
            regex_openai: Regex::new(r"\bsk-proj-[0-9a-zA-Z_-]{40,}\b").unwrap(),
            regex_slack: Regex::new(r"\bxoxb-[0-9]{10,13}-[0-9a-zA-Z]{24}\b").unwrap(),
            regex_private_key: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
            regex_jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap(),
        }
    }

    /// Scans a byte buffer and returns all confirmed secret findings.
    /// Fast-path uses Aho-Corasick prefiltering before invoking anchored regex and entropy checks.
    pub fn scan(&self, data: &[u8]) -> Vec<SecretFinding> {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Stage 1: Quick Aho-Corasick check
        let has_any_match = self.ac.find(data).is_some();
        if !has_any_match {
            // Also check for aws_secret_access_key if not caught by keyword
            if !text.contains("aws_secret") && !text.contains("secret_key") {
                return findings;
            }
        }

        // AWS Access Key ID
        for mat in self.regex_aws_key.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-AWS-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 95,
                snippet: format!("AKIA...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // AWS Secret Key
        for cap in self.regex_aws_secret.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let secret_cand = mat.as_str();
                if shannon_entropy(secret_cand.as_bytes()) >= 4.2 {
                    findings.push(SecretFinding {
                        detector: "SEC-AWS-002",
                        start: mat.start(),
                        end: mat.end(),
                        confidence: 90,
                        snippet: format!(
                            "{}...{}",
                            &secret_cand[..4],
                            &secret_cand[secret_cand.len() - 4..]
                        ),
                    });
                }
            }
        }

        // GitHub PAT
        for mat in self.regex_github_pat.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-GTH-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 98,
                snippet: format!("ghp_...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // GitHub Fine-grained PAT
        for mat in self.regex_github_fine.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-GTH-002",
                start: mat.start(),
                end: mat.end(),
                confidence: 99,
                snippet: format!("github_pat_...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // Anthropic Key
        for mat in self.regex_anthropic.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-ANT-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 95,
                snippet: format!("sk-ant-...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // OpenAI Key
        for mat in self.regex_openai.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-OAI-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 95,
                snippet: format!("sk-proj-...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // Slack Key
        for mat in self.regex_slack.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-SLK-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 95,
                snippet: format!("xoxb-...{}", &text[mat.end() - 4..mat.end()]),
            });
        }

        // Private Keys
        for mat in self.regex_private_key.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-PRV-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 100,
                snippet: "-----BEGIN PRIVATE KEY-----...".to_string(),
            });
        }

        // JWT
        for mat in self.regex_jwt.find_iter(text) {
            findings.push(SecretFinding {
                detector: "SEC-JWT-001",
                start: mat.start(),
                end: mat.end(),
                confidence: 85,
                snippet: format!("eyJ...{}", &text[mat.end() - 6..mat.end()]),
            });
        }

        // Sort by start position
        findings.sort_by_key(|f| f.start);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_detector_matches() {
        let engine = SecretScanEngine::new();

        let sample = "Here is an AWS key: AKIAIOSFODNN7EXAMPLE and GitHub ghp_111122223333444455556666777788889999.";
        let findings = engine.scan(sample.as_bytes());

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].detector, "SEC-AWS-001");
        assert_eq!(findings[1].detector, "SEC-GTH-001");
    }

    #[test]
    fn test_secret_detector_clean_text() {
        let engine = SecretScanEngine::new();
        let sample = "This is a clean developer prompt with no credentials or secrets.";
        let findings = engine.scan(sample.as_bytes());
        assert!(findings.is_empty());
    }
}
