use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::detector::SecretFinding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSecretToken {
    pub token: String,                 // e.g. "<ARC_VAULT_SECRET_01>"
    pub secret_hash: [u8; 32],         // SHA-256 of raw secret
    pub detector: &'static str,        // e.g. "SEC-AWS-001"
    pub authorized_tools: Vec<String>, // Tools permitted to re-hydrate this secret
}

#[derive(Default)]
struct SessionVaultData {
    tokens: HashMap<String, Vec<u8>>,            // token -> raw_bytes
    metadata: HashMap<String, VaultSecretToken>, // token -> metadata
    counter: usize,
}

pub struct LocalPseudonymizationVault {
    session_vault: RwLock<HashMap<String, SessionVaultData>>,
}

impl Default for LocalPseudonymizationVault {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPseudonymizationVault {
    pub fn new() -> Self {
        Self {
            session_vault: RwLock::new(HashMap::new()),
        }
    }

    /// Redacts raw secrets from prompt/context into stable local vault tokens
    /// Returns the redacted content and the list of registered vault tokens.
    pub fn redact_and_vault(
        &self,
        session_id: &str,
        raw_content: &[u8],
        findings: &[SecretFinding],
    ) -> (Vec<u8>, Vec<VaultSecretToken>) {
        if findings.is_empty() {
            return (raw_content.to_vec(), Vec::new());
        }

        let mut guard = self.session_vault.write().unwrap();
        let session_data = guard.entry(session_id.to_string()).or_default();

        let mut output = Vec::new();
        let mut last_idx = 0;
        let mut created_tokens = Vec::new();

        for finding in findings {
            if finding.start < last_idx
                || finding.end > raw_content.len()
                || finding.start >= finding.end
            {
                continue;
            }

            // Push bytes before this secret
            output.extend_from_slice(&raw_content[last_idx..finding.start]);

            let secret_bytes = &raw_content[finding.start..finding.end];
            let mut hasher = Sha256::new();
            hasher.update(secret_bytes);
            let secret_hash: [u8; 32] = hasher.finalize().into();

            // Check if we already have a token for this identical secret in this session
            let existing_token = session_data
                .metadata
                .iter()
                .find(|(_, meta)| meta.secret_hash == secret_hash)
                .map(|(tok, _)| tok.clone());

            let token_str = if let Some(existing) = existing_token {
                existing
            } else {
                session_data.counter += 1;
                let new_tok = format!("<ARC_VAULT_SECRET_{:02}>", session_data.counter);
                let meta = VaultSecretToken {
                    token: new_tok.clone(),
                    secret_hash,
                    detector: finding.detector,
                    authorized_tools: Vec::new(),
                };
                session_data
                    .tokens
                    .insert(new_tok.clone(), secret_bytes.to_vec());
                session_data.metadata.insert(new_tok.clone(), meta);
                new_tok
            };

            output.extend_from_slice(token_str.as_bytes());
            if let Some(meta) = session_data.metadata.get(&token_str) {
                created_tokens.push(meta.clone());
            }

            last_idx = finding.end;
        }

        if last_idx < raw_content.len() {
            output.extend_from_slice(&raw_content[last_idx..]);
        }

        (output, created_tokens)
    }

    /// Authorizes a tool to rehydrate a specific token within a session.
    pub fn authorize_tool(&self, session_id: &str, token: &str, tool_name: &str) {
        if let Ok(mut guard) = self.session_vault.write() {
            if let Some(session_data) = guard.get_mut(session_id) {
                if let Some(meta) = session_data.metadata.get_mut(token) {
                    if !meta.authorized_tools.iter().any(|t| t == tool_name) {
                        meta.authorized_tools.push(tool_name.to_string());
                    }
                }
            }
        }
    }

    /// Re-hydrates token back to raw bytes ONLY if destination tool is explicitly authorized.
    pub fn rehydrate(&self, session_id: &str, token: &str, target_tool: &str) -> Option<Vec<u8>> {
        let guard = self.session_vault.read().ok()?;
        let session_data = guard.get(session_id)?;

        let meta = session_data.metadata.get(token)?;
        if meta.authorized_tools.iter().any(|t| t == target_tool) {
            session_data.tokens.get(token).cloned()
        } else {
            None
        }
    }

    /// Clears data for a session when the session terminates.
    pub fn clear_session(&self, session_id: &str) {
        if let Ok(mut guard) = self.session_vault.write() {
            guard.remove(session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_redaction_and_rehydration() {
        let vault = LocalPseudonymizationVault::new();
        let session = "test_sess_01";
        let content = b"export AWS_KEY=AKIAIOSFODNN7EXAMPLE in profile";

        let finding = SecretFinding {
            detector: "SEC-AWS-001",
            start: 15,
            end: 35,
            confidence: 95,
            snippet: "AKIA...MPLE".to_string(),
        };

        let (redacted, tokens) = vault.redact_and_vault(session, content, &[finding]);
        let redacted_str = String::from_utf8(redacted).unwrap();

        assert_eq!(
            redacted_str,
            "export AWS_KEY=<ARC_VAULT_SECRET_01> in profile"
        );
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, "<ARC_VAULT_SECRET_01>");

        // Rehydration unauthorized
        let result_unauth = vault.rehydrate(session, "<ARC_VAULT_SECRET_01>", "curl_post");
        assert!(result_unauth.is_none());

        // Authorize tool
        vault.authorize_tool(session, "<ARC_VAULT_SECRET_01>", "local_aws_cli");

        // Rehydration authorized
        let result_auth = vault.rehydrate(session, "<ARC_VAULT_SECRET_01>", "local_aws_cli");
        assert_eq!(result_auth, Some(b"AKIAIOSFODNN7EXAMPLE".to_vec()));
    }
}
