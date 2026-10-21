use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Low,      // 0–249 (Default: Permitted)
    Medium,   // 250–499 (Default: Staged for review)
    High,     // 500–749 (Default: Auto-flag/block per policy)
    Critical, // 750–1000 (Default: Hard quarantine)
}

impl RiskBand {
    pub fn from_score(score: u16) -> Self {
        match score {
            0..=249 => RiskBand::Low,
            250..=499 => RiskBand::Medium,
            500..=749 => RiskBand::High,
            _ => RiskBand::Critical,
        }
    }
}

/// 3D Capability Profile mapping the Lethal Trifecta
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mcp3DCapabilityProfile {
    pub private_data_exposure: u16,    // 0–1000
    pub untrusted_content_ingest: u16, // 0–1000
    pub destructive_capabilities: u16, // 0–1000
    pub composite_risk_score: u16,     // 0–1000
    pub band: RiskBand,
    pub canonical_schema_hash: [u8; 32], // RFC 8785 JCS canonical SHA-256 hash
}

impl Mcp3DCapabilityProfile {
    pub fn calculate(
        private_data_exposure: u16,
        untrusted_content_ingest: u16,
        destructive_capabilities: u16,
        canonical_schema_hash: [u8; 32],
    ) -> Self {
        let p = private_data_exposure.min(1000) as u32;
        let u = untrusted_content_ingest.min(1000) as u32;
        let d = destructive_capabilities.min(1000) as u32;

        // Weighted composite calculation: private data (35%), untrusted ingest (30%), destructive (35%)
        let composite = ((p * 35 + u * 30 + d * 35) / 100).min(1000) as u16;
        let band = RiskBand::from_score(composite);

        Self {
            private_data_exposure: p as u16,
            untrusted_content_ingest: u as u16,
            destructive_capabilities: d as u16,
            composite_risk_score: composite,
            band,
            canonical_schema_hash,
        }
    }
}

/// Canonical RFC 8785 JSON Canonicalization Scheme (JCS) tool hashing for rug-pull detection
pub fn compute_jcs_schema_hash(tools_json: &[u8]) -> Result<[u8; 32], String> {
    let value: serde_json::Value =
        serde_json::from_slice(tools_json).map_err(|e| format!("Invalid JSON: {e}"))?;
    let canonical_bytes =
        serde_jcs::to_vec(&value).map_err(|e| format!("JCS canonicalization error: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    Ok(hasher.finalize().into())
}
