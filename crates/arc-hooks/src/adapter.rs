use arc_core::event::{ActionEvent, AgentHost, OsPrincipal};
use arc_core::verdict::Verdict;
use thiserror::Error;

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResponse {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostIntegrationStatus {
    pub host: AgentHost,
    pub is_configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_command: Option<String>,
    pub bypass_risk: bool,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Unsupported payload version: {0}")]
    UnsupportedVersion(String),

    #[error("Malformed payload: {0}")]
    Malformed(String),
}

pub trait HostAdapter: Send + Sync {
    fn host(&self) -> AgentHost;

    /// Decodes raw host hook input into ActionEvents. Must not panic.
    fn decode(&self, raw: &[u8], principal: OsPrincipal) -> Result<Vec<ActionEvent>, AdapterError>;

    /// Encodes the decision verdict into the host's expected response format.
    fn encode(&self, verdict: &Verdict) -> HostResponse;
}
