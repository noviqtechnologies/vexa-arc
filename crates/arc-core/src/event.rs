use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHost {
    ClaudeCode,
    Cursor,
    VsCodeCopilot,
    Windsurf,
    CodexCli,
    GeminiCli,
    CustomMcpClient,
    Ci,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pre,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub config_name: String,
    pub artifact: Artifact,
    pub schema_root: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Artifact {
    Npm {
        name: String,
        version: Option<String>,
    },
    Pypi {
        name: String,
        version: Option<String>,
    },
    Remote {
        url: String,
    },
    Local {
        command_sha256: [u8; 32],
    },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Cargo,
    Go,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    McpToolCall {
        server: ServerIdentity,
        tool: String,
        arguments: serde_json::Value,
    },
    McpToolResult {
        server: ServerIdentity,
        tool: String,
        content: String,
        is_error: bool,
    },
    McpToolsList {
        server: ServerIdentity,
        tools_json: String,
    },
    Shell {
        command: String,
        cwd: PathBuf,
    },
    FileRead {
        path: PathBuf,
    },
    FileWrite {
        path: PathBuf,
        new_content: Option<String>,
    },
    PackageInstall {
        ecosystem: Ecosystem,
        name: String,
        version: Option<String>,
    },
    PromptSubmit {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
}

use crate::capability::Capability;

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceConfidence {
    Verified,
    High,
    Medium,
    Low,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSourceType {
    UserInput,
    McpToolResult,
    LocalFile,
    RemoteContent,
    CiArtifact,
    PackageRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthenticatedProvenance {
    pub source_type: ProvenanceSourceType,
    pub source_identity: String,
    pub adapter_id: String,
    pub confidence: ProvenanceConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventProvenance {
    #[default]
    UserExplicit,
    UntrustedExternal {
        source: String,
    },
    TrustedInternal {
        source: String,
    },
    Authenticated(AuthenticatedProvenance),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum OsPrincipal {
    Uid(u32),
    Sid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub event_id: Uuid,
    pub observed_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<Uuid>,
    pub host: AgentHost,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub host_session_id: String,
    pub os_principal: OsPrincipal,
    pub phase: Phase,
    pub action: Action,
    #[serde(default)]
    pub provenance: EventProvenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<[u8; 32]>,
}

impl ActionEvent {
    pub fn new(
        host: AgentHost,
        host_session_id: impl Into<String>,
        os_principal: OsPrincipal,
        phase: Phase,
        action: Action,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        Self {
            schema_version: default_schema_version(),
            event_id: Uuid::now_v7(),
            observed_at_unix_ms: now,
            parent_event_id: None,
            host,
            adapter_version: None,
            transport: None,
            host_session_id: host_session_id.into(),
            os_principal,
            phase,
            action,
            provenance: EventProvenance::UserExplicit,
            capabilities: Vec::new(),
            schema_fingerprint: None,
        }
    }

    pub fn with_provenance(mut self, provenance: EventProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn with_capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_parent_event_id(mut self, parent_id: Uuid) -> Self {
        self.parent_event_id = Some(parent_id);
        self
    }

    pub fn with_adapter_version(mut self, ver: impl Into<String>) -> Self {
        self.adapter_version = Some(ver.into());
        self
    }

    pub fn with_transport(mut self, transport: impl Into<String>) -> Self {
        self.transport = Some(transport.into());
        self
    }

    pub fn with_schema_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        self.schema_fingerprint = Some(fingerprint);
        self
    }
}
