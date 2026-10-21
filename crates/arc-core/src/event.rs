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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum OsPrincipal {
    Uid(u32),
    Sid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionEvent {
    pub event_id: Uuid,
    pub observed_at_unix_ms: u64,
    pub host: AgentHost,
    pub host_session_id: String,
    pub os_principal: OsPrincipal,
    pub phase: Phase,
    pub action: Action,
    #[serde(default)]
    pub provenance: EventProvenance,
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
            event_id: Uuid::now_v7(),
            observed_at_unix_ms: now,
            host,
            host_session_id: host_session_id.into(),
            os_principal,
            phase,
            action,
            provenance: EventProvenance::UserExplicit,
        }
    }

    pub fn with_provenance(mut self, provenance: EventProvenance) -> Self {
        self.provenance = provenance;
        self
    }
}
