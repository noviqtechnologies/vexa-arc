use serde::{Deserialize, Serialize};

/// Risk classification for capabilities according to FR-CORE-003.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

/// Explicit capabilities independent of tool names (FR-CORE-003).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details", rename_all = "snake_case")]
pub enum Capability {
    /// Reading local files from disk
    LocalFileRead,
    /// Reading secrets, environment variables, or credentials
    SecretRead,
    /// Reading source-code repositories or directory structures
    SourceCodeRead,
    /// Modifying or writing local files
    FileWrite,
    /// Deleting local files or directories
    FileDelete,
    /// Executing local processes, shells, or scripts
    ProcessExecution,
    /// Outbound network egress to external hosts or APIs
    NetworkEgress,
    /// Publishing or external messaging (e.g. Slack, GitHub, email, pastebin)
    ExternalMessaging,
    /// Accessing internal databases or privileged services
    DatabaseAccess,
    /// Ingesting untrusted external content (e.g. web pages, issue comments, PRs)
    UntrustedContentIngestion,
    /// Installing dependencies or packages from registries
    PackageInstall,
    /// Invoking external AI models or providers
    ModelAccess,
    /// Unknown or unmapped capability
    Unknown(String),
}

impl Capability {
    /// Returns the default risk class for this capability.
    pub fn risk_class(&self) -> RiskClass {
        match self {
            Capability::LocalFileRead => RiskClass::Low,
            Capability::SourceCodeRead => RiskClass::Medium,
            Capability::SecretRead => RiskClass::Critical,
            Capability::FileWrite => RiskClass::Medium,
            Capability::FileDelete => RiskClass::High,
            Capability::ProcessExecution => RiskClass::Critical,
            Capability::NetworkEgress => RiskClass::High,
            Capability::ExternalMessaging => RiskClass::High,
            Capability::DatabaseAccess => RiskClass::Critical,
            Capability::UntrustedContentIngestion => RiskClass::High,
            Capability::PackageInstall => RiskClass::High,
            Capability::ModelAccess => RiskClass::Medium,
            Capability::Unknown(_) => RiskClass::High,
        }
    }

    /// Whether this capability represents an external or destructive sink.
    pub fn is_sink(&self) -> bool {
        matches!(
            self,
            Capability::NetworkEgress
                | Capability::ExternalMessaging
                | Capability::ProcessExecution
                | Capability::FileDelete
        )
    }

    /// Infers capabilities from tool name or arguments with heuristic fallback.
    pub fn infer(tool_name: &str, is_read: bool, is_write: bool, is_network: bool) -> Vec<Self> {
        let mut caps = Vec::new();
        let name_lower = tool_name.to_lowercase();

        if name_lower.contains("secret")
            || name_lower.contains("credential")
            || name_lower.contains("key")
        {
            caps.push(Capability::SecretRead);
        }

        if is_read
            || name_lower.contains("read")
            || name_lower.contains("cat")
            || name_lower.contains("get")
        {
            caps.push(Capability::LocalFileRead);
        }

        if is_write
            || name_lower.contains("write")
            || name_lower.contains("edit")
            || name_lower.contains("update")
        {
            caps.push(Capability::FileWrite);
        }

        if name_lower.contains("delete")
            || name_lower.contains("remove")
            || name_lower.contains("rm")
        {
            caps.push(Capability::FileDelete);
        }

        if name_lower.contains("bash")
            || name_lower.contains("sh")
            || name_lower.contains("exec")
            || name_lower.contains("shell")
        {
            caps.push(Capability::ProcessExecution);
        }

        if is_network
            || name_lower.contains("fetch")
            || name_lower.contains("curl")
            || name_lower.contains("http")
            || name_lower.contains("post")
        {
            caps.push(Capability::NetworkEgress);
        }

        if name_lower.contains("slack")
            || name_lower.contains("email")
            || name_lower.contains("tweet")
            || name_lower.contains("publish")
        {
            caps.push(Capability::ExternalMessaging);
        }

        if name_lower.contains("db") || name_lower.contains("sql") || name_lower.contains("query") {
            caps.push(Capability::DatabaseAccess);
        }

        if name_lower.contains("install") || name_lower.contains("add_package") {
            caps.push(Capability::PackageInstall);
        }

        if caps.is_empty() {
            caps.push(Capability::Unknown(tool_name.to_string()));
        }

        caps
    }
}

/// Source of evidence for a declared or evaluated capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceSource {
    SignedDeclaration,
    SchemaAnalysis,
    AdapterMetadata,
    OperatorAssignment,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAssertion {
    pub capability: Capability,
    pub evidence_source: CapabilityEvidenceSource,
}
