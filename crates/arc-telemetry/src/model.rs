use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub schema_version: u16,
    pub event_id: Uuid,
    pub occurred_at_unix_ms: u64,
    pub install_id: String,
    pub developer_id: String,
    pub host: String,
    pub adapter_version: Option<String>,
    pub transport: Option<String>,
    pub phase: String,
    pub action_class: String,
    pub decision: String,
    pub rule_id: Option<String>,
    pub taint_flags: Vec<String>,
    pub sink_class: Option<String>,
    pub target_class: String,
    pub session_id_hash: String,
    pub project_id_hash: Option<String>,
    pub schema_pin_status: Option<String>,
    pub latency_ms: f64,
    pub error_class: Option<String>,
    pub telemetry_dropped_before_event: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryEventBuilder {
    pub action_class: String,
    pub decision: String,
    pub rule_id: Option<String>,
    pub taint_flags: Vec<String>,
    pub sink_class: Option<String>,
    pub target_class: String,
    pub session_id_hash: String,
    pub project_id_hash: Option<String>,
    pub schema_pin_status: Option<String>,
    pub latency_ms: f64,
    pub error_class: Option<String>,
    pub policy_revision: Option<String>,
    pub policy_source: Option<String>,
    pub execution_status: Option<String>,
    pub correlation_id: Option<String>,
}

impl TelemetryEventBuilder {
    pub fn build(self, host: &str, transport: Option<&str>) -> TelemetryEvent {
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let event_id = Uuid::now_v7();
        let execution_status = self.execution_status.or_else(|| {
            Some(
                match self.decision.as_str() {
                    "deny" => "blocked",
                    "approval" => "pending_approval",
                    "quarantine" => "quarantined",
                    "allow" => "allowed",
                    _ => "unknown",
                }
                .to_string(),
            )
        });
        let correlation_id = self.correlation_id.or_else(|| Some(event_id.to_string()));
        TelemetryEvent {
            schema_version: 2,
            event_id,
            occurred_at_unix_ms: now,
            install_id: crate::install_id(),
            developer_id: crate::install_id(),
            host: host.to_string(),
            adapter_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            transport: transport.map(str::to_string),
            phase: "pre".to_string(),
            action_class: self.action_class,
            decision: self.decision,
            rule_id: self.rule_id,
            taint_flags: self.taint_flags,
            sink_class: self.sink_class,
            target_class: self.target_class,
            session_id_hash: self.session_id_hash,
            project_id_hash: self.project_id_hash,
            schema_pin_status: self.schema_pin_status,
            latency_ms: self.latency_ms,
            error_class: self.error_class,
            telemetry_dropped_before_event: 0,
            policy_revision: self.policy_revision,
            policy_source: self.policy_source,
            execution_status,
            correlation_id,
        }
    }
}
