use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scanner::AuditReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    pub bom_format: &'static str,
    pub spec_version: &'static str,
    pub serial_number: String,
    pub version: u32,
    pub metadata: BomMetadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<BomComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<BomService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomMetadata {
    pub timestamp: String,
    pub tools: Vec<BomTool>,
    pub component: BomRootComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomRootComponent {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomComponent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<BomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomService {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "x-trust-boundary", skip_serializing_if = "Option::is_none")]
    pub x_trust_boundary: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<BomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BomProperty {
    pub name: String,
    pub value: String,
}

pub fn generate_cyclonedx_1_6_bom(report: &AuditReport) -> CycloneDxBom {
    let now = chrono::Utc::now().to_rfc3339();
    let serial = format!("urn:uuid:{}", Uuid::new_v4());

    let mut components = Vec::new();
    let mut services = Vec::new();

    // 1. Models
    for model in &report.model_assets {
        components.push(BomComponent {
            kind: "machine-learning-model".to_string(),
            bom_ref: format!("model:{}", model.name),
            name: model.name.clone(),
            version: None,
            properties: vec![
                BomProperty {
                    name: "arc:asset:kind".to_string(),
                    value: "ai-model".to_string(),
                },
                BomProperty {
                    name: "arc:model:format".to_string(),
                    value: model.kind.clone(),
                },
                BomProperty {
                    name: "arc:model:size_bytes".to_string(),
                    value: model.size_bytes.to_string(),
                },
            ],
        });
    }

    // 2. Agent Skills
    for skill in &report.agent_skills {
        components.push(BomComponent {
            kind: "data".to_string(),
            bom_ref: format!("skill:{}", skill.name),
            name: skill.name.clone(),
            version: None,
            properties: vec![
                BomProperty {
                    name: "arc:asset:kind".to_string(),
                    value: "agent-skill".to_string(),
                },
                BomProperty {
                    name: "arc:skill:sha256".to_string(),
                    value: skill.content_hash.clone(),
                },
                BomProperty {
                    name: "arc:skill:lines".to_string(),
                    value: skill.line_count.to_string(),
                },
            ],
        });
    }

    // 3. MCP Servers (Services)
    for mcp in &report.mcp_servers {
        let mut props = vec![
            BomProperty {
                name: "arc:asset:kind".to_string(),
                value: "mcp-server".to_string(),
            },
            BomProperty {
                name: "arc:mcp:transport".to_string(),
                value: mcp.transport.clone(),
            },
            BomProperty {
                name: "arc:mcp:risk_band".to_string(),
                value: format!("{:?}", mcp.profile.band).to_lowercase(),
            },
            BomProperty {
                name: "arc:mcp:risk_score".to_string(),
                value: mcp.profile.composite_risk_score.to_string(),
            },
        ];

        if let Some(ref sh) = mcp.schema_hash {
            props.push(BomProperty {
                name: "arc:mcp:schema_hash".to_string(),
                value: sh.clone(),
            });
        }

        services.push(BomService {
            bom_ref: format!("mcp:{}", mcp.name),
            name: mcp.name.clone(),
            endpoints: if let Some(ref c) = mcp.command {
                vec![c.clone()]
            } else {
                Vec::new()
            },
            authenticated: Some(!mcp.env_keys.is_empty()),
            x_trust_boundary: Some(mcp.profile.untrusted_content_ingest > 250),
            properties: props,
        });
    }

    CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: serial,
        version: 1,
        metadata: BomMetadata {
            timestamp: now,
            tools: vec![BomTool {
                vendor: "Vexa".to_string(),
                name: "Arc Atlas".to_string(),
                version: "1.0.0".to_string(),
            }],
            component: BomRootComponent {
                kind: "application".to_string(),
                name: report
                    .scanned_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("workspace")
                    .to_string(),
                version: "1.0.0".to_string(),
            },
        },
        components,
        services,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::mcp_profile::Mcp3DCapabilityProfile;
    use std::path::PathBuf;

    #[test]
    fn test_cyclonedx_generation() {
        let report = AuditReport {
            scanned_path: PathBuf::from("c:/project"),
            scan_duration_ms: 120,
            mcp_servers: vec![crate::scanner::DiscoveredMcpServer {
                name: "github-mcp".to_string(),
                source_file: PathBuf::from("c:/project/.cursor/mcp.json"),
                transport: "stdio".to_string(),
                command: Some("npx".to_string()),
                args: vec!["-y".to_string(), "@mcp/github".to_string()],
                env_keys: vec!["GITHUB_TOKEN".to_string()],
                schema_hash: Some("abcd1234".to_string()),
                profile: Mcp3DCapabilityProfile::calculate(200, 200, 200, [0u8; 32]),
            }],
            agent_skills: vec![],
            model_assets: vec![],
            exposed_secrets: vec![],
            overall_risk_band: arc_core::mcp_profile::RiskBand::Low,
            total_assets: 1,
            scanned_locations: vec![PathBuf::from("c:/project")],
            unscanned_locations: vec![],
            excluded_paths: vec![],
            permission_errors: vec![],
        };

        let bom = generate_cyclonedx_1_6_bom(&report);
        let json = serde_json::to_string_pretty(&bom).unwrap();

        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert!(json.contains("\"specVersion\": \"1.6\""));
        assert!(json.contains("github-mcp"));
        assert!(json.contains("arc:mcp:risk_band"));
    }
}
