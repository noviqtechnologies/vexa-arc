use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        RuleId(s.to_string())
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        RuleId(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    pub summary: String,
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
}

impl Explanation {
    pub fn new(
        summary: impl Into<String>,
        options: Vec<String>,
        policy_url: Option<String>,
    ) -> Self {
        Self {
            summary: summary.into(),
            options,
            policy_url,
        }
    }

    pub fn format_text(&self, rule_id: &RuleId) -> String {
        let mut out = format!("• Arc Policy Violation [{}]: {}\n", rule_id.0, self.summary);
        if !self.options.is_empty() {
            out.push_str("\nRemediation Alternatives:\n");
            for (idx, opt) in self.options.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", idx + 1, opt));
            }
        }
        if let Some(ref url) = self.policy_url {
            out.push_str(&format!("\nPolicy Reference: {}\n", url));
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutAction {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Obligation {
    Redact { spans: Vec<(usize, usize, String)> },
    Spotlight { source: String },
    AddContext { text: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Verdict {
    Allow {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        obligations: Vec<Obligation>,
    },
    Deny {
        rule: RuleId,
        explanation: Explanation,
    },
    RequireApproval {
        rule: RuleId,
        explanation: Explanation,
        timeout_secs: u32,
        on_timeout: TimeoutAction,
    },
    Quarantine {
        rule: RuleId,
        explanation: Explanation,
    },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Verdict::Deny { .. } | Verdict::Quarantine { .. })
    }

    pub fn is_blocked(&self) -> bool {
        !self.is_allowed()
    }
}
