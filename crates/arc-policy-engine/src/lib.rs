pub mod approval;
pub mod evaluator;
pub mod taint_dag;
pub mod trust_store;

pub use approval::{
    compute_action_hash, compute_canonical_action_bytes, compute_grant_key, generate_secure_pin,
    ApprovalGrant, ApprovalManager, ApprovalModal, ApprovalPromptError, ApprovalStore,
    DesktopSessionPreflight,
};
pub use evaluator::{
    EvaluationObservation, PolicyConfig, PolicyEvaluator, PolicyException, PolicyMode,
    PolicyOutcomeKind, PolicySource,
};
pub use taint_dag::{
    SessionAuditRecord, SessionAuditSummary, SessionTaintDag, TaintEntry, TaintTracker,
};
pub use trust_store::{atomic_write_bytes, KeyRotationEnvelope, PolicyTrustStore};
