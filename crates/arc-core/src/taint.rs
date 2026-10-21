bitflags::bitflags! {
    /// Monotonic per-session taint labels. Never cleared within a session (ADR-004).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
    pub struct Taint: u16 {
        const PRIVATE_DATA      = 1 << 0; // sensitive files, private repos/tickets, internal docs
        const UNTRUSTED_CONTENT = 1 << 1; // web, issues, PR comments, email, chat, unknown tool output
        const SECRET_MATERIAL   = 1 << 2; // a DLP detector fired on content entering context
        const PRIVILEGED_DATA   = 1 << 3; // production DB rows, customer PII sources
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
    pub struct SinkClass: u16 {
        const EXTERNAL_EGRESS = 1 << 0; // network send to non-allowlisted destinations
        const PUBLISH         = 1 << 1; // git push, npm/pypi/cargo publish, gist, paste
        const DESTRUCTIVE     = 1 << 2; // rm -rf, DROP, terraform destroy, IAM delete
        const CODE_EXECUTION  = 1 << 3; // arbitrary interpreter/shell execution
    }
}
