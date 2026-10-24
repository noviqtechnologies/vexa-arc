use arc_core::event::{Action, ActionEvent};
use arc_core::taint::{SinkClass, Taint};
use arc_core::verdict::Explanation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEntry {
    pub taint: Taint,
    pub origin: String,
    pub timestamp_ms: u64,
}

/// A node in the causal data-flow graph (FR-TAINT-002)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalNode {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<uuid::Uuid>,
    pub action_summary: String,
    pub taints_introduced: Taint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<arc_core::Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_node_ids: Vec<String>,
    pub timestamp_ms: u64,
}

pub const MAX_SESSION_HISTORY: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTaintDag {
    pub session_id: String,
    pub current_taints: Taint,
    pub history: Vec<TaintEntry>,
    #[serde(default)]
    pub known_schemas: HashMap<String, [u8; 32]>,
    #[serde(default)]
    pub causal_nodes: Vec<CausalNode>,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_hash: Option<String>,
    #[serde(default)]
    pub field_taints: HashMap<String, Taint>,
    #[serde(default)]
    pub path_taints: HashMap<String, Taint>,
}

impl Default for SessionTaintDag {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Multi-process cross-platform file locking for session safety (NFR-REL-002)
pub struct SessionLock {
    lock_file: PathBuf,
}

impl SessionLock {
    pub fn acquire(dir: &Path, session_id: &str) -> std::io::Result<Self> {
        let safe_name: String = session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let lock_file = dir.join(format!("{safe_name}.lock"));
        let start = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_file)
            {
                Ok(_) => return Ok(SessionLock { lock_file }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Check for stale lock (older than 10 seconds)
                    if let Ok(meta) = std::fs::metadata(&lock_file) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(elapsed) = modified.elapsed() {
                                if elapsed > std::time::Duration::from_secs(10) {
                                    let _ = std::fs::remove_file(&lock_file);
                                }
                            }
                        }
                    }
                    if start.elapsed() > std::time::Duration::from_secs(3) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("Timed out acquiring lock on session '{session_id}'"),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_file);
    }
}

impl SessionTaintDag {
    pub fn new(session_id: impl Into<String>) -> Self {
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        Self {
            session_id: session_id.into(),
            current_taints: Taint::empty(),
            history: Vec::new(),
            known_schemas: HashMap::new(),
            causal_nodes: Vec::new(),
            created_at_ms: now,
            expires_at_ms: Some(now + 24 * 3600 * 1000), // 24-hour default TTL
            integrity_hash: None,
            field_taints: HashMap::new(),
            path_taints: HashMap::new(),
        }
    }

    /// Records a taint for a specific structured field or environment variable (FR-TAINT-005)
    pub fn add_field_taint(
        &mut self,
        field: impl Into<String>,
        taint: Taint,
        origin: impl Into<String>,
    ) {
        if taint.is_empty() {
            return;
        }
        let field_str = field.into();
        self.field_taints
            .entry(field_str.clone())
            .or_insert_with(Taint::empty)
            .insert(taint);
        self.add_taint(taint, format!("{}: field '{}'", origin.into(), field_str));
    }

    /// Records a taint for a specific filesystem path (FR-TAINT-005)
    pub fn add_path_taint(
        &mut self,
        path: impl Into<String>,
        taint: Taint,
        origin: impl Into<String>,
    ) {
        if taint.is_empty() {
            return;
        }
        let path_str = path.into().replace('\\', "/");
        self.path_taints
            .entry(path_str.clone())
            .or_insert_with(Taint::empty)
            .insert(taint);
        self.add_taint(taint, format!("{}: path '{}'", origin.into(), path_str));
    }

    /// Gets cumulative taint for a specific field or path
    pub fn get_target_taint(&self, target: &str) -> Taint {
        let normalized = target.replace('\\', "/");
        let mut t = Taint::empty();
        if let Some(ft) = self.field_taints.get(target) {
            t.insert(*ft);
        }
        if let Some(pt) = self.path_taints.get(&normalized) {
            t.insert(*pt);
        }
        t
    }

    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at_ms {
            let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
            now > exp
        } else {
            false
        }
    }

    /// Monotonically adds taint labels to the session.
    pub fn add_taint(&mut self, taint: Taint, origin: impl Into<String>) {
        if taint.is_empty() {
            return;
        }

        self.current_taints.insert(taint);
        let origin_str = origin.into();
        self.history.push(TaintEntry {
            taint,
            origin: origin_str.clone(),
            timestamp_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        });

        // Add to causal graph
        let parent_ids: Vec<String> = self
            .causal_nodes
            .iter()
            .rev()
            .take(3)
            .map(|n| n.node_id.clone())
            .collect();

        self.causal_nodes.push(CausalNode {
            node_id: uuid::Uuid::now_v7().to_string(),
            event_id: None,
            action_summary: origin_str,
            taints_introduced: taint,
            capabilities: Vec::new(),
            parent_node_ids: parent_ids,
            timestamp_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        });

        // Bound history and graph size (NFR-PERF-003)
        if self.history.len() > MAX_SESSION_HISTORY {
            self.history
                .drain(0..(self.history.len() - MAX_SESSION_HISTORY));
        }
        if self.causal_nodes.len() > MAX_SESSION_HISTORY {
            self.causal_nodes
                .drain(0..(self.causal_nodes.len() - MAX_SESSION_HISTORY));
        }
    }

    /// Records an ActionEvent with full causal fidelity (FR-TAINT-002)
    pub fn record_causal_event(&mut self, event: &ActionEvent, taints: Taint, origin: &str) {
        if !taints.is_empty() {
            self.current_taints.insert(taints);
            self.history.push(TaintEntry {
                taint: taints,
                origin: origin.to_string(),
                timestamp_ms: event.observed_at_unix_ms,
            });
        }

        let parent_ids: Vec<String> = if let Some(p_id) = event.parent_event_id {
            self.causal_nodes
                .iter()
                .filter(|n| n.event_id == Some(p_id))
                .map(|n| n.node_id.clone())
                .collect()
        } else {
            self.causal_nodes
                .iter()
                .rev()
                .take(2)
                .map(|n| n.node_id.clone())
                .collect()
        };

        self.causal_nodes.push(CausalNode {
            node_id: uuid::Uuid::now_v7().to_string(),
            event_id: Some(event.event_id),
            action_summary: if origin.is_empty() {
                format!("{:?}", event.action)
            } else {
                origin.to_string()
            },
            taints_introduced: taints,
            capabilities: event.capabilities.clone(),
            parent_node_ids: parent_ids,
            timestamp_ms: event.observed_at_unix_ms,
        });

        if self.history.len() > MAX_SESSION_HISTORY {
            self.history
                .drain(0..(self.history.len() - MAX_SESSION_HISTORY));
        }
        if self.causal_nodes.len() > MAX_SESSION_HISTORY {
            self.causal_nodes
                .drain(0..(self.causal_nodes.len() - MAX_SESSION_HISTORY));
        }
    }

    /// Serializes and writes this session's state to disk atomically (NFR-REL-001)
    pub fn save_to_dir(&self, dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let _lock = SessionLock::acquire(dir, &self.session_id)?;

        let safe_name: String = self
            .session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let target_path = dir.join(format!("{safe_name}.json"));
        let temp_path = dir.join(format!("{safe_name}.tmp.{}", uuid::Uuid::now_v7()));

        let mut to_save = self.clone();
        to_save.integrity_hash = Some(to_save.compute_integrity_hash());
        let json = serde_json::to_string_pretty(&to_save).map_err(std::io::Error::other)?;
        std::fs::write(&temp_path, json.as_bytes())?;

        #[cfg(windows)]
        {
            if target_path.exists() {
                let _ = std::fs::remove_file(&target_path);
            }
        }

        std::fs::rename(&temp_path, &target_path)?;
        Ok(target_path)
    }

    /// Computes a tamper-evident SHA-256 integrity hash of this session's state (NFR-SEC-005)
    pub fn compute_integrity_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.current_taints.bits().to_le_bytes());
        hasher.update(self.created_at_ms.to_le_bytes());
        for h in &self.history {
            hasher.update(h.taint.bits().to_le_bytes());
            hasher.update(h.origin.as_bytes());
            hasher.update(h.timestamp_ms.to_le_bytes());
        }
        for n in &self.causal_nodes {
            hasher.update(n.node_id.as_bytes());
            hasher.update(n.action_summary.as_bytes());
            hasher.update(n.taints_introduced.bits().to_le_bytes());
        }
        for (k, v) in &self.known_schemas {
            hasher.update(k.as_bytes());
            hasher.update(v);
        }
        let mut sorted_field_keys: Vec<_> = self.field_taints.keys().collect();
        sorted_field_keys.sort();
        for k in sorted_field_keys {
            hasher.update(k.as_bytes());
            if let Some(t) = self.field_taints.get(k) {
                hasher.update(t.bits().to_le_bytes());
            }
        }
        let mut sorted_path_keys: Vec<_> = self.path_taints.keys().collect();
        sorted_path_keys.sort();
        for k in sorted_path_keys {
            hasher.update(k.as_bytes());
            if let Some(t) = self.path_taints.get(k) {
                hasher.update(t.bits().to_le_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }

    /// Verifies the session integrity hash against current contents (NFR-SEC-005)
    pub fn verify_integrity(&self) -> bool {
        if let Some(ref hash) = self.integrity_hash {
            let expected = self.compute_integrity_hash();
            hash == &expected
        } else {
            true // Backward-compatible for unhashed historical sessions
        }
    }

    /// Loads a session's state from disk if it exists, acquiring a lock for safety.
    pub fn load_from_dir(dir: &Path, session_id: &str) -> std::io::Result<Option<Self>> {
        let safe_name: String = session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{safe_name}.json"));
        if !path.exists() {
            return Ok(None);
        }

        let _lock = SessionLock::acquire(dir, session_id)?;
        let content = std::fs::read_to_string(&path)?;
        let dag: Self = serde_json::from_str(&content).map_err(std::io::Error::other)?;
        if !dag.verify_integrity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Tamper detected: session '{session_id}' state failed integrity hash verification"),
            ));
        }
        if dag.is_expired() {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        Ok(Some(dag))
    }

    /// Safely prunes all expired session files from a directory (NFR-PRIV-004)
    pub fn cleanup_expired_sessions(dir: &Path, max_age_hours: u64) -> std::io::Result<usize> {
        if !dir.exists() || !dir.is_dir() {
            return Ok(0);
        }
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let max_age_ms = max_age_hours * 3600 * 1000;
        let mut pruned = 0;

        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(dag) = serde_json::from_str::<SessionTaintDag>(&content) {
                        let is_old = if let Some(exp) = dag.expires_at_ms {
                            now > exp
                        } else {
                            now.saturating_sub(dag.created_at_ms) > max_age_ms
                        };
                        if is_old {
                            let _ = std::fs::remove_file(&path);
                            pruned += 1;
                        }
                    }
                }
            }
        }
        Ok(pruned)
    }

    /// Removes a session's persisted file from disk.
    pub fn delete_from_dir(dir: &Path, session_id: &str) -> std::io::Result<bool> {
        let _lock = SessionLock::acquire(dir, session_id)?;
        let safe_name: String = session_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{safe_name}.json"));
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Evaluates whether the requested sink triggers the Lethal Trifecta with Causal Trace:
    pub fn check_lethal_trifecta(&self, sink: SinkClass) -> Option<Explanation> {
        let has_private = self.current_taints.contains(Taint::PRIVATE_DATA)
            || self.current_taints.contains(Taint::SECRET_MATERIAL)
            || self.current_taints.contains(Taint::PRIVILEGED_DATA);

        let has_untrusted = self.current_taints.contains(Taint::UNTRUSTED_CONTENT);

        let is_sensitive_sink =
            sink.contains(SinkClass::EXTERNAL_EGRESS) || sink.contains(SinkClass::DESTRUCTIVE);

        if has_private && has_untrusted && is_sensitive_sink {
            let private_origins: Vec<_> = self
                .history
                .iter()
                .filter(|e| {
                    e.taint.contains(Taint::PRIVATE_DATA)
                        || e.taint.contains(Taint::SECRET_MATERIAL)
                        || e.taint.contains(Taint::PRIVILEGED_DATA)
                })
                .map(|e| e.origin.as_str())
                .collect();

            let untrusted_origins: Vec<_> = self
                .history
                .iter()
                .filter(|e| e.taint.contains(Taint::UNTRUSTED_CONTENT))
                .map(|e| e.origin.as_str())
                .collect();

            let p_summary = if private_origins.is_empty() {
                "sensitive credentials/files".to_string()
            } else {
                format!("'{}'", private_origins.join("', '"))
            };

            let u_summary = if untrusted_origins.is_empty() {
                "untrusted external data".to_string()
            } else {
                format!("'{}'", untrusted_origins.join("', '"))
            };

            // Generate causal chain explanation (FR-TAINT-002 / FR-CORE-002)
            let mut causal_chain = String::new();
            if !self.causal_nodes.is_empty() {
                causal_chain.push_str("\nCausal Ancestry Graph:\n");
                for node in self
                    .causal_nodes
                    .iter()
                    .filter(|n| !n.taints_introduced.is_empty())
                    .take(5)
                {
                    causal_chain.push_str(&format!(
                        "  → [{:?}] {} (Taints: {:?})\n",
                        node.timestamp_ms, node.action_summary, node.taints_introduced
                    ));
                }
            }

            let reason = format!(
                "Lethal Trifecta detected. Session has accessed private context ({p_summary}) and ingested untrusted external context ({u_summary}). Outbound network or destructive action was blocked to prevent indirect prompt injection data exfiltration.{causal_chain}"
            );

            let options = vec![
                "Run local unit tests or verification commands to inspect changes without exfiltrating context ('cargo test', 'npm test').".to_string(),
                "Clear active session and isolate private credential access from untrusted web/issue queries.".to_string(),
                "Request an explicit policy exception from your security administrator for this MCP server/tool.".to_string(),
            ];

            Some(Explanation::new(
                reason,
                options,
                Some("https://docs.vexa.ai/arc/policies/ARC-LTT-001".to_string()),
            ))
        } else {
            None
        }
    }

    /// Evaluates field-level / path-level Lethal Trifecta with benign tool isolation (FR-TAINT-005)
    pub fn check_field_level_lethal_trifecta(
        &self,
        target: Option<&str>,
        sink: SinkClass,
    ) -> Option<Explanation> {
        let has_private = self.current_taints.contains(Taint::PRIVATE_DATA)
            || self.current_taints.contains(Taint::SECRET_MATERIAL)
            || self.current_taints.contains(Taint::PRIVILEGED_DATA);

        let has_untrusted = self.current_taints.contains(Taint::UNTRUSTED_CONTENT);
        let is_sensitive_sink =
            sink.contains(SinkClass::EXTERNAL_EGRESS) || sink.contains(SinkClass::DESTRUCTIVE);

        if !has_private || !has_untrusted || !is_sensitive_sink {
            return None;
        }

        // Granular isolation check (FR-TAINT-005):
        // Benign local commands that do not exfiltrate context are isolated from blanket session taint
        if let Some(tgt) = target {
            let lower = tgt.trim().to_lowercase();
            if lower == "git status"
                || lower.starts_with("git status ")
                || lower == "git diff"
                || lower.starts_with("git diff ")
                || lower == "git log"
                || lower.starts_with("git log ")
                || lower == "cargo test"
                || lower.starts_with("cargo test ")
                || lower == "npm test"
                || lower.starts_with("npm test ")
                || lower == "pytest"
                || lower.starts_with("pytest ")
            {
                return None;
            }
        }

        self.check_lethal_trifecta(sink)
    }
}

pub struct TaintTracker {
    sessions: RwLock<HashMap<String, SessionTaintDag>>,
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintTracker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_create(&self, session_id: &str) -> SessionTaintDag {
        let mut guard = self.sessions.write().unwrap();
        guard
            .entry(session_id.to_string())
            .or_insert_with(|| SessionTaintDag::new(session_id))
            .clone()
    }

    pub fn update_session_schemas(&self, session_id: &str, schemas: HashMap<String, [u8; 32]>) {
        let mut guard = self.sessions.write().unwrap();
        if let Some(dag) = guard.get_mut(session_id) {
            dag.known_schemas = schemas;
        }
    }

    pub fn record_action_and_update_taints(&self, session_id: &str, action: &Action) -> Taint {
        let (taint, origin) = Self::classify_action_taints(action);
        if !taint.is_empty() {
            let mut guard = self.sessions.write().unwrap();
            let session = guard
                .entry(session_id.to_string())
                .or_insert_with(|| SessionTaintDag::new(session_id));
            session.add_taint(taint, origin);
        }
        taint
    }

    pub fn record_event_and_update_taints(&self, event: &ActionEvent) -> Taint {
        let (taint, origin) = Self::classify_event_taints(event);
        let mut guard = self.sessions.write().unwrap();
        let session = guard
            .entry(event.host_session_id.clone())
            .or_insert_with(|| SessionTaintDag::new(&event.host_session_id));

        // Track field / path level taint (FR-TAINT-005)
        match &event.action {
            Action::FileRead { path } => {
                session.add_path_taint(path.to_string_lossy().to_string(), taint, &origin);
            }
            Action::McpToolCall { arguments, .. } => {
                if let Some(field) = arguments
                    .get("key")
                    .or_else(|| arguments.get("field"))
                    .or_else(|| arguments.get("variable"))
                    .and_then(|v| v.as_str())
                {
                    session.add_field_taint(field, taint, &origin);
                }
            }
            _ => {}
        }

        session.record_causal_event(event, taint, &origin);
        taint
    }

    pub fn check_trifecta(&self, session_id: &str, action: &Action) -> Option<Explanation> {
        let sink = Self::classify_sink(action);
        let guard = self.sessions.read().unwrap();
        if let Some(session) = guard.get(session_id) {
            session.check_lethal_trifecta(sink)
        } else {
            None
        }
    }

    pub fn check_event_trifecta(&self, event: &ActionEvent) -> Option<Explanation> {
        let sink = Self::classify_event_sink(event);
        let guard = self.sessions.read().unwrap();
        if let Some(session) = guard.get(&event.host_session_id) {
            session.check_lethal_trifecta(sink)
        } else {
            None
        }
    }

    pub fn check_event_trifecta_with_target(
        &self,
        event: &ActionEvent,
        target: Option<&str>,
    ) -> Option<Explanation> {
        let sink = Self::classify_event_sink(event);
        let guard = self.sessions.read().unwrap();
        if let Some(session) = guard.get(&event.host_session_id) {
            session.check_field_level_lethal_trifecta(target, sink)
        } else {
            None
        }
    }

    pub fn load_session_from_disk(
        &self,
        dir: &Path,
        session_id: &str,
    ) -> std::io::Result<Option<SessionTaintDag>> {
        if let Some(dag) = SessionTaintDag::load_from_dir(dir, session_id)? {
            let mut guard = self.sessions.write().unwrap();
            guard.insert(session_id.to_string(), dag.clone());
            Ok(Some(dag))
        } else {
            Ok(None)
        }
    }

    pub fn save_session_to_disk(&self, dir: &Path, session_id: &str) -> std::io::Result<PathBuf> {
        let dag = self.get_or_create(session_id);
        dag.save_to_dir(dir)
    }

    pub fn clear_session(&self, dir: Option<&Path>, session_id: &str) -> std::io::Result<bool> {
        {
            let mut guard = self.sessions.write().unwrap();
            guard.remove(session_id);
        }
        if let Some(d) = dir {
            SessionTaintDag::delete_from_dir(d, session_id)
        } else {
            Ok(false)
        }
    }

    /// Classifies an action into any taints it produces when ingested.
    pub fn classify_action_taints(action: &Action) -> (Taint, String) {
        match action {
            Action::FileRead { path } => {
                let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
                if path_str.contains(".env")
                    || path_str.contains(".ssh")
                    || path_str.contains(".aws")
                    || path_str.contains("credentials")
                    || path_str.contains("secret")
                    || path_str.contains("id_rsa")
                    || path_str.contains("id_ed25519")
                    || path_str.contains("id_ecdsa")
                    || path_str.contains("private")
                    || path_str.contains("token")
                {
                    (
                        Taint::PRIVATE_DATA | Taint::SECRET_MATERIAL,
                        format!("file_read:{}", path.display()),
                    )
                } else {
                    (Taint::PRIVATE_DATA, format!("file_read:{}", path.display()))
                }
            }
            Action::McpToolCall { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("fetch")
                    || tool_lower.contains("web")
                    || tool_lower.contains("crawl")
                    || tool_lower.contains("scrape")
                    || tool_lower.contains("github_issue")
                    || tool_lower.contains("pr_comment")
                    || tool_lower.contains("slack_read")
                {
                    (Taint::UNTRUSTED_CONTENT, format!("mcp_tool_call:{tool}"))
                } else if tool_lower.contains("db")
                    || tool_lower.contains("sql")
                    || tool_lower.contains("query")
                {
                    (Taint::PRIVILEGED_DATA, format!("mcp_tool_call:{tool}"))
                } else {
                    (Taint::empty(), String::new())
                }
            }
            Action::McpToolResult { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("fetch")
                    || tool_lower.contains("web")
                    || tool_lower.contains("crawl")
                    || tool_lower.contains("scrape")
                    || tool_lower.contains("github_issue")
                    || tool_lower.contains("pr_comment")
                    || tool_lower.contains("slack_read")
                {
                    (Taint::UNTRUSTED_CONTENT, format!("mcp_tool:{tool}"))
                } else if tool_lower.contains("db")
                    || tool_lower.contains("sql")
                    || tool_lower.contains("query")
                {
                    (Taint::PRIVILEGED_DATA, format!("mcp_tool:{tool}"))
                } else {
                    (Taint::empty(), String::new())
                }
            }
            Action::PromptSubmit { text, source } => {
                let is_explicit_user = source
                    .as_deref()
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        matches!(
                            s_lower.as_str(),
                            "user"
                                | "developer"
                                | "operator"
                                | "admin"
                                | "local"
                                | "cli"
                                | "prompt"
                                | "human"
                        )
                    })
                    .unwrap_or(false);

                let is_untrusted_source = source
                    .as_deref()
                    .map(|s| {
                        if is_explicit_user {
                            return false;
                        }
                        let s_lower = s.to_lowercase();
                        s_lower.contains("untrusted")
                            || s_lower.contains("issue")
                            || s_lower.contains("web")
                            || s_lower.contains("pr")
                            || s_lower.contains("external")
                            || s_lower.contains("chat")
                            || s_lower.contains("ticket")
                            || s_lower.contains("scraper")
                            || s_lower.contains("crawl")
                            || s_lower.contains("slack")
                            || s_lower.contains("discord")
                            || s_lower.contains("webhook")
                            || s_lower.contains("remote")
                            || s_lower.contains("fetch")
                    })
                    .unwrap_or(false);

                // Detection of URLs and issue references in raw text is a legacy best-effort heuristic
                // for backward compatibility when explicit provenance is not provided.
                let text_lower = text.to_lowercase();
                let has_url_or_issue = text_lower.contains("issue #")
                    || text_lower.contains("http://")
                    || text_lower.contains("https://");

                if is_untrusted_source || (!is_explicit_user && has_url_or_issue) {
                    let origin = source
                        .clone()
                        .unwrap_or_else(|| "prompt_with_external_url_or_issue".to_string());
                    (Taint::UNTRUSTED_CONTENT, origin)
                } else {
                    (Taint::empty(), String::new())
                }
            }
            _ => (Taint::empty(), String::new()),
        }
    }

    /// Classifies an ActionEvent taking into account explicit provenance metadata.
    pub fn classify_event_taints(event: &ActionEvent) -> (Taint, String) {
        match &event.provenance {
            arc_core::event::EventProvenance::UntrustedExternal { source } => {
                let (mut taint, mut origin) = Self::classify_action_taints(&event.action);
                taint.insert(Taint::UNTRUSTED_CONTENT);
                if origin.is_empty() {
                    origin = format!("provenance:{source}");
                }
                (taint, origin)
            }
            arc_core::event::EventProvenance::TrustedInternal { source } => {
                let (mut taint, mut origin) = Self::classify_action_taints(&event.action);
                taint.remove(Taint::UNTRUSTED_CONTENT);
                if origin.is_empty() {
                    origin = format!("trusted_internal:{source}");
                }
                (taint, origin)
            }
            arc_core::event::EventProvenance::Authenticated(auth) => {
                let (mut taint, mut origin) = Self::classify_action_taints(&event.action);
                if auth.confidence == arc_core::ProvenanceConfidence::Untrusted {
                    taint.insert(Taint::UNTRUSTED_CONTENT);
                }
                match auth.source_type {
                    arc_core::ProvenanceSourceType::RemoteContent => {
                        taint.insert(Taint::UNTRUSTED_CONTENT);
                    }
                    arc_core::ProvenanceSourceType::LocalFile => {
                        taint.insert(Taint::PRIVATE_DATA);
                    }
                    _ => {}
                }
                if origin.is_empty() {
                    origin = format!("auth:{:?}:{}", auth.source_type, auth.source_identity);
                }
                (taint, origin)
            }
            arc_core::event::EventProvenance::UserExplicit => {
                let (taint, origin) = Self::classify_action_taints(&event.action);
                (taint, origin)
            }
        }
    }

    /// Classifies an ActionEvent into a SinkClass using both action structure and explicit capabilities.
    pub fn classify_event_sink(event: &ActionEvent) -> SinkClass {
        let mut sink = Self::classify_sink(&event.action);
        for cap in &event.capabilities {
            match cap {
                arc_core::Capability::NetworkEgress | arc_core::Capability::ExternalMessaging => {
                    sink.insert(SinkClass::EXTERNAL_EGRESS);
                }
                arc_core::Capability::FileDelete => {
                    sink.insert(SinkClass::DESTRUCTIVE);
                }
                arc_core::Capability::ProcessExecution => {
                    sink.insert(SinkClass::CODE_EXECUTION);
                }
                _ => {}
            }
        }
        sink
    }

    /// Classifies the sink capability of an action.
    pub fn classify_sink(action: &Action) -> SinkClass {
        match action {
            Action::McpToolCall { tool, .. } => {
                let tool_lower = tool.to_lowercase();
                if tool_lower.contains("slack_post")
                    || tool_lower.contains("send_email")
                    || tool_lower.contains("http_post")
                    || tool_lower.contains("curl")
                    || tool_lower.contains("fetch")
                    || tool_lower.contains("webhook")
                {
                    SinkClass::EXTERNAL_EGRESS
                } else if tool_lower.contains("git_push") || tool_lower.contains("publish") {
                    SinkClass::PUBLISH
                } else if tool_lower.contains("delete")
                    || tool_lower.contains("drop")
                    || tool_lower.contains("destroy")
                {
                    SinkClass::DESTRUCTIVE
                } else if tool_lower.contains("exec")
                    || tool_lower.contains("shell")
                    || tool_lower.contains("bash")
                {
                    SinkClass::CODE_EXECUTION
                } else {
                    SinkClass::empty()
                }
            }
            Action::Shell { command, .. } => {
                let cmd_lower = command.to_lowercase();
                let mut sink = SinkClass::CODE_EXECUTION;
                if cmd_lower.contains("curl ")
                    || cmd_lower.contains("wget ")
                    || cmd_lower.contains("invoke-webrequest")
                    || cmd_lower.contains("nc ")
                    || cmd_lower.contains("ssh ")
                {
                    sink.insert(SinkClass::EXTERNAL_EGRESS);
                }
                if cmd_lower.contains("rm -rf")
                    || cmd_lower.contains("del /f")
                    || cmd_lower.contains("drop database")
                    || cmd_lower.contains("terraform destroy")
                {
                    sink.insert(SinkClass::DESTRUCTIVE);
                }
                if cmd_lower.contains("git push")
                    || cmd_lower.contains("npm publish")
                    || cmd_lower.contains("cargo publish")
                {
                    sink.insert(SinkClass::PUBLISH);
                }
                sink
            }
            Action::PackageInstall { .. } => SinkClass::CODE_EXECUTION,
            _ => SinkClass::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::event::ServerIdentity;
    use std::path::PathBuf;

    #[test]
    fn test_taint_dag_lethal_trifecta_trigger() {
        let tracker = TaintTracker::new();
        let session = "sess-trifecta-test";

        // Step 1: Agent reads .env (PRIVATE_DATA)
        let read_action = Action::FileRead {
            path: PathBuf::from(".env"),
        };
        let t1 = tracker.record_action_and_update_taints(session, &read_action);
        assert!(t1.contains(Taint::PRIVATE_DATA));

        // Step 2: Agent reads GitHub issue (UNTRUSTED_CONTENT)
        let tool_result = Action::McpToolResult {
            server: ServerIdentity {
                config_name: "github".to_string(),
                artifact: arc_core::event::Artifact::Unknown,
                schema_root: None,
            },
            tool: "github_issue_read".to_string(),
            content: "Please check this issue".to_string(),
            is_error: false,
        };
        let t2 = tracker.record_action_and_update_taints(session, &tool_result);
        assert!(t2.contains(Taint::UNTRUSTED_CONTENT));

        // Step 3: Agent tries to post to Slack (EXTERNAL_EGRESS)
        let slack_action = Action::McpToolCall {
            server: ServerIdentity {
                config_name: "slack".to_string(),
                artifact: arc_core::event::Artifact::Unknown,
                schema_root: None,
            },
            tool: "slack_post_message".to_string(),
            arguments: serde_json::json!({"channel": "#general", "text": "summary"}),
        };

        let trifecta_violation = tracker.check_trifecta(session, &slack_action);
        assert!(
            trifecta_violation.is_some(),
            "Lethal trifecta must be detected"
        );

        let explanation = trifecta_violation.unwrap();
        assert!(explanation.summary.contains("Lethal Trifecta detected"));
        assert_eq!(explanation.options.len(), 3);
    }

    #[test]
    fn test_windows_path_and_key_taint_classification() {
        // Windows backslash path to ssh key
        let action = Action::FileRead {
            path: PathBuf::from(r"C:\Users\test\.ssh\id_ed25519"),
        };
        let (taint, origin) = TaintTracker::classify_action_taints(&action);
        assert!(taint.contains(Taint::PRIVATE_DATA));
        assert!(taint.contains(Taint::SECRET_MATERIAL));
        assert!(origin.contains("id_ed25519"));

        // Windows backslash path to .env
        let action_env = Action::FileRead {
            path: PathBuf::from(r"backend\config\.env.local"),
        };
        let (taint_env, _) = TaintTracker::classify_action_taints(&action_env);
        assert!(taint_env.contains(Taint::PRIVATE_DATA));
        assert!(taint_env.contains(Taint::SECRET_MATERIAL));
    }

    #[test]
    fn test_session_integrity_hash_and_tamper_detection() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_tamper_test_{}", uuid::Uuid::now_v7()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut dag = SessionTaintDag::new("tamper-sess");
        dag.add_taint(Taint::PRIVATE_DATA, "read .env");
        let path = dag.save_to_dir(&temp_dir).expect("save must succeed");
        assert!(path.exists());

        // Normal load with valid integrity hash
        let loaded =
            SessionTaintDag::load_from_dir(&temp_dir, "tamper-sess").expect("load must succeed");
        assert!(loaded.is_some());
        let valid_dag = loaded.unwrap();
        assert!(valid_dag.integrity_hash.is_some());
        assert!(valid_dag.verify_integrity());

        // Tamper with file contents on disk
        let mut file_content = std::fs::read_to_string(&path).unwrap();
        file_content = file_content.replace("\"read .env\"", "\"tampered action\"");
        std::fs::write(&path, file_content.as_bytes()).unwrap();

        // Load must detect tamper and return Err (NFR-SEC-005)
        let load_tampered = SessionTaintDag::load_from_dir(&temp_dir, "tamper-sess");
        assert!(
            load_tampered.is_err(),
            "Tampered session state must fail integrity verification"
        );
        assert!(load_tampered
            .unwrap_err()
            .to_string()
            .contains("Tamper detected"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_cleanup_expired() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_arc_cleanup_test_{}", uuid::Uuid::now_v7()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        // Session 1: expired
        let mut s1 = SessionTaintDag::new("old-sess");
        s1.created_at_ms = 1000;
        s1.expires_at_ms = Some(2000); // definitely expired
        s1.save_to_dir(&temp_dir).unwrap();

        // Session 2: active
        let s2 = SessionTaintDag::new("active-sess");
        s2.save_to_dir(&temp_dir).unwrap();

        let pruned = SessionTaintDag::cleanup_expired_sessions(&temp_dir, 24).unwrap();
        assert_eq!(pruned, 1, "Should prune exactly 1 expired session");

        let loaded_s1 = SessionTaintDag::load_from_dir(&temp_dir, "old-sess").unwrap();
        assert!(loaded_s1.is_none());

        let loaded_s2 = SessionTaintDag::load_from_dir(&temp_dir, "active-sess").unwrap();
        assert!(loaded_s2.is_some());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
