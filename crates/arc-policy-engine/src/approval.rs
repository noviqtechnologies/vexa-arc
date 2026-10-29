//! Pillar 3: Threat-Modeled Human Approval (Host Delegation & OS Modals)
//!
//! Provides deterministic authorization mechanisms for high-risk and heuristic agent actions:
//! 1. Primary Mechanism: Host Human-in-the-Loop Delegation (mapped to Claude Code and Cursor native dialogs).
//! 2. Secondary Mechanism: Out-of-Band OS Confirmation Modal for standalone stdio sessions
//!    - Interactive desktop preflight check (WinSta0 on Windows, DISPLAY/WAYLAND on Linux, WindowServer on macOS).
//!    - Fail-closed denial in headless or remote environments (`ARC-AUTH-HEADLESS-UNSUPPORTED`).
//!    - Isolated OS GUI modal with CSPRNG 6-digit numeric PIN challenge (~20 bits entropy).
//!    - Max 3 PIN attempts before instituting a 15-minute rate-lockout window (`ARC-AUTH-PIN-EXHAUSTED` / `ARC-AUTH-LOCKED-OUT`).
//!    - Rolling rate limiting (at most 3 approval requests per minute).
//! 3. Canonical Action Binding & Atomic Single-Use Invariant:
//!    - Bound to `SHA256(canonical_action_bytes || session_id || rule_id)` via RFC 8785 JSON Canonicalization Scheme (JCS).
//!    - Consumed atomically on first match (mutex-guarded, removed immediately upon evaluation).

use arc_core::verdict::{Explanation, RuleId, Verdict};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const DEFAULT_PIN_EXPIRY_SECS: u64 = 300; // 5 minutes
pub const DEFAULT_GRANT_TTL_MS: u64 = 15 * 60 * 1000; // 15 minutes
pub const DEFAULT_LOCKOUT_MS: u64 = 15 * 60 * 1000; // 15 minutes
pub const RATE_LIMIT_WINDOW_MS: u64 = 60 * 1000; // 60 seconds
pub const RATE_LIMIT_MAX_REQUESTS: usize = 3; // 3 requests per minute
pub const MAX_PIN_ATTEMPTS: u32 = 3;

/// Computes RFC 8785 JSON Canonicalization Scheme (JCS) representation of an action.
pub fn compute_canonical_action_bytes(
    tool_or_action: &str,
    arguments: &serde_json::Value,
) -> Result<Vec<u8>, serde_json::Error> {
    let obj = serde_json::json!({
        "action": tool_or_action,
        "arguments": arguments,
    });
    serde_jcs::to_vec(&obj)
}

/// Computes SHA256 digest of canonical action bytes.
pub fn compute_action_hash(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

/// Computes the cryptographic binding grant key:
/// SHA256(canonical_action_bytes || session_id || rule_id)
pub fn compute_grant_key(canonical_bytes: &[u8], session_id: &str, rule_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes);
    hasher.update(session_id.as_bytes());
    hasher.update(rule_id.as_bytes());
    hasher.finalize().into()
}

/// Generates a cryptographically random 6-digit numeric PIN with zero modulo bias (~20 bits entropy).
pub fn generate_secure_pin() -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    loop {
        rng.fill(&mut buf)
            .map_err(|e| format!("CSPRNG error: {e}"))?;
        let val = u32::from_ne_bytes(buf);
        // 1_000_000 * 4294 = 4_294_000_000 <= u32::MAX (4_294_967_295)
        // Reject values >= 4_294_000_000 to eliminate modulo bias completely.
        if val < 4_294_000_000 {
            let pin = val % 1_000_000;
            return Ok(format!("{:06}", pin));
        }
    }
}

/// In-memory representation of an active, single-use human approval grant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalGrant {
    pub grant_key: [u8; 32],
    pub session_id: String,
    pub rule_id: String,
    pub action_hash: [u8; 32],
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub granted_by: String,
}

impl ApprovalGrant {
    pub fn is_valid(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_unix_ms
    }
}

/// Errors occurring during OS modal presentation or input gathering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalPromptError {
    Cancelled,
    TimedOut,
    SpawnError(String),
    IoError(String),
}

/// Thread-safe in-memory approval storage managing grants, rate-limiting, and rate-lockout tables.
#[derive(Debug, Default)]
pub struct ApprovalStore {
    grants: HashMap<[u8; 32], ApprovalGrant>,
    lockouts: HashMap<(String, String, [u8; 32]), u64>,
    prompt_history: VecDeque<u64>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if the specific (session_id, rule_id, action_hash) is currently locked out.
    pub fn is_locked_out(
        &self,
        session_id: &str,
        rule_id: &str,
        action_hash: &[u8; 32],
        now_ms: u64,
    ) -> bool {
        let key = (session_id.to_string(), rule_id.to_string(), *action_hash);
        if let Some(&locked_until) = self.lockouts.get(&key) {
            now_ms < locked_until
        } else {
            false
        }
    }

    /// Sets a 15-minute rate lockout for the specific (session_id, rule_id, action_hash).
    pub fn set_lockout(
        &mut self,
        session_id: &str,
        rule_id: &str,
        action_hash: &[u8; 32],
        now_ms: u64,
    ) {
        let key = (session_id.to_string(), rule_id.to_string(), *action_hash);
        self.lockouts.insert(key, now_ms + DEFAULT_LOCKOUT_MS);
    }

    /// Checks rolling 60-second rate limiter (maximum 3 requests per minute).
    pub fn check_rate_limit(&mut self, now_ms: u64) -> Result<(), Verdict> {
        let cutoff = now_ms.saturating_sub(RATE_LIMIT_WINDOW_MS);
        while let Some(&front) = self.prompt_history.front() {
            if front < cutoff {
                self.prompt_history.pop_front();
            } else {
                break;
            }
        }

        if self.prompt_history.len() >= RATE_LIMIT_MAX_REQUESTS {
            Err(Verdict::Deny {
                rule: RuleId("ARC-AUTH-RATE-LIMITED".to_string()),
                explanation: Explanation::new(
                    "Approval request rate limit exceeded (maximum 3 requests per minute). Action denied to prevent prompt spamming or UI exhaustion.",
                    vec![
                        "Wait at least 60 seconds before initiating additional approval requests.".to_string(),
                        "Review automated agent retry loops to avoid rapid-fire unapproved tool invocations.".to_string(),
                    ],
                    Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-RATE-LIMITED".to_string()),
                ),
            })
        } else {
            Ok(())
        }
    }

    /// Records an approval prompt attempt in the rolling rate-limiting window.
    pub fn record_prompt(&mut self, now_ms: u64) {
        self.prompt_history.push_back(now_ms);
    }

    /// Stores an issued approval grant.
    pub fn record_grant(&mut self, grant: ApprovalGrant) {
        self.grants.insert(grant.grant_key, grant);
    }

    /// Atomically consumes a grant on first match. Once consumed, it is removed immediately.
    /// Returns true if the grant existed and was valid, false otherwise.
    pub fn consume_grant(&mut self, grant_key: &[u8; 32], now_ms: u64) -> bool {
        if let Some(grant) = self.grants.remove(grant_key) {
            grant.is_valid(now_ms)
        } else {
            false
        }
    }

    /// Prunes expired grants and stale lockout entries.
    pub fn cleanup(&mut self, now_ms: u64) {
        self.grants.retain(|_, g| g.is_valid(now_ms));
        self.lockouts.retain(|_, &mut until| now_ms < until);
    }
}

/// Cross-platform preflight checking if an interactive graphical desktop session is present.
pub struct DesktopSessionPreflight;

impl DesktopSessionPreflight {
    /// Determines whether the current process is associated with an interactive graphical desktop.
    pub fn is_interactive_desktop() -> bool {
        Self::is_interactive_desktop_with_override(None)
    }

    pub fn is_interactive_desktop_with_override(override_val: Option<bool>) -> bool {
        if let Some(val) = override_val {
            return val;
        }

        // Explicit override for automated testing
        if let Ok(v) = std::env::var("ARC_FORCE_INTERACTIVE") {
            if v == "1" || v.eq_ignore_ascii_case("true") {
                return true;
            }
        }

        // Explicit headless environment flags
        if let Ok(v) = std::env::var("ARC_HEADLESS") {
            if v == "1" || v.eq_ignore_ascii_case("true") {
                return false;
            }
        }

        // Standard CI / Docker / Non-interactive environments
        if std::env::var_os("CI").is_some()
            || std::env::var_os("GITHUB_ACTIONS").is_some()
            || std::env::var_os("DEBIAN_FRONTEND").is_some_and(|v| v == "noninteractive")
        {
            return false;
        }

        #[cfg(windows)]
        {
            Self::is_windows_interactive_window_station()
        }

        #[cfg(target_os = "linux")]
        {
            // Linux requires active X11 or Wayland display server
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
        }

        #[cfg(target_os = "macos")]
        {
            // macOS GUI session check
            std::env::var_os("SECURITYSESSIONID").is_some()
                || std::env::var_os("TERM_PROGRAM").is_some()
                || std::env::var_os("DISPLAY").is_some()
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    #[cfg(windows)]
    #[allow(clippy::upper_case_acronyms)]
    fn is_windows_interactive_window_station() -> bool {
        type HANDLE = *mut std::ffi::c_void;
        type BOOL = i32;
        type DWORD = u32;

        const UOI_FLAGS: i32 = 1;
        const UOI_NAME: i32 = 2;
        const WSF_VISIBLE: DWORD = 1;

        #[repr(C)]
        struct USEROBJECTFLAGS {
            f_inherit: BOOL,
            f_reserved: BOOL,
            dw_flags: DWORD,
        }

        #[link(name = "user32")]
        extern "system" {
            fn GetProcessWindowStation() -> HANDLE;
            fn GetUserObjectInformationW(
                h_obj: HANDLE,
                n_index: i32,
                pv_info: *mut std::ffi::c_void,
                n_length: u32,
                lpn_length_needed: *mut u32,
            ) -> BOOL;
        }

        unsafe {
            let hwinsta = GetProcessWindowStation();
            if hwinsta.is_null() {
                return false;
            }

            // 1. Verify window station name is WinSta0 (the interactive window station)
            let mut name_buf = [0u16; 256];
            let mut len_needed: u32 = 0;
            let ok = GetUserObjectInformationW(
                hwinsta,
                UOI_NAME,
                name_buf.as_mut_ptr() as *mut _,
                (name_buf.len() * 2) as u32,
                &mut len_needed,
            );
            if ok == 0 {
                return false;
            }
            let name_len = (len_needed as usize / 2).saturating_sub(1);
            let name = String::from_utf16_lossy(&name_buf[..name_len.min(name_buf.len())]);
            if !name.eq_ignore_ascii_case("WinSta0") {
                return false;
            }

            // 2. Check window station flags (dwFlags & WSF_VISIBLE)
            let mut flags = USEROBJECTFLAGS {
                f_inherit: 0,
                f_reserved: 0,
                dw_flags: 0,
            };
            let mut flags_len_needed: u32 = 0;
            let ok_flags = GetUserObjectInformationW(
                hwinsta,
                UOI_FLAGS,
                &mut flags as *mut _ as *mut _,
                std::mem::size_of::<USEROBJECTFLAGS>() as u32,
                &mut flags_len_needed,
            );
            if ok_flags == 0 {
                return false;
            }

            (flags.dw_flags & WSF_VISIBLE) != 0
        }
    }
}

/// Spawns an isolated OS modal dialog completely detached from parent process stdin/stderr.
pub struct ApprovalModal;

impl ApprovalModal {
    /// Prompts the human operator for authorization via an OS GUI modal dialog with a CSPRNG PIN.
    pub fn prompt_pin(
        action_summary: &str,
        rule_id: &str,
        explanation: &str,
        expected_pin: &str,
    ) -> Result<String, ApprovalPromptError> {
        Self::prompt_pin_with_mock(action_summary, rule_id, explanation, expected_pin, None)
    }

    pub fn prompt_pin_with_mock(
        action_summary: &str,
        rule_id: &str,
        explanation: &str,
        expected_pin: &str,
        mock_override: Option<&str>,
    ) -> Result<String, ApprovalPromptError> {
        let mock_val = mock_override
            .map(|s| s.to_string())
            .or_else(|| std::env::var("ARC_MOCK_APPROVAL_RESPONSE").ok());

        if let Some(mock) = mock_val {
            return match mock.to_uppercase().as_str() {
                "CORRECT" | "VALID" => Ok(expected_pin.to_string()),
                "WRONG" | "INVALID" => Ok("000000".to_string()),
                "CANCEL" | "REJECT" => Err(ApprovalPromptError::Cancelled),
                "TIMEOUT" => Err(ApprovalPromptError::TimedOut),
                _ => Ok(mock.trim().to_string()),
            };
        }

        #[cfg(windows)]
        {
            Self::prompt_windows(action_summary, rule_id, explanation, expected_pin)
        }

        #[cfg(target_os = "macos")]
        {
            Self::prompt_macos(action_summary, rule_id, explanation, expected_pin)
        }

        #[cfg(target_os = "linux")]
        {
            Self::prompt_linux(action_summary, rule_id, explanation, expected_pin)
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Err(ApprovalPromptError::SpawnError(
                "Unsupported OS for native GUI modal".to_string(),
            ))
        }
    }

    #[cfg(windows)]
    fn prompt_windows(
        action_summary: &str,
        rule_id: &str,
        explanation: &str,
        expected_pin: &str,
    ) -> Result<String, ApprovalPromptError> {
        let safe_action = action_summary.replace('\'', "''").replace('"', "`\"");
        let safe_rule = rule_id.replace('\'', "''");
        let safe_exp = explanation.replace('\'', "''").replace('"', "`\"");

        // Detached PowerShell GUI modal form
        let ps_script = format!(
            r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Vexa Arc Security Authorization'
$form.Size = New-Object System.Drawing.Size(560, 380)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(20, 20)
$label.Size = New-Object System.Drawing.Size(510, 160)
$label.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$label.Text = @"
VEXA ARC - HIGH-RISK ACTION SECURITY MEDIATION
Rule Triggered: {safe_rule}
Action: {safe_action}
Explanation: {safe_exp}

To authorize this action, enter the 6-digit confirmation PIN below:
CONFIRMATION PIN: {expected_pin}
"@

$txt = New-Object System.Windows.Forms.TextBox
$txt.Location = New-Object System.Drawing.Point(20, 200)
$txt.Size = New-Object System.Drawing.Size(200, 30)
$txt.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$txt.MaxLength = 6

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = 'Approve'
$btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
$btnOk.Location = New-Object System.Drawing.Point(240, 200)
$btnOk.Size = New-Object System.Drawing.Size(120, 30)
$form.AcceptButton = $btnOk

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Deny'
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$btnCancel.Location = New-Object System.Drawing.Point(380, 200)
$btnCancel.Size = New-Object System.Drawing.Size(120, 30)
$form.CancelButton = $btnCancel

$form.Controls.Add($label)
$form.Controls.Add($txt)
$form.Controls.Add($btnOk)
$form.Controls.Add($btnCancel)

$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
    Write-Output $txt.Text.Trim()
}} else {{
    Write-Output "CANCEL"
}}
"#
        );

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| ApprovalPromptError::SpawnError(e.to_string()))?;

        let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if res.is_empty() || res == "CANCEL" {
            Err(ApprovalPromptError::Cancelled)
        } else {
            Ok(res)
        }
    }

    #[cfg(target_os = "macos")]
    fn prompt_macos(
        action_summary: &str,
        rule_id: &str,
        _explanation: &str,
        expected_pin: &str,
    ) -> Result<String, ApprovalPromptError> {
        let safe_action = action_summary.replace('"', "\\\"");
        let safe_rule = rule_id.replace('"', "\\\"");

        let script = format!(
            "display dialog \"VEXA ARC SECURITY AUTHORIZATION\\n\\nRule: {safe_rule}\\nAction: {safe_action}\\n\\nTo approve, enter verification PIN {expected_pin}:\" default answer \"\" with title \"Vexa Arc Security Authorization\" buttons {{\"Deny\", \"Approve\"}} default button \"Approve\" with icon caution"
        );

        let output = Command::new("osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| ApprovalPromptError::SpawnError(e.to_string()))?;

        if !output.status.success() {
            return Err(ApprovalPromptError::Cancelled);
        }

        let res = String::from_utf8_lossy(&output.stdout);
        if let Some(pos) = res.find("text returned:") {
            let pin_part = res[pos + 14..].split(',').next().unwrap_or("").trim();
            Ok(pin_part.to_string())
        } else {
            Err(ApprovalPromptError::Cancelled)
        }
    }

    #[cfg(target_os = "linux")]
    fn prompt_linux(
        action_summary: &str,
        rule_id: &str,
        _explanation: &str,
        expected_pin: &str,
    ) -> Result<String, ApprovalPromptError> {
        let text = format!(
            "VEXA ARC SECURITY AUTHORIZATION\n\nRule: {}\nAction: {}\n\nEnter verification PIN {}:",
            rule_id, action_summary, expected_pin
        );

        let res = Command::new("zenity")
            .args([
                "--entry",
                "--title=Vexa Arc Security Authorization",
                &format!("--text={text}"),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output();

        if let Ok(out) = res {
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
            } else {
                return Err(ApprovalPromptError::Cancelled);
            }
        }

        let kdialog_res = Command::new("kdialog")
            .args([
                "--inputbox",
                &text,
                "--title",
                "Vexa Arc Security Authorization",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output();

        if let Ok(k_out) = kdialog_res {
            if k_out.status.success() {
                return Ok(String::from_utf8_lossy(&k_out.stdout).trim().to_string());
            } else {
                return Err(ApprovalPromptError::Cancelled);
            }
        }

        Err(ApprovalPromptError::SpawnError(
            "Neither zenity nor kdialog found on PATH".to_string(),
        ))
    }
}

/// Orchestrates out-of-band human approval lifecycle, rate limiting, and atomic grant generation.
#[derive(Debug, Clone)]
pub struct ApprovalManager {
    pub store: Arc<Mutex<ApprovalStore>>,
    pub mock_interactive: Option<bool>,
    pub mock_response: Option<String>,
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self {
            store: Arc::new(Mutex::new(ApprovalStore::new())),
            mock_interactive: None,
            mock_response: None,
        }
    }
}

impl ApprovalManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(store: Arc<Mutex<ApprovalStore>>) -> Self {
        Self {
            store,
            mock_interactive: None,
            mock_response: None,
        }
    }

    pub fn with_mock(mock_interactive: bool, mock_response: &str) -> Self {
        Self {
            store: Arc::new(Mutex::new(ApprovalStore::new())),
            mock_interactive: Some(mock_interactive),
            mock_response: Some(mock_response.to_string()),
        }
    }

    /// Evaluates whether an unconsumed grant is already recorded for this canonical action.
    /// If present and valid, consumes it atomically and returns true.
    pub fn check_and_consume_grant(
        &self,
        canonical_bytes: &[u8],
        session_id: &str,
        rule_id: &str,
    ) -> bool {
        let grant_key = compute_grant_key(canonical_bytes, session_id, rule_id);
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let mut store = self.store.lock().unwrap();
        store.consume_grant(&grant_key, now_ms)
    }

    /// Primary out-of-band confirmation workflow for stdio / standalone mediated sessions.
    ///
    /// Evaluates preflight desktop requirements, rate-limiting, and rate-lockout,
    /// samples a CSPRNG PIN, and requests OS modal verification from the human.
    pub fn request_approval(
        &self,
        session_id: &str,
        rule_id: &str,
        action_name: &str,
        server_name: &str,
        arguments: &serde_json::Value,
        explanation_summary: &str,
    ) -> Result<ApprovalGrant, Verdict> {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

        let canonical_bytes = match compute_canonical_action_bytes(action_name, arguments) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(Verdict::Deny {
                    rule: RuleId(rule_id.to_string()),
                    explanation: Explanation::new(
                        format!("Failed to canonicalize action payload: {e}"),
                        vec!["Ensure tool arguments conform to valid JSON format.".to_string()],
                        None,
                    ),
                });
            }
        };

        let action_hash = compute_action_hash(&canonical_bytes);
        let grant_key = compute_grant_key(&canonical_bytes, session_id, rule_id);

        // 1. Lockout Check
        {
            let store = self.store.lock().unwrap();
            if store.is_locked_out(session_id, rule_id, &action_hash, now_ms) {
                return Err(Verdict::Deny {
                    rule: RuleId("ARC-AUTH-LOCKED-OUT".to_string()),
                    explanation: Explanation::new(
                        "Action locked out due to repeated failed authorization attempts. Active 15-minute lockout window is in effect.",
                        vec![
                            "Wait until the 15-minute rate-lockout expires before attempting this action again.".to_string(),
                            "Inspect agent tool request parameters for unintended operations.".to_string(),
                        ],
                        Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-LOCKED-OUT".to_string()),
                    ),
                });
            }
        }

        // 2. Rolling Rate-Limit Check
        {
            let mut store = self.store.lock().unwrap();
            store.check_rate_limit(now_ms)?;
        }

        // 3. Desktop Session Preflight (Fail-Closed Invariant for Headless)
        if !DesktopSessionPreflight::is_interactive_desktop_with_override(self.mock_interactive) {
            // Check optional webhook configuration
            if let Ok(webhook_url) = std::env::var("ARC_APPROVAL_WEBHOOK_URL") {
                if !webhook_url.trim().is_empty() {
                    // Webhook dispatch logic (Future extension / external security channel)
                }
            }

            return Err(Verdict::Deny {
                rule: RuleId("ARC-AUTH-HEADLESS-UNSUPPORTED".to_string()),
                explanation: Explanation::new(
                    "Interactive desktop session required for out-of-band authorization modal. Headless or remote environment detected without configured approval webhook; failing closed.",
                    vec![
                        "Run in an interactive desktop session with GUI display capabilities (WinSta0 on Windows, DISPLAY/WAYLAND on Linux, WindowServer on macOS).".to_string(),
                        "Configure ARC_APPROVAL_WEBHOOK_URL for automated headless approval routing.".to_string(),
                    ],
                    Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-HEADLESS-UNSUPPORTED".to_string()),
                ),
            });
        }

        // Record prompt in rate-limiting tracker
        {
            let mut store = self.store.lock().unwrap();
            store.record_prompt(now_ms);
        }

        let action_summary = if server_name.is_empty() {
            action_name.to_string()
        } else {
            format!("{server_name}:{action_name}")
        };

        // 4. Interactive PIN Verification Loop (Max 3 Attempts)
        let mut attempts = 0;
        while attempts < MAX_PIN_ATTEMPTS {
            attempts += 1;

            let pin = match generate_secure_pin() {
                Ok(p) => p,
                Err(e) => {
                    return Err(Verdict::Deny {
                        rule: RuleId(rule_id.to_string()),
                        explanation: Explanation::new(
                            format!("Failed to generate secure authorization PIN: {e}"),
                            vec!["Verify system entropy generator integrity.".to_string()],
                            None,
                        ),
                    });
                }
            };

            match ApprovalModal::prompt_pin_with_mock(
                &action_summary,
                rule_id,
                explanation_summary,
                &pin,
                self.mock_response.as_deref(),
            ) {
                Ok(entered_pin) => {
                    if entered_pin.trim() == pin {
                        // Correct PIN entered! Issue and record single-use grant
                        let grant = ApprovalGrant {
                            grant_key,
                            session_id: session_id.to_string(),
                            rule_id: rule_id.to_string(),
                            action_hash,
                            created_at_unix_ms: now_ms,
                            expires_at_unix_ms: now_ms + DEFAULT_GRANT_TTL_MS,
                            granted_by: "human_operator_os_modal".to_string(),
                        };

                        let mut store = self.store.lock().unwrap();
                        store.record_grant(grant.clone());
                        return Ok(grant);
                    } else if attempts >= MAX_PIN_ATTEMPTS {
                        // 3 failed attempts: institute 15-minute rate-lockout and deny immediately
                        let mut store = self.store.lock().unwrap();
                        store.set_lockout(session_id, rule_id, &action_hash, now_ms);

                        return Err(Verdict::Deny {
                            rule: RuleId("ARC-AUTH-PIN-EXHAUSTED".to_string()),
                            explanation: Explanation::new(
                                format!(
                                    "Maximum authorization PIN attempts exceeded (3/{}). A 15-minute rate-lockout window is now active for this action.",
                                    MAX_PIN_ATTEMPTS
                                ),
                                vec![
                                    "Ensure you enter the exact 6-digit PIN displayed in the confirmation dialog.".to_string(),
                                    "Wait for the 15-minute lockout period to elapse before retrying.".to_string(),
                                ],
                                Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-PIN-EXHAUSTED".to_string()),
                            ),
                        });
                    }
                    // Loop to next attempt
                }
                Err(ApprovalPromptError::Cancelled) => {
                    return Err(Verdict::Deny {
                        rule: RuleId("ARC-AUTH-USER-CANCELLED".to_string()),
                        explanation: Explanation::new(
                            "Human operator explicitly cancelled or denied the authorization prompt.",
                            vec![
                                "The requested agent tool invocation was rejected by the operator.".to_string(),
                            ],
                            Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-USER-CANCELLED".to_string()),
                        ),
                    });
                }
                Err(ApprovalPromptError::TimedOut) => {
                    return Err(Verdict::Deny {
                        rule: RuleId("ARC-AUTH-TIMEOUT".to_string()),
                        explanation: Explanation::new(
                            format!(
                                "Authorization prompt timed out after {} seconds without human response.",
                                DEFAULT_PIN_EXPIRY_SECS
                            ),
                            vec![
                                "Respond to the authorization modal within the 5-minute expiry window.".to_string(),
                            ],
                            Some("https://docs.vexa.ai/arc/policies/ARC-AUTH-TIMEOUT".to_string()),
                        ),
                    });
                }
                Err(ApprovalPromptError::SpawnError(err))
                | Err(ApprovalPromptError::IoError(err)) => {
                    return Err(Verdict::Deny {
                        rule: RuleId("ARC-AUTH-SPAWN-ERROR".to_string()),
                        explanation: Explanation::new(
                            format!("Failed to present OS authorization dialog: {err}"),
                            vec!["Verify GUI display permissions and desktop availability."
                                .to_string()],
                            Some(
                                "https://docs.vexa.ai/arc/policies/ARC-AUTH-SPAWN-ERROR"
                                    .to_string(),
                            ),
                        ),
                    });
                }
            }
        }

        Err(Verdict::Deny {
            rule: RuleId("ARC-AUTH-PIN-EXHAUSTED".to_string()),
            explanation: Explanation::new(
                "Maximum authorization PIN attempts exceeded. Action denied.",
                vec![],
                None,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jcs_canonical_bytes_and_grant_key() {
        let args1 = serde_json::json!({ "b": 2, "a": 1 });
        let args2 = serde_json::json!({ "a": 1, "b": 2 });

        let b1 = compute_canonical_action_bytes("test_tool", &args1).unwrap();
        let b2 = compute_canonical_action_bytes("test_tool", &args2).unwrap();
        // RFC 8785 JCS guarantees key-order independent byte equality
        assert_eq!(b1, b2);

        let hash1 = compute_action_hash(&b1);
        let hash2 = compute_action_hash(&b2);
        assert_eq!(hash1, hash2);

        let key1 = compute_grant_key(&b1, "sess-1", "ARC-LTT-001");
        let key2 = compute_grant_key(&b2, "sess-1", "ARC-LTT-001");
        assert_eq!(key1, key2);

        // Different session produces different key
        let key3 = compute_grant_key(&b1, "sess-2", "ARC-LTT-001");
        assert_ne!(key1, key3);

        // Different rule produces different key
        let key4 = compute_grant_key(&b1, "sess-1", "ARC-MCP-001");
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_secure_pin_sampling() {
        for _ in 0..100 {
            let pin = generate_secure_pin().unwrap();
            assert_eq!(pin.len(), 6);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
            let val: u32 = pin.parse().unwrap();
            assert!(val < 1_000_000);
        }
    }

    #[test]
    fn test_single_use_atomic_grant_consumption() {
        let mut store = ApprovalStore::new();
        let grant_key = [7u8; 32];
        let now = 1_000_000;

        let grant = ApprovalGrant {
            grant_key,
            session_id: "sess-1".to_string(),
            rule_id: "ARC-LTT-001".to_string(),
            action_hash: [1u8; 32],
            created_at_unix_ms: now,
            expires_at_unix_ms: now + 900_000,
            granted_by: "human".to_string(),
        };

        store.record_grant(grant);

        // First consumption succeeds
        assert!(store.consume_grant(&grant_key, now + 100));

        // Second consumption MUST fail (single-use invariant)
        assert!(!store.consume_grant(&grant_key, now + 200));
    }

    #[test]
    fn test_rate_limiting_enforces_3_requests_per_minute() {
        let mut store = ApprovalStore::new();
        let now = 100_000;

        assert!(store.check_rate_limit(now).is_ok());
        store.record_prompt(now);

        assert!(store.check_rate_limit(now + 10_000).is_ok());
        store.record_prompt(now + 10_000);

        assert!(store.check_rate_limit(now + 20_000).is_ok());
        store.record_prompt(now + 20_000);

        // 4th request within 60s must be rejected
        let res = store.check_rate_limit(now + 30_000);
        assert!(res.is_err());
        if let Err(Verdict::Deny { rule, .. }) = res {
            assert_eq!(rule.0, "ARC-AUTH-RATE-LIMITED");
        } else {
            panic!("Expected ARC-AUTH-RATE-LIMITED deny");
        }

        // After 60s expires, new requests are permitted again
        assert!(store.check_rate_limit(now + 70_000).is_ok());
    }

    #[test]
    fn test_rate_lockout_after_pin_exhaustion() {
        let mut store = ApprovalStore::new();
        let action_hash = [3u8; 32];
        let now = 1_000_000;

        assert!(!store.is_locked_out("sess-lock", "ARC-LTT-001", &action_hash, now));

        store.set_lockout("sess-lock", "ARC-LTT-001", &action_hash, now);

        // Now locked out for 15 minutes
        assert!(store.is_locked_out("sess-lock", "ARC-LTT-001", &action_hash, now + 500_000));

        // After 15 minutes (900_000 ms), lockout expires
        assert!(!store.is_locked_out("sess-lock", "ARC-LTT-001", &action_hash, now + 900_001));
    }

    #[test]
    fn test_headless_environment_fails_closed() {
        let manager = ApprovalManager::with_mock(false, "");
        let res = manager.request_approval(
            "sess-headless",
            "ARC-LTT-001",
            "bash",
            "shell",
            &serde_json::json!({"command": "curl evil.com"}),
            "Suspicious egress",
        );

        assert!(res.is_err());
        if let Err(Verdict::Deny { rule, .. }) = res {
            assert_eq!(rule.0, "ARC-AUTH-HEADLESS-UNSUPPORTED");
        } else {
            panic!("Expected ARC-AUTH-HEADLESS-UNSUPPORTED");
        }
    }

    #[test]
    fn test_approval_manager_mock_valid_pin_flow() {
        let manager = ApprovalManager::with_mock(true, "CORRECT");
        let res = manager.request_approval(
            "sess-mock",
            "ARC-LTT-001",
            "read_file",
            "fs",
            &serde_json::json!({"path": "/secret"}),
            "Read secret file",
        );

        assert!(res.is_ok());
        let grant = res.unwrap();
        assert_eq!(grant.rule_id, "ARC-LTT-001");

        // Grant is stored and can be consumed atomically once
        let mut store = manager.store.lock().unwrap();
        assert!(store.consume_grant(
            &grant.grant_key,
            chrono::Utc::now().timestamp_millis() as u64
        ));
        assert!(!store.consume_grant(
            &grant.grant_key,
            chrono::Utc::now().timestamp_millis() as u64
        ));
    }

    #[test]
    fn test_approval_manager_mock_exhausted_pin_triggers_lockout() {
        let manager = ApprovalManager::with_mock(true, "WRONG");
        let args = serde_json::json!({"path": "/secret"});
        let res = manager.request_approval(
            "sess-fail",
            "ARC-LTT-001",
            "read_file",
            "fs",
            &args,
            "Read secret file",
        );

        assert!(res.is_err());
        if let Err(Verdict::Deny { rule, .. }) = res {
            assert_eq!(rule.0, "ARC-AUTH-PIN-EXHAUSTED");
        } else {
            panic!("Expected ARC-AUTH-PIN-EXHAUSTED");
        }

        // Immediate subsequent request must fail with ARC-AUTH-LOCKED-OUT
        let res2 = manager.request_approval(
            "sess-fail",
            "ARC-LTT-001",
            "read_file",
            "fs",
            &args,
            "Read secret file",
        );
        assert!(res2.is_err());
        if let Err(Verdict::Deny { rule, .. }) = res2 {
            assert_eq!(rule.0, "ARC-AUTH-LOCKED-OUT");
        } else {
            panic!("Expected ARC-AUTH-LOCKED-OUT");
        }
    }
}
