//! Shared helpers for reading/writing agent-host hook configuration files
//! (Claude Code `.claude/settings.json`, Cursor `.cursor/hooks.json`).
//!
//! All helpers are cross-platform (Windows/macOS/Linux) and never silently
//! clobber a user's configuration file that exists but fails to parse.

use arc_core::event::AgentHost;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Substring that identifies a hook command as belonging to Vexa Arc.
pub const ARC_HOOK_MARKER: &str = "arc intercept hook";

/// Summary of an installed host integration.
#[derive(Debug, Clone)]
pub struct HostInstallSummary {
    pub host: AgentHost,
    pub config_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub executable_path: PathBuf,
    pub hook_command: String,
    pub volatile_warning: Option<String>,
}

impl HostInstallSummary {
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

/// Cleans Windows UNC extended-length prefixes (`\\?\`) so paths remain
/// compliant with standard shell execution and tools.
pub fn clean_canonical_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let p_str = path.to_string_lossy();
        if let Some(stripped) = p_str.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
    }
    path.to_path_buf()
}

/// Resolves the canonical absolute path of the running executable and runs preflight validation.
///
/// Returns `(canonical_path, optional_volatile_warning)`.
pub fn resolve_canonical_arc_binary() -> std::io::Result<(PathBuf, Option<String>)> {
    let current = std::env::current_exe()?;
    let canonical = clean_canonical_path(&current.canonicalize().unwrap_or(current));

    if !canonical.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Arc binary not found at {}", canonical.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = canonical.metadata()?.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Binary at {} is not executable (missing +x mode)",
                    canonical.display()
                ),
            ));
        }
    }

    // Check for transient / volatile directory locations
    let mut warning = None;
    let path_str = canonical.to_string_lossy();
    let temp_dir_str = std::env::temp_dir().to_string_lossy().to_string();

    if path_str.contains("target/debug")
        || path_str.contains(r"target\debug")
        || path_str.contains("target/release")
        || path_str.contains(r"target\release")
        || path_str.starts_with(&temp_dir_str)
    {
        warning = Some(format!(
            "Binary at '{}' appears to be running from a build or temporary directory. Consider installing Arc permanently to ~/.cargo/bin or /usr/local/bin so IDE sessions can always locate it.",
            canonical.display()
        ));
    }

    Ok((canonical, warning))
}

/// Formats a hook command with proper shell quoting and argument escaping.
pub fn format_hook_command(binary_path: &Path, host_arg: &str) -> String {
    let clean = clean_canonical_path(binary_path);
    format!("\"{}\" intercept hook --host {}", clean.display(), host_arg)
}

/// Returns true if the hook command string invokes the Arc hook entrypoint.
///
/// Handles bare invocations (`arc intercept hook`), quoted paths (`"/path/to/arc" intercept hook`),
/// Windows `.exe` paths (`"C:\path\arc.exe" intercept hook`), and canonical paths with spaces.
pub fn is_arc_command(cmd: &str) -> bool {
    if !cmd.contains("intercept hook") {
        return false;
    }
    if let Some((exe_part, _)) = cmd.split_once("intercept hook") {
        let trimmed = exe_part.trim().trim_matches('"').trim_matches('\'');
        let exe_name = Path::new(trimmed)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(trimmed);
        exe_name == "arc" || exe_name == "arc.exe" || exe_name.starts_with("arc")
    } else {
        false
    }
}

/// Creates a byte-for-byte backup of `config_path` at `<config_path>.arc.bak` if the file exists.
pub fn backup_existing_config(config_path: &Path) -> std::io::Result<Option<PathBuf>> {
    if !config_path.exists() {
        return Ok(None);
    }
    let bak_path = PathBuf::from(format!("{}.arc.bak", config_path.display()));
    std::fs::copy(config_path, &bak_path)?;
    Ok(Some(bak_path))
}

/// Validates that if `hooks` exists in `root`, it is a valid JSON object.
///
/// Aborts with `InvalidData` if `hooks` is a non-object value (e.g. string or array),
/// preventing accidental destruction of user configuration.
pub fn validate_hooks_object(root: &Value, config_path: &Path) -> std::io::Result<()> {
    if let Some(hooks_val) = root.get("hooks") {
        if !hooks_val.is_object() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} contains a 'hooks' field that is not a JSON object ({}); refusing to overwrite to prevent configuration loss",
                    config_path.display(),
                    hooks_val
                ),
            ));
        }
    }
    Ok(())
}

/// Reads a JSON object from `path`. A missing or empty file yields `{}`.
/// An existing but unparsable / non-object file is an error so we never
/// overwrite user configuration we do not understand.
pub fn read_json_object(path: &Path) -> std::io::Result<Value> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let data = std::fs::read_to_string(path)?;
    if data.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let val: Value = serde_json::from_str(&data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} is not valid JSON ({e}); refusing to overwrite it",
                path.display()
            ),
        )
    })?;
    if !val.is_object() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} does not contain a JSON object; refusing to overwrite it",
                path.display()
            ),
        ));
    }
    Ok(val)
}

/// Writes JSON to `path` via a temp file + rename in the same directory.
pub fn write_json_atomic(path: &Path, value: &Value) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    let temp_path = dir.join(format!(".arc-tmp.{}", uuid::Uuid::now_v7()));
    std::fs::write(&temp_path, json.as_bytes())?;
    if let Err(first) = std::fs::rename(&temp_path, path) {
        // Some Windows configurations refuse to replace an existing file.
        #[cfg(windows)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
                if std::fs::rename(&temp_path, path).is_ok() {
                    return Ok(());
                }
            }
        }
        let _ = std::fs::remove_file(&temp_path);
        return Err(first);
    }
    Ok(())
}

/// Returns true if a Claude-style matcher group (`{"matcher":..,"hooks":[{"command":..}]}`)
/// or a Cursor-style flat entry (`{"command":..}`) invokes Arc.
pub fn entry_is_arc(entry: &Value) -> bool {
    if let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) {
        if is_arc_command(cmd) {
            return true;
        }
    }
    if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
        return hooks.iter().any(entry_is_arc);
    }
    false
}

/// Finds the first Arc hook command inside an array of hook entries.
pub fn find_arc_command(entries: &Value) -> Option<String> {
    for entry in entries.as_array()? {
        if let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) {
            if is_arc_command(cmd) {
                return Some(cmd.to_string());
            }
        }
        if let Some(inner) = entry.get("hooks") {
            if let Some(cmd) = find_arc_command(inner) {
                return Some(cmd);
            }
        }
    }
    None
}

/// Removes any Arc entries from `hooks[event]`, then optionally appends `new_entry`.
/// Preserves all non-Arc entries. Returns true if the structure changed.
pub fn upsert_event_entry(hooks: &mut Value, event: &str, new_entry: Option<Value>) -> bool {
    let Some(obj) = hooks.as_object_mut() else {
        return false;
    };
    let before = obj.get(event).cloned();
    let mut entries: Vec<Value> = match obj.get(event) {
        Some(Value::Array(a)) => a.iter().filter(|e| !entry_is_arc(e)).cloned().collect(),
        _ => Vec::new(),
    };
    if let Some(e) = new_entry {
        entries.push(e);
    }
    if entries.is_empty() {
        obj.remove(event);
    } else {
        obj.insert(event.to_string(), Value::Array(entries));
    }
    obj.get(event).cloned() != before
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_marker_matches_all_supported_variants() {
        assert!(is_arc_command("arc intercept hook --host cursor"));
        assert!(is_arc_command(
            "\"/usr/local/bin/arc\" intercept hook --host claude-code"
        ));
        assert!(is_arc_command(
            "\"/Users/jane doe/.cargo/bin/arc\" intercept hook --host claude-code"
        ));
        assert!(is_arc_command(
            "\"C:\\Users\\Jane Doe\\.cargo\\bin\\arc.exe\" intercept hook --host cursor"
        ));
        assert!(is_arc_command(
            "C:\\Tools\\arc.exe intercept hook --host cursor"
        ));

        assert!(!is_arc_command("search-tool --flag"));
        assert!(!is_arc_command("unrelated intercept hook --host cursor"));
        assert!(!is_arc_command("arc status"));
    }

    #[test]
    fn format_hook_command_quotes_paths_safely() {
        let p = Path::new(r"C:\Users\Jane Doe\.cargo\bin\arc.exe");
        let cmd = format_hook_command(p, "cursor");
        assert!(cmd.starts_with('"'));
        assert!(cmd.contains("intercept hook --host cursor"));
        assert!(is_arc_command(&cmd));
    }

    #[test]
    fn validate_hooks_object_rejects_malformed_hooks() {
        let config_path = Path::new("dummy.json");

        let valid = serde_json::json!({"hooks": {"PreToolUse": []}});
        assert!(validate_hooks_object(&valid, config_path).is_ok());

        let missing = serde_json::json!({"other": 123});
        assert!(validate_hooks_object(&missing, config_path).is_ok());

        let array_hooks = serde_json::json!({"hooks": ["not", "an", "object"]});
        assert!(validate_hooks_object(&array_hooks, config_path).is_err());

        let string_hooks = serde_json::json!({"hooks": "invalid"});
        assert!(validate_hooks_object(&string_hooks, config_path).is_err());
    }

    #[test]
    fn upsert_preserves_foreign_entries_and_is_idempotent() {
        let mut hooks = serde_json::json!({
            "PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"./mine.sh"}]}]
        });
        let arc = serde_json::json!({"matcher":"*","hooks":[{"type":"command","command":"arc intercept hook --host claude-code"}]});
        upsert_event_entry(&mut hooks, "PreToolUse", Some(arc.clone()));
        upsert_event_entry(&mut hooks, "PreToolUse", Some(arc));
        assert_eq!(hooks["PreToolUse"].as_array().unwrap().len(), 2);
        upsert_event_entry(&mut hooks, "PreToolUse", None);
        assert_eq!(hooks["PreToolUse"].as_array().unwrap().len(), 1);
    }
}
