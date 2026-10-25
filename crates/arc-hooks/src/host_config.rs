//! Shared helpers for reading/writing agent-host hook configuration files
//! (Claude Code `.claude/settings.json`, Cursor `.cursor/hooks.json`).
//!
//! All helpers are cross-platform (Windows/macOS/Linux) and never silently
//! clobber a user's configuration file that exists but fails to parse.

use serde_json::Value;
use std::path::Path;

/// Substring that identifies a hook command as belonging to Vexa Arc.
pub const ARC_HOOK_MARKER: &str = "arc intercept hook";

/// Returns true if the hook command string invokes the Arc hook entrypoint.
pub fn is_arc_command(cmd: &str) -> bool {
    cmd.contains(ARC_HOOK_MARKER)
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
    fn arc_marker_does_not_match_unrelated_commands() {
        assert!(is_arc_command("arc intercept hook --host cursor"));
        assert!(!is_arc_command("search-tool --flag"));
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
