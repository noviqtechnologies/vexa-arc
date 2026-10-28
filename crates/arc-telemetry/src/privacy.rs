use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use uuid::Uuid;

static INSTALL_ID: OnceLock<String> = OnceLock::new();
static INSTALL_KEY: OnceLock<String> = OnceLock::new();

pub fn install_id() -> String {
    INSTALL_ID.get_or_init(|| keyed_hash("install-id")).clone()
}

pub fn hash_identifier(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"VEXA-ARC-LOCAL-TELEMETRY-V2\0");
    hasher.update(install_key().as_bytes());
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn keyed_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"VEXA-ARC-LOCAL-TELEMETRY-ID-V2\0");
    hasher.update(install_key().as_bytes());
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn install_key() -> String {
    INSTALL_KEY
        .get_or_init(|| {
            let path = install_key_path();
            if let Ok(existing) = fs::read_to_string(&path) {
                let trimmed = existing.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
            let generated = Uuid::new_v4().to_string();
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, &generated);
            generated
        })
        .clone()
}

fn install_key_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("ARC_TELEMETRY_DIR") {
        return PathBuf::from(dir).join("install.key");
    }
    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(dir)
                .join("VexaArc")
                .join("pilot")
                .join("install.key");
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(dir)
                .join("vexa-arc")
                .join("pilot")
                .join("install.key");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("vexa-arc")
                .join("pilot")
                .join("install.key");
        }
    }
    PathBuf::from(".arc").join("telemetry").join("install.key")
}
