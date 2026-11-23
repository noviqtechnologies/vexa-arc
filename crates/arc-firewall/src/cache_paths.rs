//! Cross-platform cache directory resolution shared with `vexa-sca`.
//!
//! Resolution order (highest priority first):
//! 1. Programmatic / CLI `--cache-dir` override via [`set_cache_dir_override`]
//! 2. `VEXA_CACHE_DIR` environment variable
//! 3. OS-standard user cache directory:
//!    - Linux / Unix: `$XDG_CACHE_HOME/vexa` (if absolute), else `$HOME/.cache/vexa`
//!    - macOS: `$XDG_CACHE_HOME/vexa` (if absolute), else `$HOME/Library/Caches/vexa`
//!    - Windows: `%LOCALAPPDATA%\vexa\cache`, else `%USERPROFILE%\AppData\Local\vexa\cache`
//! 4. Minimal container / headless fallback: `std::env::temp_dir().join("vexa-cache")`

use std::path::PathBuf;
use std::sync::RwLock;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Sets a process-wide cache directory override (e.g., from CLI `--cache-dir`).
/// Passing `None` or an empty path clears the override.
pub fn set_cache_dir_override(path: Option<PathBuf>) {
    let cleaned = path.filter(|p| !p.as_os_str().is_empty());
    vexa_sca::scanner::paths::set_cache_dir_override(cleaned.clone());
    if let Ok(mut guard) = CACHE_DIR_OVERRIDE.write() {
        *guard = cleaned;
    }
}

/// Returns the active CLI/API cache directory override, if set.
pub fn get_cache_dir_override() -> Option<PathBuf> {
    CACHE_DIR_OVERRIDE.read().ok().and_then(|g| g.clone())
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
    Unix,
}

fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(target_os = "macos")]
    {
        Platform::MacOs
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Platform::Unix
    }
}

fn non_empty_env(get_env: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get_env(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn is_absolute_unix_path(p: &str) -> bool {
    p.starts_with('/')
}

fn resolve_cache_dir_with(
    platform: Platform,
    override_dir: Option<PathBuf>,
    get_env: impl Fn(&str) -> Option<String>,
    temp_dir: PathBuf,
) -> PathBuf {
    if let Some(dir) = override_dir.filter(|p| !p.as_os_str().is_empty()) {
        return dir;
    }

    if let Some(env_dir) = non_empty_env(&get_env, "VEXA_CACHE_DIR") {
        return PathBuf::from(env_dir);
    }

    match platform {
        Platform::Windows => {
            if let Some(local_app_data) = non_empty_env(&get_env, "LOCALAPPDATA") {
                return PathBuf::from(local_app_data).join("vexa").join("cache");
            }
            if let Some(user_profile) = non_empty_env(&get_env, "USERPROFILE") {
                return PathBuf::from(user_profile)
                    .join("AppData")
                    .join("Local")
                    .join("vexa")
                    .join("cache");
            }
        }
        Platform::MacOs => {
            if let Some(xdg) =
                non_empty_env(&get_env, "XDG_CACHE_HOME").filter(|p| is_absolute_unix_path(p))
            {
                return PathBuf::from(xdg).join("vexa");
            }
            if let Some(home) = non_empty_env(&get_env, "HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Caches")
                    .join("vexa");
            }
        }
        Platform::Unix => {
            if let Some(xdg) =
                non_empty_env(&get_env, "XDG_CACHE_HOME").filter(|p| is_absolute_unix_path(p))
            {
                return PathBuf::from(xdg).join("vexa");
            }
            if let Some(home) = non_empty_env(&get_env, "HOME") {
                return PathBuf::from(home).join(".cache").join("vexa");
            }
        }
    }

    temp_dir.join("vexa-cache")
}

/// Resolves the OS-standard cache directory for Vexa advisory and registry caches.
/// Never defaults to a repo-local directory.
pub fn default_cache_dir() -> PathBuf {
    resolve_cache_dir_with(
        current_platform(),
        get_cache_dir_override(),
        |k| std::env::var(k).ok(),
        std::env::temp_dir(),
    )
}

/// Resolves the cache directory for package registry metadata lookups.
/// Falls back to a temp directory if the primary cache directory cannot be created.
pub fn registry_cache_dir() -> PathBuf {
    let dir = default_cache_dir().join("registry");
    if dir.exists() || std::fs::create_dir_all(&dir).is_ok() {
        return dir;
    }
    std::env::temp_dir().join("vexa-cache").join("registry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn cli_override_beats_env_and_platform_defaults() {
        let dir = resolve_cache_dir_with(
            Platform::Unix,
            Some(PathBuf::from("/custom/cli-cache")),
            env_from(&[
                ("VEXA_CACHE_DIR", "/custom/env-cache"),
                ("XDG_CACHE_HOME", "/xdg/cache"),
                ("HOME", "/home/alice"),
            ]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(dir, PathBuf::from("/custom/cli-cache"));
    }

    #[test]
    fn vexa_cache_dir_env_beats_platform_defaults() {
        let dir = resolve_cache_dir_with(
            Platform::Windows,
            None,
            env_from(&[
                ("VEXA_CACHE_DIR", "D:\\ci\\vexa-cache"),
                ("LOCALAPPDATA", "C:\\Users\\alice\\AppData\\Local"),
            ]),
            PathBuf::from("C:\\Temp"),
        );
        assert_eq!(dir, PathBuf::from("D:\\ci\\vexa-cache"));
    }

    #[test]
    fn windows_uses_localappdata_then_userprofile() {
        let dir = resolve_cache_dir_with(
            Platform::Windows,
            None,
            env_from(&[("LOCALAPPDATA", "C:\\Users\\alice\\AppData\\Local")]),
            PathBuf::from("C:\\Temp"),
        );
        assert_eq!(
            dir,
            PathBuf::from("C:\\Users\\alice\\AppData\\Local")
                .join("vexa")
                .join("cache")
        );

        let fallback = resolve_cache_dir_with(
            Platform::Windows,
            None,
            env_from(&[("USERPROFILE", "C:\\Users\\alice")]),
            PathBuf::from("C:\\Temp"),
        );
        assert_eq!(
            fallback,
            PathBuf::from("C:\\Users\\alice")
                .join("AppData")
                .join("Local")
                .join("vexa")
                .join("cache")
        );
    }

    #[test]
    fn macos_uses_library_caches_or_absolute_xdg() {
        let dir = resolve_cache_dir_with(
            Platform::MacOs,
            None,
            env_from(&[("HOME", "/Users/alice")]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(
            dir,
            PathBuf::from("/Users/alice")
                .join("Library")
                .join("Caches")
                .join("vexa")
        );

        let xdg = resolve_cache_dir_with(
            Platform::MacOs,
            None,
            env_from(&[("HOME", "/Users/alice"), ("XDG_CACHE_HOME", "/opt/cache")]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(xdg, PathBuf::from("/opt/cache").join("vexa"));
    }

    #[test]
    fn unix_respects_xdg_and_ignores_relative_xdg() {
        let xdg = resolve_cache_dir_with(
            Platform::Unix,
            None,
            env_from(&[("XDG_CACHE_HOME", "/var/cache/ci"), ("HOME", "/home/alice")]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(xdg, PathBuf::from("/var/cache/ci").join("vexa"));

        let rel = resolve_cache_dir_with(
            Platform::Unix,
            None,
            env_from(&[("XDG_CACHE_HOME", "relative/path"), ("HOME", "/home/alice")]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(
            rel,
            PathBuf::from("/home/alice").join(".cache").join("vexa")
        );
    }

    #[test]
    fn headless_container_falls_back_to_temp_dir() {
        let dir =
            resolve_cache_dir_with(Platform::Unix, None, env_from(&[]), PathBuf::from("/tmp"));
        assert_eq!(dir, PathBuf::from("/tmp").join("vexa-cache"));
    }
}
