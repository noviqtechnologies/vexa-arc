use arc_core::event::Ecosystem;

use crate::registry::{fetch_live_registry_metadata, RegistryMetadataSource};
use crate::slopsquat::{CompoundAntiSlopsquatEngine, PackageRegistryMetadata, SlopsquatVerdict};

#[derive(Debug, Clone)]
pub struct LivePackageInspection {
    pub verdict: SlopsquatVerdict,
    pub source: RegistryMetadataSource,
    pub metadata: Option<PackageRegistryMetadata>,
}

fn normalize_ecosystem(ecosystem: &str) -> &str {
    match ecosystem.to_ascii_lowercase().as_str() {
        "npm" | "node" => "npm",
        "pypi" | "pip" | "python" => "pypi",
        "cargo" | "crates.io" | "rust" => "cargo",
        "go" | "golang" => "go",
        _ => "unknown",
    }
}

fn ecosystem_label(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Go => "go",
    }
}

fn package_cache_key(ecosystem: &str, name: &str) -> String {
    format!(
        "{}:{}",
        normalize_ecosystem(ecosystem),
        name.to_ascii_lowercase()
    )
}

/// Legacy name: this contains seeded heuristic placeholders, not authoritative registry records.
#[derive(Debug, Clone)]
pub struct AuthoritativeRegistryCache {
    pub verified_packages: std::collections::HashMap<String, PackageRegistryMetadata>,
}

impl Default for AuthoritativeRegistryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthoritativeRegistryCache {
    pub fn new() -> Self {
        let mut verified = std::collections::HashMap::new();
        // HEURISTIC SEED, NOT LIVE REGISTRY DATA: age/downloads/stars are static
        // placeholders for well-known packages. SLSA provenance is NOT claimed because
        // it is not verified anywhere.
        for (pkg, eco) in &[
            ("react", "npm"),
            ("express", "npm"),
            ("lodash", "npm"),
            ("axios", "npm"),
            ("tokio", "crates.io"),
            ("requests", "PyPI"),
            ("numpy", "PyPI"),
        ] {
            verified.insert(
                package_cache_key(eco, pkg),
                PackageRegistryMetadata {
                    name: pkg.to_string(),
                    ecosystem: normalize_ecosystem(eco).to_string(),
                    age_days: 1000,
                    monthly_downloads: 50_000_000,
                    has_verified_repository_link: true,
                    repository_stars: 5000,
                    repository_commits: 2000,
                    has_slsa_provenance: false,
                    has_dangerous_lifecycle_scripts: false,
                    recent_registry_404: false,
                    malicious_advisory_id: None,
                },
            );
        }
        Self {
            verified_packages: verified,
        }
    }

    pub fn lookup_for_ecosystem(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Option<&PackageRegistryMetadata> {
        self.verified_packages
            .get(&package_cache_key(ecosystem_label(ecosystem), name))
    }

    /// Legacy, ambiguous name-only lookup. Do not use for security decisions.
    #[deprecated(note = "use lookup_for_ecosystem to avoid cross-ecosystem collisions")]
    pub fn lookup(&self, name: &str) -> Option<&PackageRegistryMetadata> {
        self.verified_packages
            .values()
            .find(|metadata| metadata.name.eq_ignore_ascii_case(name))
    }
}

pub struct PackageFirewall {
    engine: CompoundAntiSlopsquatEngine,
    cache: AuthoritativeRegistryCache,
}

impl Default for PackageFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageFirewall {
    pub fn new() -> Self {
        Self {
            engine: CompoundAntiSlopsquatEngine::new(),
            cache: AuthoritativeRegistryCache::new(),
        }
    }

    /// Evaluates caller-supplied/heuristic package metadata; does not fetch registry information.
    pub fn inspect_package(
        &self,
        ecosystem: Ecosystem,
        package_name: &str,
        age_days: Option<u32>,
        monthly_downloads: Option<u64>,
        has_dangerous_scripts: bool,
    ) -> SlopsquatVerdict {
        let eco = ecosystem_label(ecosystem);
        let is_popular = self
            .engine
            .is_popular_package_for_ecosystem(package_name, eco);
        let meta = PackageRegistryMetadata {
            name: package_name.to_string(),
            ecosystem: eco.to_string(),
            age_days: age_days.unwrap_or(if is_popular { 365 } else { 1 }),
            monthly_downloads: monthly_downloads.unwrap_or(if is_popular { 10_000_000 } else { 0 }),
            has_verified_repository_link: is_popular,
            repository_stars: if is_popular { 1000 } else { 0 },
            repository_commits: if is_popular { 500 } else { 0 },
            has_slsa_provenance: false,
            has_dangerous_lifecycle_scripts: has_dangerous_scripts,
            recent_registry_404: false,
            malicious_advisory_id: None,
        };

        self.engine.evaluate(&meta)
    }

    /// Legacy name: evaluates against the seeded local heuristic baseline, not an authoritative
    /// registry check. This method does not verify package metadata or intercept installation.
    pub fn inspect_package_protected(
        &self,
        ecosystem: Ecosystem,
        package_name: &str,
        has_dangerous_scripts: bool,
    ) -> SlopsquatVerdict {
        if let Some(verified_meta) = self.cache.lookup_for_ecosystem(ecosystem, package_name) {
            let mut meta = verified_meta.clone();
            if has_dangerous_scripts {
                meta.has_dangerous_lifecycle_scripts = true;
            }
            self.engine.evaluate(&meta)
        } else {
            // Unverified package: evaluate strictly with conservative bounds
            let eco = ecosystem_label(ecosystem);
            let is_popular = self
                .engine
                .is_popular_package_for_ecosystem(package_name, eco);
            let meta = PackageRegistryMetadata {
                name: package_name.to_string(),
                ecosystem: eco.to_string(),
                age_days: if is_popular { 365 } else { 1 },
                monthly_downloads: if is_popular { 10_000_000 } else { 0 },
                has_verified_repository_link: is_popular,
                repository_stars: if is_popular { 1000 } else { 0 },
                repository_commits: if is_popular { 500 } else { 0 },
                has_slsa_provenance: false,
                has_dangerous_lifecycle_scripts: has_dangerous_scripts,
                recent_registry_404: false,
                malicious_advisory_id: None,
            };
            self.engine.evaluate(&meta)
        }
    }

    /// Evaluates a package using live cached registry metadata (npm, PyPI, crates.io),
    /// falling back gracefully to the local heuristic baseline when offline or unreachable.
    pub fn inspect_package_live(
        &self,
        ecosystem: Ecosystem,
        package_name: &str,
        has_dangerous_scripts: bool,
    ) -> LivePackageInspection {
        if let Some((mut meta, source)) = fetch_live_registry_metadata(ecosystem, package_name) {
            if has_dangerous_scripts {
                meta.has_dangerous_lifecycle_scripts = true;
            }
            let verdict = self.engine.evaluate(&meta);
            LivePackageInspection {
                verdict,
                source,
                metadata: Some(meta),
            }
        } else {
            let verdict =
                self.inspect_package_protected(ecosystem, package_name, has_dangerous_scripts);
            LivePackageInspection {
                verdict,
                source: RegistryMetadataSource::HeuristicFallback,
                metadata: None,
            }
        }
    }

    /// Returns a suggested command variant for a caller to review; it does not execute or isolate it.
    pub fn suggest_safer_command(
        command: &str,
        verdict: &SlopsquatVerdict,
    ) -> Result<String, String> {
        match verdict {
            SlopsquatVerdict::Blocked { gate, reason } => {
                Err(format!("Blocked by {gate}: {reason}"))
            }
            SlopsquatVerdict::Review {
                containment_recommendation,
                ..
            } => {
                let trimmed = command.trim();
                if !containment_recommendation.contains("--ignore-scripts") {
                    return Err(format!(
                        "no automatic command rewrite satisfies this review; review manually: {containment_recommendation}"
                    ));
                }
                if trimmed.starts_with("npm")
                    || trimmed.starts_with("pnpm")
                    || trimmed.starts_with("yarn")
                {
                    if !trimmed.contains("--ignore-scripts") {
                        Ok(format!("{trimmed} --ignore-scripts"))
                    } else {
                        Ok(trimmed.to_string())
                    }
                } else {
                    Err(format!(
                        "no automatic command rewrite is available; review manually: {containment_recommendation}"
                    ))
                }
            }
            SlopsquatVerdict::Permitted { .. } => Ok(command.to_string()),
        }
    }

    /// Detects ecosystem based on common manifest files in given working directory
    pub fn detect_ecosystem(dir: &std::path::Path) -> Ecosystem {
        if dir.join("package.json").exists() {
            Ecosystem::Npm
        } else if dir.join("pyproject.toml").exists()
            || dir.join("requirements.txt").exists()
            || dir.join("Pipfile").exists()
        {
            Ecosystem::Pypi
        } else if dir.join("Cargo.toml").exists() {
            Ecosystem::Cargo
        } else if dir.join("go.mod").exists() {
            Ecosystem::Go
        } else {
            Ecosystem::Npm
        }
    }

    /// Resolves target package and ecosystem from command line input
    pub fn parse_target_or_command(
        input: &str,
        default_ecosystem: Ecosystem,
    ) -> Vec<(Ecosystem, String)> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        let parsed_cmds = Self::parse_command(trimmed);
        if !parsed_cmds.is_empty() {
            return parsed_cmds;
        }

        if let Some((prefix, name)) = trimmed.split_once(':') {
            let eco = match prefix.to_lowercase().as_str() {
                "pypi" | "pip" | "python" => Ecosystem::Pypi,
                "cargo" | "rust" | "crate" => Ecosystem::Cargo,
                "go" | "golang" => Ecosystem::Go,
                _ => Ecosystem::Npm,
            };
            return vec![(eco, name.to_string())];
        }

        vec![(default_ecosystem, trimmed.to_string())]
    }

    fn clean_package_name(raw: &str, eco: Ecosystem) -> String {
        let unquoted = raw.trim_matches(|c| c == '\'' || c == '"');
        match eco {
            Ecosystem::Npm => {
                if let Some(rest) = unquoted.strip_prefix('@') {
                    if let Some(idx) = rest.find('@') {
                        format!("@{}", &rest[..idx])
                    } else {
                        unquoted.to_string()
                    }
                } else {
                    unquoted.split('@').next().unwrap_or(unquoted).to_string()
                }
            }
            Ecosystem::Pypi => {
                let s1 = unquoted.split("==").next().unwrap_or(unquoted);
                let s2 = s1.split(">=").next().unwrap_or(s1);
                let s3 = s2.split("<=").next().unwrap_or(s2);
                let s4 = s3.split("~=").next().unwrap_or(s3);
                s4.to_string()
            }
            Ecosystem::Cargo | Ecosystem::Go => {
                unquoted.split('@').next().unwrap_or(unquoted).to_string()
            }
        }
    }

    /// Splits a shell command into individual sub-commands across `&&`, `||`, `;`, `|`, and newlines,
    /// unwrapping quoted subshell arguments (`sh -c "..."`, `bash -c "..."`, `cmd /c "..."`) and
    /// stripping leading `KEY=VAL` environment assignments so compound commands cannot bypass `ARC-PKG-001`.
    fn split_shell_subcommands(command: &str) -> Vec<Vec<String>> {
        let mut subcommands: Vec<Vec<String>> = Vec::new();
        let mut current: Vec<String> = Vec::new();
        let mut token = String::new();
        let mut quote: Option<char> = None;
        let chars: Vec<char> = command.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                } else {
                    token.push(c);
                }
                i += 1;
                continue;
            }
            match c {
                '\'' | '"' => {
                    quote = Some(c);
                    i += 1;
                }
                ';' | '\n' | '\r' => {
                    if !token.is_empty() {
                        current.push(std::mem::take(&mut token));
                    }
                    if !current.is_empty() {
                        subcommands.push(std::mem::take(&mut current));
                    }
                    i += 1;
                }
                '&' | '|' => {
                    if !token.is_empty() {
                        current.push(std::mem::take(&mut token));
                    }
                    if !current.is_empty() {
                        subcommands.push(std::mem::take(&mut current));
                    }
                    if i + 1 < chars.len() && chars[i + 1] == c {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                w if w.is_whitespace() => {
                    if !token.is_empty() {
                        current.push(std::mem::take(&mut token));
                    }
                    i += 1;
                }
                _ => {
                    token.push(c);
                    i += 1;
                }
            }
        }
        if !token.is_empty() {
            current.push(token);
        }
        if !current.is_empty() {
            subcommands.push(current);
        }

        // Unwrap nested subshells: `sh -c "..."`, `bash -c "..."`, `cmd /c "..."`
        let mut expanded = Vec::new();
        for mut parts in subcommands {
            // Strip leading ENV=VAL prefixes (e.g. `NODE_ENV=dev npm install foo`)
            while parts.len() > 1 && parts[0].contains('=') && !parts[0].starts_with('-') {
                parts.remove(0);
            }
            if parts.len() >= 3 {
                let bin = parts[0].to_ascii_lowercase();
                let flag = parts[1].to_ascii_lowercase();
                let is_subshell = (matches!(
                    bin.as_str(),
                    "sh" | "bash" | "zsh" | "/bin/sh" | "/bin/bash"
                ) && flag == "-c")
                    || (matches!(bin.as_str(), "cmd" | "cmd.exe") && flag == "/c");
                if is_subshell {
                    let inner = parts[2..].join(" ");
                    expanded.extend(Self::split_shell_subcommands(&inner));
                    continue;
                }
            }
            expanded.push(parts);
        }
        expanded
    }

    /// Extracts candidate packages from shell commands (including compound `&&`/`;`/`|` chains,
    /// env prefixes, `npx`, `bun`, `poetry`, `pipx`, `uvx`, and `sh -c` / `cmd /c` subshells).
    pub fn parse_command(command: &str) -> Vec<(Ecosystem, String)> {
        let mut out = Vec::new();
        let collect_args = |args: &[String], eco: Ecosystem, out: &mut Vec<(Ecosystem, String)>| {
            let mut skip_next = false;
            for arg in args {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                // Skip flag arguments that take a file/path value (e.g. `-r requirements.txt`)
                if matches!(
                    arg.as_str(),
                    "-r" | "--requirement" | "-c" | "--constraint" | "--prefix" | "-C"
                ) {
                    skip_next = true;
                    continue;
                }
                if !arg.starts_with('-') {
                    let cleaned = Self::clean_package_name(arg, eco);
                    if !cleaned.is_empty() {
                        out.push((eco, cleaned));
                    }
                }
            }
        };

        for parts in Self::split_shell_subcommands(command) {
            if parts.is_empty() {
                continue;
            }
            let p0 = parts[0].to_ascii_lowercase();
            let p1 = parts.get(1).map(|s| s.to_ascii_lowercase());
            let p2 = parts.get(2).map(|s| s.to_ascii_lowercase());
            let p3 = parts.get(3).map(|s| s.to_ascii_lowercase());

            if matches!(p0.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
                if matches!(p1.as_deref(), Some("install" | "i" | "add")) {
                    collect_args(&parts[2..], Ecosystem::Npm, &mut out);
                }
            } else if p0 == "npx" || p0 == "bunx" {
                // First non-flag argument to npx/bunx is the package being fetched & executed
                for arg in &parts[1..] {
                    if !arg.starts_with('-') {
                        let cleaned = Self::clean_package_name(arg, Ecosystem::Npm);
                        if !cleaned.is_empty() {
                            out.push((Ecosystem::Npm, cleaned));
                        }
                        break;
                    }
                }
            } else if p0 == "pip" || p0 == "pip3" || p0 == "pipx" {
                if matches!(p1.as_deref(), Some("install" | "add")) {
                    collect_args(&parts[2..], Ecosystem::Pypi, &mut out);
                }
            } else if p0 == "poetry" {
                if matches!(p1.as_deref(), Some("add")) {
                    collect_args(&parts[2..], Ecosystem::Pypi, &mut out);
                }
            } else if p0 == "uv" {
                if p1.as_deref() == Some("add") {
                    collect_args(&parts[2..], Ecosystem::Pypi, &mut out);
                } else if p1.as_deref() == Some("pip") && p2.as_deref() == Some("install") {
                    collect_args(&parts[3..], Ecosystem::Pypi, &mut out);
                }
            } else if p0 == "uvx" {
                for arg in &parts[1..] {
                    if !arg.starts_with('-') {
                        let cleaned = Self::clean_package_name(arg, Ecosystem::Pypi);
                        if !cleaned.is_empty() {
                            out.push((Ecosystem::Pypi, cleaned));
                        }
                        break;
                    }
                }
            } else if p0 == "cargo" && p1.as_deref() == Some("add") {
                collect_args(&parts[2..], Ecosystem::Cargo, &mut out);
            } else if p0 == "go" && p1.as_deref() == Some("get") {
                collect_args(&parts[2..], Ecosystem::Go, &mut out);
            } else if (p0 == "python" || p0 == "python3")
                && p1.as_deref() == Some("-m")
                && p2.as_deref() == Some("pip")
                && matches!(p3.as_deref(), Some("install" | "add"))
            {
                collect_args(&parts[4..], Ecosystem::Pypi, &mut out);
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_npm() {
        let pkgs = PackageFirewall::parse_command("npm install --save-dev lodash express");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0], (Ecosystem::Npm, "lodash".to_string()));
        assert_eq!(pkgs[1], (Ecosystem::Npm, "express".to_string()));
    }

    #[test]
    fn test_parse_command_pip() {
        let pkgs = PackageFirewall::parse_command("pip install requests -r requirements.txt");
        assert_eq!(pkgs, vec![(Ecosystem::Pypi, "requests".to_string())]);
    }

    #[test]
    fn test_parse_compound_shell_and_modern_package_managers() {
        let chained = PackageFirewall::parse_command(
            "cd api && NODE_ENV=production npm install evil-npm-pkg; pip install evil-py-pkg",
        );
        assert_eq!(
            chained,
            vec![
                (Ecosystem::Npm, "evil-npm-pkg".to_string()),
                (Ecosystem::Pypi, "evil-py-pkg".to_string()),
            ]
        );

        let shell_wrapped =
            PackageFirewall::parse_command("bash -c \"uv pip install fastapi && bun add zod\"");
        assert_eq!(
            shell_wrapped,
            vec![
                (Ecosystem::Pypi, "fastapi".to_string()),
                (Ecosystem::Npm, "zod".to_string()),
            ]
        );

        assert_eq!(
            PackageFirewall::parse_command("npx -y malicious-cli@1.0.0 --help"),
            vec![(Ecosystem::Npm, "malicious-cli".to_string())]
        );
        assert_eq!(
            PackageFirewall::parse_command("poetry add httpx"),
            vec![(Ecosystem::Pypi, "httpx".to_string())]
        );
        assert_eq!(
            PackageFirewall::parse_command("uvx ruff check ."),
            vec![(Ecosystem::Pypi, "ruff".to_string())]
        );
    }

    #[test]
    fn test_parse_command_go() {
        let pkgs = PackageFirewall::parse_command("go get github.com/gin-gonic/gin");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(
            pkgs[0],
            (Ecosystem::Go, "github.com/gin-gonic/gin".to_string())
        );
    }

    #[test]
    fn test_parse_command_python_module_pip() {
        let pkgs = PackageFirewall::parse_command("python -m pip install numpy pandas");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0], (Ecosystem::Pypi, "numpy".to_string()));
        assert_eq!(pkgs[1], (Ecosystem::Pypi, "pandas".to_string()));
    }

    #[test]
    fn test_parse_target_or_command() {
        let bare = PackageFirewall::parse_target_or_command("reactt", Ecosystem::Npm);
        assert_eq!(bare, vec![(Ecosystem::Npm, "reactt".to_string())]);

        let scoped = PackageFirewall::parse_target_or_command("pypi:shadow-agent", Ecosystem::Npm);
        assert_eq!(scoped, vec![(Ecosystem::Pypi, "shadow-agent".to_string())]);

        let cmd = PackageFirewall::parse_target_or_command("npm install reactt", Ecosystem::Cargo);
        assert_eq!(cmd, vec![(Ecosystem::Npm, "reactt".to_string())]);
    }

    #[test]
    fn test_parse_command_with_quotes_and_versions() {
        let npm_cmd = "npm install \"lodash@^4.17.21\" '@types/node@18.0.0'";
        let parsed = PackageFirewall::parse_command(npm_cmd);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (Ecosystem::Npm, "lodash".to_string()));
        assert_eq!(parsed[1], (Ecosystem::Npm, "@types/node".to_string()));

        let pip_cmd = "pip install 'requests==2.28.1' \"urllib3>=1.26.0\"";
        let parsed_pip = PackageFirewall::parse_command(pip_cmd);
        assert_eq!(parsed_pip.len(), 2);
        assert_eq!(parsed_pip[0], (Ecosystem::Pypi, "requests".to_string()));
        assert_eq!(parsed_pip[1], (Ecosystem::Pypi, "urllib3".to_string()));
    }

    #[test]
    fn test_authoritative_protected_mode_rejects_spoofed_age() {
        let firewall = PackageFirewall::new();
        // Unknown package "completely-untrusted-hallucinated-package"
        // In protected mode, unverified packages default to 1 day age and 0 downloads
        let verdict = firewall.inspect_package_protected(
            Ecosystem::Npm,
            "completely-untrusted-hallucinated-package",
            false,
        );
        match verdict {
            SlopsquatVerdict::Blocked { gate, .. } => {
                assert_eq!(gate, "CompoundProvenanceGate");
            }
            _ => panic!("Expected blocked verdict in protected mode, got {verdict:?}"),
        }

        // Verified package from cache (e.g., "express") passes Gate 1
        let verified_verdict = firewall.inspect_package_protected(Ecosystem::Npm, "express", false);
        assert!(matches!(
            verified_verdict,
            SlopsquatVerdict::Permitted { .. }
        ));
    }

    #[test]
    fn seeded_cache_is_scoped_by_ecosystem() {
        let firewall = PackageFirewall::new();
        let cargo_tokio = firewall.inspect_package_protected(Ecosystem::Cargo, "tokio", false);
        assert!(matches!(cargo_tokio, SlopsquatVerdict::Permitted { .. }));

        let npm_tokio = firewall.inspect_package_protected(Ecosystem::Npm, "tokio", false);
        assert!(matches!(
            npm_tokio,
            SlopsquatVerdict::Blocked {
                gate: "CompoundProvenanceGate",
                ..
            }
        ));
    }

    #[test]
    fn test_suggest_safer_command_output_only() {
        let blocked = SlopsquatVerdict::Blocked {
            gate: "Gate 1",
            reason: "Untrusted new package".to_string(),
        };
        let err = PackageFirewall::suggest_safer_command("npm install bad-pkg", &blocked);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Blocked by Gate 1"));

        let review = SlopsquatVerdict::Review {
            gate: "Gate 4",
            reason: "Suspicious install script".to_string(),
            containment_recommendation: "Run with --ignore-scripts".to_string(),
        };
        let wrapped_npm =
            PackageFirewall::suggest_safer_command("npm install suspicious-pkg", &review).unwrap();
        assert_eq!(wrapped_npm, "npm install suspicious-pkg --ignore-scripts");
        assert!(
            PackageFirewall::suggest_safer_command("pip install suspicious-pkg", &review).is_err()
        );

        let provenance_review = SlopsquatVerdict::Review {
            gate: "CompoundProvenanceGate",
            reason: "Missing provenance".to_string(),
            containment_recommendation: "Require a signed provenance attestation or explicit security review before installation.".to_string(),
        };
        let no_false_rewrite =
            PackageFirewall::suggest_safer_command("npm install new-lib", &provenance_review)
                .unwrap_err();
        assert!(no_false_rewrite.contains("review manually"));

        let permitted = SlopsquatVerdict::Permitted {
            reason: "Passed all gates",
        };
        let clean =
            PackageFirewall::suggest_safer_command("npm install express", &permitted).unwrap();
        assert_eq!(clean, "npm install express");
    }
}
