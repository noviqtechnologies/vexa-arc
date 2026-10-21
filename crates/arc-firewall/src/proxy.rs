use arc_core::event::Ecosystem;

use crate::slopsquat::{CompoundAntiSlopsquatEngine, PackageRegistryMetadata, SlopsquatVerdict};

pub struct PackageFirewall {
    engine: CompoundAntiSlopsquatEngine,
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
        }
    }

    /// Evaluates an install request for a specific package.
    pub fn inspect_package(
        &self,
        ecosystem: Ecosystem,
        package_name: &str,
        age_days: Option<u32>,
        monthly_downloads: Option<u64>,
        has_dangerous_scripts: bool,
    ) -> SlopsquatVerdict {
        let is_popular = self.engine.is_popular_package(package_name);
        let meta = PackageRegistryMetadata {
            name: package_name.to_string(),
            ecosystem: format!("{:?}", ecosystem).to_lowercase(),
            age_days: age_days.unwrap_or(if is_popular { 365 } else { 1 }),
            monthly_downloads: monthly_downloads.unwrap_or(if is_popular { 10_000_000 } else { 0 }),
            has_verified_repository_link: is_popular,
            repository_stars: if is_popular { 1000 } else { 0 },
            repository_commits: if is_popular { 500 } else { 0 },
            has_slsa_provenance: false,
            has_dangerous_lifecycle_scripts: has_dangerous_scripts,
            recent_registry_404: false,
        };

        self.engine.evaluate(&meta)
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
    /// Supports:
    /// - Full commands: "npm install reactt", "pip install shadow-agent", "cargo add tokio"
    /// - Scoped names: "npm:reactt", "pypi:shadow-agent", "cargo:tokio"
    /// - Bare package name: "reactt" (uses default_ecosystem)
    pub fn parse_target_or_command(
        input: &str,
        default_ecosystem: Ecosystem,
    ) -> Vec<(Ecosystem, String)> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        // Check if input is a package manager command
        let parsed_cmds = Self::parse_command(trimmed);
        if !parsed_cmds.is_empty() {
            return parsed_cmds;
        }

        // Check for ecosystem prefix like "npm:reactt" or "pypi:shadow-agent"
        if let Some((prefix, name)) = trimmed.split_once(':') {
            let eco = match prefix.to_lowercase().as_str() {
                "pypi" | "pip" | "python" => Ecosystem::Pypi,
                "cargo" | "rust" | "crate" => Ecosystem::Cargo,
                "go" | "golang" => Ecosystem::Go,
                _ => Ecosystem::Npm,
            };
            return vec![(eco, name.to_string())];
        }

        // Bare package name
        vec![(default_ecosystem, trimmed.to_string())]
    }

    /// Extracts candidate packages from shell commands (e.g. npm i foo, pip install bar)
    pub fn parse_command(command: &str) -> Vec<(Ecosystem, String)> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();

        if parts[0] == "npm" || parts[0] == "pnpm" || parts[0] == "yarn" {
            if parts.len() > 1 && (parts[1] == "install" || parts[1] == "i" || parts[1] == "add") {
                for &arg in &parts[2..] {
                    if !arg.starts_with('-') {
                        out.push((Ecosystem::Npm, arg.to_string()));
                    }
                }
            }
        } else if parts[0] == "pip" || parts[0] == "uv" {
            if parts.len() > 1 && (parts[1] == "install" || parts[1] == "add") {
                for &arg in &parts[2..] {
                    if !arg.starts_with('-') {
                        out.push((Ecosystem::Pypi, arg.to_string()));
                    }
                }
            }
        } else if parts[0] == "cargo" && parts.len() > 1 && parts[1] == "add" {
            for &arg in &parts[2..] {
                if !arg.starts_with('-') {
                    out.push((Ecosystem::Cargo, arg.to_string()));
                }
            }
        } else if parts[0] == "go" && parts.len() > 1 && parts[1] == "get" {
            for &arg in &parts[2..] {
                if !arg.starts_with('-') {
                    out.push((Ecosystem::Go, arg.to_string()));
                }
            }
        } else if (parts[0] == "python" || parts[0] == "python3")
            && parts.len() > 3
            && parts[1] == "-m"
            && parts[2] == "pip"
            && (parts[3] == "install" || parts[3] == "add")
        {
            for &arg in &parts[4..] {
                if !arg.starts_with('-') {
                    out.push((Ecosystem::Pypi, arg.to_string()));
                }
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
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0], (Ecosystem::Pypi, "requests".to_string()));
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
}
