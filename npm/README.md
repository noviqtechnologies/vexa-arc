# `@vexasec/arc`

Cross-platform npm launcher for [Vexa Arc](https://github.com/noviqtechnologies/vexa-arc) (Linux, macOS, Windows).

### Prerequisites (Fail-Closed Verification)

On first download of a release, `@vexasec/arc` verifies both the archive SHA-256 checksum (`checksums.txt`) **and** the release publisher signature. Ensure one of the following is available before running `npx` / `arc`:

- [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) (recommended; keyless Sigstore bundle verification), **or**
- Authenticated GitHub CLI (`gh auth login` or `GH_TOKEN` set; SLSA provenance attestation verification), **or**
- A pinned Ed25519 release public key via `ARC_RELEASE_PUBLIC_KEY_PEM` or `ARC_RELEASE_PUBLIC_KEY_FILE` (when Ed25519 release signing is configured).

Cached binaries are re-verified against their stored `.sha256` digest on every invocation, and silent version downgrades are rejected unless `ARC_ALLOW_DOWNGRADE=1` is set.

### Quickstart (zero-install)
```bash
npx @vexasec/arc@latest init
npx @vexasec/arc@latest audit
npx @vexasec/arc@latest mcp-server
```

### Global install & upgrade (recommended for IDE hooks)
```bash
npm install -g @vexasec/arc@latest
arc --version
```
