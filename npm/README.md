# `@vexasec/arc`

Cross-platform npm launcher for [Vexa Arc](https://github.com/noviqtechnologies/vexa-arc) (Linux, macOS, Windows).

### Publisher Verification (Fail-Closed, Zero External Prerequisites)

On first download of a release, `@vexasec/arc` verifies both the archive SHA-256 checksum (`checksums.txt`) **and** the cryptographic release publisher signature before extracting or executing the binary:

- **Built-in Sigstore verification (default):** Works out of the box with no external CLI tools by verifying `checksums.txt.bundle` offline against the bundled Sigstore Public Good trusted root and pinning the exact GitHub Actions release workflow + tag identity.
- **Optional CLI verifiers:** If [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) or an authenticated GitHub CLI (`gh`) is already installed in `PATH`, `@vexasec/arc` uses it automatically (falling back to built-in Sigstore verification if `gh` is unauthenticated).
- **Optional Ed25519 pinning:** Set `ARC_RELEASE_PUBLIC_KEY_PEM` or `ARC_RELEASE_PUBLIC_KEY_FILE` to verify `checksums.txt.ed25519.sig` directly.

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
