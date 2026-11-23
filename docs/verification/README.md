# Release & Live Host Verification Evidence

This directory stores versioned, reproducible host-verification evidence for **Vexa Arc** releases before promoting any host adapter from `Preview` / `Verified` to `GA`.

## 1. Running the Cross-OS Verification Harness

- **Windows (PowerShell):**
  ```powershell
  .\scripts\verify-live-hosts.ps1 -OutFile docs\verification\v1.4.1-windows.md
  ```
- **macOS / Linux (POSIX sh):**
  ```sh
  sh ./scripts/verify-live-hosts.sh docs/verification/v1.4.1-$(uname -s | tr '[:upper:]' '[:lower:]').md
  ```

> [!IMPORTANT]
> **Claude Code interactive PTY requirement:** Non-interactive print mode (`claude -p`) can bypass interactive `PreToolUse` hook loops. Live authenticated Claude Code verification **must** be executed inside an interactive terminal session on a disposable account.

## 2. Optional Zero-Dependency Ed25519 Release Key Setup (CI)

Both `vexa-arc` and `vexa-sca` sign releases with keyless **Sigstore Cosign** + **GitHub SLSA Build Provenance** by default. To also emit `checksums.txt.ed25519.sig` for zero-dependency verification via Node's built-in `crypto.verify` or OpenSSL:

```bash
# Generate an offline Ed25519 release signing keypair:
openssl genpkey -algorithm ED25519 -out vexa-release-private.pem
openssl pkey -in vexa-release-private.pem -pubout -out vexa-release-public.pem

# Store vexa-release-private.pem in GitHub Actions Secret: VEXA_RELEASE_SIGNING_KEY_PEM
# Distribute vexa-release-public.pem to endpoints via ARC_RELEASE_PUBLIC_KEY_FILE / VEXA_RELEASE_PUBLIC_KEY_FILE
```
