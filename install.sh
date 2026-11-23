#!/usr/bin/env sh
set -eu

REPO="noviqtechnologies/vexa-arc"
VERSION="${ARC_VERSION:-latest}"
INSTALL_DIR="${ARC_INSTALL_DIR:-$HOME/.local/bin}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) TARGET="linux-x86_64" ;;
      aarch64|arm64) TARGET="linux-aarch64" ;;
      *) echo "Unsupported Linux architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      x86_64) TARGET="macos-x86_64" ;;
      arm64) TARGET="macos-aarch64" ;;
      *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS (use install.ps1 on Windows)" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$TAG" ]; then
    echo "Error: Failed to resolve latest release tag from GitHub" >&2
    exit 1
  fi
else
  TAG="$VERSION"
fi
# Always pin download URL to the resolved tag to prevent TOCTOU drift between tag and assets
BASE_URL="https://github.com/$REPO/releases/download/$TAG"

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*)
    if printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$'; then
      :
    else
      echo "Error: Invalid release tag format '$TAG'" >&2
      exit 1
    fi
    ;;
  *)
    echo "Error: Invalid release tag format '$TAG' (expected vX.Y.Z)" >&2
    exit 1
    ;;
esac

ARCHIVE="vexa-arc-${TAG}-${TARGET}.zip"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Vexa Arc $TAG ($TARGET)..."
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMP_DIR/$ARCHIVE"
curl -fsSL "$BASE_URL/checksums.txt" -o "$TMP_DIR/checksums.txt"

if [ ! -s "$TMP_DIR/checksums.txt" ]; then
  echo "Error: Downloaded checksums.txt is empty or missing; failing closed." >&2
  exit 1
fi

EXPECTED_SHA="$(awk -v arch="$ARCHIVE" '$2 == arch || $2 == ("./" arch) { print tolower($1); exit }' "$TMP_DIR/checksums.txt")"
if [ -z "$EXPECTED_SHA" ]; then
  echo "Error: No SHA-256 entry found for '$ARCHIVE' in checksums.txt; failing closed." >&2
  exit 1
fi

if ! printf '%s' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "Error: Malformed SHA-256 digest '$EXPECTED_SHA' for '$ARCHIVE' in checksums.txt; failing closed." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print tolower($1)}')"
elif command -v openssl >/dev/null 2>&1; then
  ACTUAL_SHA="$(openssl dgst -sha256 "$TMP_DIR/$ARCHIVE" | awk '{print tolower($NF)}')"
else
  echo "Error: No SHA-256 verification tool found (sha256sum, shasum, or openssl required); failing closed." >&2
  exit 1
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "Error: Checksum mismatch for $ARCHIVE! Expected $EXPECTED_SHA, got $ACTUAL_SHA" >&2
  exit 1
fi

# Rollback protection: refuse to silently downgrade an existing newer installation (POSIX-portable across Linux/macOS/BSD)
if [ -x "$INSTALL_DIR/arc" ] && [ "${ARC_ALLOW_DOWNGRADE:-0}" != "1" ]; then
  EXISTING_VER="$("$INSTALL_DIR/arc" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
  REQUESTED_VER="$(printf '%s' "$TAG" | sed 's/^v//' | cut -d- -f1)"
  if [ -n "$EXISTING_VER" ] && [ -n "$REQUESTED_VER" ] && [ "$EXISTING_VER" != "$REQUESTED_VER" ]; then
    IS_DOWNGRADE="$(awk -v cur="$EXISTING_VER" -v req="$REQUESTED_VER" 'BEGIN {
      split(cur, c, "."); split(req, r, ".");
      for (i = 1; i <= 3; i++) {
        if ((r[i] + 0) < (c[i] + 0)) { print "1"; exit }
        if ((r[i] + 0) > (c[i] + 0)) { print "0"; exit }
      }
      print "0";
    }')"
    if [ "$IS_DOWNGRADE" = "1" ]; then
      echo "Error: Rollback rejected: installed version v$EXISTING_VER is newer than requested $TAG (set ARC_ALLOW_DOWNGRADE=1 to override)." >&2
      exit 1
    fi
  fi
fi

# Mandatory publisher signature & provenance verification (fail-closed)
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

if command -v cosign >/dev/null 2>&1; then
  if ! curl -fsSL "$BASE_URL/checksums.txt.bundle" -o "$TMP_DIR/checksums.txt.bundle"; then
    echo "Error: Failed to download required signature bundle checksums.txt.bundle for $TAG; failing closed." >&2
    exit 1
  fi
  if [ ! -s "$TMP_DIR/checksums.txt.bundle" ]; then
    echo "Error: Downloaded checksums.txt.bundle is empty; failing closed." >&2
    exit 1
  fi
  echo "Verifying Sigstore/Cosign publisher signature for $TAG..."
  cosign verify-blob \
    --bundle "$TMP_DIR/checksums.txt.bundle" \
    --certificate-identity "$CERT_IDENTITY" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$TMP_DIR/checksums.txt" >/dev/null
elif command -v gh >/dev/null 2>&1; then
  echo "Verifying GitHub SLSA build provenance attestation for $ARCHIVE..."
  gh attestation verify "$TMP_DIR/$ARCHIVE" \
    --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${TAG}" >/dev/null
elif command -v openssl >/dev/null 2>&1 && [ -n "${ARC_RELEASE_PUBLIC_KEY_FILE:-}" ] && [ -f "${ARC_RELEASE_PUBLIC_KEY_FILE:-}" ]; then
  if ! curl -fsSL "$BASE_URL/checksums.txt.ed25519.sig" -o "$TMP_DIR/checksums.txt.ed25519.sig"; then
    echo "Error: Failed to download checksums.txt.ed25519.sig for $TAG; failing closed." >&2
    exit 1
  fi
  echo "Verifying native Ed25519 release signature via OpenSSL..."
  openssl pkeyutl -verify -pubin -inkey "$ARC_RELEASE_PUBLIC_KEY_FILE" \
    -rawin -in "$TMP_DIR/checksums.txt" -sigfile "$TMP_DIR/checksums.txt.ed25519.sig" >/dev/null
else
  echo "Error: Mandatory publisher signature verification requires 'cosign', 'gh' (GitHub CLI), or ARC_RELEASE_PUBLIC_KEY_FILE with 'openssl'; none was available. Failing closed." >&2
  echo "Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) or gh (https://cli.github.com/) and re-run." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
unzip -q -o "$TMP_DIR/$ARCHIVE" -d "$TMP_DIR/extracted"
if [ ! -f "$TMP_DIR/extracted/bin/arc" ]; then
  echo "Error: Archive did not contain expected binary bin/arc" >&2
  exit 1
fi
cp "$TMP_DIR/extracted/bin/arc" "$INSTALL_DIR/arc"
chmod +x "$INSTALL_DIR/arc"

echo "Installed arc to $INSTALL_DIR/arc"
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    RESOLVED_BIN="$(command -v arc 2>/dev/null || true)"
    if [ -n "$RESOLVED_BIN" ] && [ "$RESOLVED_BIN" != "$INSTALL_DIR/arc" ]; then
      echo "[WARN] Another 'arc' binary earlier in PATH is shadowing this installation:" >&2
      echo "       Shadowing: $RESOLVED_BIN" >&2
      echo "       Installed: $INSTALL_DIR/arc" >&2
      echo "       Remove the older binary or prepend $INSTALL_DIR to your PATH." >&2
    fi
    ;;
  *) echo "Add $INSTALL_DIR to your PATH: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
