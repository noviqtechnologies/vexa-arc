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
  BASE_URL="https://github.com/$REPO/releases/latest/download"
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$TAG" ]; then
    echo "Error: Failed to resolve latest release tag from GitHub" >&2
    exit 1
  fi
else
  TAG="$VERSION"
  BASE_URL="https://github.com/$REPO/releases/download/$TAG"
fi

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

if [ "${ARC_REQUIRE_COSIGN:-0}" = "1" ] || command -v cosign >/dev/null 2>&1; then
  if [ "${ARC_SKIP_COSIGN:-0}" != "1" ]; then
    if curl -fsSL "$BASE_URL/checksums.txt.bundle" -o "$TMP_DIR/checksums.txt.bundle" 2>/dev/null; then
      if command -v cosign >/dev/null 2>&1; then
        cosign verify-blob \
          --bundle "$TMP_DIR/checksums.txt.bundle" \
          --certificate-identity-regexp "https://github.com/${REPO}/.github/workflows/release.yml@.*" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
          "$TMP_DIR/checksums.txt" >/dev/null
      elif [ "${ARC_REQUIRE_COSIGN:-0}" = "1" ]; then
        echo "Error: ARC_REQUIRE_COSIGN=1 set but cosign binary is not installed; failing closed." >&2
        exit 1
      fi
    elif [ "${ARC_REQUIRE_COSIGN:-0}" = "1" ]; then
      echo "Error: ARC_REQUIRE_COSIGN=1 set but checksums.txt.bundle could not be downloaded; failing closed." >&2
      exit 1
    fi
  fi
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
