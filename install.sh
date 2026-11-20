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
    echo "Failed to resolve latest release tag from GitHub" >&2
    exit 1
  fi
else
  TAG="$VERSION"
  BASE_URL="https://github.com/$REPO/releases/download/$TAG"
fi

ARCHIVE="vexa-arc-${TAG}-${TARGET}.zip"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Vexa Arc $TAG ($TARGET)..."
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMP_DIR/$ARCHIVE"
curl -fsSL "$BASE_URL/checksums.txt" -o "$TMP_DIR/checksums.txt"

EXPECTED_SHA="$(grep " $ARCHIVE" "$TMP_DIR/checksums.txt" | awk '{print $1}' | head -n 1)"
if [ -n "$EXPECTED_SHA" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA="$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA="$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')"
  else
    echo "Warning: sha256sum/shasum not found; skipping checksum verification" >&2
    ACTUAL_SHA="$EXPECTED_SHA"
  fi
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "Checksum mismatch! Expected $EXPECTED_SHA, got $ACTUAL_SHA" >&2
    exit 1
  fi
fi

mkdir -p "$INSTALL_DIR"
unzip -q -o "$TMP_DIR/$ARCHIVE" -d "$TMP_DIR/extracted"
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
