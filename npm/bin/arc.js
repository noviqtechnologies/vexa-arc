#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const pkg = require("../package.json");
const REPO = "noviqtechnologies/vexa-arc";
const TAG_REGEX = /^v\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?$/;
const SHA256_REGEX = /^[0-9a-f]{64}$/;

function validateVersionTag(version) {
  if (typeof version !== "string" || !TAG_REGEX.test(version)) {
    throw new Error(
      `Invalid Vexa Arc release version tag '${version}' (expected vX.Y.Z)`
    );
  }
  return version;
}

function resolveVersion() {
  return validateVersionTag(process.env.ARC_VERSION || `v${pkg.version}`);
}

function getPlatformTarget(platform = os.platform(), arch = os.arch()) {
  if (platform === "win32" && arch === "x64")
    return { target: "windows-x86_64", bin: "arc.exe" };
  if (platform === "darwin" && arch === "x64")
    return { target: "macos-x86_64", bin: "arc" };
  if (platform === "darwin" && arch === "arm64")
    return { target: "macos-aarch64", bin: "arc" };
  if (platform === "linux" && arch === "x64")
    return { target: "linux-x86_64", bin: "arc" };
  if (platform === "linux" && arch === "arm64")
    return { target: "linux-aarch64", bin: "arc" };
  throw new Error(`Unsupported platform: ${platform}/${arch}`);
}

function getCacheDir(version = resolveVersion()) {
  validateVersionTag(version);
  if (process.platform === "win32") {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), ".arc");
    return path.join(base, "vexa-arc", "bin", version);
  }
  const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  return path.join(base, "vexa-arc", version);
}

function downloadBuffer(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "@vexasec/arc" } }, (res) => {
        if (
          [301, 302, 307, 308].includes(res.statusCode) &&
          res.headers.location &&
          redirects > 0
        ) {
          return resolve(downloadBuffer(res.headers.location, redirects - 1));
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

function verifyArchiveChecksum(archiveName, archiveBuf, checksumsText) {
  if (typeof checksumsText !== "string" || checksumsText.trim().length === 0) {
    throw new Error(
      `Missing or empty checksums.txt while verifying ${archiveName}; failing closed`
    );
  }
  const lines = checksumsText.split(/\r?\n/);
  let expected = null;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const candidateHash = parts[0].toLowerCase();
    const candidateFile = parts[parts.length - 1].replace(/^\.\//, "");
    if (candidateFile === archiveName && SHA256_REGEX.test(candidateHash)) {
      expected = candidateHash;
      break;
    }
  }
  if (!expected) {
    throw new Error(
      `No valid SHA-256 checksum entry found for ${archiveName} in checksums.txt; failing closed`
    );
  }
  const actual = crypto
    .createHash("sha256")
    .update(archiveBuf)
    .digest("hex")
    .toLowerCase();
  if (actual !== expected) {
    throw new Error(
      `SHA-256 mismatch for ${archiveName}: expected ${expected}, got ${actual}`
    );
  }
  return actual;
}

function extractBinary(zipPath, destDir, binName) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === "win32") {
    const res = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Expand-Archive -LiteralPath $env:ARC_ZIP_PATH -DestinationPath $env:ARC_DEST_DIR -Force",
      ],
      {
        stdio: "inherit",
        env: {
          ...process.env,
          ARC_ZIP_PATH: zipPath,
          ARC_DEST_DIR: destDir,
        },
      }
    );
    if (res.status !== 0)
      throw new Error("Failed to extract archive on Windows");
  } else {
    const res = spawnSync("unzip", ["-q", "-o", zipPath, "-d", destDir], {
      stdio: "inherit",
    });
    if (res.status !== 0)
      throw new Error(
        "Failed to extract archive (ensure 'unzip' is installed)"
      );
  }
  const extractedBin = path.join(destDir, "bin", binName);
  if (!fs.existsSync(extractedBin)) {
    throw new Error(`Expected binary not found at ${extractedBin}`);
  }
  if (process.platform !== "win32") {
    fs.chmodSync(extractedBin, 0o755);
  }
  return extractedBin;
}

function expectedCertificateIdentity(tag) {
  validateVersionTag(tag);
  return `https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${tag}`;
}

function parseSemverTuple(tag) {
  validateVersionTag(tag);
  const core = tag.replace(/^v/, "").split("-")[0];
  return core.split(".").map((n) => parseInt(n, 10));
}

function checkVersionRollback(requestedTag, installedTag, allowDowngrade = false) {
  if (!installedTag || allowDowngrade) return true;
  const req = parseSemverTuple(requestedTag);
  const inst = parseSemverTuple(installedTag);
  for (let i = 0; i < 3; i++) {
    if (req[i] < inst[i]) {
      throw new Error(
        `Rollback rejected: installed version ${installedTag} is newer than requested ${requestedTag} (set ARC_ALLOW_DOWNGRADE=1 to override)`
      );
    }
    if (req[i] > inst[i]) return true;
  }
  return true;
}

function verifyEd25519Signature(dataBuf, signatureBuf, publicKeyPem) {
  if (!publicKeyPem || !publicKeyPem.includes("BEGIN PUBLIC KEY")) {
    throw new Error("Invalid or missing Ed25519 release public key PEM; failing closed");
  }
  if (!Buffer.isBuffer(signatureBuf) || signatureBuf.length !== 64) {
    throw new Error(
      `Invalid Ed25519 signature length (${signatureBuf ? signatureBuf.length : 0} bytes, expected 64); failing closed`
    );
  }
  const ok = crypto.verify(null, dataBuf, publicKeyPem, signatureBuf);
  if (!ok) {
    throw new Error("Ed25519 release signature verification failed; failing closed");
  }
  return true;
}

function resolveReleasePublicKeyPem(overridePem) {
  if (overridePem && overridePem.trim()) return overridePem.trim();
  if (process.env.ARC_RELEASE_PUBLIC_KEY_PEM && process.env.ARC_RELEASE_PUBLIC_KEY_PEM.trim()) {
    return process.env.ARC_RELEASE_PUBLIC_KEY_PEM.trim();
  }
  if (process.env.ARC_RELEASE_PUBLIC_KEY_FILE && fs.existsSync(process.env.ARC_RELEASE_PUBLIC_KEY_FILE)) {
    return fs.readFileSync(process.env.ARC_RELEASE_PUBLIC_KEY_FILE, "utf8").trim();
  }
  return null;
}

function verifyPublisherSignature({
  checksumsPath,
  bundlePath,
  ed25519SigPath,
  archivePath,
  tag,
  publicKeyPem = null,
  spawnFn = spawnSync,
}) {
  const certIdentity = expectedCertificateIdentity(tag);
  const oidcIssuer = "https://token.actions.githubusercontent.com";

  // 1. Prefer Cosign keyless Sigstore verification against checksums.txt.bundle
  const cosignProbe = spawnFn("cosign", ["version"], { stdio: "pipe" });
  if (!cosignProbe.error && cosignProbe.status === 0) {
    if (!bundlePath || !fs.existsSync(bundlePath) || fs.statSync(bundlePath).size === 0) {
      throw new Error(
        `Missing or empty signature bundle checksums.txt.bundle for ${tag}; failing closed`
      );
    }
    const res = spawnFn(
      "cosign",
      [
        "verify-blob",
        "--bundle",
        bundlePath,
        "--certificate-identity",
        certIdentity,
        "--certificate-oidc-issuer",
        oidcIssuer,
        checksumsPath,
      ],
      { stdio: "pipe", encoding: "utf8" }
    );
    if (res.error || res.status !== 0) {
      const detail = (res.stderr || res.error?.message || "unknown error").trim();
      throw new Error(
        `Cosign publisher signature verification failed for ${tag}: ${detail}`
      );
    }
    return { verifier: "cosign", identity: certIdentity };
  }

  // 2. Fallback to GitHub CLI SLSA provenance verification against the archive
  const ghProbe = spawnFn("gh", ["--version"], { stdio: "pipe" });
  if (!ghProbe.error && ghProbe.status === 0) {
    const res = spawnFn(
      "gh",
      [
        "attestation",
        "verify",
        archivePath,
        "--repo",
        REPO,
        "--signer-workflow",
        `${REPO}/.github/workflows/release.yml`,
        "--source-ref",
        `refs/tags/${tag}`,
      ],
      { stdio: "pipe", encoding: "utf8" }
    );
    if (res.error || res.status !== 0) {
      const detail = (res.stderr || res.error?.message || "unknown error").trim();
      throw new Error(
        `GitHub SLSA provenance attestation verification failed for ${tag}: ${detail}`
      );
    }
    return { verifier: "gh-attestation", identity: certIdentity };
  }

  // 3. Zero-dependency native Node.js Ed25519 verification against pinned release public key
  const pem = resolveReleasePublicKeyPem(publicKeyPem);
  if (pem) {
    if (!ed25519SigPath || !fs.existsSync(ed25519SigPath)) {
      throw new Error(
        `Missing Ed25519 signature file checksums.txt.ed25519.sig for ${tag}; failing closed`
      );
    }
    verifyEd25519Signature(
      fs.readFileSync(checksumsPath),
      fs.readFileSync(ed25519SigPath),
      pem
    );
    return { verifier: "ed25519-native", identity: "pinned-release-key" };
  }

  throw new Error(
    `Mandatory publisher signature verification requires 'cosign', 'gh' (GitHub CLI), or a pinned Ed25519 release public key (ARC_RELEASE_PUBLIC_KEY_PEM/FILE); none was found. Failing closed.`
  );
}

async function ensureBinary() {
  const version = resolveVersion();
  const { target, bin } = getPlatformTarget();
  const cacheDir = getCacheDir(version);
  const cachedBin = path.join(cacheDir, "bin", bin);
  if (fs.existsSync(cachedBin)) {
    return cachedBin;
  }

  const archiveName = `vexa-arc-${version}-${target}.zip`;
  const baseUrl = `https://github.com/${REPO}/releases/download/${version}`;
  process.stderr.write(`[arc] Downloading ${archiveName}...\n`);

  const [archiveBuf, checksumsBuf, bundleBuf, ed25519SigBuf] = await Promise.all([
    downloadBuffer(`${baseUrl}/${archiveName}`),
    downloadBuffer(`${baseUrl}/checksums.txt`),
    downloadBuffer(`${baseUrl}/checksums.txt.bundle`).catch(() => null),
    downloadBuffer(`${baseUrl}/checksums.txt.ed25519.sig`).catch(() => null),
  ]);

  verifyArchiveChecksum(
    archiveName,
    archiveBuf,
    checksumsBuf.toString("utf8")
  );

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vexa-arc-npm-"));
  const tmpZip = path.join(tmpDir, archiveName);
  const tmpChecksums = path.join(tmpDir, "checksums.txt");
  const tmpBundle = path.join(tmpDir, "checksums.txt.bundle");
  const tmpEdSig = path.join(tmpDir, "checksums.txt.ed25519.sig");
  fs.writeFileSync(tmpZip, archiveBuf);
  fs.writeFileSync(tmpChecksums, checksumsBuf);
  if (bundleBuf) fs.writeFileSync(tmpBundle, bundleBuf);
  if (ed25519SigBuf) fs.writeFileSync(tmpEdSig, ed25519SigBuf);
  try {
    verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: bundleBuf ? tmpBundle : null,
      ed25519SigPath: ed25519SigBuf ? tmpEdSig : null,
      archivePath: tmpZip,
      tag: version,
    });
    return extractBinary(tmpZip, cacheDir, bin);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  ensureBinary()
    .then((binPath) => {
      const result = spawnSync(binPath, process.argv.slice(2), {
        stdio: "inherit",
      });
      process.exit(result.status ?? 1);
    })
    .catch((err) => {
      process.stderr.write(`[arc] ${err.message}\n`);
      process.exit(1);
    });
}

module.exports = {
  validateVersionTag,
  getPlatformTarget,
  getCacheDir,
  verifyArchiveChecksum,
  expectedCertificateIdentity,
  checkVersionRollback,
  verifyEd25519Signature,
  verifyPublisherSignature,
  extractBinary,
};
