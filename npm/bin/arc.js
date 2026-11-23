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

function getCacheRoot(platform = process.platform, env = process.env, homeDir = os.homedir()) {
  if (platform === "win32") {
    const base = env.LOCALAPPDATA || path.join(homeDir, ".arc");
    return path.join(base, "vexa-arc", "bin");
  }
  const base = env.XDG_CACHE_HOME || path.join(homeDir, ".cache");
  return path.join(base, "vexa-arc");
}

function getCacheDir(version = resolveVersion(), cacheRoot = getCacheRoot()) {
  validateVersionTag(version);
  return path.join(cacheRoot, version);
}

function compareSemverTags(a, b) {
  const ta = parseSemverTuple(a);
  const tb = parseSemverTuple(b);
  for (let i = 0; i < 3; i++) {
    if (ta[i] !== tb[i]) return ta[i] - tb[i];
  }
  return 0;
}

function getHighestInstalledVersion(cacheRoot = getCacheRoot()) {
  let highest = null;
  const statePath = path.join(cacheRoot, "installed-version.txt");
  if (fs.existsSync(statePath)) {
    const raw = fs.readFileSync(statePath, "utf8").trim();
    if (TAG_REGEX.test(raw)) {
      highest = raw;
    }
  }
  if (fs.existsSync(cacheRoot)) {
    for (const entry of fs.readdirSync(cacheRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !TAG_REGEX.test(entry.name)) continue;
      const candidateBinDir = path.join(cacheRoot, entry.name, "bin");
      if (!fs.existsSync(candidateBinDir)) continue;
      if (!highest || compareSemverTags(entry.name, highest) > 0) {
        highest = entry.name;
      }
    }
  }
  return highest;
}

function recordInstalledVersion(version, cacheRoot = getCacheRoot()) {
  validateVersionTag(version);
  fs.mkdirSync(cacheRoot, { recursive: true });
  const existing = getHighestInstalledVersion(cacheRoot);
  const next =
    existing && compareSemverTags(existing, version) > 0 ? existing : version;
  const statePath = path.join(cacheRoot, "installed-version.txt");
  const tmpPath = `${statePath}.tmp-${process.pid}`;
  fs.writeFileSync(tmpPath, `${next}\n`, "utf8");
  fs.renameSync(tmpPath, statePath);
  return next;
}

function computeFileSha256(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex").toLowerCase();
}

function getCachedBinaryHashPath(binPath) {
  return `${binPath}.sha256`;
}

function writeCachedBinaryHash(binPath) {
  const digest = computeFileSha256(binPath);
  const hashPath = getCachedBinaryHashPath(binPath);
  const tmpPath = `${hashPath}.tmp-${process.pid}`;
  fs.writeFileSync(tmpPath, `${digest}\n`, "utf8");
  fs.renameSync(tmpPath, hashPath);
  return digest;
}

function verifyCachedBinary(binPath) {
  const hashPath = getCachedBinaryHashPath(binPath);
  if (!fs.existsSync(hashPath)) {
    throw new Error(
      `Cached binary integrity digest missing at ${hashPath}; failing closed (remove cache directory to re-download and re-verify)`
    );
  }
  const expected = fs.readFileSync(hashPath, "utf8").trim().toLowerCase();
  if (!SHA256_REGEX.test(expected)) {
    throw new Error(
      `Malformed cached binary SHA-256 digest at ${hashPath}; failing closed`
    );
  }
  const actual = computeFileSha256(binPath);
  if (actual !== expected) {
    throw new Error(
      `Cached binary SHA-256 mismatch for ${binPath}: expected ${expected}, got ${actual}; failing closed`
    );
  }
  return actual;
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
  let ghAuthSkipped = null;
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
    if (!res.error && res.status === 0) {
      return { verifier: "gh-attestation", identity: certIdentity };
    }
    const detail = (res.stderr || res.error?.message || "unknown error").trim();
    const isUnauthenticated =
      /gh auth login|GH_TOKEN|not logged into any GitHub hosts|authentication required/i.test(
        detail
      );
    // Only fall through to Ed25519 if `gh` is unauthenticated and an Ed25519 key is configured;
    // actual attestation verification failures always fail closed immediately.
    if (isUnauthenticated && resolveReleasePublicKeyPem(publicKeyPem)) {
      ghAuthSkipped = detail;
    } else {
      throw new Error(
        `GitHub SLSA provenance attestation verification failed for ${tag}: ${detail}`
      );
    }
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

  const extra = ghAuthSkipped ? ` (gh CLI was unauthenticated: ${ghAuthSkipped})` : "";
  throw new Error(
    `Mandatory publisher signature verification requires 'cosign', authenticated 'gh' (run 'gh auth login' or set GH_TOKEN), or a pinned Ed25519 release public key (ARC_RELEASE_PUBLIC_KEY_PEM/FILE); none was available${extra}. Failing closed.`
  );
}

async function ensureBinary(options = {}) {
  const version = validateVersionTag(options.version || resolveVersion());
  const { target, bin } = options.platformTarget || getPlatformTarget();
  const cacheRoot = options.cacheRoot || getCacheRoot();
  const allowDowngrade =
    options.allowDowngrade !== undefined
      ? Boolean(options.allowDowngrade)
      : process.env.ARC_ALLOW_DOWNGRADE === "1";

  // Enforce rollback protection before serving a cached binary or downloading an older release
  const installedVersion = getHighestInstalledVersion(cacheRoot);
  checkVersionRollback(version, installedVersion, allowDowngrade);

  const cacheDir = getCacheDir(version, cacheRoot);
  const cachedBin = path.join(cacheDir, "bin", bin);
  if (fs.existsSync(cachedBin)) {
    verifyCachedBinary(cachedBin);
    return cachedBin;
  }

  const downloadFn = options.downloadFn || downloadBuffer;
  const verifySigFn = options.verifyPublisherSignatureFn || verifyPublisherSignature;
  const extractFn = options.extractFn || extractBinary;

  const archiveName = `vexa-arc-${version}-${target}.zip`;
  const baseUrl = `https://github.com/${REPO}/releases/download/${version}`;
  process.stderr.write(`[arc] Downloading ${archiveName}...\n`);

  const [archiveBuf, checksumsBuf, bundleBuf, ed25519SigBuf] = await Promise.all([
    downloadFn(`${baseUrl}/${archiveName}`),
    downloadFn(`${baseUrl}/checksums.txt`),
    downloadFn(`${baseUrl}/checksums.txt.bundle`).catch(() => null),
    downloadFn(`${baseUrl}/checksums.txt.ed25519.sig`).catch(() => null),
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
    verifySigFn({
      checksumsPath: tmpChecksums,
      bundlePath: bundleBuf ? tmpBundle : null,
      ed25519SigPath: ed25519SigBuf ? tmpEdSig : null,
      archivePath: tmpZip,
      tag: version,
      publicKeyPem: options.publicKeyPem || null,
    });
    const extractedBin = extractFn(tmpZip, cacheDir, bin);
    writeCachedBinaryHash(extractedBin);
    recordInstalledVersion(version, cacheRoot);
    return extractedBin;
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
  getCacheRoot,
  getCacheDir,
  getHighestInstalledVersion,
  recordInstalledVersion,
  verifyCachedBinary,
  writeCachedBinaryHash,
  verifyArchiveChecksum,
  expectedCertificateIdentity,
  checkVersionRollback,
  verifyEd25519Signature,
  verifyPublisherSignature,
  extractBinary,
  ensureBinary,
};
