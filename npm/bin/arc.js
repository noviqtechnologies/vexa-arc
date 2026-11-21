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

  const [archiveBuf, checksumsBuf] = await Promise.all([
    downloadBuffer(`${baseUrl}/${archiveName}`),
    downloadBuffer(`${baseUrl}/checksums.txt`),
  ]);

  verifyArchiveChecksum(
    archiveName,
    archiveBuf,
    checksumsBuf.toString("utf8")
  );

  const tmpZip = path.join(os.tmpdir(), `${archiveName}.${process.pid}.zip`);
  fs.writeFileSync(tmpZip, archiveBuf);
  try {
    return extractBinary(tmpZip, cacheDir, bin);
  } finally {
    fs.rmSync(tmpZip, { force: true });
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
  extractBinary,
};
