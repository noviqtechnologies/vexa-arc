"use strict";

const assert = require("assert");
const {
  MARKER,
  findExistingCommentId,
  resolvePullRequestNumber,
  upsertPrComment,
} = require("./comment-pr");

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
    requestFn: async (method, path, _tok, body) => {
      calls.push({ method, path, body });
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
    requestFn: async (method, path, _tok, body) => {
      calls.push({ method, path, body });
      if (method === "GET") return { status: 200, body: [] };
      return { status: 201, body: { id: 101 } };
    },
  });
  assert.strictEqual(resCreate.created, true);
  assert.strictEqual(calls[1].method, "POST");
  assert.strictEqual(calls[1].path, "/repos/org/repo/issues/8/comments");

  console.log("comment-pr.test.js: all assertions passed");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
