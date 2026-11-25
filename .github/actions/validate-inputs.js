"use strict";

const VERSION_REGEX = /^(latest|source|v\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?)$/;
const VALID_FAIL_ON = new Set(["", "critical", "high", "medium", "low"]);
const VALID_BOOL = new Set(["true", "false"]);

function validateActionInputs(env = process.env) {
  const version = env.INPUT_VERSION ?? "latest";
  if (!VERSION_REGEX.test(version)) {
    throw new Error(
      `Invalid 'version' input: '${version}'. Expected 'latest', 'source', or 'vX.Y.Z'.`
    );
  }

  const failOn = (env.INPUT_FAIL_ON ?? "").toLowerCase();
  if (!VALID_FAIL_ON.has(failOn)) {
    throw new Error(
      `Invalid 'fail-on' input: '${env.INPUT_FAIL_ON}'. Expected one of: '', 'critical', 'high', 'medium', 'low'.`
    );
  }

  const boolFields = [
    ["fail-on-secrets", env.INPUT_FAIL_ON_SECRETS ?? "true"],
    ["fail-on-unpinned-mcp", env.INPUT_FAIL_ON_UNPINNED_MCP ?? "false"],
    ["run-sca", env.INPUT_RUN_SCA ?? "true"],
    ["run-policy-test", env.INPUT_RUN_POLICY_TEST ?? "false"],
    ["comment-pr", env.INPUT_COMMENT_PR ?? "true"],
  ];

  for (const [name, val] of boolFields) {
    if (!VALID_BOOL.has(String(val))) {
      throw new Error(
        `Invalid '${name}' input: '${val}'. Expected 'true' or 'false'.`
      );
    }
  }

  const targetPath = env.INPUT_PATH ?? ".";
  if (typeof targetPath !== "string" || targetPath.includes("\0") || targetPath.includes("\n") || targetPath.includes("\r")) {
    throw new Error("Invalid 'path' input: must not contain NUL or newline characters.");
  }

  return true;
}

if (require.main === module) {
  try {
    validateActionInputs(process.env);
  } catch (err) {
    console.error(`::error::${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  validateActionInputs,
};
