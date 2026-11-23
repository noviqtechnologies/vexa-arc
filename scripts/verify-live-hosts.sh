#!/usr/bin/env sh
# Reproducible Cross-OS Live Host Verification Harness (Linux / macOS) for Vexa Arc.
set -eu

ARC_BIN="${ARC_BIN:-arc}"
OUT_FILE="${1:-}"

ARC_VER="$("$ARC_BIN" --version 2>&1 || true)"
CLAUDE_VER="$(command -v claude >/dev/null 2>&1 && claude --version 2>&1 || echo "not installed")"
CURSOR_VER="$(command -v cursor >/dev/null 2>&1 && cursor --version 2>&1 | head -n 1 || echo "not installed")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

(
  cd "$TMP_DIR"
  "$ARC_BIN" init --host all >/dev/null
  printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' > "$TMP_DIR/.env"
  printf 'AWS_ACCESS_KEY_ID=YOUR_KEY_HERE\n' > "$TMP_DIR/.env.example"

  ENV_OUT="$(printf '{"hook_event_name":"PreToolUse","session_id":"live-v1","tool_name":"Read","tool_input":{"file_path":"%s/.env"},"cwd":"%s"}' "$TMP_DIR" "$TMP_DIR" | "$ARC_BIN" intercept hook --host claude-code 2>&1 || true)"
  EX_OUT="$(printf '{"hook_event_name":"PreToolUse","session_id":"live-v1","tool_name":"Read","tool_input":{"file_path":"%s/.env.example"},"cwd":"%s"}' "$TMP_DIR" "$TMP_DIR" | "$ARC_BIN" intercept hook --host claude-code 2>&1 || true)"
  MCP_OUT="$(printf '{"hook_event_name":"beforeMCPExecution","conversation_id":"live-v1","server":"rogue-unapproved","tool_name":"dump","tool_input":"{}","cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host cursor 2>&1 || true)"
  set +e
  RM_ERR="$(printf '{"hook_event_name":"beforeShellExecution","conversation_id":"live-v1","command":"rm -rf /tmp/prod","cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host cursor 2>&1)"
  RM_CODE=$?
  set -e

  REPORT="# Vexa Arc Live Host Verification Evidence

- **Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- **OS:** $(uname -s) $(uname -m)
- **Arc Binary:** $ARC_VER
- **Claude Code CLI:** $CLAUDE_VER
- **Cursor CLI:** $CURSOR_VER

## Automated Hook Probes (Fresh \`arc init\` Disposable Project)

| Scenario | Host | Result |
| --- | --- | --- |
| \`.env\` read (\`ARC-FS-001\`) | claude-code | \`$ENV_OUT\` |
| \`.env.example\` read (benign template) | claude-code | \`$EX_OUT\` |
| Unapproved MCP call (\`ARC-MCP-001\`) | cursor | \`$MCP_OUT\` |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | cursor | exit $RM_CODE (\`$RM_ERR\`) |

## Interactive Authenticated Session Checklist (Run Manually in Interactive PTY — NOT \`claude -p\`)
- [ ] \`.env\` read -> user-visible ask/deny
- [ ] \`.env.example\` read -> allowed
- [ ] Unapproved MCP call -> user-visible ask/deny
- [ ] Approved pinned MCP call -> allowed
- [ ] MCP schema rug-pull -> blocked (\`ARC-MCP-003\`)
- [ ] Destructive shell \`rm -rf\` -> blocked (exit 2)
- [ ] Untrusted issue + secret read + egress -> blocked (\`ARC-LTT-001\`)
- [ ] Out-of-boundary (documented, not intercepted): direct manual editor write, external terminal, unwrapped MCP, direct network client"

  if [ -n "$OUT_FILE" ]; then
    printf '%s\n' "$REPORT" > "$OUT_FILE"
    echo "Wrote verification report to $OUT_FILE"
  else
    printf '%s\n' "$REPORT"
  fi
)
