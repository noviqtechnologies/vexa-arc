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
  COPILOT_OUT="$(printf '{"hookEventName":"preToolUse","sessionId":"live-v1","toolName":"bash","toolArgs":{"command":"rm -rf /tmp/prod"},"cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host github-copilot 2>&1)"
  COPILOT_CODE=$?
  CODEX_OUT="$(printf '{"hook_event_name":"PreToolUse","session_id":"live-v1","tool_name":"shell","tool_input":{"command":"rm -rf /tmp/prod"},"cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host codex-cli 2>&1)"
  CODEX_CODE=$?
  GEMINI_OUT="$(printf '{"hook_event_name":"BeforeTool","session_id":"live-v1","tool_name":"run_shell_command","tool_input":{"command":"rm -rf /tmp/prod"},"cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host gemini-cli 2>&1)"
  GEMINI_CODE=$?
  WINDSURF_OUT="$(printf '{"agent_action_name":"pre_run_command","trajectory_id":"live-v1","tool_info":{"command_line":"rm -rf /tmp/prod","cwd":"%s"}}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host windsurf 2>&1)"
  WINDSURF_CODE=$?
  CLINE_OUT="$(printf '{"hookName":"PreToolUse","taskId":"live-v1","workspaceRoots":["%s"],"preToolUse":{"toolName":"execute_command","parameters":{"command":"rm -rf /tmp/prod"}}}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host cline 2>&1)"
  CLINE_CODE=$?
  KIRO_OUT="$(printf '{"trigger":"PreToolUse","session_id":"live-v1","tool_name":"shell","tool_input":{"command":"rm -rf /tmp/prod"},"cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host kiro 2>&1)"
  KIRO_CODE=$?
  OPENCODE_OUT="$(printf '{"event":"tool.execute.before","sessionID":"live-v1","tool":"bash","args":{"command":"rm -rf /tmp/prod"},"cwd":"%s"}' "$TMP_DIR" | "$ARC_BIN" intercept hook --host opencode 2>&1)"
  OPENCODE_CODE=$?
  set -e

  REPORT="# Vexa Arc Live Host Verification Evidence

- **Date:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- **OS:** $(uname -s) $(uname -m)
- **Arc Binary:** $ARC_VER
- **Claude Code CLI:** $CLAUDE_VER
- **Cursor CLI:** $CURSOR_VER

## Automated Hook Probes (Fresh \`arc init --host all\` Disposable Project)

| Scenario | Host | Result |
| --- | --- | --- |
| \`.env\` read (\`ARC-FS-001\`) | claude-code | \`$ENV_OUT\` |
| \`.env.example\` read (benign template) | claude-code | \`$EX_OUT\` |
| Unapproved MCP call (\`ARC-MCP-001\`) | cursor | \`$MCP_OUT\` |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | cursor | exit $RM_CODE (\`$RM_ERR\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | github-copilot | exit $COPILOT_CODE (\`$COPILOT_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | codex-cli | exit $CODEX_CODE (\`$CODEX_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | gemini-cli | exit $GEMINI_CODE (\`$GEMINI_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | windsurf | exit $WINDSURF_CODE (\`$WINDSURF_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | cline | exit $CLINE_CODE (\`$CLINE_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | kiro | exit $KIRO_CODE (\`$KIRO_OUT\`) |
| Destructive \`rm -rf\` (\`ARC-CMD-001\`) | opencode | exit $OPENCODE_CODE (\`$OPENCODE_OUT\`) |

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
