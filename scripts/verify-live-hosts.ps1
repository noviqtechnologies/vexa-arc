<#
.SYNOPSIS
    Reproducible Cross-OS Live Host Verification Harness (Windows) for Vexa Arc.
.DESCRIPTION
    Initializes a disposable project with `arc init`, records installed host CLI versions
    (Claude Code, Cursor), runs deterministic pre-hook probes, and emits a Markdown evidence
    template for the 11-scenario live authenticated session matrix.
#>
param(
    [string]$ArcBin = "arc",
    [string]$OutFile = ""
)

$ErrorActionPreference = "Stop"

$ArcVer = (& $ArcBin --version 2>&1) | Out-String
$ClaudeCmd = Get-Command claude -ErrorAction SilentlyContinue
$CursorCmd = Get-Command cursor -ErrorAction SilentlyContinue
$ClaudeVer = if ($ClaudeCmd) { (& $ClaudeCmd.Source --version 2>&1) | Out-String } else { "not installed" }
$CursorVer = if ($CursorCmd) { (& $CursorCmd.Source --version 2>&1 | Select-Object -First 1) | Out-String } else { "not installed" }

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vexa-arc-live-verify-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    Push-Location $TmpDir
    & $ArcBin init --host all | Out-Null
    Set-Content -Path (Join-Path $TmpDir ".env") -Value "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    Set-Content -Path (Join-Path $TmpDir ".env.example") -Value "AWS_ACCESS_KEY_ID=YOUR_KEY_HERE"

    function Invoke-HookProbe([string]$HostName, [string]$Payload) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Get-Command $ArcBin).Source
        $psi.Arguments = "intercept hook --host $HostName"
        $psi.WorkingDirectory = $TmpDir
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Write($Payload)
        $proc.StandardInput.Close()
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        return @{ Code = $proc.ExitCode; Stdout = $stdout.Trim(); Stderr = $stderr.Trim() }
    }

    $CwdJson = ($TmpDir -replace '\\', '\\')
    $EnvProbe = Invoke-HookProbe "claude-code" "{`"hook_event_name`":`"PreToolUse`",`"session_id`":`"live-v1`",`"tool_name`":`"Read`",`"tool_input`":{`"file_path`":`"$CwdJson\\.env`"},`"cwd`":`"$CwdJson`"}"
    $ExampleProbe = Invoke-HookProbe "claude-code" "{`"hook_event_name`":`"PreToolUse`",`"session_id`":`"live-v1`",`"tool_name`":`"Read`",`"tool_input`":{`"file_path`":`"$CwdJson\\.env.example`"},`"cwd`":`"$CwdJson`"}"
    $McpProbe = Invoke-HookProbe "cursor" "{`"hook_event_name`":`"beforeMCPExecution`",`"conversation_id`":`"live-v1`",`"server`":`"rogue-unapproved`",`"tool_name`":`"dump`",`"tool_input`":`"{}`",`"cwd`":`"$CwdJson`"}"
    $RmProbe = Invoke-HookProbe "cursor" "{`"hook_event_name`":`"beforeShellExecution`",`"conversation_id`":`"live-v1`",`"command`":`"rm -rf /tmp/prod`",`"cwd`":`"$CwdJson`"}"

    $Report = @"
# Vexa Arc Live Host Verification Evidence

- **Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz")
- **OS:** Windows ($([System.Environment]::OSVersion.VersionString))
- **Arc Binary:** $($ArcVer.Trim())
- **Claude Code CLI:** $($ClaudeVer.Trim())
- **Cursor CLI:** $($CursorVer.Trim())

## Automated Hook Probes (Fresh ``arc init`` Disposable Project)

| Scenario | Host | Exit Code | Output Summary |
| --- | --- | --- | --- |
| ``.env`` read (``ARC-FS-001``) | claude-code | $($EnvProbe.Code) | ``$($EnvProbe.Stdout)`` |
| ``.env.example`` read (benign template) | claude-code | $($ExampleProbe.Code) | ``$($ExampleProbe.Stdout)`` |
| Unapproved MCP call (``ARC-MCP-001``) | cursor | $($McpProbe.Code) | ``$($McpProbe.Stdout)`` |
| Destructive ``rm -rf`` (``ARC-CMD-001``) | cursor | $($RmProbe.Code) | ``$($RmProbe.Stderr)`` |

## Interactive Authenticated Session Checklist (Run Manually in Interactive PTY — NOT ``claude -p``)
- [ ] ``.env`` read -> user-visible ask/deny
- [ ] ``.env.example`` read -> allowed
- [ ] Unapproved MCP call -> user-visible ask/deny
- [ ] Approved pinned MCP call -> allowed
- [ ] MCP schema rug-pull -> blocked (``ARC-MCP-003``)
- [ ] Destructive shell ``rm -rf`` -> blocked (exit 2)
- [ ] Untrusted issue + secret read + egress -> blocked (``ARC-LTT-001``)
- [ ] Out-of-boundary (documented, not intercepted): direct manual editor write, external terminal, unwrapped MCP, direct network client
"@

    if ($OutFile) {
        Set-Content -Path $OutFile -Value $Report
        Write-Host "Wrote verification report to $OutFile"
    } else {
        Write-Output $Report
    }
} finally {
    Pop-Location
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
