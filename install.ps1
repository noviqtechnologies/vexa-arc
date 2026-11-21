$ErrorActionPreference = "Stop"

$Repo = "noviqtechnologies/vexa-arc"
$Version = if ($env:ARC_VERSION) { $env:ARC_VERSION } else { "latest" }
$InstallDir = if ($env:ARC_INSTALL_DIR) { $env:ARC_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "vexa-arc\bin" }

if ($Version -eq "latest") {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Tag = $Release.tag_name
}
else {
    $Tag = $Version
}

if ([string]::IsNullOrWhiteSpace($Tag) -or ($Tag -notmatch '^v\d+\.\d+\.\d+(-[A-Za-z0-9._-]+)?$')) {
    throw "Invalid release tag format '$Tag' (expected vX.Y.Z); failing closed."
}

$Archive = "vexa-arc-$Tag-windows-x86_64.zip"
$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vexa-arc-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    Write-Host "Downloading Vexa Arc $Tag (windows-x86_64)..."
    $ArchivePath = Join-Path $TmpDir $Archive
    $ChecksumsPath = Join-Path $TmpDir "checksums.txt"
    Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath
    Invoke-WebRequest -Uri "$BaseUrl/checksums.txt" -OutFile $ChecksumsPath

    if (-not (Test-Path -LiteralPath $ChecksumsPath) -or ((Get-Item -LiteralPath $ChecksumsPath).Length -eq 0)) {
        throw "Downloaded checksums.txt is empty or missing; failing closed."
    }

    $ExpectedLine = Get-Content -LiteralPath $ChecksumsPath | Where-Object { $_ -match "^\s*([0-9a-fA-F]{64})\s+(\./)?$([regex]::Escape($Archive))\s*$" } | Select-Object -First 1
    if (-not $ExpectedLine) {
        throw "No valid SHA-256 entry found for '$Archive' in checksums.txt; failing closed."
    }

    $ExpectedSha = (($ExpectedLine.Trim() -split "\s+")[0]).ToLowerInvariant()
    if ($ExpectedSha -notmatch '^[0-9a-f]{64}$') {
        throw "Malformed SHA-256 digest '$ExpectedSha' in checksums.txt; failing closed."
    }

    $ActualSha = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha -ne $ExpectedSha) {
        throw "Checksum mismatch for $Archive! Expected $ExpectedSha, got $ActualSha"
    }

    $ExtractDir = Join-Path $TmpDir "extracted"
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractDir -Force
    $ExtractedBin = Join-Path $ExtractDir "bin\arc.exe"
    if (-not (Test-Path -LiteralPath $ExtractedBin)) {
        throw "Extracted archive did not contain expected binary bin\arc.exe; failing closed."
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $InstalledExe = Join-Path $InstallDir "arc.exe"
    Copy-Item -LiteralPath $ExtractedBin -Destination $InstalledExe -Force

    # Prepend InstallDir to User PATH so the newly installed binary takes precedence
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        $NewUserPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $InstallDir } else { "$InstallDir;$UserPath" }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
        Write-Host "Added $InstallDir to your User PATH."
    }
    if ($env:Path -notlike "*$InstallDir*") {
        $env:Path = "$InstallDir;$env:Path"
    }

    Write-Host "Installed arc.exe to $InstalledExe"

    # Warn if an older arc binary earlier in PATH shadows this installation
    $FirstResolved = Get-Command arc -ErrorAction SilentlyContinue
    if ($FirstResolved -and $FirstResolved.Source -and ($FirstResolved.Source -ne $InstalledExe)) {
        Write-Host ""
        Write-Host "[WARN] Another 'arc' binary earlier in PATH is shadowing this installation:" -ForegroundColor Yellow
        Write-Host "       Shadowing: $($FirstResolved.Source)" -ForegroundColor Yellow
        Write-Host "       Installed: $InstalledExe" -ForegroundColor Yellow
        Write-Host "       Remove the older binary (e.g. Remove-Item '$($FirstResolved.Source)') or move $InstallDir earlier in PATH." -ForegroundColor Yellow
    }
}
finally {
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
