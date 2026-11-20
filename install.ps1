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

    $ExpectedLine = Get-Content $ChecksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($Archive))$" } | Select-Object -First 1
    if ($ExpectedLine) {
        $ExpectedSha = ($ExpectedLine -split "\s+")[0].ToLowerInvariant()
        $ActualSha = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ActualSha -ne $ExpectedSha) {
            throw "Checksum mismatch! Expected $ExpectedSha, got $ActualSha"
        }
    }

    $ExtractDir = Join-Path $TmpDir "extracted"
    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $InstalledExe = Join-Path $InstallDir "arc.exe"
    Copy-Item -Path (Join-Path $ExtractDir "bin\arc.exe") -Destination $InstalledExe -Force

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
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
