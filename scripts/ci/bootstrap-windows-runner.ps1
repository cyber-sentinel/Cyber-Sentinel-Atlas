#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoUrl = 'https://github.com/cyber-sentinel/Cyber-Sentinel-Atlas'
$RunnerName = 'ATLAS-CI-WIN01'
$RunnerVersion = '2.337.0'
$RunnerArchive = "actions-runner-win-x64-$RunnerVersion.zip"
$RunnerUrl = "https://github.com/actions/runner/releases/download/v$RunnerVersion/$RunnerArchive"
$RunnerSha256 = '1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc'
$RunnerRoot = 'C:\AtlasRunner'
$RunnerLabels = 'atlas-ci,atlas-windows'

if ([string]::IsNullOrWhiteSpace($env:GITHUB_RUNNER_TOKEN)) {
    throw 'Set GITHUB_RUNNER_TOKEN to a fresh repository-scoped runner registration token before running this script.'
}

if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    throw 'Git for Windows is required and must be available on PATH before runner bootstrap.'
}

if (-not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
    throw 'Python 3.12 x64 is required and must be available on PATH before runner bootstrap.'
}

$pythonVersion = (& python.exe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')").Trim()
if ($pythonVersion -ne '3.12') {
    throw "Python 3.12 is required for the Atlas CI baseline; found $pythonVersion."
}

New-Item -ItemType Directory -Path $RunnerRoot -Force | Out-Null
$tempRoot = Join-Path $env:TEMP ("atlas-runner-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    $archivePath = Join-Path $tempRoot $RunnerArchive

    $downloaded = $false
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
            Write-Host "Downloading GitHub Actions Runner (attempt $attempt/5)..."
            Invoke-WebRequest -Uri $RunnerUrl -OutFile $archivePath -UseBasicParsing
            $downloaded = $true
            break
        }
        catch {
            if ($attempt -eq 5) { throw }
            Write-Warning "Runner download attempt $attempt failed: $($_.Exception.Message)"
            Start-Sleep -Seconds (3 * $attempt)
        }
    }

    if (-not $downloaded -or -not (Test-Path -LiteralPath $archivePath)) {
        throw 'Runner archive download did not complete.'
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $RunnerSha256) {
        throw "Runner archive SHA-256 mismatch. Expected $RunnerSha256, got $actualHash."
    }

    if (Test-Path (Join-Path $RunnerRoot 'config.cmd')) {
        throw "Runner root $RunnerRoot is already populated. Remove or decommission the existing runner before re-bootstrap."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $RunnerRoot -Force

    Push-Location $RunnerRoot
    try {
        & .\config.cmd --unattended --replace `
            --url $RepoUrl `
            --token $env:GITHUB_RUNNER_TOKEN `
            --name $RunnerName `
            --labels $RunnerLabels `
            --work '_work' `
            --runasservice
        if ($LASTEXITCODE -ne 0) {
            throw "Runner configuration failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    Remove-Item Env:GITHUB_RUNNER_TOKEN -ErrorAction SilentlyContinue
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "Runner bootstrap complete: $RunnerName"
Write-Host 'Expected labels: self-hosted, windows, x64, atlas-ci, atlas-windows'
Write-Host 'Verify it is Idle in GitHub repository Settings -> Actions -> Runners.'
