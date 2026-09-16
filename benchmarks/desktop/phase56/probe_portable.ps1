param(
    [Parameter(Mandatory = $true)][string]$StageDir,
    [Parameter(Mandatory = $true)][string]$EvidenceDir
)

$ErrorActionPreference = 'Stop'

function Get-DirectorySize([string]$Path) {
    return [int64]((Get-ChildItem -LiteralPath $Path -File -Recurse | Measure-Object -Property Length -Sum).Sum)
}

$candidates = @(
    @{ id = 'dotnet-wpf'; source = 'dotnet'; host = 'Atlas.DotNetCandidate.exe'; runtime = '.NET 10 Desktop Runtime for framework-dependent candidate build'; installer = @('MSIX', 'WiX/MSI') },
    @{ id = 'electron'; source = 'electron'; host = 'electron.exe'; runtime = 'Bundled Electron runtime'; installer = @('NSIS-class', 'MSI-class') },
    @{ id = 'tauri-v2'; source = 'tauri'; host = 'atlas-tauri-candidate.exe'; runtime = 'Microsoft Edge WebView2 Runtime'; installer = @('NSIS', 'MSI') }
)

$portableRoot = Join-Path $env:RUNNER_TEMP 'ATLAS Portable Feasibility Probe'
Remove-Item -Recurse -Force $portableRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $portableRoot,$EvidenceDir | Out-Null
$stageRoot = (Resolve-Path $StageDir).Path
$evidenceRoot = (Resolve-Path $EvidenceDir).Path

$results = @()
foreach ($candidate in $candidates) {
    $source = Join-Path $stageRoot $candidate.source
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "missing staged candidate directory: $source"
    }

    $destination = Join-Path $portableRoot $candidate.id
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force

    $host = Join-Path $destination $candidate.host
    $core = Join-Path $destination 'atlas-core.exe'
    $manifest = Join-Path $destination 'atlas-core.exe.sha256'
    foreach ($path in @($host, $core, $manifest)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "portable payload missing: $path" }
    }

    $expected = ((Get-Content -Raw -LiteralPath $manifest).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $core).Hash.ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $actual) {
        throw "portable sidecar integrity failure for $($candidate.id)"
    }

    $probePath = Join-Path $evidenceRoot "portable-$($candidate.id)-probe.json"
    $process = Start-Process -FilePath $host -WorkingDirectory $destination `
        -ArgumentList @('--atlas-probe',"--probe-output=$probePath") -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "portable probe failed for $($candidate.id) with exit code $($process.ExitCode)"
    }
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw "portable probe evidence missing for $($candidate.id)"
    }

    $probe = Get-Content -Raw -LiteralPath $probePath | ConvertFrom-Json
    if ($probe.status_result.network_listener -ne $false -or $probe.status_result.offline_capable -ne $true) {
        throw "portable probe returned invalid core network/offline state for $($candidate.id)"
    }
    if ($probe.sidecar_sha256 -ne $actual) {
        throw "portable probe sidecar hash mismatch for $($candidate.id)"
    }

    $results += [ordered]@{
        candidate = $candidate.id
        relocated_probe = $true
        relocated_path_contains_spaces = $destination.Contains(' ')
        probe_exit_code = $process.ExitCode
        sidecar_sha256 = $actual
        network_listener = $false
        offline_capable = $true
        portable_size_bytes = Get-DirectorySize $destination
        runtime_prerequisite = $candidate.runtime
        installer_options = $candidate.installer
        installer_payload_model = 'host + atlas-core.exe + atlas-core.exe.sha256 + candidate runtime files'
        signing_boundary = 'Authenticode-sign release host/sidecar/installer and preserve sidecar SHA-256 manifest verification'
        binary_auto_update = 'disabled/not part of First Preview'
    }
}

$document = [ordered]@{
    evidence_version = 1
    phase = '5.6.2'
    gate = 'G-D8-installer-and-portable-mode-feasibility'
    scope = 'portable-relocation-executable-proof-plus-installer-feasibility'
    candidates = $results
    installer_build_proven = $false
    clean_machine_installer_smoke = 'DEFERRED_TO_5.6.4'
    selection_authorized = $false
}

$output = Join-Path $evidenceRoot 'packaging-feasibility.json'
$document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding utf8
Write-Host ($document | ConvertTo-Json -Depth 8)
