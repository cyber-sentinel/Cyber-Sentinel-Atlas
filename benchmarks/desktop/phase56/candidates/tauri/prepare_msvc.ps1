$ErrorActionPreference = 'Stop'

function Import-CmdEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BatchFile,
        [string]$Arguments = ''
    )

    $command = "call `"$BatchFile`" $Arguments >nul && set"
    $lines = & cmd.exe /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC developer environment initialization failed with exit code $LASTEXITCODE"
    }

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('=')) {
            continue
        }
        $index = $line.IndexOf('=')
        if ($index -le 0) {
            continue
        }
        $name = $line.Substring(0, $index)
        $value = $line.Substring($index + 1)
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

$link = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$source = 'existing-process-environment'
$vsDevCmd = $null

if (-not $link -or -not $cl) {
    $vswhereCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { $_ -and (Test-Path $_) }

    $vswhere = $vswhereCandidates | Select-Object -First 1
    if ($vswhere) {
        $installationPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1)
        if ($installationPath) {
            $candidate = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
            if (Test-Path $candidate) {
                $vsDevCmd = $candidate
                $source = 'vswhere'
            }
        }
    }

    if (-not $vsDevCmd) {
        $commonCandidates = @()
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $root) { continue }
            foreach ($year in @('2026', '2022')) {
                foreach ($edition in @('BuildTools', 'Enterprise', 'Professional', 'Community')) {
                    $commonCandidates += Join-Path $root "Microsoft Visual Studio\$year\$edition\Common7\Tools\VsDevCmd.bat"
                }
            }
        }
        $vsDevCmd = $commonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($vsDevCmd) {
            $source = 'known-installation-path'
        }
    }

    if (-not $vsDevCmd) {
        throw 'MSVC C++ Build Tools were not found. Tauri requires a Windows linker; no machine-level installer will be invoked by this CI job.'
    }

    Import-CmdEnvironment -BatchFile $vsDevCmd -Arguments '-no_logo -arch=x64 -host_arch=x64'
    $link = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
}

if (-not $link) {
    throw 'MSVC developer environment initialized but link.exe is still unavailable.'
}
if (-not $cl) {
    throw 'MSVC developer environment initialized but cl.exe is still unavailable.'
}

Write-Host "MSVC environment source: $source"
Write-Host "link.exe: $($link.Source)"
Write-Host "cl.exe: $($cl.Source)"

if ($env:PHASE561_EVIDENCE) {
    New-Item -ItemType Directory -Force -Path $env:PHASE561_EVIDENCE | Out-Null
    $evidence = [ordered]@{
        schema_version = '1.0.0'
        phase = '5.6.1'
        environment_source = $source
        vsdevcmd = $vsDevCmd
        link_path = $link.Source
        cl_path = $cl.Source
        vc_tools_install_dir = $env:VCToolsInstallDir
        windows_sdk_dir = $env:WindowsSdkDir
        windows_sdk_version = $env:WindowsSDKVersion
    }
    $evidence | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $env:PHASE561_EVIDENCE 'tauri-msvc-environment.json')
}
