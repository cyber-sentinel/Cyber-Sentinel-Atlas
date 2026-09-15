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

function Resolve-RustLld {
    $sysroot = (& rustc --print sysroot 2>$null | Select-Object -First 1)
    if (-not $sysroot -or $LASTEXITCODE -ne 0) {
        return $null
    }

    $expected = Join-Path $sysroot 'lib\rustlib\x86_64-pc-windows-msvc\bin\rust-lld.exe'
    if (Test-Path $expected -PathType Leaf) {
        return (Resolve-Path $expected).Path
    }

    $rustlib = Join-Path $sysroot 'lib\rustlib'
    if (-not (Test-Path $rustlib -PathType Container)) {
        return $null
    }

    $fallback = Get-ChildItem -Path $rustlib -Filter 'rust-lld.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'x86_64-pc-windows-msvc' } |
        Select-Object -First 1
    if ($fallback) {
        return $fallback.FullName
    }
    return $null
}

$link = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$source = 'existing-process-environment'
$vsDevCmd = $null
$rustLld = $null

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

    if ($vsDevCmd) {
        Import-CmdEnvironment -BatchFile $vsDevCmd -Arguments '-no_logo -arch=x64 -host_arch=x64'
        $link = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        $cl = Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $link -or -not $cl) {
            throw 'MSVC developer environment initialized but link.exe/cl.exe are still unavailable.'
        }
    }
    else {
        # Self-hosted runner intentionally has no machine-level Visual C++ Build Tools.
        # Prefer the linker shipped with the already checksum-pinned Rust toolchain rather
        # than mutating the runner. This remains fail-closed: any missing Windows SDK or
        # resource-tool prerequisite will surface as the next real Cargo/Tauri build error.
        $rustLld = Resolve-RustLld
        if (-not $rustLld) {
            throw 'Neither MSVC C++ Build Tools nor the checksum-pinned Rust rust-lld.exe linker were found; refusing machine-level installation.'
        }
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $rustLld
        $source = 'checksum-pinned-rust-lld'
    }
}

Write-Host "Windows linker environment source: $source"
if ($link) { Write-Host "link.exe: $($link.Source)" }
if ($cl) { Write-Host "cl.exe: $($cl.Source)" }
if ($rustLld) { Write-Host "rust-lld.exe: $rustLld" }

if ($env:PHASE561_EVIDENCE) {
    New-Item -ItemType Directory -Force -Path $env:PHASE561_EVIDENCE | Out-Null
    $evidence = [ordered]@{
        schema_version = '1.0.0'
        phase = '5.6.1'
        environment_source = $source
        vsdevcmd = $vsDevCmd
        link_path = if ($link) { $link.Source } else { $null }
        cl_path = if ($cl) { $cl.Source } else { $null }
        rust_lld_path = $rustLld
        cargo_target_linker = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
        vc_tools_install_dir = $env:VCToolsInstallDir
        windows_sdk_dir = $env:WindowsSdkDir
        windows_sdk_version = $env:WindowsSDKVersion
    }
    $evidence | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $env:PHASE561_EVIDENCE 'tauri-msvc-environment.json')
}
