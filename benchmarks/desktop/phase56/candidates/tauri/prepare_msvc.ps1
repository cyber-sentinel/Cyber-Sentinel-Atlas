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

function Install-PinnedLlvmTools {
    $version = '22.1.8'
    $expectedSha256 = 'd96c2cc1736f4eb7fa43cb9bbdf56d93551a9ae0a9aadb9c99c3c3b2b712a234'
    $archiveName = "clang+llvm-$version-x86_64-pc-windows-msvc.tar.xz"
    $archiveUrlName = "clang%2Bllvm-$version-x86_64-pc-windows-msvc.tar.xz"
    $url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$version/$archiveUrlName"
    $root = Join-Path $env:RUNNER_TEMP "llvm-$version-phase561"
    $archive = Join-Path $env:RUNNER_TEMP $archiveName
    $topDirectory = "clang+llvm-$version-x86_64-pc-windows-msvc"

    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    Remove-Item -Force $archive -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $root | Out-Null

    Invoke-WebRequest -Uri $url -OutFile $archive
    $actualSha256 = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "LLVM archive SHA-256 mismatch: expected $expectedSha256, got $actualSha256"
    }

    # Do not resolve tar.exe through PATH here: Git for Windows ships GNU tar,
    # which shells out to xz.exe and fails under the NetworkService runner when
    # that helper is absent from PATH. Windows System32 tar is bsdtar/libarchive
    # and handles .tar.xz directly without installing an additional decompressor.
    $tarPath = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (-not (Test-Path $tarPath -PathType Leaf)) {
        throw "Windows bsdtar is required at the fixed path: $tarPath"
    }

    # Extract only the executable toolchain and Clang resource directory. This keeps
    # the fallback runner-local and avoids installing or registering LLVM system-wide.
    & $tarPath -xf $archive -C $root "$topDirectory/bin" "$topDirectory/lib/clang"
    $extractExitCode = $LASTEXITCODE
    if ($extractExitCode -ne 0) {
        throw "LLVM archive extraction failed with exit code $extractExitCode"
    }

    $binDirectory = Join-Path $root "$topDirectory\bin"
    $requiredTools = @('lld-link.exe', 'clang-cl.exe', 'llvm-lib.exe', 'llvm-rc.exe')
    foreach ($toolName in $requiredTools) {
        $toolPath = Join-Path $binDirectory $toolName
        if (-not (Test-Path $toolPath -PathType Leaf)) {
            throw "checksum-verified LLVM archive is missing required tool: $toolName"
        }
    }

    $env:PATH = "$binDirectory;$env:PATH"
    $env:ATLAS_TAURI_LLVM_VERSION = $version
    $env:ATLAS_TAURI_LLVM_SHA256 = $actualSha256
    $env:ATLAS_TAURI_LLVM_BIN = $binDirectory

    $lldOutput = @(& (Join-Path $binDirectory 'lld-link.exe') --version 2>&1)
    $lldExitCode = $LASTEXITCODE
    if ($lldExitCode -ne 0) {
        throw "lld-link version query failed with exit code $lldExitCode"
    }

    $clangOutput = @(& (Join-Path $binDirectory 'clang-cl.exe') --version 2>&1)
    $clangExitCode = $LASTEXITCODE
    if ($clangExitCode -ne 0) {
        throw "clang-cl version query failed with exit code $clangExitCode"
    }

    return [ordered]@{
        version = $version
        archive_url = $url
        archive_sha256 = $actualSha256
        bin_path = $binDirectory
        lld_link_version = ([string]($lldOutput | Select-Object -First 1)).Trim()
        clang_cl_version = ([string]($clangOutput | Select-Object -First 1)).Trim()
        required_tools = $requiredTools
        extractor = $tarPath
    }
}

function Install-PinnedCargoXwin {
    $version = '0.23.0'
    $expectedSha256 = 'af084297230d9d4d6b933471d544289c09ab40906ca8acf6ca2a5a643117fff3'
    $archiveName = "cargo-xwin-v$version.windows-x64.zip"
    $url = "https://github.com/rust-cross/cargo-xwin/releases/download/v$version/$archiveName"
    $root = Join-Path $env:RUNNER_TEMP "cargo-xwin-v$version-phase561"
    $archive = Join-Path $env:RUNNER_TEMP $archiveName

    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    Remove-Item -Force $archive -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $root | Out-Null

    Invoke-WebRequest -Uri $url -OutFile $archive
    $actualSha256 = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "cargo-xwin archive SHA-256 mismatch: expected $expectedSha256, got $actualSha256"
    }

    Expand-Archive -Path $archive -DestinationPath $root -Force
    $binary = Get-ChildItem -Path $root -Filter 'cargo-xwin.exe' -File -Recurse -ErrorAction Stop | Select-Object -First 1
    if (-not $binary) {
        throw 'checksum-verified cargo-xwin archive did not contain cargo-xwin.exe'
    }

    $binaryDirectory = Split-Path $binary.FullName -Parent
    $env:PATH = "$binaryDirectory;$env:PATH"
    $env:XWIN_CACHE_DIR = Join-Path $env:RUNNER_TEMP 'atlas-xwin-phase561-cache'
    $env:ATLAS_TAURI_BUILD_MODE = 'cargo-xwin'
    $env:ATLAS_TAURI_CARGO_XWIN_VERSION = $version
    $env:ATLAS_TAURI_CARGO_XWIN_SHA256 = $actualSha256
    $env:ATLAS_TAURI_CARGO_XWIN_PATH = $binary.FullName

    $versionOutput = @(& $binary.FullName xwin --version 2>&1)
    $versionExitCode = $LASTEXITCODE
    if ($versionExitCode -ne 0) {
        throw "cargo-xwin version query failed with exit code $versionExitCode"
    }
    $reportedVersion = ($versionOutput | Select-Object -First 1)
    if ([string]$reportedVersion -notmatch [regex]::Escape($version)) {
        throw "cargo-xwin $version required; found $reportedVersion"
    }

    return [ordered]@{
        version = $version
        archive_url = $url
        archive_sha256 = $actualSha256
        binary_path = $binary.FullName
        reported_version = ([string]$reportedVersion).Trim()
        xwin_cache_dir = $env:XWIN_CACHE_DIR
    }
}

$link = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$source = 'existing-process-environment'
$vsDevCmd = $null
$cargoXwin = $null
$llvmTools = $null
$env:ATLAS_TAURI_BUILD_MODE = 'native-msvc'

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
        # Rust's MSVC target needs the Windows CRT/SDK plus an MSVC-compatible linker.
        # Tauri documents LLVM/lld alongside cargo-xwin for this path. Keep both
        # dependencies checksum-pinned and runner-local instead of mutating the host.
        $llvmTools = Install-PinnedLlvmTools
        $cargoXwin = Install-PinnedCargoXwin
        $source = 'checksum-pinned-cargo-xwin+llvm'
    }
}

Write-Host "Tauri Windows build environment source: $source"
Write-Host "Tauri build mode: $env:ATLAS_TAURI_BUILD_MODE"
if ($link) { Write-Host "link.exe: $($link.Source)" }
if ($cl) { Write-Host "cl.exe: $($cl.Source)" }
if ($llvmTools) {
    Write-Host "LLVM: $($llvmTools.version)"
    Write-Host "lld-link: $($llvmTools.lld_link_version)"
}
if ($cargoXwin) { Write-Host "cargo-xwin: $($cargoXwin.reported_version)" }

if ($env:PHASE561_EVIDENCE) {
    New-Item -ItemType Directory -Force -Path $env:PHASE561_EVIDENCE | Out-Null
    $evidence = [ordered]@{
        schema_version = '1.0.0'
        phase = '5.6.1'
        environment_source = $source
        build_mode = $env:ATLAS_TAURI_BUILD_MODE
        vsdevcmd = $vsDevCmd
        link_path = if ($link) { $link.Source } else { $null }
        cl_path = if ($cl) { $cl.Source } else { $null }
        vc_tools_install_dir = $env:VCToolsInstallDir
        windows_sdk_dir = $env:WindowsSdkDir
        windows_sdk_version = $env:WindowsSDKVersion
        llvm = $llvmTools
        cargo_xwin = $cargoXwin
    }
    $evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $env:PHASE561_EVIDENCE 'tauri-build-environment.json')
}
