param(
    [Parameter(Mandatory = $true)]
    [string]$Output
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-CommandEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string[]]$Arguments = @('--version')
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        return [ordered]@{
            present = $false
            command = $Name
            version = $null
        }
    }

    $version = $null
    try {
        $raw = & $Name @Arguments 2>&1 | Select-Object -First 1
        if ($null -ne $raw) {
            $version = ([string]$raw).Trim()
        }
    }
    catch {
        $version = "version-query-failed: $($_.Exception.GetType().Name)"
    }

    return [ordered]@{
        present = $true
        command = $Name
        version = $version
    }
}

function Get-RegistryWebView2Evidence {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*',
        'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*'
    )

    $found = @()
    foreach ($root in $roots) {
        try {
            $items = Get-ItemProperty -Path $root -ErrorAction Stop
            foreach ($item in $items) {
                $name = $null
                foreach ($propertyName in @('DisplayName', 'name')) {
                    if ($item.PSObject.Properties.Name -contains $propertyName -and $item.$propertyName) {
                        $name = [string]$item.$propertyName
                        break
                    }
                }

                if (-not $name -or $name -notmatch 'WebView2') {
                    continue
                }

                $version = $null
                foreach ($propertyName in @('DisplayVersion', 'pv')) {
                    if ($item.PSObject.Properties.Name -contains $propertyName -and $item.$propertyName) {
                        $version = [string]$item.$propertyName
                        break
                    }
                }

                $found += [ordered]@{
                    name = $name
                    version = $version
                    registry_scope = ($root -split ':')[0]
                }
            }
        }
        catch {
            # Missing/blocked registry branches are acceptable preflight outcomes.
        }
    }

    return @($found | Sort-Object name, version -Unique)
}

function Get-WindowsAppSdkEvidence {
    $packages = @()
    try {
        $packages = @(
            Get-AppxPackage -ErrorAction Stop |
                Where-Object { $_.Name -like 'Microsoft.WindowsAppRuntime*' } |
                Sort-Object Name, Version |
                ForEach-Object {
                    [ordered]@{
                        name = $_.Name
                        version = [string]$_.Version
                        architecture = [string]$_.Architecture
                    }
                }
        )
    }
    catch {
        return [ordered]@{
            query_succeeded = $false
            packages = @()
            error_type = $_.Exception.GetType().Name
        }
    }

    return [ordered]@{
        query_succeeded = $true
        packages = $packages
        error_type = $null
    }
}

function Get-VisualStudioEvidence {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    ) | Where-Object { $_ }

    $vswhere = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vswhere) {
        return [ordered]@{
            vswhere_present = $false
            instances = @()
        }
    }

    try {
        $raw = & $vswhere -all -products * -format json -utf8 2>$null
        $instances = @()
        if ($raw) {
            $parsed = $raw | ConvertFrom-Json
            foreach ($instance in @($parsed)) {
                $instances += [ordered]@{
                    product_id = $instance.productId
                    display_name = $instance.displayName
                    installation_version = $instance.installationVersion
                    is_complete = $instance.isComplete
                    is_launchable = $instance.isLaunchable
                }
            }
        }
        return [ordered]@{
            vswhere_present = $true
            instances = $instances
        }
    }
    catch {
        return [ordered]@{
            vswhere_present = $true
            instances = @()
            query_error_type = $_.Exception.GetType().Name
        }
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$computerSystem = Get-CimInstance Win32_ComputerSystem

$commands = [ordered]@{
    git = Get-CommandEvidence -Name 'git'
    go = Get-CommandEvidence -Name 'go'
    python = Get-CommandEvidence -Name 'python'
    node = Get-CommandEvidence -Name 'node'
    npm = Get-CommandEvidence -Name 'npm'
    rustc = Get-CommandEvidence -Name 'rustc'
    cargo = Get-CommandEvidence -Name 'cargo'
    dotnet = Get-CommandEvidence -Name 'dotnet'
}

$result = [ordered]@{
    schema_version = '1.0.0'
    phase = '5.6.1'
    evidence_kind = 'windows-runner-read-only-preflight'
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    mutation_policy = 'read-only; no installs, upgrades, registry writes, firewall changes, package changes, or persistent runner configuration'
    runner = [ordered]@{
        name = $env:RUNNER_NAME
        os = $env:RUNNER_OS
        arch = $env:RUNNER_ARCH
    }
    windows = [ordered]@{
        caption = $os.Caption
        version = $os.Version
        build_number = $os.BuildNumber
        os_architecture = $os.OSArchitecture
        system_type = $computerSystem.SystemType
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
    commands = $commands
    webview2 = @(Get-RegistryWebView2Evidence)
    windows_app_sdk = Get-WindowsAppSdkEvidence
    visual_studio = Get-VisualStudioEvidence
}

$directory = Split-Path -Parent $Output
if ($directory) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

$result | ConvertTo-Json -Depth 8 | Set-Content -Path $Output -Encoding utf8
Write-Host "Phase 5.6.1 read-only Windows preflight evidence written to $Output"
