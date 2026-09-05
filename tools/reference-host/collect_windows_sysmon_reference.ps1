[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9]+\.[0-9]+$')]
    [string]$ExpectedSysmonVersion = '15.21'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$SysmonDistributionUri = 'https://download.sysinternals.com/files/Sysmon.zip'
$WindowsProvider = 'Microsoft-Windows-Security-Auditing'
$WindowsChannel = 'Security'
$SysmonProvider = 'Microsoft-Windows-Sysmon'
$SysmonChannel = 'Microsoft-Windows-Sysmon/Operational'

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Get-Sha256Digest {
    param([Parameter(Mandatory = $true)][string]$Path)
    return 'sha256-' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-MicrosoftSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "$Label Authenticode signature is not valid: $($signature.Status)"
    }
    $subject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
    if ($subject -notmatch 'Microsoft') {
        throw "$Label signer is not Microsoft: $subject"
    }
    return $signature
}

function New-ReferenceEnvironment {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVersion = if ($cv.PSObject.Properties.Name -contains 'DisplayVersion' -and $cv.DisplayVersion) { [string]$cv.DisplayVersion } else { [string]$cv.ReleaseId }
    $ubr = if ($cv.PSObject.Properties.Name -contains 'UBR') { [string]$cv.UBR } else { '0' }
    $build = "$($cv.CurrentBuildNumber).$ubr"
    return [ordered]@{
        platform = 'windows'
        product = [string]$cv.ProductName
        version = $displayVersion
        build = $build
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
        locale = (Get-Culture).Name
    }
}

function Write-Metadata {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Metadata,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $json = $Metadata | ConvertTo-Json -Depth 10
    Write-Utf8NoBom -Path $Path -Content ($json + "`n")
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$work = Join-Path $env:RUNNER_TEMP ("atlas-reference-export-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    $environment = New-ReferenceEnvironment
    $collectedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Windows Security provider metadata. This is a first-party OS metadata export;
    # it executes outside Atlas core on the controlled reference host.
    $wevtutil = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
    if (-not (Test-Path -LiteralPath $wevtutil -PathType Leaf)) {
        throw "wevtutil.exe not found at expected path: $wevtutil"
    }
    $wevtSignature = Assert-MicrosoftSignature -Path $wevtutil -Label 'wevtutil.exe'
    $wevtVersion = (Get-Item -LiteralPath $wevtutil).VersionInfo.FileVersion
    $windowsRawPath = Join-Path $resolvedOutput 'windows-security-provider.xml'
    $windowsOutput = & $wevtutil gp $WindowsProvider /ge:true /f:xml 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil provider export failed with exit code $LASTEXITCODE"
    }
    $windowsText = ($windowsOutput | ForEach-Object { [string]$_ }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($windowsText) -or $windowsText -notmatch [regex]::Escape($WindowsProvider)) {
        throw 'wevtutil provider export did not contain the expected publisher identity'
    }
    Write-Utf8NoBom -Path $windowsRawPath -Content ($windowsText + "`n")

    $windowsMetadataPath = Join-Path $work 'windows-security-provider.metadata.json'
    $windowsMetadata = [ordered]@{
        ingestion_contract_version = '1.0.0'
        reference_export_contract_version = '1.0.0'
        source_id = 'atlas:source:atlas.source:microsoft-windows-provider-metadata'
        source_version = "windows-build-$($environment.build)"
        export_type = 'windows-event-provider-metadata'
        collection_method = 'wevtutil-gp-ge'
        reference_environment = $environment
        collector = [ordered]@{
            tool_name = 'wevtutil'
            tool_publisher = 'Microsoft'
            tool_version = [string]$wevtVersion
            command_shape = 'wevtutil gp Microsoft-Windows-Security-Auditing /ge:true /f:xml'
            binary_sha256 = Get-Sha256Digest -Path $wevtutil
            signature_status = [string]$wevtSignature.Status
            signer_subject = [string]$wevtSignature.SignerCertificate.Subject
        }
        collected_at = $collectedAt
        scope = [ordered]@{
            provider = $WindowsProvider
            channels = @($WindowsChannel)
            native_identifier_types = @('event_id')
            notes = 'Reference-host provider metadata denominator candidate; requires parser validation and operator review before authoritative inventory promotion.'
        }
        controls = [ordered]@{
            collected_outside_atlas_core = $true
            upstream_binary_executed_by_atlas_core = $false
            immutable_after_ingest = $true
            source_execution_isolated = $true
            operator_review_required = $true
        }
        retention_mode = 'full'
        fixture_only = $false
        diagnostics = @(
            'Collected on a controlled Windows reference host; this artifact is not automatically authoritative or PACK_READY.',
            'Exact Windows product/build, architecture, locale, collector version, signature and binary digest are bound into the descriptor.'
        )
    }
    Write-Metadata -Metadata $windowsMetadata -Path $windowsMetadataPath
    python tools/ingestion/build_reference_export_descriptor.py `
        --metadata $windowsMetadataPath `
        --artifact $windowsRawPath `
        --media-type application/xml `
        --encoding utf-8 `
        --output (Join-Path $resolvedOutput 'windows-security-provider.descriptor.json')
    if ($LASTEXITCODE -ne 0) { throw 'Windows ReferenceExport descriptor build failed' }

    # Sysmon schema collection. The archive is downloaded only on the reference host,
    # validated for Microsoft Authenticode and expected version, then deleted. No binary
    # is copied into the uploaded Atlas reference-export artifact.
    $sysmonZip = Join-Path $work 'Sysmon.zip'
    $sysmonDir = Join-Path $work 'sysmon'
    Invoke-WebRequest -Uri $SysmonDistributionUri -OutFile $sysmonZip -MaximumRedirection 3
    Expand-Archive -LiteralPath $sysmonZip -DestinationPath $sysmonDir -Force

    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    $sysmonName = if ($arch -eq 'arm64') { 'Sysmon64a.exe' } elseif ($arch -eq 'x64') { 'Sysmon64.exe' } else { 'Sysmon.exe' }
    $sysmonExe = Join-Path $sysmonDir $sysmonName
    if (-not (Test-Path -LiteralPath $sysmonExe -PathType Leaf)) {
        throw "Expected Sysmon executable not found after official archive extraction: $sysmonName"
    }
    $sysmonSignature = Assert-MicrosoftSignature -Path $sysmonExe -Label $sysmonName
    $sysmonVersion = [string](Get-Item -LiteralPath $sysmonExe).VersionInfo.FileVersion
    $expectedPattern = '^' + [regex]::Escape($ExpectedSysmonVersion) + '(?:\.|$)'
    if ($sysmonVersion -notmatch $expectedPattern) {
        throw "Sysmon version drift: expected $ExpectedSysmonVersion, got $sysmonVersion"
    }

    $sysmonRawPath = Join-Path $resolvedOutput 'sysmon-schema.txt'
    $sysmonOutput = & $sysmonExe -accepteula -s all 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon schema export failed with exit code $LASTEXITCODE"
    }
    $sysmonText = ($sysmonOutput | ForEach-Object { [string]$_ }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($sysmonText) -or $sysmonText -notmatch '<Sysmon') {
        throw 'Sysmon schema export did not contain an expected Sysmon schema element'
    }
    Write-Utf8NoBom -Path $sysmonRawPath -Content ($sysmonText + "`n")

    $sysmonMetadataPath = Join-Path $work 'sysmon-schema.metadata.json'
    $sysmonMetadata = [ordered]@{
        ingestion_contract_version = '1.0.0'
        reference_export_contract_version = '1.0.0'
        source_id = 'atlas:source:atlas.source:microsoft-sysmon-schema-export'
        source_version = "sysmon-$ExpectedSysmonVersion"
        export_type = 'sysmon-schema'
        collection_method = 'sysmon-s-all'
        reference_environment = $environment
        collector = [ordered]@{
            tool_name = 'Sysmon'
            tool_publisher = 'Microsoft Sysinternals'
            tool_version = $sysmonVersion
            command_shape = 'sysmon64 -accepteula -s all'
            binary_sha256 = Get-Sha256Digest -Path $sysmonExe
            distribution_uri = $SysmonDistributionUri
            signature_status = [string]$sysmonSignature.Status
            signer_subject = [string]$sysmonSignature.SignerCertificate.Subject
        }
        collected_at = $collectedAt
        scope = [ordered]@{
            provider = $SysmonProvider
            channels = @($SysmonChannel)
            native_identifier_types = @('event_id')
            notes = 'Version-checked Sysmon schema export; requires deterministic offline parsing and operator review before release-scope completeness claims.'
        }
        controls = [ordered]@{
            collected_outside_atlas_core = $true
            upstream_binary_executed_by_atlas_core = $false
            immutable_after_ingest = $true
            source_execution_isolated = $true
            operator_review_required = $true
        }
        retention_mode = 'full'
        fixture_only = $false
        diagnostics = @(
            'Sysmon is downloaded from the official Microsoft Sysinternals distribution only on the controlled reference host.',
            'The downloaded archive and executable are not uploaded or committed; only schema output and its provenance descriptor leave the reference host.',
            'Version, Authenticode signer and collector binary SHA-256 are validated and bound into the descriptor.'
        )
    }
    Write-Metadata -Metadata $sysmonMetadata -Path $sysmonMetadataPath
    python tools/ingestion/build_reference_export_descriptor.py `
        --metadata $sysmonMetadataPath `
        --artifact $sysmonRawPath `
        --media-type text/plain `
        --encoding utf-8 `
        --output (Join-Path $resolvedOutput 'sysmon-schema.descriptor.json')
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon ReferenceExport descriptor build failed' }

    $outputFiles = @(Get-ChildItem -LiteralPath $resolvedOutput -File | Select-Object -ExpandProperty Name | Sort-Object)
    $expectedFiles = @(
        'sysmon-schema.descriptor.json',
        'sysmon-schema.txt',
        'windows-security-provider.descriptor.json',
        'windows-security-provider.xml'
    )
    if ((Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $outputFiles).Count -ne 0) {
        throw "Reference output contains an unexpected file set: $($outputFiles -join ', ')"
    }

    Write-Host "Controlled reference-host collection completed for Windows build $($environment.build) and Sysmon $sysmonVersion."
    Write-Host 'Artifacts require operator review and are not automatically authoritative, PACK_READY, committed, or promoted.'
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
