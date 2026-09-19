[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9]+\.[0-9]+$')]
    [string]$ExpectedSysmonVersion = '15.22'
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

function Convert-EventMetadataNamedValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    $result = [ordered]@{}
    foreach ($name in @('Value', 'Name', 'DisplayName')) {
        if ($Value.PSObject.Properties.Name -contains $name -and $null -ne $Value.$name) {
            $key = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)
            $result[$key] = [string]$Value.$name
        }
    }
    if ($result.Count -eq 0) {
        $result['value'] = [string]$Value
    }
    return $result
}

function Export-WindowsProviderMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$ProviderName,
        [Parameter(Mandatory = $true)][string]$RequiredChannel,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $providerMetadata = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($ProviderName)
    try {
        $logLinks = @(
            $providerMetadata.LogLinks |
                ForEach-Object {
                    [ordered]@{
                        log_name = [string]$_.LogName
                        display_name = if ($null -ne $_.DisplayName) { [string]$_.DisplayName } else { $null }
                        is_imported = [bool]$_.IsImported
                    }
                } |
                Sort-Object log_name
        )
        if (-not ($logLinks | Where-Object { $_.log_name -eq $RequiredChannel })) {
            throw "Provider $ProviderName does not expose required channel $RequiredChannel in ProviderMetadata.LogLinks"
        }

        $events = @(
            $providerMetadata.Events |
                ForEach-Object {
                    $keywordValues = @(
                        $_.Keywords |
                            Where-Object { $null -ne $_ } |
                            ForEach-Object { Convert-EventMetadataNamedValue $_ }
                    )
                    [ordered]@{
                        event_id = [string]$_.Id
                        version = if ($null -ne $_.Version) { [string]$_.Version } else { '0' }
                        log_name = if ($null -ne $_.LogLink) { [string]$_.LogLink.LogName } else { $null }
                        level = Convert-EventMetadataNamedValue $_.Level
                        opcode = Convert-EventMetadataNamedValue $_.Opcode
                        task = Convert-EventMetadataNamedValue $_.Task
                        keywords = $keywordValues
                        template = if ($null -ne $_.Template) { [string]$_.Template } else { $null }
                    }
                } |
                Sort-Object @{ Expression = { [long]$_.event_id } }, @{ Expression = { [int]$_.version } }
        )
        if ($events.Count -eq 0) {
            throw "ProviderMetadata.Events returned no events for $ProviderName"
        }
        if (-not ($events | Where-Object { $_.log_name -eq $RequiredChannel })) {
            throw "ProviderMetadata.Events did not contain any event linked to $RequiredChannel"
        }

        $export = [ordered]@{
            export_format_version = '1.0.0'
            provider = $ProviderName
            provider_guid = $providerMetadata.Id.ToString()
            log_links = $logLinks
            events = $events
            structural_only = $true
            descriptions_included = $false
        }
        Write-Utf8NoBom -Path $OutputPath -Content (($export | ConvertTo-Json -Depth 15) + "`n")
        return $events.Count
    }
    finally {
        $providerMetadata.Dispose()
    }
}

function Invoke-SysmonSchemaText {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    # Sysmon emits its schema stream as UTF-16LE. PowerShell's native command
    # capture can preserve each NUL byte as a literal U+0000, so the controlled
    # reference host uses ProcessStartInfo with an explicit UTF-16LE decoder instead
    # of mutating the captured text by stripping NULs.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ExecutablePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    $psi.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    [void]$psi.ArgumentList.Add('-accepteula')
    [void]$psi.ArgumentList.Add('-s')
    [void]$psi.ArgumentList.Add('all')

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) {
        throw 'Failed to start Sysmon schema export process'
    }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Sysmon schema export failed with exit code $($process.ExitCode): $stderr"
        }
        $combined = @($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        return ($combined -join "`n")
    }
    finally {
        $process.Dispose()
    }
}

function Write-Metadata {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Metadata,
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

    $windowsRawPath = Join-Path $resolvedOutput 'windows-security-provider.json'
    $windowsEventCount = Export-WindowsProviderMetadata `
        -ProviderName $WindowsProvider `
        -RequiredChannel $WindowsChannel `
        -OutputPath $windowsRawPath
    $eventLogAssemblyVersion = [System.Diagnostics.Eventing.Reader.ProviderMetadata].Assembly.GetName().Version.ToString()
    Write-Host "Windows ProviderMetadata event/version definitions: $windowsEventCount"

    $windowsMetadataPath = Join-Path $work 'windows-security-provider.metadata.json'
    $windowsMetadata = [ordered]@{
        ingestion_contract_version = '1.0.0'
        reference_export_contract_version = '1.0.0'
        source_id = 'atlas:source:atlas.source:microsoft-windows-provider-metadata'
        source_version = "windows-build-$($environment.build)"
        export_type = 'windows-event-provider-metadata'
        collection_method = 'windows-event-log-api'
        reference_environment = $environment
        collector = [ordered]@{
            tool_name = 'System.Diagnostics.Eventing.Reader.ProviderMetadata'
            tool_publisher = 'Microsoft'
            tool_version = $eventLogAssemblyVersion
            command_shape = 'ProviderMetadata(Microsoft-Windows-Security-Auditing).Events'
        }
        collected_at = $collectedAt
        scope = [ordered]@{
            provider = $WindowsProvider
            channels = @($WindowsChannel)
            native_identifier_types = @('event_id')
            notes = "Structured first-party provider metadata export containing $windowsEventCount event/version definitions; denominator candidate requires deterministic import and operator review."
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
            'ProviderMetadata.Events is exported structurally without localized event descriptions; exact Windows build, architecture and locale are bound into the descriptor.',
            'The reference-host transformer is repository-controlled and the resulting JSON is immutable and SHA-256 bound before Atlas import.'
        )
    }
    Write-Metadata -Metadata $windowsMetadata -Path $windowsMetadataPath
    python tools/ingestion/build_reference_export_descriptor.py `
        --metadata $windowsMetadataPath `
        --artifact $windowsRawPath `
        --media-type application/json `
        --encoding utf-8 `
        --output (Join-Path $resolvedOutput 'windows-security-provider.descriptor.json')
    if ($LASTEXITCODE -ne 0) { throw 'Windows ReferenceExport descriptor build failed' }

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
    $sysmonText = Invoke-SysmonSchemaText -ExecutablePath $sysmonExe
    if (
        [string]::IsNullOrWhiteSpace($sysmonText) -or
        $sysmonText -notmatch '<manifest' -or
        $sysmonText -notmatch 'schemaversion=' -or
        $sysmonText -notmatch '<event '
    ) {
        $previewLength = [Math]::Min(4000, $sysmonText.Length)
        $preview = if ($previewLength -gt 0) { $sysmonText.Substring(0, $previewLength) } else { '<empty>' }
        $preview = $preview.Replace("`r", '\r').Replace("`n", '\n')
        Write-Warning "Sysmon schema validation failed after UTF-16LE decoding. version=$sysmonVersion chars=$($sysmonText.Length) bounded_preview=$preview"
        throw 'Sysmon schema export did not contain the expected manifest/event schema structure'
    }
    Write-Utf8NoBom -Path $sysmonRawPath -Content ($sysmonText + "`n")
    Write-Host "Sysmon schema export bytes: $((Get-Item -LiteralPath $sysmonRawPath).Length)"

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
            'Version, Authenticode signer and collector binary SHA-256 are validated and bound into the descriptor.',
            'Sysmon schema stdout/stderr is decoded explicitly as UTF-16LE before deterministic UTF-8 artifact serialization.'
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
        'windows-security-provider.json'
    )
    # Compare-Object returns $null for an exact match and a scalar for a single
    # difference. Under StrictMode, neither reliably exposes .Count, so force the
    # result into an array before cardinality evaluation.
    $fileSetDiff = @(Compare-Object -ReferenceObject $expectedFiles -DifferenceObject $outputFiles)
    if ($fileSetDiff.Count -ne 0) {
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
