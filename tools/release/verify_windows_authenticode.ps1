param(
    [Parameter(Mandatory = $true)]
    [string]$File,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSignedSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCertificateSha256Fingerprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedCertificateSubject,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ReleaseCommit,

    [Parameter(Mandatory = $true)]
    [string]$SigningRunOrAuditId,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceOutput,

    [string]$SignToolPath = 'signtool.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha.ComputeHash($Bytes))).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

$resolved = (Resolve-Path -LiteralPath $File).Path
$expectedFileHash = $ExpectedSignedSha256.ToLowerInvariant()
$actualFileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
if ($actualFileHash -ne $expectedFileHash) {
    throw "Signed artifact SHA-256 mismatch: expected $expectedFileHash got $actualFileHash"
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolved
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode signature is not valid: $($signature.Status) / $($signature.StatusMessage)"
}
if ($null -eq $signature.SignerCertificate) {
    throw 'Authenticode signer certificate is missing'
}
if ($null -eq $signature.TimeStamperCertificate) {
    throw 'Trusted timestamp certificate is missing'
}

$certificate = $signature.SignerCertificate
$certificateFingerprint = Get-Sha256Hex -Bytes $certificate.RawData
if ($certificateFingerprint -ne $ExpectedCertificateSha256Fingerprint.ToLowerInvariant()) {
    throw "Certificate SHA-256 fingerprint mismatch: expected $ExpectedCertificateSha256Fingerprint got $certificateFingerprint"
}
if ($certificate.Subject -ne $ExpectedCertificateSubject) {
    throw "Certificate subject mismatch: expected '$ExpectedCertificateSubject' got '$($certificate.Subject)'"
}

$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$ekuVerified = $false
foreach ($extension in $certificate.Extensions) {
    if ($extension.Oid.Value -eq '2.5.29.37') {
        $ekuExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension
        foreach ($oid in $ekuExtension.EnhancedKeyUsages) {
            if ($oid.Value -eq $codeSigningOid) {
                $ekuVerified = $true
            }
        }
    }
}
if (-not $ekuVerified) {
    throw 'Signer certificate does not expose the Code Signing EKU'
}

if ($certificate.NotBefore.ToUniversalTime() -ge $certificate.NotAfter.ToUniversalTime()) {
    throw 'Signer certificate validity interval is invalid'
}

$tool = Get-Command $SignToolPath -ErrorAction Stop
$signtoolArgs = @('verify', '/pa', '/all', '/v', '/tw', $resolved)
$signtoolOutput = (& $tool.Source @signtoolArgs 2>&1 | Out-String)
$signtoolExitCode = $LASTEXITCODE
if ($signtoolExitCode -ne 0) {
    throw ("signtool verification failed with exit code " + $signtoolExitCode + [Environment]::NewLine + $signtoolOutput)
}
$signtoolOutputSha256 = Get-Sha256Hex -Bytes ([Text.Encoding]::UTF8.GetBytes($signtoolOutput))

$timestampCertificate = $signature.TimeStamperCertificate
$evidence = [ordered]@{
    schema_version = '1.0.0'
    gate = 'PPR-05'
    evidence_class = 'WINDOWS_AUTHENTICODE_VERIFICATION'
    release_commit = $ReleaseCommit
    signing_run_or_audit_id = $SigningRunOrAuditId
    file_name = [IO.Path]::GetFileName($resolved)
    signed_artifact_sha256 = $actualFileHash
    authenticode_status = [string]$signature.Status
    certificate_subject = $certificate.Subject
    certificate_serial = $certificate.SerialNumber
    certificate_sha256_fingerprint = $certificateFingerprint
    certificate_not_before = $certificate.NotBefore.ToUniversalTime().ToString('o')
    certificate_not_after = $certificate.NotAfter.ToUniversalTime().ToString('o')
    code_signing_eku_verified = $ekuVerified
    timestamp_present = $true
    timestamp_certificate_subject = $timestampCertificate.Subject
    timestamp_certificate_serial = $timestampCertificate.SerialNumber
    signtool_path = $tool.Source
    signtool_exit_code = $signtoolExitCode
    signtool_output_sha256 = $signtoolOutputSha256
    windows_trust_verification = $true
    verification_tool = 'PowerShell Get-AuthenticodeSignature + signtool verify /pa /all /v /tw'
    verified_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
}

$parent = Split-Path -Parent $EvidenceOutput
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidenceOutput -Encoding utf8
Write-Host "Authenticode verification evidence written to $EvidenceOutput"
