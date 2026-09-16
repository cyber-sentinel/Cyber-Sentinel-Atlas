param(
    [Parameter(Mandatory = $true)]
    [string]$StageDir,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDir,

    [int]$WarmupCount = 1,
    [int]$MeasuredCount = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($WarmupCount -lt 1) { throw 'WarmupCount must be at least 1.' }
if ($MeasuredCount -lt 5) { throw 'MeasuredCount must be at least 5.' }

$StageDir = [System.IO.Path]::GetFullPath($StageDir)
$EvidenceDir = [System.IO.Path]::GetFullPath($EvidenceDir)
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Get-FolderSizeBytes {
    param([Parameter(Mandatory = $true)][string]$Path)
    $sum = 0L
    Get-ChildItem -LiteralPath $Path -File -Recurse -Force | ForEach-Object { $sum += $_.Length }
    return $sum
}

function Get-PercentileNearestRank {
    param(
        [Parameter(Mandatory = $true)][double[]]$Values,
        [Parameter(Mandatory = $true)][double]$Percentile
    )
    if ($Values.Count -eq 0) { throw 'Percentile requires at least one value.' }
    $sorted = @($Values | Sort-Object)
    $rank = [Math]::Ceiling($Percentile * $sorted.Count)
    if ($rank -lt 1) { $rank = 1 }
    if ($rank -gt $sorted.Count) { $rank = $sorted.Count }
    return [double]$sorted[$rank - 1]
}

function Get-Median {
    param([Parameter(Mandatory = $true)][double[]]$Values)
    if ($Values.Count -eq 0) { throw 'Median requires at least one value.' }
    $sorted = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function Get-ProcessTreeIds {
    param([Parameter(Mandatory = $true)][int]$RootPid)

    $rows = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId)
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    [void]$seen.Add($RootPid)
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($row in $rows) {
            $childPid = [int]$row.ProcessId
            $parentPid = [int]$row.ParentProcessId
            if ($seen.Contains($parentPid) -and -not $seen.Contains($childPid)) {
                [void]$seen.Add($childPid)
                $changed = $true
            }
        }
    }
    return @($seen | ForEach-Object { [int]$_ })
}

function Get-ObservedProcessName {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    try {
        return [string](Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    }
    catch {
        return '<exited-or-unavailable>'
    }
}

function Get-TCPListenerDetailsForPids {
    param([Parameter(Mandatory = $true)][int[]]$ProcessIds)

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        throw 'Get-NetTCPConnection is required for the fail-closed TCP listener measurement.'
    }
    $matches = @()
    foreach ($listener in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
        $owningProcess = [int]$listener.OwningProcess
        if ($ProcessIds -contains $owningProcess) {
            $matches += [ordered]@{
                owning_process = $owningProcess
                process_name = Get-ObservedProcessName -ProcessId $owningProcess
                local_address = [string]$listener.LocalAddress
                local_port = [int]$listener.LocalPort
                state = [string]$listener.State
            }
        }
    }
    return @($matches)
}

function Get-UDPEndpointDetailsForPids {
    param([Parameter(Mandatory = $true)][int[]]$ProcessIds)

    if (-not (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        throw 'Get-NetUDPEndpoint is required for the fail-closed UDP endpoint measurement.'
    }
    $matches = @()
    foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
        $owningProcess = [int]$endpoint.OwningProcess
        if ($ProcessIds -contains $owningProcess) {
            $matches += [ordered]@{
                owning_process = $owningProcess
                process_name = Get-ObservedProcessName -ProcessId $owningProcess
                local_address = [string]$endpoint.LocalAddress
                local_port = [int]$endpoint.LocalPort
            }
        }
    }
    return @($matches)
}

function Add-NetworkObservations {
    param(
        [AllowNull()]$Details,
        [Parameter(Mandatory = $true)][System.Collections.Generic.HashSet[string]]$Keys,
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$Target,
        [Parameter(Mandatory = $true)][string]$Protocol
    )

    if ($null -eq $Details) { return }

    foreach ($detail in @($Details)) {
        $key = "$Protocol|$($detail.owning_process)|$($detail.local_address)|$($detail.local_port)"
        if ($Keys.Add($key)) {
            [void]$Target.Add($detail)
        }
    }
}

function Invoke-ProbeSample {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][int]$SampleIndex,
        [Parameter(Mandatory = $true)][string]$SampleKind
    )

    Remove-Item -Force -LiteralPath $OutputPath -ErrorAction SilentlyContinue
    $workingDirectory = Split-Path -Parent $Executable
    $stdoutPath = Join-Path $EvidenceDir ("measure-$Candidate-$SampleKind-$SampleIndex.stdout.txt")
    $stderrPath = Join-Path $EvidenceDir ("measure-$Candidate-$SampleKind-$SampleIndex.stderr.txt")
    $networkPath = Join-Path $EvidenceDir ("measure-$Candidate-$SampleKind-$SampleIndex-network.json")
    Remove-Item -Force -LiteralPath $stdoutPath,$stderrPath,$networkPath -ErrorAction SilentlyContinue

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.WorkingDirectory = $workingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add('--atlas-probe')
    [void]$psi.ArgumentList.Add("--probe-output=$OutputPath")

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw "$Candidate failed to start" }
    $rootPid = [int]$process.Id
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    $peakTreeWorkingSet = 0L
    $maxProcessCount = 1
    $tcpKeys = [System.Collections.Generic.HashSet[string]]::new()
    $udpKeys = [System.Collections.Generic.HashSet[string]]::new()
    $tcpObservations = [System.Collections.ArrayList]::new()
    $udpObservations = [System.Collections.ArrayList]::new()
    $timeout = [TimeSpan]::FromSeconds(25)

    while (-not $process.HasExited) {
        if ($stopwatch.Elapsed -gt $timeout) {
            try { $process.Kill($true) } catch { }
            throw "$Candidate measurement timed out"
        }

        $treeIds = @(Get-ProcessTreeIds -RootPid $rootPid)
        if ($treeIds.Count -gt $maxProcessCount) { $maxProcessCount = $treeIds.Count }

        $treeWorkingSet = 0L
        foreach ($treePid in $treeIds) {
            try {
                $treeProcess = Get-Process -Id $treePid -ErrorAction Stop
                $treeWorkingSet += [long]$treeProcess.WorkingSet64
            }
            catch { }
        }
        if ($treeWorkingSet -gt $peakTreeWorkingSet) { $peakTreeWorkingSet = $treeWorkingSet }

        Add-NetworkObservations -Details (Get-TCPListenerDetailsForPids -ProcessIds $treeIds) -Keys $tcpKeys -Target $tcpObservations -Protocol 'tcp'
        Add-NetworkObservations -Details (Get-UDPEndpointDetailsForPids -ProcessIds $treeIds) -Keys $udpKeys -Target $udpObservations -Protocol 'udp'
        Start-Sleep -Milliseconds 20
    }

    $process.WaitForExit()
    $stopwatch.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Set-Content -LiteralPath $stdoutPath -Value $stdout -Encoding utf8
    Set-Content -LiteralPath $stderrPath -Value $stderr -Encoding utf8

    $networkEvidence = [ordered]@{
        evidence_version = 1
        candidate = $Candidate
        sample_kind = $SampleKind
        sample_index = $SampleIndex
        root_pid = $rootPid
        executable = $Executable
        tcp_listeners = @($tcpObservations)
        udp_endpoints = @($udpObservations)
        fail_closed = $true
    }
    $networkEvidence | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $networkPath -Encoding utf8

    if ($process.ExitCode -ne 0) {
        throw "$Candidate probe failed with exit code $($process.ExitCode): $($stderr.Substring(0, [Math]::Min(2000, $stderr.Length)))"
    }
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "$Candidate did not write probe evidence: $OutputPath"
    }

    $probe = Get-Content -Raw -LiteralPath $OutputPath | ConvertFrom-Json -Depth 100
    if ($probe.protocol -ne 'atlas-core' -or $probe.protocol_version -ne '1.0.0' -or $probe.session_nonce_echoed -ne $true) {
        throw "$Candidate emitted invalid protocol evidence"
    }
    if ($probe.status_result.network_listener -ne $false -or $probe.status_result.offline_capable -ne $true) {
        throw "$Candidate core status violated the offline/no-listener boundary"
    }

    $tcpListenerSeen = $tcpObservations.Count -gt 0
    $udpEndpointSeen = $udpObservations.Count -gt 0
    if ($tcpListenerSeen) {
        throw "$Candidate process tree opened a TCP listener during the controlled probe; attribution: $networkPath"
    }
    if ($udpEndpointSeen) {
        throw "$Candidate process tree opened a UDP endpoint during the controlled probe; attribution: $networkPath"
    }

    return [ordered]@{
        candidate = $Candidate
        sample_kind = $SampleKind
        sample_index = $SampleIndex
        external_process_total_ms = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
        peak_tree_working_set_bytes = $peakTreeWorkingSet
        max_process_count = $maxProcessCount
        network_listener_seen = ($tcpListenerSeen -or $udpEndpointSeen)
        tcp_listener_seen = $tcpListenerSeen
        udp_endpoint_seen = $udpEndpointSeen
        sidecar_sha256 = [string]$probe.sidecar_sha256
        host_sha256 = [string]$probe.host_sha256
        internal_round_trip_ms_reference_only = [double]$probe.round_trip_ms
    }
}

$candidates = @(
    [ordered]@{ id = 'dotnet-wpf'; executable = (Join-Path $StageDir 'dotnet\Atlas.DotNetCandidate.exe') },
    [ordered]@{ id = 'electron'; executable = (Join-Path $StageDir 'electron\electron.exe') },
    [ordered]@{ id = 'tauri-v2'; executable = (Join-Path $StageDir 'tauri\atlas-tauri-candidate.exe') }
)

$results = @()
$expectedSidecarHash = $null

foreach ($candidate in $candidates) {
    $id = [string]$candidate.id
    $exe = [string]$candidate.executable
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "candidate executable missing: $exe" }

    $candidateDirectory = Split-Path -Parent $exe
    $core = Join-Path $candidateDirectory 'atlas-core.exe'
    $manifest = "$core.sha256"
    if (-not (Test-Path -LiteralPath $core -PathType Leaf) -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "$id packaged sidecar or integrity manifest is missing"
    }
    $sidecarHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $core).Hash.ToLowerInvariant()
    if ($null -eq $expectedSidecarHash) { $expectedSidecarHash = $sidecarHash }
    elseif ($sidecarHash -ne $expectedSidecarHash) { throw 'candidate sidecar hashes differ' }

    $candidateEvidenceDirectory = Join-Path $EvidenceDir "measure-$id"
    New-Item -ItemType Directory -Force -Path $candidateEvidenceDirectory | Out-Null

    $first = Invoke-ProbeSample -Candidate $id -Executable $exe -OutputPath (Join-Path $candidateEvidenceDirectory 'first.json') -SampleIndex 0 -SampleKind 'first-launch'

    for ($i = 1; $i -le $WarmupCount; $i++) {
        [void](Invoke-ProbeSample -Candidate $id -Executable $exe -OutputPath (Join-Path $candidateEvidenceDirectory "warmup-$i.json") -SampleIndex $i -SampleKind 'warmup')
    }

    $samples = @()
    for ($i = 1; $i -le $MeasuredCount; $i++) {
        $samples += Invoke-ProbeSample -Candidate $id -Executable $exe -OutputPath (Join-Path $candidateEvidenceDirectory "measured-$i.json") -SampleIndex $i -SampleKind 'measured'
    }

    $timings = [double[]]@($samples | ForEach-Object { [double]$_.external_process_total_ms })
    $memory = [double[]]@($samples | ForEach-Object { [double]$_.peak_tree_working_set_bytes })
    $processCounts = [double[]]@($samples | ForEach-Object { [double]$_.max_process_count })

    $results += [ordered]@{
        candidate = $id
        package_size_bytes = Get-FolderSizeBytes -Path $candidateDirectory
        host_size_bytes = (Get-Item -LiteralPath $exe).Length
        sidecar_size_bytes = (Get-Item -LiteralPath $core).Length
        sidecar_sha256 = $sidecarHash
        first_launch = $first
        warmup_count = $WarmupCount
        measured_count = $MeasuredCount
        measured_samples = $samples
        external_process_total_ms_median = [Math]::Round((Get-Median -Values $timings), 3)
        external_process_total_ms_p95 = [Math]::Round((Get-PercentileNearestRank -Values $timings -Percentile 0.95), 3)
        peak_tree_working_set_bytes_median = [Math]::Round((Get-Median -Values $memory), 0)
        peak_tree_working_set_bytes_p95 = [Math]::Round((Get-PercentileNearestRank -Values $memory -Percentile 0.95), 0)
        max_process_count_p95 = [int](Get-PercentileNearestRank -Values $processCounts -Percentile 0.95)
        network_listener_seen = $false
        tcp_listener_seen = $false
        udp_endpoint_seen = $false
    }
}

$document = [ordered]@{
    evidence_version = 1
    phase = '5.6.2'
    measurement_scope = 'common-external-windows-host-probe'
    ranking_note = 'Candidate-internal round_trip_ms is reference-only and MUST NOT be used for cross-candidate ranking.'
    first_launch_note = 'first_launch is the first launch after the staged build; it is not a laboratory OS cold-cache measurement.'
    network_probe_note = 'The common harness fails closed if any candidate process tree owns a TCP listener or any UDP endpoint during a controlled probe. Per-sample network attribution evidence records PID, process name, local address and local port before any failure is raised.'
    warmup_count = $WarmupCount
    measured_count = $MeasuredCount
    common_sidecar_sha256 = $expectedSidecarHash
    candidates = $results
}

$output = Join-Path $EvidenceDir 'phase562-common-measurements.json'
$document | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $output -Encoding utf8
Write-Host "Phase 5.6.2 common measurement evidence: $output"
