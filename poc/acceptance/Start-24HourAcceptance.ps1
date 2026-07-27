[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^https?://')]
    [string]$BaseUrl = 'http://127.0.0.1:8090',

    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$DurationHours = 24,

    [Parameter()]
    [ValidateRange(15, 3600)]
    [int]$IntervalSeconds = 60,

    [Parameter()]
    [ValidateRange(90, 100)]
    [double]$RequiredAvailabilityPercent = 99,

    [Parameter()]
    [pscredential]$Credential,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\runtime\acceptance')
)

$ErrorActionPreference = 'Stop'
$base = $BaseUrl.TrimEnd('/')
if (-not $Credential) {
    $Credential = Get-Credential -Message 'Camera-Hub-Konto für ausschließlich passive Statusabfragen'
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
$workspaceRuntime = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\runtime'))
if (-not $resolvedOutput.StartsWith($workspaceRuntime, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory muss innerhalb von poc/runtime liegen.'
}
[IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null

$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$loginBody = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
} | ConvertTo-Json
$login = Invoke-RestMethod -Uri "$base/api/auth/login" -Method Post -Body $loginBody -ContentType 'application/json' -WebSession $session
if (-not $login.authenticated) {
    throw 'Anmeldung fehlgeschlagen.'
}

$cameraCatalog = (Invoke-RestMethod -Uri "$base/api/cameras" -WebSession $session).cameras
$continuous = @($cameraCatalog | Where-Object { -not $_.onDemand -and -not $_.externalSource -and $_.displayMode -eq 'stream' })
$cameraRefs = @{}
foreach ($camera in $continuous) {
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$camera.id)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    $cameraRefs[$camera.id] = [Convert]::ToHexString($digest).Substring(0, 12).ToLowerInvariant()
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $resolvedOutput "camera-hub-soak-$stamp.jsonl"
$summaryPath = Join-Path $resolvedOutput "camera-hub-soak-$stamp-summary.json"
$started = [DateTimeOffset]::UtcNow
$deadline = $started.AddHours($DurationHours)
$samples = @{}
$outages = @{}
$recoveries = [Collections.Generic.List[double]]::new()
$runtimeSamples = [Collections.Generic.List[object]]::new()
$gatewaySamples = 0
$gatewayHealthySamples = 0
$mediaHealthySamples = 0
$lastGatewayHealthy = $false
$lastMediaHealthy = $false
$gatewayOutage = $null
$mediaOutage = $null
foreach ($camera in $continuous) {
    $samples[$camera.id] = @{ total = 0; live = 0 }
}

try {
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $observedAt = [DateTimeOffset]::UtcNow
        $healthzOk = $false
        $mediaState = 'unknown'
        $statuses = @()
        $runtimeMetrics = $null
        try {
            $healthz = Invoke-RestMethod -Uri "$base/healthz" -TimeoutSec 10
            $healthzOk = $healthz.status -eq 'ok'
        } catch {
            $healthzOk = $false
        }
        try {
            $health = Invoke-RestMethod -Uri "$base/api/health" -WebSession $session -TimeoutSec 15
            $mediaState = [string]$health.mediaMTX
            $statuses = @($health.cameras)
            $runtimeMetrics = $health.runtime
            if ($runtimeMetrics) {
                $runtimeSamples.Add([pscustomobject]@{
                    observedAt = $observedAt
                    processRssBytes = $runtimeMetrics.processRssBytes
                    hlsMuxers = $runtimeMetrics.hlsMuxers
                    hlsSessions = $runtimeMetrics.hlsSessions
                    webRtcSessions = $runtimeMetrics.webRtcSessions
                })
            }
        } catch {
            $mediaState = 'unavailable'
        }
        $gatewaySamples += 1
        if ($healthzOk) { $gatewayHealthySamples += 1 }
        if ($mediaState -eq 'online') { $mediaHealthySamples += 1 }
        $lastGatewayHealthy = $healthzOk
        $lastMediaHealthy = $mediaState -eq 'online'
        if ($lastGatewayHealthy) {
            if ($gatewayOutage) {
                $recoveries.Add(($observedAt - $gatewayOutage).TotalSeconds)
                $gatewayOutage = $null
            }
        } elseif (-not $gatewayOutage) {
            $gatewayOutage = $observedAt
        }
        if ($lastMediaHealthy) {
            if ($mediaOutage) {
                $recoveries.Add(($observedAt - $mediaOutage).TotalSeconds)
                $mediaOutage = $null
            }
        } elseif (-not $mediaOutage) {
            $mediaOutage = $observedAt
        }

        $sanitized = [Collections.Generic.List[object]]::new()
        foreach ($camera in $continuous) {
            $status = $statuses | Where-Object camera -eq $camera.id | Select-Object -First 1
            $state = if ($status) { [string]$status.state } else { 'unknown' }
            $samples[$camera.id].total += 1
            if ($state -eq 'live') {
                $samples[$camera.id].live += 1
                if ($outages.ContainsKey($camera.id)) {
                    $recoveries.Add(($observedAt - $outages[$camera.id]).TotalSeconds)
                    $outages.Remove($camera.id)
                }
            } elseif (-not $outages.ContainsKey($camera.id)) {
                $outages[$camera.id] = $observedAt
            }
            $sanitized.Add(@{ cameraRef = $cameraRefs[$camera.id]; state = $state })
        }

        @{
            observedAt = $observedAt.ToString('o')
            healthz = $healthzOk
            mediaServer = $mediaState
            continuousStreams = $sanitized
            runtime = $runtimeMetrics
        } | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $logPath -Encoding utf8

        $remaining = ($deadline - [DateTimeOffset]::UtcNow).TotalSeconds
        if ($remaining -gt 0) {
            Start-Sleep -Seconds ([Math]::Min($IntervalSeconds, [int][Math]::Ceiling($remaining)))
        }
    }
} finally {
    try {
        Invoke-RestMethod -Uri "$base/api/auth/logout" -Method Post -Headers @{'X-CSRF-Token' = $login.csrfToken} -WebSession $session | Out-Null
    } catch {}
}

$cameraSummary = foreach ($camera in $continuous) {
    $sample = $samples[$camera.id]
    $availability = if ($sample.total) { [Math]::Round(100 * $sample.live / $sample.total, 3) } else { 0 }
    @{
        cameraRef = $cameraRefs[$camera.id]
        samples = $sample.total
        liveSamples = $sample.live
        availabilityPercent = $availability
        passed = $availability -ge $RequiredAvailabilityPercent
    }
}
$finished = [DateTimeOffset]::UtcNow
$observedRecoveryDurations = [Collections.Generic.List[double]]::new()
foreach ($recovery in $recoveries) { $observedRecoveryDurations.Add($recovery) }
foreach ($outage in $outages.Values) {
    $observedRecoveryDurations.Add(($finished - $outage).TotalSeconds)
}
if ($gatewayOutage) { $observedRecoveryDurations.Add(($finished - $gatewayOutage).TotalSeconds) }
if ($mediaOutage) { $observedRecoveryDurations.Add(($finished - $mediaOutage).TotalSeconds) }
$openOutagesAtEnd = $outages.Count
if ($gatewayOutage) { $openOutagesAtEnd += 1 }
if ($mediaOutage) { $openOutagesAtEnd += 1 }
$maxRecovery = if ($observedRecoveryDurations.Count) {
    ($observedRecoveryDurations | Measure-Object -Maximum).Maximum
} else { 0 }
$gatewayAvailability = if ($gatewaySamples) {
    [Math]::Round(100 * $gatewayHealthySamples / $gatewaySamples, 3)
} else { 0 }
$mediaAvailability = if ($gatewaySamples) {
    [Math]::Round(100 * $mediaHealthySamples / $gatewaySamples, 3)
} else { 0 }
$runtimeAvailable = $runtimeSamples.Count -gt 0
$firstRuntime = if ($runtimeAvailable) { $runtimeSamples[0] } else { $null }
$lastRuntime = if ($runtimeAvailable) { $runtimeSamples[$runtimeSamples.Count - 1] } else { $null }
$rssStart = if ($firstRuntime -and $null -ne $firstRuntime.processRssBytes) { [double]$firstRuntime.processRssBytes } else { $null }
$rssEnd = if ($lastRuntime -and $null -ne $lastRuntime.processRssBytes) { [double]$lastRuntime.processRssBytes } else { $null }
$rssGrowth = if ($null -ne $rssStart -and $null -ne $rssEnd) { $rssEnd - $rssStart } else { $null }
$allowedRssGrowth = if ($null -ne $rssStart) { [Math]::Max(128MB, $rssStart * 0.25) } else { $null }
$memoryStable = $null -ne $rssGrowth -and $rssGrowth -le $allowedRssGrowth
$hlsSessionsAtEnd = if ($lastRuntime -and $null -ne $lastRuntime.hlsSessions) { [int]$lastRuntime.hlsSessions } else { $null }
$hlsSessionsClosed = $null -ne $hlsSessionsAtEnd -and $hlsSessionsAtEnd -eq 0
$summary = @{
    startedAt = $started.ToString('o')
    finishedAt = $finished.ToString('o')
    durationHours = $DurationHours
    intervalSeconds = $IntervalSeconds
    passiveEndpoints = @('/healthz', '/api/health')
    onDemandOrCloudCamerasPolled = $false
    requiredAvailabilityPercent = $RequiredAvailabilityPercent
    maximumObservedRecoverySeconds = [Math]::Round($maxRecovery, 1)
    recoveryWithin90Seconds = $maxRecovery -le 90 -and $openOutagesAtEnd -eq 0
    gatewayAvailabilityPercent = $gatewayAvailability
    mediaServerAvailabilityPercent = $mediaAvailability
    gatewayHealthyAtEnd = $lastGatewayHealthy
    mediaServerHealthyAtEnd = $lastMediaHealthy
    openOutagesAtEnd = $openOutagesAtEnd
    runtimeMetricsAvailable = $runtimeAvailable
    processRssStartBytes = $rssStart
    processRssEndBytes = $rssEnd
    processRssGrowthBytes = $rssGrowth
    allowedProcessRssGrowthBytes = $allowedRssGrowth
    memoryGrowthNotSuspicious = $memoryStable
    hlsSessionsAtEnd = $hlsSessionsAtEnd
    hlsSessionsClosedAtEnd = $hlsSessionsClosed
    cameras = @($cameraSummary)
    passed = ($cameraSummary.passed -notcontains $false) -and
        $maxRecovery -le 90 -and $openOutagesAtEnd -eq 0 -and
        $gatewayAvailability -ge $RequiredAvailabilityPercent -and
        $mediaAvailability -ge $RequiredAvailabilityPercent -and
        $lastGatewayHealthy -and $lastMediaHealthy -and $runtimeAvailable -and
        $memoryStable -and $hlsSessionsClosed
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding utf8

Write-Host "Bereinigtes Betriebsprotokoll: $logPath"
Write-Host "Abnahmezusammenfassung: $summaryPath"
if (-not $summary.passed) {
    throw 'Die Dauerabnahme hat mindestens ein Freigabekriterium nicht erfüllt.'
}
