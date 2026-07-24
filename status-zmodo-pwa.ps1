[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$poc = Join-Path $PSScriptRoot 'poc'
$runtime = Join-Path $poc 'runtime'
$composeEnv = Join-Path $runtime 'compose.env'
$modeFile = Join-Path $runtime 'stack-mode.json'
$modeState = if (Test-Path -LiteralPath $modeFile) { Get-Content -Raw $modeFile | ConvertFrom-Json } else { $null }
$composeFiles = if ($modeState) { @($modeState.composeFiles) } else { @('docker-compose.yml') }
$args = @()
$localEnv = Join-Path $poc '.env'
if (Test-Path -LiteralPath $localEnv) { $args += @('--env-file', $localEnv) }
if (Test-Path -LiteralPath $composeEnv) { $args += @('--env-file', $composeEnv) }
foreach ($file in $composeFiles) { $args += @('-f', $file) }

Push-Location $poc
try {
    $rows = @(& docker compose @args ps --format json | ForEach-Object { $_ | ConvertFrom-Json })
    $ids = @(& docker compose @args ps -q)
} finally { Pop-Location }
$restarts = @{}
foreach ($id in $ids) {
    $item = docker inspect $id | ConvertFrom-Json
    $restarts[$item[0].Config.Labels.'com.docker.compose.service'] = $item[0].RestartCount
}
$rows | ForEach-Object {
    [pscustomobject]@{
        Service=$_.Service; State=$_.State; Health=$_.Health; Restarts=$restarts[$_.Service]
        Ports=($_.Publishers | ForEach-Object { "$($_.URL):$($_.PublishedPort)/$($_.Protocol)" }) -join ', '
    }
} | Sort-Object Service | Format-Table -AutoSize

$healthUrl = if ($modeState -and $modeState.mode -eq 'Https') {
    "https://$($modeState.bindAddress)/healthz"
} elseif ($modeState) { "http://$($modeState.bindAddress):8090/healthz" } else { 'http://127.0.0.1:8090/healthz' }
try {
    if ($modeState -and $modeState.mode -eq 'Https') {
        Push-Location $poc
        try { $caddyContainer = (& docker compose @args ps -q caddy | Select-Object -First 1) } finally { Pop-Location }
        if (-not $caddyContainer) { throw 'Der HTTPS-Proxy läuft nicht.' }
        $health = (& docker exec $caddyContainer wget --no-check-certificate -qO- $healthUrl) | ConvertFrom-Json
    } else {
        $health = Invoke-RestMethod $healthUrl -TimeoutSec 5
    }
    $health | Select-Object status,mediaServer,sourcesReady,sourcesExpected | Format-Table -AutoSize
} catch { Write-Warning "Die Health-API ist derzeit nicht erreichbar: $healthUrl" }

$projectRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like 'PKWS-ZMODO-PWA-*')
if ($modeState -and $modeState.mode -eq 'Https' -and -not $projectRules) {
    Write-Warning 'HTTPS ist gebunden, aber es existiert noch keine begrenzte PKWS-ZMODO-PWA-Firewallregel.'
}
