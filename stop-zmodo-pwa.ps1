[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$poc = Join-Path $PSScriptRoot 'poc'
$runtime = Join-Path $poc 'runtime'
$composeEnv = Join-Path $runtime 'compose.env'
$modeFile = Join-Path $runtime 'stack-mode.json'
$composeFiles = @('docker-compose.yml')
if (Test-Path -LiteralPath $modeFile) { $composeFiles = @((Get-Content -Raw $modeFile | ConvertFrom-Json).composeFiles) }
$args = @()
$localEnv = Join-Path $poc '.env'
if (Test-Path -LiteralPath $localEnv) { $args += @('--env-file', $localEnv) }
if (Test-Path -LiteralPath $composeEnv) { $args += @('--env-file', $composeEnv) }
foreach ($file in $composeFiles) { $args += @('-f', $file) }
$args += 'stop'
Push-Location $poc
try {
    & docker compose @args
    if ($LASTEXITCODE -ne 0) { throw 'Der kontrollierte Containerstopp ist fehlgeschlagen.' }
} finally { Pop-Location }
Write-Output 'Zmodo-PWA-Container wurden gestoppt. Konfigurationen und Volumes blieben erhalten.'
