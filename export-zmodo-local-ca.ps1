[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'poc\runtime'
$public = Join-Path $runtime 'public'
$composeEnv = Join-Path $runtime 'compose.env'
$pem = Join-Path $public 'PKWS-ZMODO-LOCAL-CA.pem'
$cer = Join-Path $public 'PKWS-ZMODO-LOCAL-CA.cer'
New-Item -ItemType Directory -Force -Path $public | Out-Null

$container = docker compose --env-file $composeEnv `
    -f (Join-Path $PSScriptRoot 'poc\docker-compose.yml') `
    -f (Join-Path $PSScriptRoot 'poc\docker-compose.https.yml') ps -q caddy
if (-not $container) { throw 'Der lokale HTTPS-Proxy läuft nicht.' }

docker cp "${container}:/data/caddy/pki/authorities/local/root.crt" $pem | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Das öffentliche Stammzertifikat konnte nicht exportiert werden.' }
certutil.exe -decode $pem $cer | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Die iOS-kompatible CER-Datei konnte nicht erzeugt werden.' }
$fingerprint = (Get-FileHash -Algorithm SHA256 -LiteralPath $cer).Hash
Write-Output "Öffentliches Zertifikat: $cer"
Write-Output "SHA-256: $fingerprint"
Write-Output 'Der private CA-Schlüssel blieb ausschließlich im persistenten Docker-Volume.'
