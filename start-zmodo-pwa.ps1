[CmdletBinding()]
param(
    [ValidateSet('Loopback', 'HttpTest', 'Https')]
    [string]$Mode = 'Loopback',
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$LanAddress,
    [ValidateRange(30, 300)]
    [int]$WaitSeconds = 150
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$poc = Join-Path $projectRoot 'poc'
$runtime = Join-Path $poc 'runtime'
$composeEnv = Join-Path $runtime 'compose.env'
$modeFile = Join-Path $runtime 'stack-mode.json'
$localEnv = Join-Path $poc '.env'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$secretDirectory = Join-Path $runtime 'secrets'
New-Item -ItemType Directory -Force -Path $secretDirectory | Out-Null

function Initialize-LocalSecret([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $bytes = [byte[]]::new(32)
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
        $value = [Convert]::ToBase64String($bytes)
        [IO.File]::WriteAllText($Path, $value, [Text.UTF8Encoding]::new($false))
    }
    $acl = Get-Acl -LiteralPath $Path
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowedSids = @($currentSid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $presentSids = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } | Sort-Object -Unique)
    if ($acl.AreAccessRulesProtected -and
        @($presentSids | Where-Object { $_ -notin $allowedSids }).Count -eq 0 -and
        @($allowedSids | Where-Object { $_ -notin $presentSids }).Count -eq 0) {
        return
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($existingRule)
    }
    foreach ($sid in @(
        $currentSid,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-IPv4NetworkCidr([string]$Address, [int]$PrefixLength) {
    $bytes = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    $network = [byte[]]::new(4)
    for ($index = 0; $index -lt 4; $index++) {
        $remaining = $PrefixLength - ($index * 8)
        $mask = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else { (256 - [math]::Pow(2, 8 - $remaining)) }
        $network[$index] = $bytes[$index] -band [int]$mask
    }
    return "$([Net.IPAddress]::new($network))/$PrefixLength"
}
Initialize-LocalSecret (Join-Path $secretDirectory 'zmodo_secret_key')
Initialize-LocalSecret (Join-Path $secretDirectory 'zmodo_internal_token')
Initialize-LocalSecret (Join-Path $secretDirectory 'czeview_adapter_token')
Initialize-LocalSecret (Join-Path $secretDirectory 'netatmo_adapter_token')
Initialize-LocalSecret (Join-Path $secretDirectory 'blink_adapter_token')
Initialize-LocalSecret (Join-Path $secretDirectory 'detection_adapter_token')

docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop ist nicht erreichbar.' }

$composeFiles = @('docker-compose.yml')
$bindAddress = '127.0.0.1'
$configValue = './mediamtx.yml'
$browserUrl = 'http://127.0.0.1:8090/'
$privateHttpNetworks = ''


if ($Mode -ne 'Loopback') {
    if (-not $LanAddress) {
        throw 'Für HttpTest und Https muss -LanAddress mit der privaten Host-IP angegeben werden.'
    }
    $address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $LanAddress -ErrorAction SilentlyContinue |
        Where-Object AddressState -eq 'Preferred'
    if (-not $address) { throw "Die LAN-Adresse $LanAddress ist auf diesem Rechner nicht aktiv." }
    $profile = Get-NetConnectionProfile -InterfaceIndex $address.InterfaceIndex
    if ($profile.NetworkCategory -ne 'Private') {
        throw "LAN-Start nur mit Netzwerkprofil Private; aktuell: $($profile.NetworkCategory)."
    }
    $bindAddress = $LanAddress
    $privateHttpNetworks = Get-IPv4NetworkCidr -Address $address.IPAddress -PrefixLength $address.PrefixLength

}

switch ($Mode) {
    'HttpTest' {
        $lanTemplate = Join-Path $poc 'mediamtx.lan.template.yml'
        $lanRuntimeConfig = Join-Path $runtime 'mediamtx.lan.yml'
        if (-not (Test-Path -LiteralPath $lanTemplate)) { throw 'Die LAN-MediaMTX-Vorlage fehlt.' }
        $renderedMediaConfig = ([IO.File]::ReadAllText($lanTemplate)).Replace('__BIND_IP__', $bindAddress)
        [IO.File]::WriteAllText($lanRuntimeConfig, $renderedMediaConfig, [Text.UTF8Encoding]::new($false))
        $configValue = './runtime/mediamtx.lan.yml'
        $composeFiles += 'docker-compose.http-test.yml'
        $browserUrl = "http://${bindAddress}:8090/"
    }
    'Https' {
        $httpsOverride = Join-Path $poc 'docker-compose.https.yml'
        if (-not (Test-Path -LiteralPath $httpsOverride)) { throw 'Die HTTPS-Konfiguration ist noch nicht eingerichtet.' }
        $httpsTemplate = Join-Path $poc 'mediamtx.https.template.yml'
        $httpsRuntimeConfig = Join-Path $runtime 'mediamtx.https.yml'
        if (-not (Test-Path -LiteralPath $httpsTemplate)) { throw 'Die HTTPS-MediaMTX-Vorlage fehlt.' }
        $renderedMediaConfig = ([IO.File]::ReadAllText($httpsTemplate)).Replace('__BIND_IP__', $bindAddress)
        [IO.File]::WriteAllText($httpsRuntimeConfig, $renderedMediaConfig, [Text.UTF8Encoding]::new($false))
        $configValue = './runtime/mediamtx.https.yml'
        $composeFiles += 'docker-compose.https.yml'
        $browserUrl = "https://${bindAddress}/"
    }
}

$allowOwnerSetup = if ($Mode -eq 'Loopback') { '1' } else { '0' }
$sourceVariables = [ordered]@{
    CAMERA_GARTEN_SOURCE_URI = 'garten'
    CAMERA_EINGANG_SOURCE_URI = 'eingang'
    CAMERA_SERVERRAUM_SOURCE_URI = 'serverraum'
    CAMERA_RUECKSEITE_SOURCE_URI = 'rueckseite'
    CAMERA_EINFAHRT_SOURCE_URI = 'einfahrt'
    CAMERA_GARAGE_SOURCE_URI = 'garage'
}
$staticAuthenticatedIds = [Collections.Generic.List[string]]::new()
$localValues = @{}
$czeviewEnabled = $false
$czeviewSecretPath = Join-Path $secretDirectory 'czeview_credentials.json'
if (Test-Path -LiteralPath $localEnv) {
    foreach ($line in [IO.File]::ReadAllLines($localEnv)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $separator = $trimmed.IndexOf('=')
        if ($separator -lt 1) { continue }
        $localValues[$trimmed.Substring(0, $separator).Trim()] = $trimmed.Substring($separator + 1).Trim()
    }
    foreach ($entry in $sourceVariables.GetEnumerator()) {
        $sourceValue = [string]$localValues[$entry.Key]
        if (-not $sourceValue) { continue }
        try {
            $sourceUri = [Uri]$sourceValue
            if (-not [string]::IsNullOrWhiteSpace($sourceUri.UserInfo)) {
                $staticAuthenticatedIds.Add($entry.Value)
            }
        } catch {
            # Die eigentliche Compose-Validierung meldet eine ungültige Quelle.
        }
    }
    $czeviewRequired = @(
        'CZEVIEW_USEREMAIL',
        'CZEVIEW_PASSWORD',
        'CZEVIEW_COUNTRY_CODE',
        'CZEVIEW_PHONE_CODE',
        'CZEVIEW_SOURCE_APP'
    )
    $czeviewEnabled = @(
        $czeviewRequired | Where-Object {
            [string]::IsNullOrWhiteSpace([string]$localValues[$_])
        }
    ).Count -eq 0
    if ($czeviewEnabled) {
        $czeviewSecret = [ordered]@{}
        foreach ($key in $czeviewRequired + @('CZEVIEW_USERNAME', 'CZEVIEW_DEVICE_SERIAL', 'CZEVIEW_CAMERA_NAME')) {
            $value = [string]$localValues[$key]
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $czeviewSecret[$key] = $value.Trim().Trim('"').Trim("'")
            }
        }
        [IO.File]::WriteAllText(
            $czeviewSecretPath,
            ($czeviewSecret | ConvertTo-Json -Compress),
            [Text.UTF8Encoding]::new($false)
        )
    }
}
if (-not $czeviewEnabled) {
    [IO.File]::WriteAllText($czeviewSecretPath, '{}', [Text.UTF8Encoding]::new($false))
}
Initialize-LocalSecret $czeviewSecretPath
$staticAuthenticatedValue = ($staticAuthenticatedIds | Sort-Object -Unique) -join ','
$envText = "ZMODO_BIND_IP=$bindAddress`nZMODO_MEDIAMTX_CONFIG=$configValue`nCAMERA_HUB_ALLOW_OWNER_SETUP=$allowOwnerSetup`nCAMERA_HUB_STATIC_AUTHENTICATED_IDS=$staticAuthenticatedValue`nCAMERA_HUB_PRIVATE_HTTP_NETWORKS=$privateHttpNetworks`n"

[IO.File]::WriteAllText($composeEnv, $envText, [Text.UTF8Encoding]::new($false))
$state = [ordered]@{ mode=$Mode; bindAddress=$bindAddress; composeFiles=$composeFiles; browserUrl=$browserUrl; czeviewEnabled=$czeviewEnabled }
[IO.File]::WriteAllText($modeFile, ($state | ConvertTo-Json), [Text.UTF8Encoding]::new($false))

$composeArgs = @()
if (Test-Path -LiteralPath $localEnv) { $composeArgs += @('--env-file', $localEnv) }
$composeArgs += @('--env-file', $composeEnv)
$requestedProfiles = @('czeview')
if (Test-Path -LiteralPath $localEnv) {
    $profileLine = @(Get-Content -LiteralPath $localEnv |
        Where-Object { $_ -match '^\s*COMPOSE_PROFILES\s*=' } |
        Select-Object -Last 1)
    if ($profileLine) {
        $profileValue = ($profileLine -split '=', 2)[1].Trim().Trim('"').Trim("'")
        $requestedProfiles += @($profileValue -split '[,\s]+' | Where-Object { $_ })
    }
}
foreach ($profile in @($requestedProfiles | Sort-Object -Unique)) {
    $composeArgs += @('--profile', $profile)
}
foreach ($file in $composeFiles) { $composeArgs += @('-f', $file) }
$upArgs = @($composeArgs) + @('up', '-d', '--build', '--remove-orphans')
Push-Location $poc
try {
    & docker compose @upArgs
    if ($LASTEXITCODE -ne 0) { throw 'docker compose up ist fehlgeschlagen.' }
} finally { Pop-Location }

$healthUrl = if ($Mode -eq 'Https') { "https://${bindAddress}/healthz" } else { "http://${bindAddress}:8090/healthz" }
$deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
$health = $null
do {
    Start-Sleep -Seconds 3
    try {
        if ($Mode -eq 'Https') {
            Push-Location $poc
            try { $caddyContainer = (& docker compose @composeArgs ps -q caddy | Select-Object -First 1) } finally { Pop-Location }
            if (-not $caddyContainer) { throw 'Der HTTPS-Proxy läuft nicht.' }
            $healthJson = & docker exec $caddyContainer wget --no-check-certificate -qO- $healthUrl
            if ($LASTEXITCODE -ne 0) { throw 'HTTPS-Healthcheck fehlgeschlagen.' }
            $health = $healthJson | ConvertFrom-Json
        } else {
            $health = Invoke-RestMethod $healthUrl -TimeoutSec 5
        }
    } catch { $health = $null }
    $allLive = $health -and $health.status -eq 'ok'
} until ($allLive -or [DateTime]::UtcNow -ge $deadline)

if (-not $health) { throw "Die Health-API unter $healthUrl ist nicht erreichbar." }
$health | Select-Object status,mediaServer,sourcesReady,sourcesExpected | Format-Table -AutoSize
if (-not $allLive) { Write-Warning 'Der Stack läuft, aber noch nicht alle Kameraquellen melden live.' }
Write-Output "PWA: $browserUrl"
Write-Output "Bindung: $bindAddress (Modus: $Mode)"
Write-Output "CZEview-Brücke: aktiv (Konten werden in Camera Hub verwaltet)"
Write-Output "Blink-Brücke: aktiv (Konten und 2FA werden in Camera Hub verwaltet)"
if ($Mode -eq 'Https') {
    $projectRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object DisplayName -like 'PKWS-ZMODO-PWA-*')
    if (-not $projectRules) {
        Write-Warning ("Für andere Geräte fehlt noch die administrative Firewallfreigabe. " +
            "Als Administrator ausführen: .\enable-zmodo-private-access.ps1 " +
            "-BindAddress $bindAddress -RemoteAddress <PRIVATES-NETZ/CIDR>")
    }
}
