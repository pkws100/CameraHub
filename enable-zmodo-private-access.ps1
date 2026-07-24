#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$BindAddress,
    [Parameter(Mandatory)]
    [string[]]$RemoteAddress,
    [switch]$WithoutWebRtc
)

$ErrorActionPreference = 'Stop'

function Test-PrivateIpv4Network([string]$Value) {
    if ($Value -in @('Any', '*', '0.0.0.0/0', '::/0')) { return $false }
    $parts = $Value.Split('/', 2)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $prefix = 32
    if ($parts.Count -eq 2 -and (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 8 -or $prefix -gt 32)) { return $false }
    $bytes = $parsed.GetAddressBytes()
    [uint64]$addressValue = ([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor
        ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
    [uint64]$hostMask = if ($prefix -eq 32) { 0 } else { ([uint64]1 -shl (32 - $prefix)) - 1 }
    [uint64]$networkStart = $addressValue -band (0xFFFFFFFF -bxor $hostMask)
    [uint64]$networkEnd = $networkStart + $hostMask
    $privateRanges = @(
        @([uint64]0x0A000000, [uint64]0x0AFFFFFF),
        @([uint64]0xAC100000, [uint64]0xAC1FFFFF),
        @([uint64]0xC0A80000, [uint64]0xC0A8FFFF)
    )
    return @($privateRanges | Where-Object { $networkStart -ge $_[0] -and $networkEnd -le $_[1] }).Count -eq 1
}

if (-not (Test-PrivateIpv4Network $BindAddress)) {
    throw 'Die Bindeadresse muss eine private IPv4-Adresse sein.'
}
if (-not $RemoteAddress -or @($RemoteAddress | Where-Object { -not (Test-PrivateIpv4Network $_) }).Count) {
    throw 'Jeder erlaubte Quellbereich muss ein konkreter privater IPv4-Bereich sein; Any ist verboten.'
}

$address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindAddress -ErrorAction SilentlyContinue |
    Where-Object AddressState -eq 'Preferred'
if (-not $address) { throw "Die lokale Adresse $BindAddress ist nicht aktiv." }
$profile = Get-NetConnectionProfile -InterfaceIndex $address.InterfaceIndex
if ($profile.NetworkCategory -ne 'Private') {
    throw "Private Freigabe nur auf Netzwerkprofil Private; aktuell: $($profile.NetworkCategory)."
}

$prefix = 'PKWS-ZMODO-PWA-'
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like "$prefix*" |
    Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "${prefix}HTTPS-TCP" `
    -Direction Inbound -Action Allow -Enabled True -Profile Private `
    -Protocol TCP -LocalPort 443 -LocalAddress $BindAddress `
    -RemoteAddress $RemoteAddress | Out-Null

if (-not $WithoutWebRtc) {
    New-NetFirewallRule -DisplayName "${prefix}WEBRTC-TCP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol TCP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
    New-NetFirewallRule -DisplayName "${prefix}WEBRTC-UDP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol UDP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
}

$runtime = Join-Path $PSScriptRoot 'poc\runtime'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$policy = [ordered]@{
    createdAt = (Get-Date).ToString('o')
    bindAddress = $BindAddress
    remoteAddress = @($RemoteAddress)
    httpsPort = 443
    webRtcPorts = if ($WithoutWebRtc) { @() } else { @('8189/tcp', '8189/udp') }
    profile = 'Private'
}
[IO.File]::WriteAllText(
    (Join-Path $runtime 'private-access-policy.json'),
    ($policy | ConvertTo-Json -Depth 4),
    [Text.UTF8Encoding]::new($false)
)

Get-NetFirewallRule -ErrorAction Stop |
    Where-Object DisplayName -like "$prefix*" |
    ForEach-Object {
        $addressFilter = $_ | Get-NetFirewallAddressFilter
        $portFilter = $_ | Get-NetFirewallPortFilter
        [pscustomobject]@{
            Name = $_.DisplayName
            Profile = $_.Profile
            Protocol = $portFilter.Protocol
            LocalPort = $portFilter.LocalPort
            LocalAddress = $addressFilter.LocalAddress -join ','
            RemoteAddress = $addressFilter.RemoteAddress -join ','
        }
    }
