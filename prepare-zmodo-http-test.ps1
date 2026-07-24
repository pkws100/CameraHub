#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$BindAddress,
    [Parameter(Mandatory)]
    [string]$RemoteAddress
)

$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'poc\runtime'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null

$ip = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindAddress -ErrorAction Stop |
    Where-Object AddressState -eq 'Preferred')
if ($ip.Count -ne 1) {
    throw 'Die angegebene private Host-IP konnte nicht eindeutig einem aktiven Adapter zugeordnet werden.'
}

$targetIndex = $ip[0].InterfaceIndex
$adapter = Get-NetAdapter -InterfaceIndex $targetIndex -ErrorAction Stop
$configuration = Get-NetIPConfiguration -InterfaceIndex $targetIndex
if ($adapter.Status -ne 'Up' -or $adapter.Virtual -or -not $configuration.IPv4DefaultGateway) {
    throw 'Die Host-IP gehört nicht zu einem aktiven physischen Adapter mit Standardgateway.'
}

$profile = Get-NetConnectionProfile -InterfaceIndex $targetIndex -ErrorAction Stop
$rollback = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    interfaceIndex = $targetIndex
    interfaceAlias = $adapter.Name
    address = $BindAddress
    previousCategory = [string]$profile.NetworkCategory
}
[IO.File]::WriteAllText(
    (Join-Path $runtime 'network-profile-rollback.json'),
    ($rollback | ConvertTo-Json),
    [Text.UTF8Encoding]::new($false)
)

Set-NetConnectionProfile -InterfaceIndex $targetIndex -NetworkCategory Private
if ((Get-NetConnectionProfile -InterfaceIndex $targetIndex).NetworkCategory -ne 'Private') {
    throw 'Das Zielprofil konnte nicht eindeutig auf Private gestellt werden.'
}

& (Join-Path $PSScriptRoot 'enable-zmodo-test-firewall.ps1') `
    -Mode HttpTest -BindAddress $BindAddress -RemoteAddress $RemoteAddress

$result = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    interfaceIndex = $targetIndex
    interfaceAlias = $adapter.Name
    address = $BindAddress
    gateway = [string]$configuration.IPv4DefaultGateway.NextHop
    before = [string]$profile.NetworkCategory
    after = [string](Get-NetConnectionProfile -InterfaceIndex $targetIndex).NetworkCategory
    firewallMode = 'HttpTest'
    remoteAddress = $RemoteAddress
}
[IO.File]::WriteAllText(
    (Join-Path $runtime 'admin-http-setup-result.json'),
    ($result | ConvertTo-Json -Depth 4),
    [Text.UTF8Encoding]::new($false)
)
