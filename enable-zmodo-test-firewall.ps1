#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('HttpTest', 'Https')]
    [string]$Mode,
    [Parameter(Mandatory)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$BindAddress,
    [Parameter(Mandatory)]
    [string]$RemoteAddress
)

$ErrorActionPreference = 'Stop'
$prefix = 'PKWS-ZMODO-PWA-'
$address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindAddress -ErrorAction SilentlyContinue |
    Where-Object AddressState -eq 'Preferred'
if (-not $address) { throw "Die lokale Adresse $BindAddress ist nicht aktiv." }

$profile = Get-NetConnectionProfile -InterfaceIndex $address.InterfaceIndex
if ($profile.NetworkCategory -ne 'Private') {
    throw "Firewallregeln werden nur für das private Profil erstellt. Aktuell: $($profile.NetworkCategory)."
}

# Nur Regeln dieses Projekts ersetzen. Fremde Regeln bleiben unangetastet.
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like "$prefix*" |
    Remove-NetFirewallRule

if ($Mode -eq 'HttpTest') {
    New-NetFirewallRule -DisplayName "${prefix}HTTP-TEST-TCP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol TCP -LocalPort 8090 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
    New-NetFirewallRule -DisplayName "${prefix}HTTP-WEBRTC-TCP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol TCP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
    New-NetFirewallRule -DisplayName "${prefix}HTTP-WEBRTC-UDP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol UDP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
} else {
    New-NetFirewallRule -DisplayName "${prefix}HTTPS-TCP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol TCP -LocalPort 443 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
    New-NetFirewallRule -DisplayName "${prefix}WEBRTC-TCP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol TCP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
    New-NetFirewallRule -DisplayName "${prefix}WEBRTC-UDP" `
        -Direction Inbound -Action Allow -Enabled True -Profile Private `
        -Protocol UDP -LocalPort 8189 -LocalAddress $BindAddress `
        -RemoteAddress $RemoteAddress | Out-Null
}

$rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object DisplayName -like "$prefix*")
foreach ($rule in $rules) {
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    $portFilter = $rule | Get-NetFirewallPortFilter
    [pscustomobject]@{
        Name = $rule.DisplayName
        Profile = $rule.Profile
        Direction = $rule.Direction
        Action = $rule.Action
        Protocol = $portFilter.Protocol
        LocalPort = $portFilter.LocalPort
        LocalAddress = $addressFilter.LocalAddress -join ','
        RemoteAddress = $addressFilter.RemoteAddress -join ','
    }
}
