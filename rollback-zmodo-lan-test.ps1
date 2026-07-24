#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$RestoreOriginalNetworkProfile
)

$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'poc\runtime'
$rollbackFile = Join-Path $runtime 'network-profile-rollback.json'

& (Join-Path $PSScriptRoot 'remove-zmodo-test-firewall.ps1') -Confirm:$false
& (Join-Path $PSScriptRoot 'start-zmodo-pwa.ps1') -Mode Loopback

if ($RestoreOriginalNetworkProfile) {
    if (-not (Test-Path -LiteralPath $rollbackFile)) {
        throw 'Die lokale Rollbackdatei für das frühere Netzwerkprofil fehlt.'
    }
    $saved = Get-Content -Raw -LiteralPath $rollbackFile | ConvertFrom-Json
    $adapter = Get-NetAdapter -InterfaceIndex $saved.interfaceIndex -ErrorAction Stop
    $address = Get-NetIPAddress -InterfaceIndex $saved.interfaceIndex -AddressFamily IPv4 `
        -IPAddress $saved.address -ErrorAction SilentlyContinue
    if ($adapter.Name -ne $saved.interfaceAlias -or -not $address) {
        throw 'Rollback abgebrochen: Der gespeicherte Netzwerkadapter ist nicht mehr eindeutig vorhanden.'
    }
    if ($saved.previousCategory -notin @('Public', 'Private', 'DomainAuthenticated')) {
        throw 'Rollback abgebrochen: Die gespeicherte Profilkategorie ist ungültig.'
    }
    Set-NetConnectionProfile -InterfaceIndex $saved.interfaceIndex `
        -NetworkCategory $saved.previousCategory
}

Write-Output 'Rollback abgeschlossen: Projekt nur auf Loopback; Projekt-Firewallregeln entfernt.'
if (-not $RestoreOriginalNetworkProfile) {
    Write-Output 'Das Netzwerkprofil blieb unverändert. Für den gespeicherten Ausgangswert: -RestoreOriginalNetworkProfile.'
}
Write-Output 'Persistente Konfigurationen, Zertifikatsdaten und Docker-Volumes wurden nicht gelöscht.'
