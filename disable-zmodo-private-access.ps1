#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param()

& (Join-Path $PSScriptRoot 'remove-zmodo-test-firewall.ps1') -Confirm:$false
Write-Output 'Der private Camera-Hub-Zugriff wurde aus der Windows-Firewall entfernt.'
Write-Output 'Für vollständigen Loopbackbetrieb zusätzlich ausführen: .\start-zmodo-pwa.ps1 -Mode Loopback'
