#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param()

$prefix = 'PKWS-ZMODO-PWA-'
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like "$prefix*")
foreach ($rule in $rules) {
    if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Projekt-Testregel entfernen')) {
        $rule | Remove-NetFirewallRule
    }
}
Write-Output ("Entfernte Regeln mit Präfix {0}: {1}" -f $prefix, $rules.Count)
