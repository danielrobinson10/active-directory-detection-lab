<#
.SYNOPSIS
    JOINER — provisions a new employee end-to-end from a single command:
    creates the AD account in the correct OU, sets attributes, and grants
    exactly the RBAC groups their role requires.
.EXAMPLE
    .\New-Joiner.ps1 -First "Alice" -Last "Nguyen" -Role "Financial Analyst" -Manager "jsmith"
.NOTES
    Run on ADDC01 (elevated). Supports -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$First,
    [Parameter(Mandatory)][string]$Last,
    [Parameter(Mandatory)][string]$Role,
    [string]$Manager                      # optional: SamAccountName of the manager
)

. "$PSScriptRoot\Common.ps1"

$def  = Get-RoleDefinition -Role $Role
$sam  = New-UniqueSamAccountName -First $First -Last $Last
$upn  = "$sam@$UpnSuffix"
$ou   = Get-UsersOUForDept -OuLeaf $def.OU
$pwd  = New-RandomPassword
$disp = "$First $Last"

Write-Log "JOINER: $disp | role='$Role' | dept='$($def.Department)' | sam='$sam'"

if ($PSCmdlet.ShouldProcess($sam, "Create user in $ou")) {
    $params = @{
        Name                  = $disp
        GivenName             = $First
        Surname               = $Last
        DisplayName           = $disp
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        EmailAddress          = $upn
        Title                 = $Role
        Department            = $def.Department
        Company               = 'Robins Capital'
        Path                  = $ou
        AccountPassword       = (ConvertTo-SecureString $pwd -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
        Description           = "Joiner $(Get-Date -Format yyyy-MM-dd) - $Role"
    }
    New-ADUser @params
    Write-Log "Created account $sam in $ou" OK

    if ($Manager) {
        try { Set-ADUser -Identity $sam -Manager $Manager; Write-Log "Manager set to $Manager" }
        catch { Write-Log "Manager '$Manager' not found - skipped" WARN }
    }

    foreach ($g in $def.Groups) {
        try { Add-ADGroupMember -Identity $g -Members $sam; Write-Log "Added to group: $g" OK }
        catch { Write-Log "Could not add to '$g' (run Setup-LabIAM.ps1?): $_" ERROR }
    }

    Write-Host ""
    Write-Log "JOINER COMPLETE: $sam ($upn)" OK
    Write-Host "  Temporary password (deliver securely, user must change at logon):" -ForegroundColor Cyan
    Write-Host "  $pwd" -ForegroundColor Cyan
}
