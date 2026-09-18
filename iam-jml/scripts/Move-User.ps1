<#
.SYNOPSIS
    MOVER — handles a role/department change. Strips the groups from the old
    role, grants the new role's groups, updates title/department/OU, so access
    always matches the *current* job (no privilege creep).
.EXAMPLE
    .\Move-User.ps1 -SamAccountName "alice.nguyen" -NewRole "IT Support" -Manager "jsmith"
.NOTES
    Run on ADDC01 (elevated). Supports -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$NewRole,
    [string]$Manager
)

. "$PSScriptRoot\Common.ps1"

$user = Get-ADUser -Identity $SamAccountName -Properties Title, Department, MemberOf -ErrorAction Stop
$newDef = Get-RoleDefinition -Role $NewRole
$oldRole = $user.Title

Write-Log "MOVER: $SamAccountName | '$oldRole' -> '$NewRole'"

# 1) Remove any RBAC group (Role-* / RES-*) the user currently holds — clean slate.
$rbacCurrent = foreach ($dn in $user.MemberOf) {
    $g = Get-ADGroup -Identity $dn
    if ($g.Name -like 'Role-*' -or $g.Name -like 'RES-*') { $g.Name }
}
foreach ($g in $rbacCurrent) {
    if ($PSCmdlet.ShouldProcess($g, "Remove $SamAccountName")) {
        Remove-ADGroupMember -Identity $g -Members $SamAccountName -Confirm:$false
        Write-Log "Removed from old group: $g" WARN
    }
}

# 2) Add the new role's groups.
foreach ($g in $newDef.Groups) {
    if ($PSCmdlet.ShouldProcess($g, "Add $SamAccountName")) {
        Add-ADGroupMember -Identity $g -Members $SamAccountName
        Write-Log "Added to new group: $g" OK
    }
}

# 3) Update attributes + move to the new department OU.
if ($PSCmdlet.ShouldProcess($SamAccountName, 'Update attributes')) {
    Set-ADUser -Identity $SamAccountName -Title $NewRole -Department $newDef.Department
    if ($Manager) { try { Set-ADUser -Identity $SamAccountName -Manager $Manager } catch { Write-Log "Manager '$Manager' not found" WARN } }

    $targetOU = Get-UsersOUForDept -OuLeaf $newDef.OU
    if ($user.DistinguishedName -notlike "*$targetOU") {
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $targetOU
        Write-Log "Moved to OU: $targetOU" OK
    }
}

Write-Log "MOVER COMPLETE: $SamAccountName is now '$NewRole'" OK
