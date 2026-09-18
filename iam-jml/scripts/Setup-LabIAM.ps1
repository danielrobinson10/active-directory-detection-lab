<#
.SYNOPSIS
    One-time setup: builds the OU tree and the RBAC security groups the JML
    process relies on. Idempotent — safe to re-run.
.NOTES
    Run on ADDC01 in an elevated PowerShell (RSAT AD module present by default
    on a domain controller).
#>
[CmdletBinding(SupportsShouldProcess)]
param()

. "$PSScriptRoot\Common.ps1"

function Ensure-OU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($dn, 'Create OU')) {
            New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
            Write-Log "Created OU: $dn" OK
        }
    } else { Write-Log "OU exists: $dn" }
}

function Ensure-Group {
    param([string]$Name, [string]$Scope, [string]$Path, [string]$Desc)
    if (-not (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($Name, "Create $Scope group")) {
            New-ADGroup -Name $Name -GroupScope $Scope -GroupCategory Security -Path $Path -Description $Desc
            Write-Log "Created group: $Name ($Scope)" OK
        }
    } else { Write-Log "Group exists: $Name" }
}

Write-Log "=== Setting up RobinsCapital IAM structure ===" OK

# 1) OU tree
Ensure-OU 'RobinsCapital' $DomainDN
Ensure-OU 'Users'   $RootOU
Ensure-OU 'Groups'  $RootOU
Ensure-OU 'Disabled Users' $RootOU
Ensure-OU 'Roles'     "OU=Groups,$RootOU"
Ensure-OU 'Resources' "OU=Groups,$RootOU"

# 2) Department user OUs (from the role catalog, so it stays in sync)
$roles = Import-PowerShellDataFile -Path $RolesFile
$roles.Values.OU | Sort-Object -Unique | ForEach-Object { Ensure-OU $_ $UsersOU }

# 3) Role (global) groups + Resource (domain-local) groups from the catalog
$roleGroups = $roles.Values.Groups | Where-Object { $_ -like 'Role-*' } | Sort-Object -Unique
$resGroups  = $roles.Values.Groups | Where-Object { $_ -like 'RES-*'  } | Sort-Object -Unique

foreach ($g in $roleGroups) { Ensure-Group $g 'Global'      $GroupsRole "RBAC role group ($g)" }
foreach ($g in $resGroups)  { Ensure-Group $g 'DomainLocal' $GroupsRes  "Resource access group ($g)" }

Write-Log "=== Setup complete. Roles available: $($roles.Keys -join ', ') ===" OK
