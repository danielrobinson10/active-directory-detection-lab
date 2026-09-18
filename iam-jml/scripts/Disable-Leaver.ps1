<#
.SYNOPSIS
    LEAVER — securely offboards an employee: disables the account, rotates the
    password to a random value, strips all group memberships, hides it from the
    address book, stamps the description, and moves it to the Disabled Users OU.
.EXAMPLE
    .\Disable-Leaver.ps1 -SamAccountName "alice.nguyen"
.NOTES
    Run on ADDC01 (elevated). Supports -WhatIf. Accounts are disabled (not
    deleted) so investigations/audits can still resolve historical activity.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SamAccountName
)

. "$PSScriptRoot\Common.ps1"

$user = Get-ADUser -Identity $SamAccountName -Properties MemberOf -ErrorAction Stop
Write-Log "LEAVER: offboarding $SamAccountName ($($user.Name))"

# 1) Disable the account.
if ($PSCmdlet.ShouldProcess($SamAccountName, 'Disable account')) {
    Disable-ADAccount -Identity $SamAccountName
    Write-Log "Account disabled" OK
}

# 2) Rotate the password so any known/leaked credential is dead.
if ($PSCmdlet.ShouldProcess($SamAccountName, 'Reset password to random')) {
    $pwd = New-RandomPassword -Length 24
    Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
    Write-Log "Password rotated to random 24-char value" OK
}

# 3) Remove ALL group memberships except the primary group (Domain Users).
foreach ($dn in $user.MemberOf) {
    $g = Get-ADGroup -Identity $dn
    if ($PSCmdlet.ShouldProcess($g.Name, "Remove $SamAccountName")) {
        try { Remove-ADGroupMember -Identity $g -Members $SamAccountName -Confirm:$false; Write-Log "Removed from group: $($g.Name)" WARN }
        catch { Write-Log "Could not remove from $($g.Name): $_" ERROR }
    }
}

# 4) Hide from the Global Address List (only if the Exchange schema exists) + stamp description.
if ($PSCmdlet.ShouldProcess($SamAccountName, 'Hide from GAL + stamp description')) {
    try {
        Set-ADUser -Identity $SamAccountName -Replace @{ msExchHideFromAddressLists = $true } -ErrorAction Stop
        Write-Log "Hidden from Global Address List" OK
    } catch {
        Write-Log "Exchange schema not present - skipped GAL hide (expected in this lab)" INFO
    }
    Set-ADUser -Identity $SamAccountName -Description "LEAVER - disabled $(Get-Date -Format yyyy-MM-dd)"
    Write-Log "Stamped description with leave date" OK
}

# 5) Move to the Disabled Users OU (out of active department OUs).
if ($PSCmdlet.ShouldProcess($SamAccountName, "Move to $DisabledOU")) {
    Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU
    Write-Log "Moved to $DisabledOU" OK
}

Write-Log "LEAVER COMPLETE: $SamAccountName fully offboarded (retained for audit)" OK
