# Common.ps1 — shared helpers for the JML scripts.
# Dot-source this at the top of each script:  . "$PSScriptRoot\Common.ps1"

Import-Module ActiveDirectory -ErrorAction Stop

# --- Paths -------------------------------------------------------------
$script:RepoRoot  = Split-Path -Parent $PSScriptRoot
$script:LogDir    = Join-Path $RepoRoot 'logs'
$script:RolesFile = Join-Path $RepoRoot 'config\Roles.psd1'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

# --- Domain / OU layout (derived from the live domain) -----------------
$script:DomainDN   = (Get-ADDomain).DistinguishedName
$script:NetBIOS    = (Get-ADDomain).NetBIOSName
$script:UpnSuffix  = (Get-ADDomain).DNSRoot
$script:RootOU     = "OU=RobinsCapital,$DomainDN"
$script:UsersOU    = "OU=Users,$RootOU"
$script:GroupsRole = "OU=Roles,OU=Groups,$RootOU"
$script:GroupsRes  = "OU=Resources,OU=Groups,$RootOU"
$script:DisabledOU = "OU=Disabled Users,$RootOU"

function Get-UsersOUForDept {
    param([Parameter(Mandatory)][string]$OuLeaf)
    "OU=$OuLeaf,$script:UsersOU"
}

# --- Logging (console + dated log file) --------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "{0} [{1}] {2}" -f $ts, $Level, $Message
    $file = Join-Path $script:LogDir ("jml-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
    Add-Content -Path $file -Value $line
    $color = @{ INFO='Gray'; WARN='Yellow'; ERROR='Red'; OK='Green' }[$Level]
    Write-Host $line -ForegroundColor $color
}

# --- Role catalog loader ----------------------------------------------
function Get-RoleDefinition {
    param([Parameter(Mandatory)][string]$Role)
    $roles = Import-PowerShellDataFile -Path $script:RolesFile
    if (-not $roles.ContainsKey($Role)) {
        throw "Role '$Role' not found in Roles.psd1. Valid roles: $($roles.Keys -join ', ')"
    }
    $roles[$Role]
}

# --- Username generator (first.last, deduped) --------------------------
function New-UniqueSamAccountName {
    param([string]$First, [string]$Last)
    $base = ("{0}.{1}" -f $First, $Last).ToLower() -replace '[^a-z0-9.]', ''
    $sam  = $base; $i = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $i++; $sam = "$base$i"
    }
    $sam
}

# --- Random initial password ------------------------------------------
function New-RandomPassword {
    param([int]$Length = 16)
    $set = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*'
    -join (1..$Length | ForEach-Object { $set[(Get-Random -Max $set.Length)] })
}
