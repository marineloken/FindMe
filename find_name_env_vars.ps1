<#
.SYNOPSIS
  Scan environment variables for a target string (case-insensitive) and export matches to CSV.

.PARAMETER Needle
  The string to search for.

.PARAMETER OutputPath
  Path to CSV file.

.EXAMPLE
  .\Find-Needle-InEnv.ps1 -Needle "oldname" -OutputPath "C:\needle_env_hits.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Needle,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

function Test-ContainsCI
{
    param([string]$Text, [string]$Needle)
    if ( [string]::IsNullOrEmpty($Text))
    {
        return $false
    }
    return $Text.ToLowerInvariant().Contains($Needle.ToLowerInvariant())
}

$results = New-Object System.Collections.Generic.List[object]

# 1. Process-level (what your current shell sees)
foreach ($pair in Get-ChildItem env:)
{
    if (Test-ContainsCI $pair.Name $Needle -or Test-ContainsCI $pair.Value $Needle)
    {
        $results.Add([pscustomobject]@{
            Scope = "Process"
            Name = $pair.Name
            Value = $pair.Value
            RegistryPath = ""
        })
    }
}

# 2. User-level (HKCU\Environment)
$regPathUser = "HKCU:\Environment"
if (Test-Path $regPathUser)
{
    $key = Get-Item $regPathUser
    foreach ($vn in $key.GetValueNames())
    {
        $val = $key.GetValue($vn)
        if (Test-ContainsCI $vn $Needle -or Test-ContainsCI $val $Needle)
        {
            $results.Add([pscustomobject]@{
                Scope = "User"
                Name = $vn
                Value = $val
                RegistryPath = $regPathUser
            })
        }
    }
}

# 3. System-level (HKLM\...\Session Manager\Environment)
$regPathSys = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
if (Test-Path $regPathSys)
{
    $key = Get-Item $regPathSys
    foreach ($vn in $key.GetValueNames())
    {
        $val = $key.GetValue($vn)
        if (Test-ContainsCI $vn $Needle -or Test-ContainsCI $val $Needle)
        {
            $results.Add([pscustomobject]@{
                Scope = "System"
                Name = $vn
                Value = $val
                RegistryPath = $regPathSys
            })
        }
    }
}

# Export to CSV
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Matches exported to $OutputPath"
