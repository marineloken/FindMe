<#
.SYNOPSIS
  Find occurrences of a target string in Windows Services and Startup items; export matches to CSV.

.PARAMETER Needle
  String to search for (case-insensitive).

.PARAMETER OutputPath
  CSV output path.

.EXAMPLE
  .\Find-Needle-InServicesAndStartup.ps1 -Needle "oldname" -OutputPath "C:\needle_services_startup_hits.csv"
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
    param([AllowNull()][string]$Text, [string]$Needle)
    if ( [string]::IsNullOrEmpty($Text))
    {
        return $false
    }
    return $Text.ToLowerInvariant().Contains($Needle.ToLowerInvariant())
}

# Ensure output directory exists
try
{
    $dir = Split-Path -Path $OutputPath -Parent
    if ($dir -and -not (Test-Path $dir))
    {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
catch
{
}

$results = New-Object System.Collections.Generic.List[object]

# --------------------------
# Services (WMI + Registry)
# --------------------------
Write-Verbose "Scanning services via WMI/ CIM..."
try
{
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
}
catch
{
    $services = @()
}

foreach ($s in $services)
{
    $fields = @{
        'ServiceName' = [string]$s.Name
        'DisplayName' = [string]$s.DisplayName
        'Description' = [string]$s.Description
        'PathName' = [string]$s.PathName     # executable/command
        'StartName' = [string]$s.StartName    # "Log On As"
        'State' = [string]$s.State
        'StartMode' = [string]$s.StartMode
    }

    $hitInWmi = $false
    foreach ($k in $fields.Keys)
    {
        if (Test-ContainsCI $fields[$k] $Needle)
        {
            $hitInWmi = $true
            $results.Add([pscustomobject]@{
                Category = 'Service (WMI)'
                Name = $s.Name
                Location = 'Win32_Service'
                Field = $k
                Value = $fields[$k]
                Extra = "DisplayName=$( $s.DisplayName ); StartName=$( $s.StartName )"
            })
        }
    }

    # Also check registry for each service
    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$( $s.Name )"
    if (Test-Path $svcRegPath)
    {
        try
        {
            $rk = Get-Item $svcRegPath
            foreach ($vn in $rk.GetValueNames())
            {
                $vk = $rk.GetValueKind($vn)
                # Only check text-like kinds
                if ($vk -in 'String', 'ExpandString', 'MultiString')
                {
                    $val = $rk.GetValue($vn)
                    $text = if ($vk -eq 'MultiString')
                    {
                        ($val -join '; ')
                    }
                    else
                    {
                        [string]$val
                    }
                    if (Test-ContainsCI $vn $Needle -or Test-ContainsCI $text $Needle)
                    {
                        $results.Add([pscustomobject]@{
                            Category = 'Service (Registry)'
                            Name = $s.Name
                            Location = $svcRegPath
                            Field = $vn
                            Value = $text
                            Extra = "DisplayName=$( $s.DisplayName )"
                        })
                    }
                }
            }
            # Common subkey: Parameters
            $paramPath = Join-Path $svcRegPath 'Parameters'
            if (Test-Path $paramPath)
            {
                $prk = Get-Item $paramPath
                foreach ($vn in $prk.GetValueNames())
                {
                    $vk = $prk.GetValueKind($vn)
                    if ($vk -in 'String', 'ExpandString', 'MultiString')
                    {
                        $val = $prk.GetValue($vn)
                        $text = if ($vk -eq 'MultiString')
                        {
                            ($val -join '; ')
                        }
                        else
                        {
                            [string]$val
                        }
                        if (Test-ContainsCI $vn $Needle -or Test-ContainsCI $text $Needle)
                        {
                            $results.Add([pscustomobject]@{
                                Category = 'Service (Registry)'
                                Name = $s.Name
                                Location = $paramPath
                                Field = $vn
                                Value = $text
                                Extra = "Parameters"
                            })
                        }
                    }
                }
            }
        }
        catch
        {
        }
    }
}

# ----------------------------------
# Startup: Registry (Run locations)
# ----------------------------------
$runRoots = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    # 32-bit view on 64-bit systems
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)

foreach ($path in $runRoots)
{
    if (-not (Test-Path $path))
    {
        continue
    }
    try
    {
        $rk = Get-Item $path
        foreach ($vn in $rk.GetValueNames())
        {
            $val = [string]$rk.GetValue($vn)
            if (Test-ContainsCI $vn $Needle -or Test-ContainsCI $val $Needle -or Test-ContainsCI $path $Needle)
            {
                $results.Add([pscustomobject]@{
                    Category = 'Startup (Registry)'
                    Name = $vn
                    Location = $path
                    Field = 'Value'
                    Value = $val
                    Extra = ''
                })
            }
        }
    }
    catch
    {
    }
}

# ----------------------------------
# Startup: Folders (All Users + User)
# ----------------------------------
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

# Resolve .lnk targets via COM
function Resolve-ShortcutTarget
{
    param([string]$lnkPath)
    try
    {
        $ws = New-Object -ComObject WScript.Shell
        $sc = $ws.CreateShortcut($lnkPath)
        return [pscustomobject]@{
            TargetPath = [string]$sc.TargetPath
            Arguments = [string]$sc.Arguments
            WorkingDir = [string]$sc.WorkingDirectory
            Description = [string]$sc.Description
        }
    }
    catch
    {
        return $null
    }
}

foreach ($folder in $startupFolders)
{
    if (-not (Test-Path $folder))
    {
        continue
    }

    Get-ChildItem -Path $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $item = $_
        if ($item.PSIsContainer)
        {
            return
        }

        $hit = $false
        $loc = Join-Path $folder $item.Name

        if ($item.Extension -eq '.lnk')
        {
            $resolved = Resolve-ShortcutTarget -lnkPath $item.FullName
            if ($resolved)
            {
                $fields = @{
                    'LnkPath' = $item.FullName
                    'TargetPath' = $resolved.TargetPath
                    'Arguments' = $resolved.Arguments
                    'WorkingDir' = $resolved.WorkingDir
                    'Description' = $resolved.Description
                }
                foreach ($k in $fields.Keys)
                {
                    if (Test-ContainsCI $fields[$k] $Needle)
                    {
                        $hit = $true
                        $results.Add([pscustomobject]@{
                            Category = 'Startup (Folder)'
                            Name = $item.Name
                            Location = $fields['LnkPath']
                            Field = $k
                            Value = $fields[$k]
                            Extra = ''
                        })
                    }
                }
            }
            else
            {
                # Fallback: just check the filename/path
                if (Test-ContainsCI $loc $Needle)
                {
                    $results.Add([pscustomobject]@{
                        Category = 'Startup (Folder)'
                        Name = $item.Name
                        Location = $loc
                        Field = 'Path'
                        Value = $loc
                        Extra = 'Unresolved .lnk'
                    })
                }
            }
        }
        else
        {
            # Non-link file — check path/name
            if (Test-ContainsCI $loc $Needle)
            {
                $results.Add([pscustomobject]@{
                    Category = 'Startup (Folder)'
                    Name = $item.Name
                    Location = $loc
                    Field = 'Path'
                    Value = $loc
                    Extra = 'Non-shortcut file'
                })
            }
        }
    }
}

# ----------------------------------
# Startup: WMI aggregator
# ----------------------------------
try
{
    $wmiStartups = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
}
catch
{
    $wmiStartups = @()
}

foreach ($sc in $wmiStartups)
{
    $fields = @{
        'Name' = [string]$sc.Name
        'Command' = [string]$sc.Command
        'Location' = [string]$sc.Location
        'User' = [string]$sc.User
        'Caption' = [string]$sc.Caption
    }
    foreach ($k in $fields.Keys)
    {
        if (Test-ContainsCI $fields[$k] $Needle)
        {
            $results.Add([pscustomobject]@{
                Category = 'Startup (WMI)'
                Name = $sc.Name
                Location = $sc.Location
                Field = $k
                Value = $fields[$k]
                Extra = ''
            })
        }
    }
}

# --------------------------
# Export
# --------------------------
$results |
        Sort-Object Category, Name, Location, Field |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Matches exported to $OutputPath"
