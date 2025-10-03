<#
.SYNOPSIS
  Audit or enforce removal/exclusion of an old profile path from Windows Search (CrawlScopeManager).

.PARAMETER OldProfilePath
  Full path to old profile (e.g. C:\Users\OldName). A trailing \* pattern is used where appropriate.

.PARAMETER Report
  CSV path for findings and actions.

.PARAMETER Mode
  'Audit' (read-only) or 'Enforce' (apply exclusion; optional prune).

.PARAMETER PrunePaths
  (Enforce only) Also delete Sites\LocalHost\Paths entries referencing the old path.

.EXAMPLE
  # Audit only
  .\Search-CrawlScope-AuditEnforce.ps1 -OldProfilePath "C:\Users\OldName" -Report "C:\needle_search_rules.csv" -Mode Audit

.EXAMPLE
  # Enforce + prune
  .\Search-CrawlScope-AuditEnforce.ps1 -OldProfilePath "C:\Users\OldName" -Report "C:\needle_search_rules.csv" -Mode Enforce -PrunePaths
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OldProfilePath,

    [Parameter(Mandatory = $true)]
    [string]$Report,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Audit', 'Enforce')]
    [string]$Mode,

    [switch]$PrunePaths
)

# --- Helpers ---
function Write-Info($m)
{
    Write-Host "[*] $m" -ForegroundColor Cyan
}
function Write-Ok($m)
{
    Write-Host "[+] $m" -ForegroundColor Green
}
function Write-Warn($m)
{
    Write-Host "[!] $m" -ForegroundColor Yellow
}
function Write-Err($m)
{
    Write-Host "[x] $m" -ForegroundColor Red
}

function Contains-Target([string]$text, [string[]]$needles)
{
    if ( [string]::IsNullOrWhiteSpace($text))
    {
        return $false
    }
    $t = $text.ToLowerInvariant()
    foreach ($n in $needles)
    {
        if ( $t.Contains($n))
        {
            return $true
        }
    }
    return $false
}

function Export-Reg($path, $out)
{
    try
    {
        if (Test-Path $path)
        {
            & reg.exe export ($path -replace '^HKLM:\\', 'HKLM\') $out /y | Out-Null
            Write-Ok "Exported $path -> $out"
        }
    }
    catch
    {
        Write-Warn "Backup failed for ${path}: $( $_.Exception.Message )"
    }
}

function Ensure-Admins-FullControl($path)
{
    try
    {
        if (-not (Test-Path $path))
        {
            return
        }
        $acl = Get-Acl $path
        $admins = New-Object System.Security.Principal.NTAccount("Administrators")
        $acl.SetOwner($admins)
        Set-Acl -Path $path -AclObject $acl

        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "Administrators", "FullControl",
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $false) # protect, remove inheritance
        $null = $acl.ResetAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl
    }
    catch
    {
        Write-Warn "ACL ensure failed on ${path}: $( $_.Exception.Message )"
    }
}

function Remove-RegKey-Force
{
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$TryAsSystem)

    if (-not (Test-Path $Path))
    {
        return
    }

    # bottom-up list
    $keys = @()
    try
    {
        $keys = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSPath
    }
    catch
    {
    }
    $keys = @($keys + $Path) | Sort-Object { $_.Length } -Descending

    # Take ownership + FullControl
    $admins = New-Object System.Security.Principal.NTAccount("Administrators")
    foreach ($k in $keys)
    {
        try
        {
            $acl = Get-Acl -Path $k
            $acl.SetOwner($admins)
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "Administrators", "FullControl",
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
            )
            $null = $acl.ResetAccessRule($rule)
            Set-Acl -Path $k -AclObject $acl
        }
        catch
        {
        }
    }

    $failed = $false
    foreach ($k in $keys)
    {
        try
        {
            Remove-Item -Path $k -Recurse -Force -ErrorAction Stop
        }
        catch
        {
            $failed = $true
        }
    }

    if ($failed -and $TryAsSystem -and (Test-Path $Path))
    {
        try
        {
            $safe = $Path.Replace("'", "''")
            $inner = "Remove-Item -Path '$safe' -Recurse -Force"
            $psCmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"${inner}`""
            $taskName = "\Temp\RegDel_$( Get-Random )"
            schtasks /Create /TN $taskName /SC ONCE /ST 00:00 /TR "$psCmd" /RL HIGHEST /RU SYSTEM /F | Out-Null
            schtasks /Run /TN $taskName | Out-Null
            Start-Sleep -Seconds 5
            schtasks /Delete /TN $taskName /F | Out-Null
        }
        catch
        {
            Write-Warn "SYSTEM removal failed for ${Path}: $( $_.Exception.Message )"
        }
    }
}

# --- Constants & Matching Forms ---
$resolved = $null
try
{
    $resolved = (Resolve-Path -LiteralPath $OldProfilePath -ErrorAction Stop).Path
}
catch
{
    # Ignore if path not found
}

if ($null -ne $resolved)
{
    $OldProfilePath = $resolved
}

$matchers = @(
    $OldProfilePath.ToLowerInvariant(),
    ($OldProfilePath.TrimEnd('\') + '\*').ToLowerInvariant(),
    ('file:///' + $OldProfilePath.Replace('\', '/')).ToLowerInvariant(),
    ('file:///' + $OldProfilePath.TrimEnd('\').Replace('\', '/') + '/*').ToLowerInvariant()
)

$CSMBase = 'HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex'
$UserRulesKey = Join-Path $CSMBase 'UserScopeRules'
$DefaultRules = Join-Path $CSMBase 'DefaultRules'
$SitesPathsKey = 'HKLM:\SOFTWARE\Microsoft\Windows Search\Gather\Windows\SystemIndex\Sites\LocalHost\Paths'

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($Category, $RegistryPath, $KeyName, $Field, $Action, $OldValue, $NewValue)
{
    $rows.Add([pscustomobject]@{
        Category = $Category; RegistryPath = $RegistryPath; KeyName = $KeyName; Field = $Field;
        Action = $Action; OldValue = $OldValue; NewValue = $NewValue
    })
}

# --- Scan functions ---
function Scan-Rules
{
    param(
        $root,
        $label
    )

    if (-not (Test-Path $root))
    {
        return
    }

    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
        $rk = Get-Item $_.PSPath
        $vals = @{ }
        foreach ($vn in $rk.GetValueNames())
        {
            $vals[$vn] = $rk.GetValue($vn)
        }

        $hit = $false
        foreach ($kv in $vals.GetEnumerator())
        {
            if ($kv.Value -is [string] -and (Contains-Target $kv.Value $matchers))
            {
                $hit = $true
                break
            }
        }

        if ($hit)
        {
            foreach ($kv in $vals.GetEnumerator())
            {
                $valTxt = $null
                if ($kv.Value -is [string])
                {
                    $valTxt = $kv.Value
                }
                elseif ($kv.Value -is [string[]])
                {
                    $valTxt = ($kv.Value -join '; ')
                }
                else
                {
                    $valTxt = [string]$kv.Value
                }

                if (Contains-Target $valTxt $matchers)
                {
                    Add-Row $label $rk.PSPath $rk.PSChildName $kv.Key 'Found' $valTxt ''
                }
            }
        }
    }
}

function Scan-SitesPaths()
{
    if (-not (Test-Path $SitesPathsKey))
    {
        return
    }
    Get-ChildItem -Path $SitesPathsKey -ErrorAction SilentlyContinue | ForEach-Object {
        $rk = Get-Item $_.PSPath
        foreach ($vn in $rk.GetValueNames())
        {
            $val = $rk.GetValue($vn)
            if ($val -is [string] -and (Contains-Target $val $matchers))
            {
                Add-Row 'Gather Sites Paths' $rk.PSPath $rk.PSChildName $vn 'Found' $val ''
            }
        }
    }
}

# --- AUDIT ---
Write-Info "Mode: $Mode"
Write-Info "Target: $OldProfilePath"

Scan-Rules $UserRulesKey 'CrawlScope (UserRule)'
Scan-Rules $DefaultRules 'CrawlScope (DefaultRule)'
Scan-SitesPaths

if ($Mode -eq 'Audit')
{
    $rows | Sort-Object Category, RegistryPath, KeyName, Field |
            Export-Csv -Path $Report -NoTypeInformation -Encoding UTF8
    Write-Ok "Audit complete. Report: $Report"
    return
}

# --- ENFORCE ---
# Backups
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
Write-Info "Backing up keys..."
Export-Reg $CSMBase       "C:\CrawlScopeManager_backup_$stamp.reg"
Export-Reg $SitesPathsKey "C:\SearchSitesPaths_backup_$stamp.reg"

# Stop service
Write-Info "Stopping WSearch..."
try
{
    net stop WSearch | Out-Null
}
catch
{
}

# Ensure we can write UserScopeRules
if (-not (Test-Path $UserRulesKey))
{
    Ensure-Admins-FullControl (Split-Path $UserRulesKey -Parent)
    try
    {
        New-Item -Path $UserRulesKey -Force | Out-Null
    }
    catch
    {
        Write-Warn "Create UserScopeRules failed: $( $_.Exception.Message )"
    }
}
Ensure-Admins-FullControl $UserRulesKey

# Flip any existing user rules that reference old path -> Exclude=1, Include=0
if (Test-Path $UserRulesKey)
{
    Get-ChildItem -Path $UserRulesKey -ErrorAction SilentlyContinue | ForEach-Object {
        $rk = Get-Item $_.PSPath
        $vals = @{ }
        foreach ($vn in $rk.GetValueNames())
        {
            $vals[$vn] = $rk.GetValue($vn)
        }

        $hasHit = $false
        foreach ($kv in $vals.GetEnumerator())
        {
            if ($kv.Value -is [string] -and (Contains-Target $kv.Value $matchers))
            {
                $hasHit = $true
                break
            }
        }

        if ($hasHit)
        {
            if ( $vals.ContainsKey('Include'))
            {
                $old = $vals['Include']
                New-ItemProperty -Path $rk.PSPath -Name 'Include' -PropertyType DWord -Value 0 -Force | Out-Null
                Add-Row 'CrawlScope (UserRule)' $rk.PSPath $rk.PSChildName 'Include' 'Set 0 (exclude)' $old 0
            }

            $oldEx = ''
            if ( $vals.ContainsKey('Exclude'))
            {
                $oldEx = $vals['Exclude']
            }

            New-ItemProperty -Path $rk.PSPath -Name 'Exclude' -PropertyType DWord -Value 1 -Force | Out-Null
            Add-Row 'CrawlScope (UserRule)' $rk.PSPath $rk.PSChildName 'Exclude' 'Set 1' $oldEx 1
        }
    }
}


# Ensure explicit Exclude rule exists for this path (GUID key)
try
{
    $guid = ([guid]::NewGuid()).ToString('B')
    $targetRulePath = Join-Path $UserRulesKey $guid
    Ensure-Admins-FullControl $UserRulesKey
    New-Item -Path $targetRulePath -Force | Out-Null

    $pathWild = ($OldProfilePath.TrimEnd('\') + '\*')
    $urlWild = ('file:///' + $OldProfilePath.TrimEnd('\').Replace('\', '/') + '/*')

    New-ItemProperty -Path $targetRulePath -Name 'Exclude' -PropertyType DWord  -Value 1 -Force | Out-Null
    Add-Row 'CrawlScope (UserRule)' $targetRulePath $guid 'Exclude' 'Set 1' '' 1

    New-ItemProperty -Path $targetRulePath -Name 'Path'    -PropertyType String -Value "$pathWild" -Force | Out-Null
    Add-Row 'CrawlScope (UserRule)' $targetRulePath $guid 'Path' 'Set' '' "$pathWild"

    # Store URL variants as well for robustness
    New-ItemProperty -Path $targetRulePath -Name 'URL'     -PropertyType String -Value "$urlWild"  -Force | Out-Null
    Add-Row 'CrawlScope (UserRule)' $targetRulePath $guid 'URL'  'Set' '' "$urlWild"

    # Optional alternates used on some builds
    try
    {
        New-ItemProperty -Path $targetRulePath -Name 'Pattern'      -PropertyType String -Value "$pathWild" -Force | Out-Null
    }
    catch
    {
    }
    try
    {
        New-ItemProperty -Path $targetRulePath -Name 'PatternOrURL' -PropertyType String -Value "$urlWild"  -Force | Out-Null
    }
    catch
    {
    }

    Write-Ok "Created explicit exclusion rule for $OldProfilePath"
}
catch
{
    Write-Warn "Failed to create exclusion rule: $( $_.Exception.Message )"
}

# Optional prune of Sites\LocalHost\Paths
if ($PrunePaths -and (Test-Path $SitesPathsKey))
{
    Write-Info "Pruning Sites\\LocalHost\\Paths entries referencing old path..."
    Get-ChildItem -Path $SitesPathsKey -ErrorAction SilentlyContinue | ForEach-Object {
        $rk = Get-Item $_.PSPath
        $hit = $false; $preview = ''
        foreach ($vn in $rk.GetValueNames())
        {
            $val = $rk.GetValue($vn)
            if ($val -is [string] -and (Contains-Target $val $matchers))
            {
                $hit = $true; $preview = $val; break
            }
        }
        if ($hit)
        {
            Remove-RegKey-Force -Path $rk.PSPath -TryAsSystem
            Add-Row 'Gather Sites Paths' $rk.PSPath $rk.PSChildName '(key)' 'Deleted (PrunePaths)' $preview ''
        }
    }
}

# Restart service
Write-Info "Starting WSearch..."
try
{
    net start WSearch | Out-Null
}
catch
{
}

# Export report
$rows | Sort-Object Category, RegistryPath, KeyName, Field |
        Export-Csv -Path $Report -NoTypeInformation -Encoding UTF8

Write-Ok "Done. Mode=$Mode. Report: $Report"
Write-Host "Tip: In Indexing Options → Advanced → Rebuild to refresh the index with the new scope."
