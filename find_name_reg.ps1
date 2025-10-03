<#
.SYNOPSIS
  Find every registry key/value containing a target string (case-insensitive) and export to CSV.

.PARAMETER Needle
  The string to search for (your old name).

.PARAMETER OutputPath
  CSV output path.

.EXAMPLE
  .\Find-Needle-InRegistry.ps1 -Needle "oldname" -OutputPath "C:\needle_registry_hits.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Needle,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

# --- Config ---
$hives = @('HKLM:', 'HKCU:', 'HKU:', 'HKCR:', 'HKCC:')
$needleCI = $Needle.ToLowerInvariant()

# Try to make output directory
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

function Test-ContainsCI
{
    param([string]$Text, [string]$Needle)
    if ( [string]::IsNullOrEmpty($Text))
    {
        return $false
    }
    return $Text.ToLowerInvariant().Contains($Needle)
}

function Convert-BinaryToStrings
{
    param([byte[]]$Bytes)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Bytes -or $Bytes.Length -eq 0)
    {
        return $out
    }

    # Try UTF-16LE (Windows "Unicode")
    try
    {
        $u16 = [System.Text.Encoding]::Unicode.GetString($Bytes)
        if ($u16)
        {
            $out.Add($u16)
        }
    }
    catch
    {
    }

    # Try ASCII (best-effort)
    try
    {
        $ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)
        if ($ascii)
        {
            $out.Add($ascii)
        }
    }
    catch
    {
    }

    return $out
}

$results = New-Object System.Collections.Generic.List[object]
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$keysScanned = 0

foreach ($hive in $hives)
{
    Write-Verbose "Scanning $hive ..."
    try
    {
        # Use -Recurse with error suppression; some paths will be access-denied.
        $allKeys = Get-ChildItem -Path $hive -Recurse -ErrorAction SilentlyContinue
    }
    catch
    {
        $allKeys = @()
    }

    # Include the hive root itself
    $allKeys = @((Get-Item -Path $hive -ErrorAction SilentlyContinue)) + $allKeys | Where-Object { $_ }

    $total = $allKeys.Count
    $i = 0

    foreach ($key in $allKeys)
    {
        $i++
        $keysScanned++

        if ($i % 200 -eq 0)
        {
            $pct = if ($total -gt 0)
            {
                [int](($i / $total) * 100)
            }
            else
            {
                0
            }
            Write-Progress -Activity "Scanning $hive" -Status "$i of $total keys..." -PercentComplete $pct
        }

        $registryView = '32-bit view'
        if ([Environment]::Is64BitProcess)
        {
            $registryView = '64-bit view'
        }

        # Key name match
        $keyPath = $key.Name
        if (Test-ContainsCI -Text $keyPath -Needle $needleCI)
        {
            $results.Add([pscustomobject]@{
                Hive = $hive.TrimEnd(':')
                RegistryView = $registryView
                KeyPath = $keyPath
                MatchType = 'KeyName'
                ValueName = ''
                ValueKind = ''
                DataSample = ''
            })
        }

        # Value name/data matches
        try
        {
            $values = $key.GetValueNames() 2> $null
            foreach ($vn in $values)
            {
                $vk = $key.GetValueKind($vn) 2> $null
                $val = $key.GetValue($vn, $null) 2> $null

                $registryView = '32-bit view'
                if ([Environment]::Is64BitProcess)
                {
                    $registryView = '64-bit view'
                }

                # Value name match
                if (Test-ContainsCI -Text $vn -Needle $needleCI)
                {
                    $results.Add([pscustomobject]@{
                        Hive = $hive.TrimEnd(':')
                        RegistryView = $registryView
                        KeyPath = $keyPath
                        MatchType = 'ValueName'
                        ValueName = $vn
                        ValueKind = $vk
                        DataSample = ''
                    })
                }

                # Value data match
                $matched = $false
                $sample = $null

                switch ($vk)
                {
                    'String' {
                        $sample = [string]$val
                        if (Test-ContainsCI -Text $sample -Needle $needleCI)
                        {
                            $matched = $true
                        }
                    }
                    'ExpandString' {
                        $sample = [string]$val
                        if (Test-ContainsCI -Text $sample -Needle $needleCI)
                        {
                            $matched = $true
                        }
                    }
                    'MultiString' {
                        $sample = ($val -join '; ')
                        if (Test-ContainsCI -Text $sample -Needle $needleCI)
                        {
                            $matched = $true
                        }
                    }
                    'DWord' {
                        # Not text, skip
                    }
                    'QWord' {
                        # Not text, skip
                    }
                    'Binary' {
                        # $strs = Convert-BinaryToStrings -Bytes ([byte[]]$val)
                        # foreach ($s in $strs)
                        # {
                        #     if (Test-ContainsCI -Text $s -Needle $needleCI)
                        #     {
                        #         $matched = $true
                        #         if (-not $sample)
                        #         {
                        #             $sample = $s
                        #         }
                        #     }
                        # }
                        # if (-not $sample -and $val)
                        # {
                        #     # If nothing decoded nicely, keep a small hex preview
                        #     $max = [Math]::Min(32, $val.Length)
                        #     $sample = ("0x" + ($val[0..($max - 1)] | ForEach-Object { $_.ToString("X2") } | Join-String -Separator ''))
                        # }
                    }
                    default {
                        # Unknown kind; best-effort string
                        try
                        {
                            $sample = [string]$val
                            if (Test-ContainsCI -Text $sample -Needle $needleCI)
                            {
                                $matched = $true
                            }
                        }
                        catch
                        {
                        }
                    }
                }

                if ($matched)
                {
                    # Trim overly long samples
                    if ($sample -and $sample.Length -gt 400)
                    {
                        $sample = $sample.Substring(0, 400) + '…'
                    }

                    $registryView = '32-bit view'
                    if ([Environment]::Is64BitProcess)
                    {
                        $registryView = '64-bit view'
                    }

                    $results.Add([pscustomobject]@{
                        Hive = $hive.TrimEnd(':')
                        RegistryView = $registryView
                        KeyPath = $keyPath
                        MatchType = 'ValueData'
                        ValueName = $vn
                        ValueKind = $vk
                        DataSample = $sample
                    })
                }
            }
        }
        catch
        {
            # Access denied or transient errors — ignore
        }
    }

    Write-Progress -Activity "Scanning $hive" -Completed
}

$results |
        Sort-Object Hive, KeyPath, MatchType, ValueName |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$sw.Stop()
Write-Host "Done. Keys scanned: $keysScanned in $( [int]$sw.Elapsed.TotalSeconds )s"
Write-Host "Results: $OutputPath"
