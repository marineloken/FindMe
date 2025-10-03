<#
.SYNOPSIS
  Scan Windows Scheduled Tasks for any occurrence of a target string and export matches to CSV.

.PARAMETER Needle
  String to search for (case-insensitive).

.PARAMETER OutputPath
  CSV output path.

.EXAMPLE
  .\Find-Needle-InScheduledTasks.ps1 -Needle "oldname" -OutputPath "C:\needle_task_hits.csv"
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

# Helper: safely export a task's XML (Export-ScheduledTask is reliable and fast)
function Get-TaskXml
{
    param([Microsoft.Management.Infrastructure.CimInstance]$Task)
    try
    {
        $xmlText = Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop | Out-String
        return $xmlText
    }
    catch
    {
        # Fallback via schtasks in case of odd access failures
        try
        {
            $fullName = ($Task.TaskPath.TrimEnd('\') + '\' + $Task.TaskName).Replace('\\', '\')
            $xmlText = & schtasks.exe /Query /TN $fullName /XML 2> $null
            if ($LASTEXITCODE -eq 0 -and $xmlText)
            {
                return $xmlText
            }
        }
        catch
        {
        }
    }
    return $null
}

# Gather all tasks (including hidden)
try
{
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
}
catch
{
    $tasks = @()
}

$idx = 0
$total = $tasks.Count

foreach ($t in $tasks)
{
    $idx++
    if ($idx % 100 -eq 0)
    {
        $pct = if ($total -gt 0)
        {
            [int](($idx / $total) * 100)
        }
        else
        {
            0
        }
        Write-Progress -Activity "Scanning Scheduled Tasks" -Status "$idx of $total..." -PercentComplete $pct
    }

    # Get dynamic info
    try
    {
        $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
    }
    catch
    {
        $info = $null
    }

    # Pull XML and parse key fields
    $xmlRaw = Get-TaskXml -Task $t
    $xml = $null
    if ($xmlRaw)
    {
        try
        {
            $xml = [xml]$xmlRaw
        }
        catch
        {
        }
    }

    # Extract useful bits (best-effort)
    $author = $null
    $description = $null
    $runAsUser = $null
    $hidden = $null
    $actions = @()

    if ($xml)
    {
        $author = $xml.Task.RegistrationInfo.Author
        $description = $xml.Task.RegistrationInfo.Description
        $hidden = $xml.Task.Settings.Hidden

        # Principals
        $principalNodes = $xml.Task.Principals.Principal
        if ($principalNodes)
        {
            foreach ($p in $principalNodes)
            {
                if ($p.UserId)
                {
                    $runAsUser = $p.UserId
                }
            }
        }

        # Actions (Exec)
        $actionNodes = $xml.Task.Actions.Exec
        if ($actionNodes)
        {
            foreach ($a in $actionNodes)
            {
                $actions += [pscustomobject]@{
                    Command = [string]$a.Command
                    Arguments = [string]$a.Arguments
                    WorkingDir = [string]$a.WorkingDirectory
                }
            }
        }
    }

    # Build strings to search
    $fieldsToCheck = @()
    $fieldsToCheck += @(
        [string]$t.TaskName,
        [string]$t.TaskPath,
        [string]$t.Description
    )
    if ($info)
    {
        $fieldsToCheck += @(
            [string]$info.State
        )
    }
    $fieldsToCheck += @(
        [string]$author,
        [string]$description,
        [string]$runAsUser,
        [string]$hidden
    )

    foreach ($a in $actions)
    {
        $fieldsToCheck += @(
            [string]$a.Command,
            [string]$a.Arguments,
            [string]$a.WorkingDir
        )
    }

    $hit = $false
    $hitFields = New-Object System.Collections.Generic.List[string]

    # Check explicit fields
    $fieldNames = @(
        'TaskName', 'TaskPath', 'TaskDescription', 'State',
        'Author', 'Description', 'RunAsUser', 'Hidden',
        'Action.Command', 'Action.Arguments', 'Action.WorkingDir'
    )

    $fi = 0
    foreach ($field in $fieldsToCheck)
    {
        if (Test-ContainsCI $field $Needle)
        {
            $hit = $true
            $hitFields.Add($fieldNames[$fi])
        }
        $fi++
    }

    # Check full XML text too (to catch anything else)
    $xmlMatch = $false
    if ($xmlRaw -and (Test-ContainsCI $xmlRaw $Needle))
    {
        $xmlMatch = $true
        $hit = $true
    }

    if ($hit)
    {
        # Flatten first action for CSV readability (most tasks have one)
        $firstAction = $actions | Select-Object -First 1

        # Short XML snippet (avoid huge CSV fields)
        $xmlSnippet = $null
        if ($xmlRaw)
        {
            $pos = $xmlRaw.ToLowerInvariant().IndexOf($Needle.ToLowerInvariant())
            if ($pos -ge 0)
            {
                $start = [Math]::Max(0, $pos - 120)
                $len = [Math]::Min(400, $xmlRaw.Length - $start)
                $xmlSnippet = $xmlRaw.Substring($start, $len).Replace("`r", " ").Replace("`n", " ")
            }
            else
            {
                $xmlSnippet = $xmlRaw.Substring(0,[Math]::Min(400, $xmlRaw.Length)).Replace("`r", " ").Replace("`n", " ")
            }
        }

        $results.Add([pscustomobject]@{
            TaskPath = $t.TaskPath
            TaskName = $t.TaskName
            Hidden = [string]$hidden
            State = if ($info)
            {
                [string]$info.State
            }
            else
            {
                ''
            }
            Author = [string]$author
            RunAsUser = [string]$runAsUser
            ActionCommand = if ($firstAction)
            {
                [string]$firstAction.Command
            }
            else
            {
                ''
            }
            ActionArguments = if ($firstAction)
            {
                [string]$firstAction.Arguments
            }
            else
            {
                ''
            }
            WorkingDir = if ($firstAction)
            {
                [string]$firstAction.WorkingDir
            }
            else
            {
                ''
            }
            HitFields = ($hitFields -join '; ')
            XmlContainsHit = [bool]$xmlMatch
            XmlSnippet = $xmlSnippet
        })
    }
}

Write-Progress -Activity "Scanning Scheduled Tasks" -Completed

$results |
        Sort-Object TaskPath, TaskName |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Matches exported to $OutputPath"
