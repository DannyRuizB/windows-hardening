#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 33: does `powershell.exe -Version 2` still
    start the PowerShell 2.0 engine?

.DESCRIPTION
    The 2.0 engine predates script-block logging (and AMSI), so asking for it
    is the classic downgrade: the same command, run with -Version 2, leaves
    nothing in event 4104. Measured on the Server 2022 runner, which ships
    the engine together with .NET 3.5 (what it needs to start): with
    script-block logging on, a marker run by the default engine landed in
    4104 and the same marker run with -Version 2 did not.

    The probe asks for the 2.0 engine and reads back which major version
    actually ran. Returns one object:
      Result = DOWNGRADES   a 2.x engine ran
               REFUSED      Windows says the 2.0 engine is not installed
                            (the step removed it)
               REDIRECTED   this Windows has no 2.0 engine at all: it warns
                            that 2.0 is deprecated and runs the current one,
                            which logs (measured on Server 2025)
               SETUP-FAILED anything else - a FAILED proof, never a pass
      Detail = what powershell.exe answered.

    -CheckLogging (meaningful only with script-block logging on) runs a
    unique marker through the default engine as well, and reports in
    DefaultLogged / V2Logged whether each marker reached event 4104 - the
    bypass itself, not just the engine version.

.NOTES
    ASCII ONLY (see harden.ps1). Runs elevated or not; changes nothing.
#>
[CmdletBinding()]
param([switch]$CheckLogging)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function New-ProbeResult {
    param([string]$Result, [string]$Detail, $DefaultLogged = $null, $V2Logged = $null)
    [pscustomobject]@{ Result = $Result; Detail = $Detail; DefaultLogged = $DefaultLogged; V2Logged = $V2Logged }
}

# One child powershell.exe that carries $Marker in its script block and
# prints the major version of the engine that ran it. The 2.0 engine's
# refusal arrives on stderr as UTF-16 read as bytes - the NULs go.
function Invoke-Engine {
    param([string]$Marker, [switch]$Version2)
    $argv = @('-NoProfile', '-NonInteractive', '-Command', "`$m = '$Marker'; `$PSVersionTable.PSVersion.Major")
    if ($Version2) { $argv = @('-Version', '2') + $argv }
    $lines = @(& powershell.exe @argv 2>&1 | ForEach-Object { ("$_" -replace '\x00', '').Trim() } | Where-Object { $_ })
    [pscustomobject]@{ Rc = $LASTEXITCODE; Lines = $lines }
}

function Test-Logged {
    param([string]$Marker)
    foreach ($attempt in 1..10) {
        Start-Sleep -Milliseconds 700
        $evts = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
            StartTime = (Get-Date).AddMinutes(-5)
        } -MaxEvents 300 -ErrorAction SilentlyContinue
        if ($evts | Where-Object { $_.Message -like "*$Marker*" }) { return $true }
    }
    $false
}

$tag = [guid]::NewGuid().ToString('N').Substring(0, 12)
$markV2 = "WH-PSV2-$tag"
$r = Invoke-Engine -Marker $markV2 -Version2
$flat = ($r.Lines -join ' ') -replace '\s+', ' '
$major = $r.Lines | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1

if ($major -eq '2') {
    if (-not $CheckLogging) { return (New-ProbeResult 'DOWNGRADES' "-Version 2 started engine 2 ($flat)") }
    # The default engine is the control: a marker it runs must land in 4104,
    # or a missing 2.0 marker would only say that logging is off.
    $markDefault = "WH-PSV5-$tag"
    $null = Invoke-Engine -Marker $markDefault
    $defaultLogged = Test-Logged $markDefault
    $v2Logged = Test-Logged $markV2
    return (New-ProbeResult 'DOWNGRADES' "-Version 2 started engine 2; in event 4104: default engine's marker $(if ($defaultLogged) { 'FOUND' } else { 'missing' }), 2.0 engine's marker $(if ($v2Logged) { 'FOUND' } else { 'missing' })" $defaultLogged $v2Logged)
}
# 0xFFFB0000 is what powershell.exe returns when it cannot load the engine
# asked for (measured: rc -327680 once the feature was removed); the message
# is matched too, but it is English-only, so the code is the anchor.
if ($r.Rc -eq -327680 -or $flat -match 'PowerShell 2 engine is not installed') {
    return (New-ProbeResult 'REFUSED' "rc $($r.Rc): $flat")
}
if ($major -and [int]$major -ge 3) {
    return (New-ProbeResult 'REDIRECTED' "-Version 2 ran engine $major instead ($flat)")
}
New-ProbeResult 'SETUP-FAILED' "unexpected answer from powershell.exe -Version 2 (rc $($r.Rc)): $flat"
