#Requires -Version 5.1
<#
.SYNOPSIS
    Asserts every promise harden.ps1 makes, on the machine it hardened.

.DESCRIPTION
    Reads the EFFECTIVE state (what the cmdlets and the OS report) rather
    than the files the script wrote - asking sshd -T instead of trusting
    sshd_config, in the Linux siblings' idiom. Two checks go further and
    prove behaviour:

      * script-block logging: run a unique string through a FRESH PowerShell
        process and find it in event 4104. The engine reads the policy at
        startup, so only a new process can prove the logging is live.
      * password policy: ask the OS to set a 4-character password on a
        throwaway local account. It must REFUSE, and then accept a compliant
        one - the policy is real, not just written down.

    Exit code 0 = every check passed.

.NOTES
    ASCII only (see harden.ps1). Run elevated, after harden.ps1.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Script:Failures = 0
function Pass { param([string]$m) Write-Host "  OK   $m" -ForegroundColor Green }
function Fail { param([string]$m) Write-Host "  FAIL $m" -ForegroundColor Red; $Script:Failures++ }

function Test-RegEquals {
    param([string]$Label, [string]$Path, [string]$Name, $Expected)
    $actual = try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { '<absent>' }
    if ("$actual" -eq "$Expected") { Pass "$Label ($Name = $actual)" }
    else { Fail "$Label - expected $Name = $Expected, got $actual" }
}

Write-Host ''
Write-Host '== SMB signing ==' -ForegroundColor White
$smb = Get-SmbServerConfiguration
if ($smb.RequireSecuritySignature) { Pass 'SMB server REQUIRES signing (effective config)' }
else { Fail 'SMB server requires signing' }
if ($smb.EnableSecuritySignature) { Pass 'SMB server signing enabled' }
else { Fail 'SMB server signing enabled' }
Test-RegEquals 'SMB client refuses unsigned sessions' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1

Write-Host '== WDigest (cleartext credentials in LSASS) ==' -ForegroundColor White
Test-RegEquals 'WDigest will not cache cleartext credentials' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0

Write-Host '== Name-resolution poisoning (LLMNR + NetBIOS) ==' -ForegroundColor White
Test-RegEquals 'LLMNR is disabled by policy' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
# Every interface, not just one: NetBIOS is per adapter, and one adapter
# left at "use the DHCP setting" is one adapter that still answers Responder.
$ifBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$bad = @()
foreach ($iface in (Get-ChildItem -LiteralPath $ifBase -ErrorAction SilentlyContinue)) {
    $v = try { (Get-ItemProperty -LiteralPath $iface.PSPath -Name NetbiosOptions -ErrorAction Stop).NetbiosOptions } catch { '<absent>' }
    if ("$v" -ne '2') { $bad += "$($iface.PSChildName)=$v" }
}
if ($bad.Count -eq 0) { Pass 'NetBIOS over TCP/IP is disabled on every interface' }
else { Fail "NetBIOS still enabled on: $($bad -join ', ')" }

Write-Host '== NTLM policy ==' -ForegroundColor White
Test-RegEquals 'Only NTLMv2 is accepted' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
Test-RegEquals 'LM hashes are never stored' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1

Write-Host '== Firewall posture ==' -ForegroundColor White
foreach ($name in @('Domain', 'Private', 'Public')) {
    $p = Get-NetFirewallProfile -Name $name
    if ($p.Enabled -eq $true -and $p.DefaultInboundAction -eq 'Block') {
        Pass "$name profile enabled with inbound Block (effective)"
    } else {
        Fail "$name profile - Enabled=$($p.Enabled), DefaultInboundAction=$($p.DefaultInboundAction)"
    }
}

Write-Host '== PowerShell logging ==' -ForegroundColor White
Test-RegEquals 'script-block logging is on' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Test-RegEquals 'module logging is on' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1

# THE behavioural check. The PowerShell engine reads the logging policy when
# it STARTS, so this session (older than the hardening) would never log no
# matter what the registry says - a check run in-process would be a lie.
# Spawn a fresh powershell.exe, have it emit a unique marker, then look for
# that marker in event 4104.
$marker = 'WH-VERIFY-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$null = & powershell.exe -NoProfile -Command "`$x = '$marker'; Write-Output `$x" 2>&1
$found = $false
foreach ($attempt in 1..10) {
    Start-Sleep -Milliseconds 700
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($evts | Where-Object { $_.Message -like "*$marker*" }) { $found = $true; break }
}
if ($found) { Pass 'a fresh PowerShell session really lands in event 4104 (script-block logging is live)' }
else { Fail 'script-block logging did not record a fresh session (marker not found in 4104)' }

Write-Host '== Password and lockout policy ==' -ForegroundColor White
# Effective values as an auditor reads them, not the values we wrote.
$acct = (net accounts) | Out-String
if ($acct -match 'Minimum password length:\s+(\d+)' -and [int]$Matches[1] -ge 14) {
    Pass "minimum password length is $($Matches[1])"
} else { Fail "minimum password length below 14 (net accounts says: $($Matches[1]))" }
if ($acct -match 'Length of password history maintained:\s+(\d+)' -and [int]$Matches[1] -ge 24) {
    Pass "password history keeps $($Matches[1]) passwords"
} else { Fail 'password history below 24' }
if ($acct -match 'Lockout threshold:\s+(\d+)' -and [int]$Matches[1] -le 5 -and [int]$Matches[1] -gt 0) {
    Pass "account lockout after $($Matches[1]) bad attempts"
} else { Fail 'lockout threshold not set to 5 or fewer' }

# The second behavioural check: ask the OS to break its own policy. A weak
# password must be REFUSED and a compliant one accepted - proving the policy
# is enforced at the point of use, not merely recorded. The probe account is
# created and removed here; the finally block runs even on failure.
$probeUser = 'whVerifyProbe'
try {
    $null = net user $probeUser /add /y 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "could not create the probe account (rc=$LASTEXITCODE) - behavioural password check skipped"
    } else {
        $weak = (net user $probeUser 'short1!' 2>&1 | Out-String)
        $weakRc = $LASTEXITCODE
        $strong = (net user $probeUser 'Vh7#qL2m!Xr9tBw4' 2>&1 | Out-String)
        $strongRc = $LASTEXITCODE
        if ($weakRc -ne 0) { Pass 'the OS REFUSES a 7-character password (policy enforced at the point of use)' }
        else { Fail "a 7-character password was accepted: $($weak.Trim())" }
        if ($strongRc -eq 0) { Pass '...and accepts a compliant one (the refusal was the policy, not a broken account)' }
        else { Fail "a compliant password was also refused: $($strong.Trim())" }
    }
} finally {
    $null = net user $probeUser /delete 2>&1
}

Write-Host ''
if ($Script:Failures -gt 0) {
    Write-Host "$Script:Failures check(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed' -ForegroundColor Green
