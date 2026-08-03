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
      * password policy: three linked probes on a throwaway local account -
        creating it with NO password must be refused, the same account with a
        compliant password must be accepted, and changing that password to a
        7-character one must be refused again. A refusal only means something
        next to an acceptance.

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
    # Not $p: see the counter-collision note in audit.ps1 - short variable
    # names are how a CIM object ended up inside a counter.
    $fwProfile = Get-NetFirewallProfile -Name $name
    if ($fwProfile.Enabled -eq $true -and $fwProfile.DefaultInboundAction -eq 'Block') {
        Pass "$name profile enabled with inbound Block (effective)"
    } else {
        Fail "$name profile - Enabled=$($fwProfile.Enabled), DefaultInboundAction=$($fwProfile.DefaultInboundAction)"
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

# The second behavioural check: ask the OS to break its own policy on a
# throwaway account. Three linked probes, because a refusal only means
# something next to an acceptance. The probe account is removed in the
# finally block, which runs even when an assertion fails.
#
# Probe 1 exists because the FIRST version of this check tripped over it: a
# plain `net user X /add` creates an account with NO password, and the 14-char
# minimum we just applied refuses that outright. The check was "broken" by the
# hardening working - so the refusal became the assertion.
$probeUser = 'whVerifyProbe'
# EXACTLY 14 characters, and /y on every net.exe call that can prompt. A
# password LONGER than 14 makes net.exe ask "Computers with Windows prior to
# Windows 2000 will not be able to use this account. Continue? (Y/N)" - and
# with no interactive stdin that becomes "No valid response was provided",
# which looked exactly like a policy refusal. Two belts: a length that does
# not trigger the prompt, and /y in case someone raises the minimum later.
$strongPw = 'Vh7#qL2m!Xr9tB'
$weakPw = 'short1!'
try {
    $noPwOut = (net user $probeUser /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        Pass 'the OS REFUSES creating an account with no password (the 14-char minimum bites)'
    } else {
        Fail "an account with NO password was created: $noPwOut"
        $null = net user $probeUser /delete 2>&1
    }

    $addOut = (net user $probeUser $strongPw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0) {
        Pass '...and accepts the same account with a compliant password (the refusal was policy, not breakage)'

        $weakOut = (net user $probeUser $weakPw /y 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            Pass 'changing that password to a 7-character one is REFUSED too (enforced at the point of use)'
        } else {
            Fail "a 7-character password was accepted: $weakOut"
        }
    } else {
        Fail "a compliant password was refused as well (rc=$LASTEXITCODE): $addOut"
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
