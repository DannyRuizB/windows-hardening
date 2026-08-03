#Requires -Version 5.1
<#
.SYNOPSIS
    Scores this Windows box against a CIS-style checklist.

.DESCRIPTION
    Unlike verify.ps1 (which confirms the baseline was applied) this grades a
    WIDER set of best practices - including ones harden.ps1 deliberately does
    NOT touch - so the score is honest and the warnings are a to-do list
    rather than a victory lap. Same contract as the Linux siblings:

      PASS = control in place
      WARN = hardening not applied (improvable, or deliberately out of scope)
      FAIL = a core control is missing (serious)

    Score = (PASS + 0.5*WARN) / total. Exit code is non-zero only when
    something FAILS - a WARN is information, not a broken build.

.NOTES
    ASCII only (see harden.ps1). Run elevated.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Script:P = 0; $Script:W = 0; $Script:F = 0
function P { param([string]$m) Write-Host "  PASS  $m" -ForegroundColor Green; $Script:P++ }
function W { param([string]$m, [string]$fix) Write-Host "  WARN  $m" -ForegroundColor Yellow; Write-Host "        -> $fix" -ForegroundColor DarkGray; $Script:W++ }
function F { param([string]$m, [string]$fix) Write-Host "  FAIL  $m" -ForegroundColor Red; Write-Host "        -> $fix" -ForegroundColor DarkGray; $Script:F++ }

function Get-Reg {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

Write-Host ''
Write-Host '=============================================================' -ForegroundColor White
Write-Host ' COMPLIANCE AUDIT - Windows host vs a CIS-style checklist' -ForegroundColor White
Write-Host '=============================================================' -ForegroundColor White
$os = Get-CimInstance Win32_OperatingSystem
Write-Host " $($os.Caption) ($($os.Version))"
Write-Host ''

Write-Host '-- SMB -------------------------------------------------------'
$smb = Get-SmbServerConfiguration
if ($smb.RequireSecuritySignature) { P 'SMB server requires signing (relay-resistant)' }
else { F 'SMB server does not require signing' 'run harden.ps1 (SMB signing step)' }
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') -eq 1) {
    P 'SMB client refuses unsigned sessions'
} else { W 'SMB client will accept unsigned sessions' 'run harden.ps1 (SMB signing step)' }
# Wider than the baseline: SMB1 is a separate concern the script reports on
# but cannot always remove (a runner image ships it payload-removed).
if (-not $smb.EnableSMB1Protocol) { P 'SMBv1 is disabled (no EternalBlue-era protocol)' }
else { F 'SMBv1 is ENABLED' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false; remove the optional feature' }

Write-Host '-- Credential exposure ---------------------------------------'
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 0) {
    P 'WDigest will not cache cleartext credentials'
} else { F 'WDigest may keep cleartext passwords in LSASS' 'run harden.ps1 (WDigest step)' }
$lm = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
if ($lm -eq 5) { P 'NTLMv2 only (LM and NTLMv1 refused)' }
elseif ($null -eq $lm) { W 'LmCompatibilityLevel not set (inherited default)' 'run harden.ps1 (NTLM step)' }
else { W "LmCompatibilityLevel is $lm, not 5" 'run harden.ps1 (NTLM step)' }
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash') -eq 1) { P 'No LM hash is stored' }
else { W 'LM hashes may be stored' 'run harden.ps1 (NTLM step)' }
# Wider than the baseline: LSA protection is a good control the script does
# not apply, because it needs a reboot AND can break legacy SSO agents.
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1, 2)) {
    P 'LSASS runs as a protected process (RunAsPPL)'
} else { W 'LSASS is not a protected process' 'set Lsa\RunAsPPL=1 after checking your SSO/AV agents (out of this baseline on purpose)' }

Write-Host '-- Name resolution -------------------------------------------'
if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0) {
    P 'LLMNR is disabled (no Responder-style poisoning)'
} else { F 'LLMNR is enabled' 'run harden.ps1 (name-resolution step)' }
$ifBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$loose = @()
foreach ($iface in (Get-ChildItem -LiteralPath $ifBase -ErrorAction SilentlyContinue)) {
    if ("$(Get-Reg $iface.PSPath 'NetbiosOptions')" -ne '2') { $loose += $iface.PSChildName }
}
if ($loose.Count -eq 0) { P 'NetBIOS over TCP/IP disabled on every interface' }
else { F "NetBIOS still enabled on $($loose.Count) interface(s)" 'run harden.ps1 (name-resolution step)' }

Write-Host '-- Firewall --------------------------------------------------'
foreach ($name in @('Domain', 'Private', 'Public')) {
    $p = Get-NetFirewallProfile -Name $name
    if ($p.Enabled -eq $true -and $p.DefaultInboundAction -eq 'Block') { P "$name profile: on, inbound denied" }
    elseif ($p.Enabled -ne $true) { F "$name profile is OFF" 'run harden.ps1 (firewall step)' }
    else { W "$name profile inbound default is $($p.DefaultInboundAction), not Block" 'run harden.ps1 (firewall step)' }
}

Write-Host '-- Logging and audit -----------------------------------------'
if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1) {
    P 'PowerShell script-block logging is on (fileless attacks are recorded)'
} else { F 'PowerShell script-block logging is off' 'run harden.ps1 (PowerShell logging step)' }
if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1) {
    P 'PowerShell module logging is on'
} else { W 'PowerShell module logging is off' 'run harden.ps1 (PowerShell logging step)' }
# Wider than the baseline: advanced audit policy is the next step on the
# roadmap, so it is graded but not yet applied.
$logonAudit = (auditpol /get /subcategory:"Logon" 2>&1 | Out-String)
if ($logonAudit -match 'Success and Failure') { P 'Logon auditing records success AND failure' }
else { W 'Logon auditing does not record both success and failure' 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable (roadmap)' }

Write-Host '-- Accounts --------------------------------------------------'
$acct = (net accounts) | Out-String
if ($acct -match 'Minimum password length:\s+(\d+)') {
    $len = [int]$Matches[1]
    if ($len -ge 14) { P "Minimum password length is $len" }
    elseif ($len -eq 0) { F 'Minimum password length is 0 (a local account may have NO password)' 'run harden.ps1 (password policy step)' }
    else { W "Minimum password length is $len, below 14" 'run harden.ps1 (password policy step)' }
}
if ($acct -match 'Length of password history maintained:\s+(\S+)') {
    $hist = $Matches[1]
    if ($hist -match '^\d+$' -and [int]$hist -ge 24) { P "Password history keeps $hist passwords" }
    else { W "Password history is $hist, below 24" 'run harden.ps1 (password policy step)' }
}
if ($acct -match 'Lockout threshold:\s+(\S+)') {
    $th = $Matches[1]
    if ($th -match '^\d+$' -and [int]$th -le 5 -and [int]$th -gt 0) { P "Account lockout after $th bad attempts" }
    else { W "Lockout threshold is $th" 'run harden.ps1 (password policy step)' }
}
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
if ($null -eq $guest) { P 'No Guest account on this box' }
elseif (-not $guest.Enabled) { P 'Guest account is disabled' }
else { F 'Guest account is ENABLED' 'Disable-LocalUser -Name Guest' }

Write-Host '-- Endpoint protection ---------------------------------------'
# Deliberately graded but NOT enforced by harden.ps1: a CI image ships
# real-time protection off for build speed, and forcing it there would fight
# the platform. On a real server this WARN is a genuine to-do.
try {
    $mp = Get-MpPreference
    if (-not $mp.DisableRealtimeMonitoring) { P 'Defender real-time protection is on' }
    else { W 'Defender real-time protection is OFF' 'Set-MpPreference -DisableRealtimeMonitoring $false (not enforced by this baseline)' }
    if ($mp.PUAProtection -ge 1) { P 'Potentially-unwanted-application protection is on' }
    else { W 'PUA protection is off' 'Set-MpPreference -PUAProtection 1 (roadmap)' }
} catch { W 'Defender preferences unavailable' 'check whether Defender is present/managed on this host' }

Write-Host '-- UAC -------------------------------------------------------'
# Out of the baseline ON PURPOSE, and the audit says why: raising the admin
# consent prompt on a machine with no interactive session (a CI runner, an
# unattended server) can hang anything that needs elevation. Graded so the
# gap is visible, never silently applied.
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1) { P 'UAC is enabled' }
else { F 'UAC is DISABLED' 'set Policies\System\EnableLUA=1 (needs a reboot)' }
$consent = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
if ($consent -in @(1, 2)) { P "Admins are prompted for elevation (ConsentPromptBehaviorAdmin=$consent)" }
else { W "Admins elevate without a prompt (ConsentPromptBehaviorAdmin=$consent)" 'set it to 2 on interactive machines - deliberately not applied by this baseline (see README)' }

$total = $Script:P + $Script:W + $Script:F
$score = [math]::Round((($Script:P + 0.5 * $Script:W) / $total) * 100, 0)
Write-Host ''
Write-Host '=============================================================' -ForegroundColor White
Write-Host " Score: $Script:P PASS, $Script:W WARN, $Script:F FAIL  ->  $score% compliant" -ForegroundColor White
if ($Script:F -gt 0) {
    Write-Host ' Verdict: core controls MISSING - fix the FAIL items first.' -ForegroundColor Red
    Write-Host '=============================================================' -ForegroundColor White
    exit 1
}
if ($Script:W -gt 0) {
    Write-Host ' Verdict: core baseline solid; WARN items are hardening still on the table.' -ForegroundColor Yellow
} else {
    Write-Host ' Verdict: fully compliant with this checklist.' -ForegroundColor Green
}
Write-Host '=============================================================' -ForegroundColor White
