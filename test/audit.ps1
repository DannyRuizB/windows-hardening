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

# Counter names are spelled out ON PURPOSE. They used to be $Script:P /
# $Script:W / $Script:F, and a perfectly innocent `$p = Get-NetFirewallProfile`
# in the firewall section SILENTLY overwrote the PASS counter: PowerShell
# variable names are case-insensitive, so $p IS $Script:P. Every later PASS
# then threw "The '++' operator works only on numbers" and the final score
# printed as a CIM object with an empty percentage - while the job still went
# green, because the audit only fails on FAIL. Long names, and a type guard at
# the bottom, so this can never fail quietly again.
$Script:PassCount = 0; $Script:WarnCount = 0; $Script:FailCount = 0
function P { param([string]$m) Write-Host "  PASS  $m" -ForegroundColor Green; $Script:PassCount++ }
function W { param([string]$m, [string]$fix) Write-Host "  WARN  $m" -ForegroundColor Yellow; Write-Host "        -> $fix" -ForegroundColor DarkGray; $Script:WarnCount++ }
function F { param([string]$m, [string]$fix) Write-Host "  FAIL  $m" -ForegroundColor Red; Write-Host "        -> $fix" -ForegroundColor DarkGray; $Script:FailCount++ }

function Get-Reg {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# Advanced audit policy, read the locale-proof way: auditpol /get prints the
# setting as localized words, the backup CSV carries a numeric Setting Value
# (0 none, 1 success, 2 failure, 3 both). See harden.ps1 step 9.
$Script:AuditPolicyByGuid = @{}
$apCsv = Join-Path $env:TEMP ('wh-audit-auditpol-' + [guid]::NewGuid().ToString('N') + '.csv')
try {
    $null = auditpol /backup /file:"$apCsv"
    foreach ($line in Get-Content -LiteralPath $apCsv) {
        $cols = $line -split ','
        if ($cols.Count -ge 7) { $Script:AuditPolicyByGuid[$cols[3].ToUpper()] = $cols[6] }
    }
} finally { Remove-Item -LiteralPath $apCsv -ErrorAction SilentlyContinue }
function Get-AuditValue {
    param([string]$Guid)
    if ($Script:AuditPolicyByGuid.ContainsKey($Guid)) { [int]$Script:AuditPolicyByGuid[$Guid] } else { -1 }
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
# Step 14 owns this now (server dialect, client driver, optional feature).
# but cannot always remove (a runner image ships it payload-removed).
if (-not $smb.EnableSMB1Protocol) { P 'SMBv1 is disabled (no EternalBlue-era protocol)' }
else { F 'SMBv1 is ENABLED' 'run harden.ps1 (SMBv1 step); Set-SmbServerConfiguration -EnableSMB1Protocol $false; remove the optional feature' }
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -eq 0) { P 'SMB1 server dialect pinned off in the registry' }
else { W 'SMB1 server dialect not pinned in the registry (relies on the build default)' 'run harden.ps1 (SMBv1 step): LanmanServer\Parameters\SMB1 = 0' }
$smb1drv = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue
if ($null -eq $smb1drv -or $smb1drv.StartType -eq 'Disabled') { P 'SMB1 client driver (mrxsmb10) absent or disabled - this box does not speak SMB1 outbound' }
else { W "SMB1 client driver mrxsmb10 is $($smb1drv.StartType)" 'run harden.ps1 (SMBv1 step): a downgrade attack needs a willing client' }

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
    $fwProfile = Get-NetFirewallProfile -Name $name
    if ($fwProfile.Enabled -eq $true -and $fwProfile.DefaultInboundAction -eq 'Block') { P "$name profile: on, inbound denied" }
    elseif ($fwProfile.Enabled -ne $true) { F "$name profile is OFF" 'run harden.ps1 (firewall step)' }
    else { W "$name profile inbound default is $($fwProfile.DefaultInboundAction), not Block" 'run harden.ps1 (firewall step)' }
}

Write-Host '-- Logging and audit -----------------------------------------'
if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1) {
    P 'PowerShell script-block logging is on (fileless attacks are recorded)'
} else { F 'PowerShell script-block logging is off' 'run harden.ps1 (PowerShell logging step)' }
if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1) {
    P 'PowerShell module logging is on'
} else { W 'PowerShell module logging is off' 'run harden.ps1 (PowerShell logging step)' }
# Applied by harden.ps1 step 9 - graded through the backup CSV because it is
# the only locale-proof interface auditpol has (the old version of this very
# check matched the words 'Success and Failure' and would have judged a
# Spanish server as failing forever).
if (((Get-AuditValue '{0CCE9215-69AE-11D9-BED3-505054503030}') -band 3) -eq 3) {
    P 'Logon auditing records success AND failure (4624/4625)'
} else { F 'Logon auditing does not record both success and failure' 'run harden.ps1 (audit policy step)' }
if (((Get-AuditValue '{0CCE922B-69AE-11D9-BED3-505054503030}') -band 1) -eq 1) {
    P 'Process creation is audited (event 4688)'
} else { F 'Process creation is not audited' 'run harden.ps1 (audit policy step)' }
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1) {
    P 'Event 4688 includes the full command line'
} else { W '4688 names the process but not its arguments' 'run harden.ps1 (audit policy step)' }
if (((Get-AuditValue '{0CCE922F-69AE-11D9-BED3-505054503030}') -band 1) -eq 1) {
    P 'Changes to the audit policy itself are audited (event 4719)'
} else { W 'Audit-policy changes go unrecorded' 'run harden.ps1 (audit policy step)' }
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy') -eq 1) {
    P 'Subcategory audit policy overrides the legacy categories'
} else { W 'Legacy category policy can silently override the subcategories' 'run harden.ps1 (audit policy step)' }

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
    if ([int]$mp.PUAProtection -eq 1) { P 'Potentially-unwanted-application protection is on (Block)' }
    elseif ([int]$mp.PUAProtection -eq 2) { W 'PUA protection is in audit mode (logs, blocks nothing)' 'run harden.ps1 (Defender PUA step)' }
    else { W 'PUA protection is off' 'run harden.ps1 (Defender PUA step)' }
    if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' 'MpEnablePus') -eq 1) { P 'PUA block is pinned as machine policy' }
    else { W 'PUA block relies on the local preference only (no policy pin)' 'run harden.ps1 (Defender PUA step)' }
} catch { W 'Defender preferences unavailable' 'check whether Defender is present/managed on this host' }

Write-Host '-- Remote access ---------------------------------------------'
$rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$denyRdp = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$nla = Get-Reg $rdpKey 'UserAuthentication'
# One combined judgement on exposure: RDP off is the smallest surface; RDP on
# is a legitimate choice on a server IF the client must authenticate before a
# session exists. On WITHOUT NLA hands the pre-auth surface (the BlueKeep
# class) to anyone who can reach 3389 - that is the serious one.
if ($denyRdp -ne 0) { P 'RDP is not accepting connections (fDenyTSConnections)' }
elseif ($nla -eq 1) { P 'RDP is on and requires NLA (no pre-auth surface)' }
else { F 'RDP is ON without NLA - the logon screen answers before authentication' 'run harden.ps1 (RDP step)' }
if ((Get-Reg $rdpKey 'SecurityLayer') -eq 2) { P 'RDP transport is TLS (SecurityLayer=2)' }
else { W 'RDP transport can negotiate down to legacy RDP crypto' 'run harden.ps1 (RDP step)' }
if ((Get-Reg $rdpKey 'MinEncryptionLevel') -ge 3) { P 'RDP encryption level is High or FIPS' }
else { W 'RDP encryption level below High (128-bit)' 'run harden.ps1 (RDP step)' }

Write-Host '-- Removable media / AutoRun ---------------------------------'
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255) {
    P 'AutoRun is off for every drive type (NoDriveTypeAutoRun 0xFF)'
} else { W 'Some drive types still get AutoRun' 'run harden.ps1 (AutoRun step)' }
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun') -eq 1) {
    P 'autorun.inf is never processed'
} else { W 'autorun.inf may still be honored' 'run harden.ps1 (AutoRun step)' }
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutoplayfornonVolume') -eq 1) {
    P 'Non-volume devices (MTP/cameras) get no autoplay'
} else { W 'Non-volume devices may still autoplay' 'run harden.ps1 (AutoRun step)' }

Write-Host '-- Attack-surface services ------------------------------------'
# Graded WARN, not FAIL, because both have a legitimate niche (a real print
# server; a legacy monitoring tool) - but on a baseline they are pure attack
# surface: Spooler is the PrintNightmare class running as SYSTEM, and
# RemoteRegistry is reconnaissance as a service.
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if (-not $spooler -or ($spooler.Status -eq 'Stopped' -and $spooler.StartType -eq 'Disabled')) {
    P 'Print Spooler is stopped and disabled (PrintNightmare class off)'
} else {
    W "Print Spooler is $($spooler.Status)/$($spooler.StartType)" 'stop and disable it unless this box actually prints (harden.ps1 service step)'
}
$remoteReg = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
if (-not $remoteReg -or ($remoteReg.Status -eq 'Stopped' -and $remoteReg.StartType -eq 'Disabled')) {
    P 'RemoteRegistry is stopped and disabled (no registry reads over the wire)'
} else {
    W "RemoteRegistry is $($remoteReg.Status)/$($remoteReg.StartType)" 'stop and disable it (harden.ps1 service step)'
}

Write-Host '-- Null sessions (anonymous enumeration) -----------------------'
# The anonymous SMB logon hands over the map (users, shares, password
# policy) before any credential is touched - enum4linux's opening move.
$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$srvKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
if ((Get-Reg $lsaKey 'RestrictAnonymousSAM') -eq 1) { P 'Anonymous SAM account enumeration is refused' }
else { F 'Anonymous callers can enumerate SAM accounts (the password-spray shopping list)' 'set Lsa\RestrictAnonymousSAM=1 (harden.ps1 null-session step)' }
if ((Get-Reg $lsaKey 'RestrictAnonymous') -eq 1) { P 'Anonymous share enumeration is refused' }
else { W 'Anonymous callers can enumerate shares' 'set Lsa\RestrictAnonymous=1 (harden.ps1 null-session step)' }
if ((Get-Reg $lsaKey 'EveryoneIncludesAnonymous') -ne 1) { P 'The anonymous token does not carry Everyone' }
else { F 'Anonymous callers are treated as Everyone - every Everyone ACL covers them' 'set Lsa\EveryoneIncludesAnonymous=0 (harden.ps1 null-session step)' }
if ((Get-Reg $srvKey 'RestrictNullSessAccess') -eq 1) { P 'Null sessions reach only listed exceptions' }
else { W 'Null sessions are not restricted to the exception lists' 'set LanmanServer RestrictNullSessAccess=1 (harden.ps1 null-session step)' }
$nullPipes = @((Get-Reg $srvKey 'NullSessionPipes') | Where-Object { $_ })
if ($nullPipes.Count -eq 0) { P 'No null-session pipe exceptions' }
else { W "Null-session pipes still listed: $($nullPipes -join ', ')" 'empty NullSessionPipes unless a legacy service truly needs it (harden.ps1 null-session step)' }

Write-Host '-- Windows Script Host --------------------------------------'
# The .vbs/.js/.wsf engine: absent = enabled (the default). A server has no
# mail client and no user double-clicking attachments; automation is PowerShell.
if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled') -eq 0) { P 'Windows Script Host is disabled machine-wide' }
else { F 'Windows Script Host is enabled - a .vbs/.js attachment runs on double-click' 'run harden.ps1 (Script Host step): Windows Script Host\Settings\Enabled=0' }

Write-Host '-- Event log capacity ---------------------------------------'
# Step 9 turned the events on; this keeps them. 20 MB (the default) of
# Security log is minutes of a password spray. CIS 18.10.25.x sizes.
foreach ($pair in @(@('Security', 196608), @('System', 32768), @('Application', 32768))) {
    $log = $pair[0]; $kb = [int64]$pair[1]
    $mb = [math]::Round((Get-WinEvent -ListLog $log).MaximumSizeInBytes / 1MB)
    if ($mb -ge ($kb / 1024)) { P "$log log holds $mb MB (>= $($kb / 1024) MB)" }
    else { W "$log log holds only $mb MB - a burst of events pushes the evidence out in minutes" "run harden.ps1 (event log step): wevtutil sl $log /ms:$($kb * 1024) and policy EventLog\$log\MaxSize=$kb" }
}

Write-Host '-- Firewall logging -----------------------------------------'
# A firewall that denies in silence: the scan and the brute force vanish, and
# so does the connection that got through. CIS 9.x per profile.
foreach ($name in @('Domain', 'Private', 'Public')) {
    $fwl = Get-NetFirewallProfile -Name $name
    if ("$($fwl.LogBlocked)" -eq 'True' -and "$($fwl.LogAllowed)" -eq 'True' -and [int]$fwl.LogMaxSizeKilobytes -ge 16384) {
        P "$name profile logs dropped and allowed connections ($($fwl.LogMaxSizeKilobytes) KB)"
    } else {
        W "$name profile logging: dropped=$($fwl.LogBlocked) allowed=$($fwl.LogAllowed) size=$($fwl.LogMaxSizeKilobytes) KB" 'run harden.ps1 (firewall logging step): Set-NetFirewallProfile -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384'
    }
}

Write-Host '-- SMB client: guest logons ---------------------------------'
# No authentication means no signing, no encryption, no identity: a spoofed
# share mounts silently. CIS 18.6.8.1.
$smbCli = Get-SmbClientConfiguration
if (-not $smbCli.EnableInsecureGuestLogons) { P 'SMB client refuses insecure guest logons' }
else { F 'SMB client accepts insecure guest logons - a rogue share mounts with no credential challenged' 'run harden.ps1 (SMB guest step): Set-SmbClientConfiguration -EnableInsecureGuestLogons $false' }

Write-Host '-- Hardened UNC paths ---------------------------------------'
# A UNC fetch trusts whatever answers the name; name resolution is spoofable.
# CIS 18.6.14.1: SYSVOL/NETLOGON require mutual auth + integrity.
$hp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
foreach ($unc in @('\\*\SYSVOL', '\\*\NETLOGON')) {
    $v = Get-Reg $hp $unc
    if ($v -match 'RequireMutualAuthentication=1' -and $v -match 'RequireIntegrity=1') {
        P "$unc requires mutual auth and integrity"
    } else {
        $shown = if ($v) { $v } else { '<absent>' }
        F "$unc is not hardened ($shown) - a spoofed server can feed this client over UNC" "run harden.ps1 (Hardened UNC step)"
    }
}

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

# The guard the old bug earned: a counter that is not an integer means
# something clobbered it, and a score built on that would be fiction. Fail
# loudly rather than print a broken line and exit 0.
foreach ($c in @(@{n='PASS'; v=$Script:PassCount}, @{n='WARN'; v=$Script:WarnCount}, @{n='FAIL'; v=$Script:FailCount})) {
    if ($c.v -isnot [int]) {
        throw "the $($c.n) counter is a $($c.v.GetType().Name), not a number - a variable name collision clobbered it"
    }
}
$total = $Script:PassCount + $Script:WarnCount + $Script:FailCount
$score = [math]::Round((($Script:PassCount + 0.5 * $Script:WarnCount) / $total) * 100, 0)
Write-Host ''
Write-Host '=============================================================' -ForegroundColor White
Write-Host " Score: $Script:PassCount PASS, $Script:WarnCount WARN, $Script:FailCount FAIL  ->  $score% compliant" -ForegroundColor White
if ($Script:FailCount -gt 0) {
    Write-Host ' Verdict: core controls MISSING - fix the FAIL items first.' -ForegroundColor Red
    Write-Host '=============================================================' -ForegroundColor White
    exit 1
}
if ($Script:WarnCount -gt 0) {
    Write-Host ' Verdict: core baseline solid; WARN items are hardening still on the table.' -ForegroundColor Yellow
} else {
    Write-Host ' Verdict: fully compliant with this checklist.' -ForegroundColor Green
}
Write-Host '=============================================================' -ForegroundColor White
# Same contract as verify.ps1: the exit code is this script's verdict, never
# whatever $LASTEXITCODE the last native command (net, auditpol) left behind.
exit 0
