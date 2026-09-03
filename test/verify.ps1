#Requires -Version 5.1
<#
.SYNOPSIS
    Asserts every promise harden.ps1 makes, on the machine it hardened.

.DESCRIPTION
    Reads the EFFECTIVE state (what the cmdlets and the OS report) rather
    than the files the script wrote - asking sshd -T instead of trusting
    sshd_config, in the Linux siblings' idiom. Four checks go further and
    prove behaviour:

      * script-block logging: run a unique string through a FRESH PowerShell
        process and find it in event 4104. The engine reads the policy at
        startup, so only a new process can prove the logging is live.
      * password policy: three linked probes on a throwaway local account -
        creating it with NO password must be refused, the same account with a
        compliant password must be accepted, and changing that password to a
        7-character one must be refused again. A refusal only means something
        next to an acceptance.
      * process auditing: spawn a process whose command line carries a unique
        marker and find that marker in Security event 4688 - which only
        happens when BOTH the subcategory and the command-line inclusion are
        live.
      * logon auditing: one deliberately failed network logon against this
        very box (a unique nonexistent user, IPC$ on loopback) must land in
        Security event 4625.

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

Write-Host '== RDP posture ==' -ForegroundColor White
# The effective state as the Terminal Services WMI provider reports it - the
# same class the System Properties Remote tab talks to - rather than the raw
# keys the script wrote. sshd -T instead of sshd_config, continued. If the
# provider is absent on this SKU, fall back to the registry and say so.
$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting `
    -Filter "TerminalName='RDP-Tcp'" -ErrorAction SilentlyContinue
if ($null -ne $ts) {
    if ($ts.UserAuthenticationRequired -eq 1) { Pass 'RDP requires NLA (the TS provider reports it, not just the registry)' }
    else { Fail "RDP does not require NLA - UserAuthenticationRequired=$($ts.UserAuthenticationRequired)" }
    if ($ts.SecurityLayer -eq 2) { Pass 'RDP transport is TLS (SecurityLayer=2, effective)' }
    else { Fail "RDP SecurityLayer is $($ts.SecurityLayer), not 2 (TLS)" }
    if ($ts.MinEncryptionLevel -ge 3) { Pass "RDP encryption level is $($ts.MinEncryptionLevel) (High or FIPS)" }
    else { Fail "RDP MinEncryptionLevel is $($ts.MinEncryptionLevel), below High (3)" }
} else {
    Write-Host '  (TS WMI provider not available - falling back to the registry)' -ForegroundColor DarkGray
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Test-RegEquals 'RDP requires NLA' $rdpKey 'UserAuthentication' 1
    Test-RegEquals 'RDP transport is TLS' $rdpKey 'SecurityLayer' 2
    Test-RegEquals 'RDP encryption level is High' $rdpKey 'MinEncryptionLevel' 3
}

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

Write-Host '== Audit policy ==' -ForegroundColor White
# auditpol's only locale-proof read is the backup CSV: /get prints the
# setting as words and the words are localized, the backup carries a numeric
# Setting Value column (0 none, 1 success, 2 failure, 3 both). See the note
# on Get-AuditSettingValue in harden.ps1.
$auditValues = @{}
$auditCsv = Join-Path $env:TEMP ('wh-verify-auditpol-' + [guid]::NewGuid().ToString('N') + '.csv')
try {
    $null = auditpol /backup /file:"$auditCsv"
    foreach ($line in Get-Content -LiteralPath $auditCsv) {
        $cols = $line -split ','
        if ($cols.Count -ge 7) { $auditValues[$cols[3].ToUpper()] = $cols[6] }
    }
} finally { Remove-Item -LiteralPath $auditCsv -ErrorAction SilentlyContinue }
function Test-AuditBits {
    param([string]$Label, [string]$Guid, [int]$Mask)
    $v = if ($auditValues.ContainsKey($Guid)) { [int]$auditValues[$Guid] } else { -1 }
    if ($v -ge 0 -and (($v -band $Mask) -eq $Mask)) { Pass "$Label (Setting Value $v)" }
    else { Fail "$Label - Setting Value is $v, mask $Mask not satisfied" }
}
Test-AuditBits 'Logon auditing records success AND failure' '{0CCE9215-69AE-11D9-BED3-505054503030}' 3
Test-AuditBits 'Process creation is audited' '{0CCE922B-69AE-11D9-BED3-505054503030}' 1
Test-AuditBits 'Changes to the audit policy itself are audited' '{0CCE922F-69AE-11D9-BED3-505054503030}' 1
Test-RegEquals 'event 4688 includes the command line' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Test-RegEquals 'subcategory policy overrides the legacy categories' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1

# Behavioural, success side: an audit policy is only real if events land.
# Spawn a process whose command line carries a unique marker, then find the
# marker in Security event 4688. The marker sits in the ARGUMENTS, so the
# match also proves ProcessCreationIncludeCmdLine_Enabled is in effect -
# without it the event names cmd.exe and omits everything after it.
$procMarker = 'WH-AUDIT-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$null = & cmd.exe /c "rem $procMarker" 2>&1
$procFound = $false
foreach ($attempt in 1..10) {
    Start-Sleep -Milliseconds 700
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4688
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 300 -ErrorAction SilentlyContinue
    if ($evts | Where-Object { $_.Message -like "*$procMarker*" }) { $procFound = $true; break }
}
if ($procFound) { Pass 'a spawned process really lands in event 4688 WITH its command line (the marker was in the arguments)' }
else { Fail 'process creation did not land in 4688 with the command line (marker not found)' }

# Behavioural, failure side: one deliberately bad network logon against this
# very box must land in event 4625. The username is unique so the search
# cannot match a stale event; the target is IPC$ on loopback so nothing
# leaves the host and nothing gets created. The user does not exist and the
# password is wrong twice over - the attempt CANNOT succeed.
$logonProbe = 'whNoSuch' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$null = net use '\\127.0.0.1\IPC$' WrongPass123x /user:$logonProbe 2>&1
$logonFound = $false
foreach ($attempt in 1..10) {
    Start-Sleep -Milliseconds 700
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4625
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 300 -ErrorAction SilentlyContinue
    if ($evts | Where-Object { $_.Message -like "*$logonProbe*" }) { $logonFound = $true; break }
}
if ($logonFound) { Pass 'a failed logon really lands in event 4625 (the probe username was recorded)' }
else { Fail 'the failed-logon probe did not land in event 4625' }

Write-Host '== AutoRun / AutoPlay ==' -ForegroundColor White
# Machine policy values ARE the mechanism here (Explorer reads them at
# insertion time), so the registry check is the effective check - the
# WDigest/LLMNR precedent.
$explorerPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
Test-RegEquals 'no drive type gets AutoRun (all eight bits set)' $explorerPol 'NoDriveTypeAutoRun' 255
Test-RegEquals 'autorun.inf is never processed' $explorerPol 'NoAutorun' 1
Test-RegEquals 'no autoplay for non-volume devices (MTP/cameras)' $explorerPol 'NoAutoplayfornonVolume' 1

Write-Host '== Attack-surface services ==' -ForegroundColor White
# The CI plants both services RUNNING with StartType Automatic before the
# harden, so these checks flip from red to green because of real work.
foreach ($svcName in 'Spooler', 'RemoteRegistry') {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { Fail "$svcName exists on this box (the CI plants it running)"; continue }
    if ($svc.Status -eq 'Stopped') { Pass "$svcName is stopped" }
    else { Fail "$svcName should be stopped, is $($svc.Status)" }
    if ($svc.StartType -eq 'Disabled') { Pass "$svcName is disabled (won't return at boot)" }
    else { Fail "$svcName should be disabled, StartType is $($svc.StartType)" }
}
# Behavioural: disabled means it CANNOT be started - the lock, not the label.
# Start-Service against a disabled service must throw; if it ever succeeds,
# undo it so the box stays hardened, and fail loudly.
$spoolerStarted = $false
try { Start-Service -Name Spooler -ErrorAction Stop; $spoolerStarted = $true } catch { }
if ($spoolerStarted) {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
    Fail 'a disabled Spooler must refuse to start (Start-Service succeeded)'
} else {
    Pass 'a disabled Spooler refuses to start (the disable is a lock, not a label)'
}
# And the process is really gone: no spoolsv.exe parsing anything as SYSTEM.
if (Get-Process -Name spoolsv -ErrorAction SilentlyContinue) {
    Fail 'no spoolsv.exe process is running'
} else {
    Pass 'no spoolsv.exe process is running (nothing to exploit)'
}

Write-Host '== Null sessions (anonymous enumeration) ==' -ForegroundColor White
# The CI plants the whole family weak (RestrictAnonymous 0, Everyone includes
# Anonymous, legacy null pipes), so these flip red-to-green from real work.
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$srvPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Test-RegEquals 'anonymous callers cannot enumerate SAM accounts' $lsaPath 'RestrictAnonymousSAM' 1
Test-RegEquals 'anonymous callers cannot enumerate shares' $lsaPath 'RestrictAnonymous' 1
Test-RegEquals 'the anonymous token does not carry Everyone' $lsaPath 'EveryoneIncludesAnonymous' 0
Test-RegEquals 'null sessions reach only listed exceptions' $srvPath 'RestrictNullSessAccess' 1
# The exception lists must be PRESENT and EMPTY: absent is a default, not a
# decision, and one legacy pipe left behind is how a restricted box answers.
foreach ($listName in 'NullSessionPipes', 'NullSessionShares') {
    $present = $false
    $entries = @()
    try {
        $raw = (Get-ItemProperty -LiteralPath $srvPath -Name $listName -ErrorAction Stop).$listName
        $present = $true
        $entries = @($raw | Where-Object { $_ })
    } catch { $present = $false }
    if ($present -and $entries.Count -eq 0) { Pass "$listName is pinned to the empty list" }
    elseif (-not $present) { Fail "$listName should be pinned empty, is absent" }
    else { Fail "$listName still lists exceptions: $($entries -join ', ')" }
}

Write-Host '== Defender PUA protection ==' -ForegroundColor White
# The CI image ships PUA off - the audit graded it WARN before this step
# existed - so absence is the natural offender, nothing to plant. Effective
# value first: Get-MpPreference is what the engine actually runs with.
try {
    $pua = [int](Get-MpPreference -ErrorAction Stop).PUAProtection
    if ($pua -eq 1) { Pass "Defender blocks potentially unwanted applications (PUAProtection = $pua)" }
    else { Fail "Defender should block PUA - PUAProtection = $pua (1 = Block)" }
} catch { Fail 'Defender preferences unavailable - cannot confirm PUA protection' }
Test-RegEquals 'PUA block pinned as machine policy (survives a preference reset)' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' 'MpEnablePus' 1

Write-Host '== SMBv1 off ==' -ForegroundColor White
# The CI plants LanmanServer\Parameters\SMB1 = 1 (a modern image ships the
# dialect off and the payload removed - measured: the cmdlet cannot even
# enable it there, "The specified service does not exist"), so the registry
# check flips red-to-green from real work; the effective read must agree.
# The client driver and the optional feature are absent on a modern Server
# image and asserted as such.
Test-RegEquals 'SMB1 server dialect pinned off in the registry (payload or not)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
$smb1 = Get-SmbServerConfiguration
if (-not $smb1.EnableSMB1Protocol) { Pass 'SMB server refuses the SMB1 dialect (effective config)' }
else { Fail 'SMB server still speaks SMB1 (EnableSMB1Protocol = True)' }
$drv = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue
if ($null -eq $drv) { Pass 'SMB1 client driver (mrxsmb10) is not present' }
elseif ($drv.StartType -eq 'Disabled') { Pass 'SMB1 client driver (mrxsmb10) is disabled' }
else { Fail "SMB1 client driver mrxsmb10 is $($drv.StartType) - this box would still speak SMB1 outbound" }
$feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($null -eq $feat -or "$($feat.State)" -like 'Disabled*') { Pass "SMB1Protocol optional feature is not installed ($(if ($feat) { $feat.State } else { 'absent' }))" }
else { Fail "SMB1Protocol optional feature is $($feat.State)" }

Write-Host ''
if ($Script:Failures -gt 0) {
    Write-Host "$Script:Failures check(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed' -ForegroundColor Green
# Explicit, not optional: the failed-logon probe above leaves a NON-ZERO
# $LASTEXITCODE behind by design (net use failing IS the check), and GitHub's
# powershell shell appends `exit $LASTEXITCODE` to every step - so without
# this line the step inherits the probe's rc and fails while printing
# "All checks passed". The exit code is this script's verdict, not the last
# native command's.
exit 0
