#Requires -Version 5.1
<#
.SYNOPSIS
    Scenario tests for harden.ps1's -No* switches, on the machine it hardened.

.DESCRIPTION
    The contract of every -No<Step> switch is double: the skipped step must
    leave its knob EXACTLY as found, and the rest of the baseline must still
    apply. There is one machine here (no throwaway containers like the Linux
    siblings' scenarios.sh), so each scenario RE-PLANTS its step's offender
    on the already-hardened box, runs harden.ps1 with that one switch, and
    proves the offender survived - plus a canary from another step (WDigest
    for most, SMB signing for the WDigest scenario itself) proving the rest
    reapplied.

    The closing act is the cleanup AND a free extra proof: one full
    harden.ps1 run must repair every planted offender in one pass - the
    reconcile-over-real-drift check, once per step.

    Exit code 0 = every scenario behaved.

.NOTES
    ASCII only (see harden.ps1). Run elevated, after harden.ps1 + verify.ps1.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Script:Failures = 0
function Pass { param([string]$m) Write-Host "  OK   $m" -ForegroundColor Green }
function Fail { param([string]$m) Write-Host "  FAIL $m" -ForegroundColor Red; $Script:Failures++ }

$HardenScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'harden.ps1'

# Small readers shared by plants and probes.
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function Get-AuditLogonValue {
    # The CSV backup is the only auditpol interface with a numeric column -
    # names and words are localized (the step 9 lesson).
    $csv = Join-Path $env:TEMP 'scenario-audit.csv'
    auditpol /backup /file:$csv | Out-Null
    $row = (Get-Content $csv | Select-String '0cce9215' | Select-Object -First 1).Line
    Remove-Item $csv -ErrorAction SilentlyContinue
    if ($row) { ($row -split ',')[-1] } else { $null }
}
function Get-MinPasswordLength {
    $line = (net accounts) | Select-String 'Minimum password length'
    if ($line -match '(\d+)\s*$') { [int]$Matches[1] } else { -1 }
}

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$dnsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$explorerPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

# One row per step: the switch, how to re-plant its offender on a hardened
# box, and the probe that must still see the offender after the skip.
$scenarios = @(
    @{ Switch = 'NoSmbSigning'
       Plant  = { Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force }
       Probe  = { -not (Get-SmbServerConfiguration).RequireSecuritySignature }
       Desc   = 'unsigned SMB survives' }
    @{ Switch = 'NoWDigest'
       Plant  = { New-ItemProperty -Path $wdigest -Name UseLogonCredential -Value 1 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $wdigest UseLogonCredential) -eq 1 }
       Desc   = 'cleartext credential caching survives' }
    @{ Switch = 'NoNameResolution'
       Plant  = { New-ItemProperty -Path $dnsPol -Name EnableMulticast -Value 1 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $dnsPol EnableMulticast) -eq 1 }
       Desc   = 'LLMNR stays enabled' }
    @{ Switch = 'NoNtlm'
       Plant  = { New-ItemProperty -Path $lsa -Name LmCompatibilityLevel -Value 1 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $lsa LmCompatibilityLevel) -eq 1 }
       Desc   = 'the weak NTLM level survives' }
    @{ Switch = 'NoFirewall'
       Plant  = { Set-NetFirewallProfile -Name Public -DefaultInboundAction NotConfigured }
       Probe  = { (Get-NetFirewallProfile -Name Public).DefaultInboundAction -ne 'Block' }
       Desc   = 'the unconfigured inbound policy survives' }
    @{ Switch = 'NoPowerShellLogging'
       Plant  = { New-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $sbl EnableScriptBlockLogging) -eq 0 }
       Desc   = 'script-block logging stays off' }
    @{ Switch = 'NoPasswordPolicy'
       Plant  = { $null = net accounts /minpwlen:0 }
       Probe  = { (Get-MinPasswordLength) -eq 0 }
       Desc   = 'the zero minimum password length survives' }
    @{ Switch = 'NoRdp'
       Plant  = { New-ItemProperty -Path $rdp -Name UserAuthentication -Value 0 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $rdp UserAuthentication) -eq 0 }
       Desc   = 'RDP without NLA survives' }
    @{ Switch = 'NoAuditPolicy'
       Plant  = { auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable | Out-Null }
       Probe  = { (Get-AuditLogonValue) -eq '0' }
       Desc   = 'the un-audited Logon subcategory survives' }
    @{ Switch = 'NoAutoRun'
       Plant  = { New-ItemProperty -Path $explorerPol -Name NoDriveTypeAutoRun -Value 0x91 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $explorerPol NoDriveTypeAutoRun) -eq 0x91 }
       Desc   = 'the weak 0x91 AutoRun mask survives' }
    @{ Switch = 'NoServiceSurface'
       Plant  = { foreach ($n in 'Spooler', 'RemoteRegistry') { Set-Service -Name $n -StartupType Automatic; Start-Service -Name $n } }
       Probe  = { (Get-Service Spooler).Status -eq 'Running' -and (Get-Service RemoteRegistry).Status -eq 'Running' }
       Desc   = 'both planted services stay running' }
    @{ Switch = 'NoNullSessions'
       Plant  = { New-ItemProperty -Path $lsa -Name RestrictAnonymous -Value 0 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $lsa RestrictAnonymous) -eq 0 }
       Desc   = 'anonymous enumeration survives' }
    # The policy pin goes first: policy wins over preference, so the
    # preference alone could not be planted back to 0 under it.
    @{ Switch = 'NoDefenderPua'
       Plant  = { Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' -Name MpEnablePus -ErrorAction SilentlyContinue; Set-MpPreference -PUAProtection 0 }
       Probe  = { [int](Get-MpPreference).PUAProtection -eq 0 }
       Desc   = 'PUA protection stays off' }
    # Planted in the registry: on an image with the SMB1 payload removed the
    # cmdlet cannot even enable the dialect ("The specified service does not
    # exist", measured), but the pin the step writes is a registry value.
    @{ Switch = 'NoSmb1'
       Plant  = { New-ItemProperty -Path $srv -Name SMB1 -Value 1 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue $srv SMB1) -eq 1 }
       Desc   = 'the planted SMB1 registry value survives' }
    @{ Switch = 'NoScriptHost'
       Plant  = { New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null }
       Probe  = { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' Enabled) -eq 1 }
       Desc   = 'Windows Script Host stays enabled' }
    # The policy pin is removed first so the shrink lands on a box that looks
    # unhardened for this step; the switch must then leave the 1 MB alone.
    # Application, not Security: the Security channel refuses to go below
    # 20 MB (measured on the runner), so a shrink there proves nothing.
    @{ Switch = 'NoEventLogSize'
       Plant  = { Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Recurse -Force -ErrorAction SilentlyContinue; & wevtutil.exe sl Application /ms:1052672 | Out-Null }
       Probe  = { [int64](Get-WinEvent -ListLog Application).MaximumSizeInBytes -lt (32768 * 1024) }
       Desc   = 'the shrunken Application log (1 MB) survives' }
    @{ Switch = 'NoFirewallLogging'
       Plant  = { Set-NetFirewallProfile -Name Public -LogBlocked False -LogAllowed False -LogMaxSizeKilobytes 4096 }
       Probe  = { "$((Get-NetFirewallProfile -Name Public).LogBlocked)" -eq 'False' }
       Desc   = 'the Public profile stays silent about dropped packets' }
    @{ Switch = 'NoSmbGuest'
       Plant  = { Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force }
       Probe  = { (Get-SmbClientConfiguration).EnableInsecureGuestLogons -eq $true }
       Desc   = 'the SMB client keeps accepting insecure guest logons' }
)

Write-Host ''
Write-Host '=== -No* switch scenarios (one per step) ===' -ForegroundColor White
foreach ($s in $scenarios) {
    Write-Host "-- -$($s.Switch) --" -ForegroundColor White
    & $s.Plant
    if (-not (& $s.Probe)) {
        Fail "-$($s.Switch): the offender could not even be planted"
        continue
    }
    $args = @{ Yes = $true; $($s.Switch) = $true }
    & $HardenScript @args | Out-Null
    if (& $s.Probe) { Pass "-$($s.Switch): $($s.Desc) (step skipped)" }
    else { Fail "-$($s.Switch): the skipped step still changed its knob" }
    # The rest of the baseline must still have applied. WDigest is the
    # canary for every scenario except its own, which uses SMB signing.
    if ($s.Switch -eq 'NoWDigest') {
        if ((Get-SmbServerConfiguration).RequireSecuritySignature) { Pass 'the rest still applied (SMB signing required)' }
        else { Fail 'the rest should still apply (SMB signing)' }
    } else {
        if ((Get-RegValue $wdigest UseLogonCredential) -eq 0) { Pass 'the rest still applied (WDigest stays 0)' }
        else { Fail 'the rest should still apply (WDigest)' }
    }
}

# Closing act: ONE full run must repair every planted offender - each step's
# reconcile proven against real drift, and the box leaves as hardened as it
# arrived.
Write-Host ''
Write-Host '=== full run repairs every planted offender ===' -ForegroundColor White
& $HardenScript -Yes | Out-Null
foreach ($s in $scenarios) {
    if (& $s.Probe) { Fail "the full run should have repaired -$($s.Switch)'s plant" }
    else { Pass "full run repaired -$($s.Switch)'s plant" }
}

Write-Host ''
if ($Script:Failures -gt 0) {
    Write-Host "$Script:Failures scenario check(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host 'All scenarios behaved' -ForegroundColor Green
# The exit code is this script's verdict, never whatever $LASTEXITCODE the
# last native command (net, auditpol) left behind - the step 9 lesson.
exit 0
