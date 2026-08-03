#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline security hardening for Windows Server / Windows 10-11.

.DESCRIPTION
    One idempotent script that applies a defensible baseline and reports
    exactly what it changed. Sibling of debian-hardening (Bash) and
    debian-hardening-ansible, same discipline on the other OS.

    Every step was designed against MEASURED behaviour on a real Windows
    Server 2025 box (see the probe evidence in README) - never assumptions.

    Steps:
      1. SMB signing (server and client): sign every SMB session so an
         attacker on the path cannot relay or tamper with it. The classic
         NTLM-relay enabler is an unsigned SMB session.
      2. WDigest credential caching: pin UseLogonCredential to 0 so LSASS
         stops keeping cleartext passwords in memory for a 2008-era
         protocol. This is the single line that turns a mimikatz dump from
         "here are the passwords" into "here are some hashes".
      3. Name-resolution poisoning (LLMNR + NetBIOS): both protocols
         broadcast "who is FILESRV?" to the whole segment and believe
         whoever answers first. That is what Responder answers. DNS does
         not need them.
      4. NTLM policy: refuse LM and NTLMv1 (LmCompatibilityLevel 5) and
         never store an LM hash. LM is brute-forceable in minutes.
      5. Firewall posture: all three profiles enabled with an explicit
         inbound DENY default (an unconfigured default is not a policy)
         and dropped-packet logging.
      6. PowerShell logging: script-block and module logging, so what an
         attacker runs in PowerShell lands in the event log even when it
         never touches disk. Fileless is only invisible without this.
      7. Password and lockout policy: minimum length, history and a
         lockout threshold with an observation window.

.PARAMETER DryRun
    Print what would change and change nothing.

.PARAMETER Yes
    Skip the confirmation prompt (for CI and unattended runs).

.EXAMPLE
    .\harden.ps1 -DryRun
    .\harden.ps1 -Yes
    .\harden.ps1 -NoFirewall -Yes

.NOTES
    ASCII ONLY, on purpose. Windows PowerShell 5.1 reads a .ps1 without a
    BOM as the system ANSI codepage, so a UTF-8 em dash or curly quote in a
    comment becomes mojibake and can break the PARSER - it cost this repo
    its very first CI run. The lint workflow fails on any non-ASCII byte.
#>
[CmdletBinding()]
param(
    [switch]$NoSmbSigning,
    [switch]$NoWDigest,
    [switch]$NoNameResolution,
    [switch]$NoNtlm,
    [switch]$NoFirewall,
    [switch]$NoPowerShellLogging,
    [switch]$NoPasswordPolicy,
    [switch]$DryRun,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# How many real changes this run made. The second pass of a correct run must
# report 0 - that is the idempotence contract the CI enforces.
$Script:ChangeCount = 0
# Steps that need a reboot before the kernel/LSA picks them up. Reported at
# the end instead of silently pretending the box is already there.
$Script:RebootNeeded = @()

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn2 { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Skip { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor DarkGray }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
    The workhorse. Reads the current value first and writes ONLY when it
    differs, so the change counter reports real work and a second pass is
    silent. Creating a missing key counts as a change; an absent value is
    not the same as a value that happens to match (an absent LLMNR setting
    means LLMNR is ON).
#>
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String', 'MultiString', 'QWord')][string]$Type = 'DWord',
        [string]$Because = ''
    )
    $current = $null
    $present = $false
    if (Test-Path -LiteralPath $Path) {
        try {
            $current = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
            $present = $true
        } catch { $present = $false }
    }
    $label = "$Path\$Name"
    if ($present -and $current -eq $Value) {
        Write-Ok "$label already $Value"
        return $false
    }
    $was = if ($present) { $current } else { '<absent>' }
    if ($DryRun) {
        Write-Warn2 "(dry-run) would set $label = $Value (currently $was)"
        return $false
    }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    $Script:ChangeCount++
    $why = if ($Because) { " ($Because)" } else { '' }
    Write-Warn2 "set $label = $Value, was $was$why"
    return $true
}

# ---- Step 1: SMB signing ---------------------------------------------------

function Set-SmbSigning {
    if ($NoSmbSigning) { Write-Skip 'Skipping SMB signing'; return }
    Write-Step 'Requiring SMB signing (server and client)'
    # An unsigned SMB session can be relayed: the attacker sits in the middle,
    # forwards the victim's NTLM authentication to a third host and lands a
    # session there. Signing makes the tampering detectable, which is why
    # every relay tutorial starts by checking whether signing is required.
    # Measured on the runner: RequireSecuritySignature was False out of the
    # box, so this step does real work rather than confirming a default.
    $cfg = Get-SmbServerConfiguration
    if ($cfg.RequireSecuritySignature -and $cfg.EnableSecuritySignature) {
        Write-Ok 'SMB server already requires signing'
    } elseif ($DryRun) {
        Write-Warn2 "(dry-run) would require SMB server signing (currently Require=$($cfg.RequireSecuritySignature))"
    } else {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true `
            -Confirm:$false -Force
        $Script:ChangeCount++
        Write-Warn2 "SMB server now requires signing, was Require=$($cfg.RequireSecuritySignature)"
    }
    # The client half, so this machine also refuses to speak unsigned to a
    # server that would happily skip it.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Name 'RequireSecuritySignature' -Value 1 -Because 'client refuses unsigned SMB' | Out-Null
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Name 'EnableSecuritySignature' -Value 1 | Out-Null
    Write-Ok 'SMB sessions are signed in both directions'
}

# ---- Step 2: WDigest credential caching ------------------------------------

function Disable-WDigestCaching {
    if ($NoWDigest) { Write-Skip 'Skipping WDigest hardening'; return }
    Write-Step 'Stopping WDigest from caching cleartext credentials'
    # WDigest is a 2008-era authentication protocol that needs the password
    # in the clear, so LSASS keeps it in memory for every logged-on user.
    # Windows 8.1+ defaults to off, but the value is ABSENT on a fresh box
    # (measured) - and absent means "whatever this build decided", which a
    # GPO, an upgrade or an application can flip back. Pinning 0 makes the
    # answer explicit and auditable.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -Value 0 -Because 'no cleartext passwords in LSASS' | Out-Null
    Write-Ok 'WDigest will not hand out cleartext passwords'
}

# ---- Step 3: name-resolution poisoning (LLMNR + NetBIOS) -------------------

function Disable-NameResolutionPoisoning {
    if ($NoNameResolution) { Write-Skip 'Skipping LLMNR/NetBIOS hardening'; return }
    Write-Step 'Disabling LLMNR and NetBIOS name resolution'
    # Both protocols shout "who is FILESRV?" at the whole broadcast domain
    # and trust whoever answers first. Responder answers first, collects the
    # NTLM exchange and either cracks it offline or relays it. DNS does not
    # need either protocol; on a domain network nothing legitimate does.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name 'EnableMulticast' -Value 0 -Because 'LLMNR off' | Out-Null

    # NetBIOS is per interface: NetbiosOptions 0 = "use the DHCP setting"
    # (i.e. usually ON), 1 = enabled, 2 = disabled. All five interfaces on
    # the runner shipped 0, so this loop does real work.
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    if (Test-Path -LiteralPath $base) {
        $touched = 0
        foreach ($iface in Get-ChildItem -LiteralPath $base) {
            if (Set-RegistryValue -Path $iface.PSPath -Name 'NetbiosOptions' -Value 2 `
                    -Because "NetBIOS off on $($iface.PSChildName)") { $touched++ }
        }
        if ($touched -gt 0) {
            $Script:RebootNeeded += 'NetBIOS over TCP/IP (per-interface setting)'
        }
    } else {
        Write-Warn2 'no NetBT interfaces found - nothing to disable'
    }
    Write-Ok 'Nothing on this host answers LLMNR or NetBIOS name queries'
}

# ---- Step 4: NTLM policy ---------------------------------------------------

function Set-NtlmPolicy {
    if ($NoNtlm) { Write-Skip 'Skipping NTLM policy'; return }
    Write-Step 'Refusing LM and NTLMv1 authentication'
    # LmCompatibilityLevel 5 = send NTLMv2 only, refuse LM and NTLMv1. LM
    # hashes fall to brute force in minutes (no salt, uppercased, split into
    # two 7-byte halves); NTLMv1 is trivially relayable. The value was
    # ABSENT on the runner, so the effective level was whatever the build
    # defaults to - explicit beats inherited.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LmCompatibilityLevel' -Value 5 -Because 'NTLMv2 only' | Out-Null
    if (Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'NoLMHash' -Value 1 -Because 'never store an LM hash') {
        $Script:RebootNeeded += 'NoLMHash (existing hashes clear at next password change)'
    }
    Write-Ok 'Only NTLMv2 is accepted, and no LM hash is stored'
}

# ---- Step 5: firewall posture ----------------------------------------------

function Set-FirewallPosture {
    if ($NoFirewall) { Write-Skip 'Skipping firewall posture'; return }
    Write-Step 'Enabling all firewall profiles with an explicit inbound deny'
    # Measured: all three profiles were enabled but their default inbound
    # action was NotConfigured. "Not configured" is not a policy - it means
    # the answer comes from somewhere else and can change without anyone
    # editing this machine. An explicit Block is a decision.
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $p = Get-NetFirewallProfile -Name $profileName
        $wantEnabled = $true
        $needsChange = ($p.Enabled -ne $wantEnabled) -or ($p.DefaultInboundAction -ne 'Block')
        if (-not $needsChange) {
            Write-Ok "$profileName profile already enabled with inbound Block"
            continue
        }
        if ($DryRun) {
            Write-Warn2 "(dry-run) would set $profileName to enabled + inbound Block (currently Enabled=$($p.Enabled), Inbound=$($p.DefaultInboundAction))"
            continue
        }
        Set-NetFirewallProfile -Name $profileName -Enabled True -DefaultInboundAction Block `
            -DefaultOutboundAction Allow -LogBlocked True -NotifyOnListen False
        $Script:ChangeCount++
        Write-Warn2 "$profileName profile set to enabled + inbound Block, was Enabled=$($p.Enabled), Inbound=$($p.DefaultInboundAction)"
    }
    Write-Ok 'Unsolicited inbound traffic is denied by policy on every profile'
}

# ---- Step 6: PowerShell logging --------------------------------------------

function Enable-PowerShellLogging {
    if ($NoPowerShellLogging) { Write-Skip 'Skipping PowerShell logging'; return }
    Write-Step 'Enabling PowerShell script-block and module logging'
    # An attacker's PowerShell never has to touch disk: it arrives over the
    # network and runs from memory, so file-based forensics find nothing.
    # Script-block logging records the code itself (event 4104) as the engine
    # compiles it - after any decoding or de-obfuscation. Both keys were
    # ABSENT on the runner: no logging at all.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -Value 1 -Because 'record what PowerShell runs' | Out-Null
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -Name 'EnableModuleLogging' -Value 1 | Out-Null
    # Module logging only means anything with a module list; * covers all.
    $modNames = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    Set-RegistryValue -Path $modNames -Name '*' -Value '*' -Type String | Out-Null
    Write-Ok 'What runs in PowerShell is recorded, even when it never hits disk'
}

# ---- Step 7: password and lockout policy -----------------------------------

function Set-PasswordPolicy {
    if ($NoPasswordPolicy) { Write-Skip 'Skipping password/lockout policy'; return }
    Write-Step 'Setting local password and lockout policy'
    # Measured on the runner: MinimumPasswordLength 0 and PasswordHistorySize
    # 0 - a local account could literally have no password and reuse it
    # forever. net.exe is used rather than secedit for the knobs it covers:
    # it is idempotent by nature (setting a value that already holds changes
    # nothing) and its output is what an auditor reads back.
    $want = @{
        MinPwLen      = 14   # CIS: 14 characters
        MaxPwAge      = 365
        MinPwAge      = 1
        UniquePw      = 24   # password history
        LockoutThresh = 5
        LockoutWindow = 15
        LockoutDur    = 15
    }
    $current = @{}
    (net accounts) | ForEach-Object {
        if ($_ -match 'Minimum password length:\s+(\d+)') { $current.MinPwLen = [int]$Matches[1] }
        elseif ($_ -match 'Maximum password age \(days\):\s+(\S+)') { $current.MaxPwAge = $Matches[1] }
        elseif ($_ -match 'Minimum password age \(days\):\s+(\d+)') { $current.MinPwAge = [int]$Matches[1] }
        elseif ($_ -match 'Length of password history maintained:\s+(\S+)') { $current.UniquePw = $Matches[1] }
        elseif ($_ -match 'Lockout threshold:\s+(\S+)') { $current.LockoutThresh = $Matches[1] }
    }
    $needed = ($current.MinPwLen -ne $want.MinPwLen) -or
              ("$($current.UniquePw)" -ne "$($want.UniquePw)") -or
              ("$($current.LockoutThresh)" -ne "$($want.LockoutThresh)") -or
              ($current.MinPwAge -ne $want.MinPwAge)
    if (-not $needed) {
        Write-Ok "password policy already at length $($want.MinPwLen), history $($want.UniquePw), lockout $($want.LockoutThresh)"
        return
    }
    if ($DryRun) {
        Write-Warn2 "(dry-run) would set minimum length $($want.MinPwLen) (currently $($current.MinPwLen)), history $($want.UniquePw) (currently $($current.UniquePw)), lockout $($want.LockoutThresh) (currently $($current.LockoutThresh))"
        return
    }
    # Lockout duration must be set together with the window, and the window
    # cannot exceed the duration - net.exe rejects the pair otherwise.
    $null = net accounts /minpwlen:$($want.MinPwLen) /maxpwage:$($want.MaxPwAge) /minpwage:$($want.MinPwAge) /uniquepw:$($want.UniquePw)
    $null = net accounts /lockoutthreshold:$($want.LockoutThresh) /lockoutwindow:$($want.LockoutWindow) /lockoutduration:$($want.LockoutDur)
    $Script:ChangeCount++
    Write-Warn2 "password policy set: length $($want.MinPwLen), history $($want.UniquePw), lockout $($want.LockoutThresh) in $($want.LockoutWindow) min"
    Write-Ok 'Local accounts need a real password, and brute force gets locked out'
}

# ---- Main ------------------------------------------------------------------

function Invoke-Main {
    if (-not (Test-Elevated)) {
        throw 'This script must run elevated (Run as Administrator).'
    }
    Write-Host ''
    Write-Host '=== Windows baseline hardening ===' -ForegroundColor White
    Write-Host 'About to apply:'
    if (-not $NoSmbSigning) { Write-Host '    - SMB signing required (server and client)' }
    if (-not $NoWDigest) { Write-Host '    - WDigest cleartext credential caching off' }
    if (-not $NoNameResolution) { Write-Host '    - LLMNR and NetBIOS name resolution off' }
    if (-not $NoNtlm) { Write-Host '    - NTLMv2 only, no LM hash' }
    if (-not $NoFirewall) { Write-Host '    - all firewall profiles on, inbound denied by default' }
    if (-not $NoPowerShellLogging) { Write-Host '    - PowerShell script-block and module logging' }
    if (-not $NoPasswordPolicy) { Write-Host '    - password length/history and account lockout' }
    if ($DryRun) { Write-Warn2 'DRY-RUN: nothing will be changed.' }
    if (-not $Yes -and -not $DryRun) {
        $answer = Read-Host 'Proceed? [y/N]'
        if ($answer -notmatch '^[yY]') { Write-Warn2 'Aborted.'; return }
    }
    Write-Host ''

    Set-SmbSigning
    Disable-WDigestCaching
    Disable-NameResolutionPoisoning
    Set-NtlmPolicy
    Set-FirewallPosture
    Enable-PowerShellLogging
    Set-PasswordPolicy

    Write-Host ''
    # Write-OUTPUT, not Write-Host: this line is the script's machine-readable
    # contract (the CI asserts "Changes applied: 0" on the second pass) and
    # Write-Host does NOT go to the pipeline - it writes straight to the host,
    # so a caller doing `$out = .\harden.ps1` would capture nothing. That
    # exact mistake failed this repo's first e2e run while the script was
    # perfectly idempotent: the cousin of "capture the real rc, not the pipe's".
    Write-Output "Changes applied: $Script:ChangeCount"
    if ($Script:RebootNeeded.Count -gt 0) {
        Write-Warn2 'A reboot is needed before these take full effect:'
        foreach ($r in ($Script:RebootNeeded | Select-Object -Unique)) { Write-Host "      - $r" }
    }
    Write-Ok 'Done. Verify with: .\test\verify.ps1   Score with: .\test\audit.ps1'
}

# Dot-sourcing the script (". .\harden.ps1") loads the functions WITHOUT
# running Main, which is what the unit tests do - the same guard the Bash
# sibling gets from its BASH_SOURCE check.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
