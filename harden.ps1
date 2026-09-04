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
      8. RDP posture: require NLA (authenticate BEFORE a session exists),
         force TLS for the transport and high encryption. Whether RDP is
         reachable at all is a business decision this script does not make;
         when it is, the session must be safe.
      9. Advanced audit policy: logons (success AND failure), process
         creation with the full command line, and changes to the audit
         policy itself. Steps 1-8 shrink the attack surface; this one makes
         whatever still happens VISIBLE. Detection, not prevention.
     10. AutoRun/AutoPlay off: no drive type gets to run code by being
         plugged in or inserted. NoDriveTypeAutoRun 0xFF, autorun.inf never
         processed, no autoplay for non-volume devices. The USB-stick
         attack is older than most of this list and still works wherever
         these three values are left at their defaults.
     11. Attack-surface services: Print Spooler (the PrintNightmare class,
         running as SYSTEM) and RemoteRegistry (reconnaissance as a
         service) stopped AND disabled - either alone leaks.
     12. Null sessions: the anonymous SMB logon that hands over the map
         before any credential is touched - user list, share list,
         password policy. RestrictAnonymous family pinned, the anonymous
         token stripped of Everyone, and the server's null-session
         exception lists (pipes/shares) emptied.
     13. Defender PUA protection: potentially unwanted applications -
         adware, bundlers, coin miners, "optimizers" - are not malware on
         paper and are the most common way a box picks up code that runs
         with real rights. Defender does NOT block them by default on
         Server. Pinned as machine policy (MpEnablePus=1, what Group
         Policy writes - survives a preference reset) AND applied live via
         Set-MpPreference, so the effective value flips now.
     14. SMBv1 off: the 1980s dialect behind EternalBlue / WannaCry /
         NotPetya - no real signing, no encryption, a parser the world
         spent 2017 patching. Three doors: the server dialect
         (EnableSMB1Protocol), the client redirector (the mrxsmb10
         driver) and the optional feature itself, each skipped (not
         failed) when Windows says it is not there.
     15. Windows Script Host off: wscript/cscript, the engine behind the
         .vbs/.js/.wsf attachment that has opened more phishing chains
         than any macro. Machine-wide Enabled=0 under Windows Script
         Host\Settings; a server has no business running scripts from
         a mail client, and admin automation lives in PowerShell.

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
    [switch]$NoRdp,
    [switch]$NoAuditPolicy,
    [switch]$NoAutoRun,
    [switch]$NoServiceSurface,
    [switch]$NoNullSessions,
    [switch]$NoDefenderPua,
    [switch]$NoSmb1,
    [switch]$NoScriptHost,
    [switch]$NoEventLogSize,
    [switch]$NoFirewallLogging,
    [switch]$NoSmbGuest,
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
        # Logging is step 17's business (per profile, dropped + allowed, 16 MB).
        Set-NetFirewallProfile -Name $profileName -Enabled True -DefaultInboundAction Block `
            -DefaultOutboundAction Allow -NotifyOnListen False
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

# ---- Step 8: RDP posture ----------------------------------------------------

function Set-RdpPosture {
    if ($NoRdp) { Write-Skip 'Skipping RDP posture'; return }
    Write-Step 'Hardening RDP: NLA required, TLS transport, high encryption'
    # Whether RDP should be reachable at all is a business decision this
    # baseline does not make - fDenyTSConnections is left alone. What it does
    # decide: WHEN the port answers, the session must be safe. Three knobs:
    #   UserAuthentication = 1 (NLA): the client authenticates BEFORE any
    #     session or logon screen is created. Without it, anyone who can
    #     reach 3389 talks to the pre-auth attack surface - the BlueKeep
    #     class of bugs lived exactly there, and so does username-less
    #     credential guessing against the logon UI.
    #   SecurityLayer = 2: TLS required for the transport. 0 is legacy RDP
    #     crypto and 1 means "negotiate", which is an invitation to settle
    #     for whatever the client prefers.
    #   MinEncryptionLevel = 3: High (128-bit both directions). Below it,
    #     "client compatible" accepts what the client offers.
    $rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Set-RegistryValue -Path $rdp -Name 'UserAuthentication' -Value 1 `
        -Because 'NLA: authenticate before a session exists' | Out-Null
    Set-RegistryValue -Path $rdp -Name 'SecurityLayer' -Value 2 `
        -Because 'TLS, never legacy RDP crypto' | Out-Null
    Set-RegistryValue -Path $rdp -Name 'MinEncryptionLevel' -Value 3 `
        -Because '128-bit in both directions' | Out-Null
    Write-Ok 'If RDP answers, it demands NLA over TLS with high encryption'
}

# ---- Step 9: advanced audit policy ------------------------------------------

<#
    auditpol has no locale-proof READ. Its /get output prints the setting as
    WORDS, and the words are localized: "Success and Failure" on this runner
    is "Aciertos y errores" on a Spanish box, so any script parsing them
    breaks the moment it leaves en-US. The backup CSV is the one interface
    that carries a NUMERIC Setting Value column instead (0 = no auditing,
    1 = success, 2 = failure, 3 = both) - so that is what gets read.
#>
function Get-AuditSettingValue {
    param([Parameter(Mandatory)][string]$Guid)
    $csv = Join-Path $env:TEMP ('wh-auditpol-' + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        $null = auditpol /backup /file:"$csv"
        if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (rc $LASTEXITCODE)" }
        foreach ($line in Get-Content -LiteralPath $csv) {
            $cols = $line -split ','
            if ($cols.Count -ge 7 -and $cols[3] -eq $Guid) { return [int]$cols[6] }
        }
        throw "subcategory $Guid not found in the auditpol backup"
    } finally {
        Remove-Item -LiteralPath $csv -ErrorAction SilentlyContinue
    }
}

function Set-AuditPolicy {
    if ($NoAuditPolicy) { Write-Skip 'Skipping audit policy'; return }
    Write-Step 'Enabling the audit trail: logons, process creation, policy changes'
    # Subcategories are addressed by GUID and never by name, for the same
    # locale reason as the read side: auditpol localizes the NAMES too, so
    # /subcategory:"Logon" works on an en-US box and fails on a Spanish one.
    # The GUIDs are the same everywhere.
    $subcats = @(
        @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Label = 'Logon'
           Mask = 3; Flags = @('/success:enable', '/failure:enable')
           Because = '4624/4625: who got in and who tried' }
        @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Label = 'Process Creation'
           Mask = 1; Flags = @('/success:enable')
           Because = '4688: every process that starts' }
        @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Label = 'Audit Policy Change'
           Mask = 1; Flags = @('/success:enable')
           Because = '4719: the log records who turns the log off' }
    )
    foreach ($sc in $subcats) {
        $current = Get-AuditSettingValue -Guid $sc.Guid
        # A bitmask test, not equality: a box already auditing MORE than the
        # target (failure on top of success, say) is compliant, and knocking
        # it down to the target would be the opposite of hardening.
        if (($current -band $sc.Mask) -eq $sc.Mask) {
            Write-Ok "$($sc.Label) auditing already on (Setting Value $current)"
            continue
        }
        if ($DryRun) {
            Write-Warn2 "(dry-run) would enable $($sc.Label) auditing (currently $current)"
            continue
        }
        $null = auditpol /set /subcategory:"$($sc.Guid)" $sc.Flags
        if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed for $($sc.Label) (rc $LASTEXITCODE)" }
        $Script:ChangeCount++
        Write-Warn2 "$($sc.Label) auditing enabled, was $current ($($sc.Because))"
    }
    # A 4688 without the command line names the actor but not the act: the
    # event says "powershell.exe started" and omits the -EncodedCommand that
    # mattered. One registry value adds the arguments to the event.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 `
        -Because 'event 4688 carries the full command line' | Out-Null
    # Without this, the legacy 9-category policy silently overrides the
    # subcategories above the moment a GPO or secedit template touches it.
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 `
        -Because 'subcategory settings win over legacy categories' | Out-Null
    Write-Ok 'Logons, new processes and audit-policy changes now leave a record'
}

# ---- Step 10: AutoRun / AutoPlay ---------------------------------------------

function Disable-AutoRun {
    if ($NoAutoRun) { Write-Skip 'Skipping AutoRun/AutoPlay hardening'; return }
    Write-Step 'Disabling AutoRun and AutoPlay for every drive type'
    # The oldest trick on this list and still alive: plug in a prepared USB
    # stick (or mount an ISO/network share) and let the OS offer to run what
    # is on it. Three machine-level policy values close the whole family:
    #   NoDriveTypeAutoRun 0xFF: bit per drive type, all eight set - no
    #     drive type (removable, fixed, network, CD, RAM disk, unknown)
    #     gets autorun. The OS default leaves several bits clear.
    #   NoAutorun 1: autorun.inf is never parsed at all - the file that
    #     turned every shared USB stick of the Conficker era into a dropper.
    #   NoAutoplayfornonVolume 1: no autoplay for non-volume devices (MTP
    #     phones, cameras) - the modern edge the two classics miss.
    $explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-RegistryValue -Path $explorer -Name 'NoDriveTypeAutoRun' -Value 255 `
        -Because 'no drive type runs code on insertion' | Out-Null
    Set-RegistryValue -Path $explorer -Name 'NoAutorun' -Value 1 `
        -Because 'autorun.inf is never processed' | Out-Null
    Set-RegistryValue -Path $explorer -Name 'NoAutoplayfornonVolume' -Value 1 `
        -Because 'no autoplay for MTP/camera-class devices' | Out-Null
    Write-Ok 'Nothing runs just because it was plugged in'
}

# ---- Step 11: attack-surface services ----------------------------------------

function Disable-AttackSurfaceServices {
    if ($NoServiceSurface) { Write-Skip 'Skipping attack-surface services'; return }
    Write-Step 'Stopping and disabling attack-surface services (Spooler, RemoteRegistry)'
    # Two services whose job description IS the attack story:
    #   Spooler: the Print Spooler runs as SYSTEM, accepts driver packages
    #     from callers, and gave the world PrintNightmare (CVE-2021-34527) -
    #     remote code execution as SYSTEM on any box with the service up. A
    #     server that never prints runs it anyway, because it ships enabled.
    #   RemoteRegistry: hands a remote caller this machine's registry -
    #     reconnaissance as a service. A hardened baseline has WinRM and
    #     PowerShell for administration; nothing needs this one.
    # Stopped AND disabled, because either alone leaks: a stopped service
    # with StartType Automatic comes back at the next boot, and a disabled
    # one that is still running keeps serving until then.
    foreach ($svcName in 'Spooler', 'RemoteRegistry') {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Skip "$svcName is not installed here - nothing to disable"
            continue
        }
        if ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled') {
            Write-Ok "$svcName already stopped and disabled"
            continue
        }
        if ($DryRun) {
            Write-Warn2 "(dry-run) would stop and disable $svcName (currently $($svc.Status)/$($svc.StartType))"
            continue
        }
        $was = "$($svc.Status)/$($svc.StartType)"
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $svcName -Force }
        if ($svc.StartType -ne 'Disabled') { Set-Service -Name $svcName -StartupType Disabled }
        $Script:ChangeCount++
        Write-Warn2 "$svcName stopped and disabled, was $was"
    }
    Write-Ok 'Nobody exploits a service that is not running - and this one cannot even be started'
}

# ---- Step 12: null sessions (anonymous enumeration) --------------------------

function Disable-NullSessions {
    if ($NoNullSessions) { Write-Skip 'Skipping null-session lockdown'; return }
    Write-Step 'Locking down null sessions (anonymous enumeration)'
    # A null session is an SMB logon with an EMPTY username and password -
    # NT-era plumbing that attack tooling still tries first, because where it
    # answers it hands over the whole map before any credential is touched:
    # the user list, the share list, the password policy. enum4linux's
    # opening move, and the reason RID cycling exists. Four values, because
    # each one guards a DIFFERENT door:
    #   RestrictAnonymousSAM = 1: anonymous callers cannot enumerate SAM
    #     accounts (the user list - the input every password spray needs).
    #   RestrictAnonymous = 1: anonymous callers cannot enumerate shares
    #     either. NOT 2: that NT-era value breaks trust and cluster
    #     scenarios, which is why every guide since has said 1.
    #   EveryoneIncludesAnonymous = 0: the anonymous token does not carry
    #     the Everyone group - every ACL granting Everyone stops covering
    #     the caller with no name.
    #   RestrictNullSessAccess = 1 (server side): a null session reaches
    #     only the pipes and shares EXPLICITLY listed as exceptions...
    # ...and the exception lists themselves are emptied, because
    # NullSessionPipes shipping legacy entries (browser, netlogon) is
    # exactly how a "restricted" box still answers anonymous callers.
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Set-RegistryValue -Path $lsa -Name 'RestrictAnonymousSAM' -Value 1 `
        -Because 'no anonymous SAM account enumeration' | Out-Null
    Set-RegistryValue -Path $lsa -Name 'RestrictAnonymous' -Value 1 `
        -Because 'no anonymous share enumeration' | Out-Null
    Set-RegistryValue -Path $lsa -Name 'EveryoneIncludesAnonymous' -Value 0 `
        -Because 'anonymous is nobody, not Everyone' | Out-Null
    Set-RegistryValue -Path $srv -Name 'RestrictNullSessAccess' -Value 1 `
        -Because 'null sessions reach only listed exceptions' | Out-Null
    # The exception lists are MultiString and Set-RegistryValue compares
    # scalars, so they are handled here: present-and-empty is the goal state,
    # anything else (legacy entries, or the value absent) gets pinned to the
    # empty list - absent only means "this build's default", and a default is
    # not a decision (the WDigest argument, applied to a list).
    foreach ($listName in 'NullSessionPipes', 'NullSessionShares') {
        $present = $false
        $entries = @()
        try {
            $raw = (Get-ItemProperty -LiteralPath $srv -Name $listName -ErrorAction Stop).$listName
            $present = $true
            $entries = @($raw | Where-Object { $_ })
        } catch { $present = $false }
        if ($present -and $entries.Count -eq 0) {
            Write-Ok "$listName already empty"
            continue
        }
        $was = if (-not $present) { '<absent>' } else { $entries -join ', ' }
        if ($DryRun) {
            Write-Warn2 "(dry-run) would empty $listName (currently $was)"
            continue
        }
        New-ItemProperty -LiteralPath $srv -Name $listName -Value ([string[]]@()) `
            -PropertyType MultiString -Force | Out-Null
        $Script:ChangeCount++
        Write-Warn2 "$listName pinned to the empty list, was $was"
    }
    Write-Ok 'The machine no longer answers questions from a caller with no name'
}

# ---- Step 13: Defender PUA protection ---------------------------------------

function Enable-DefenderPua {
    if ($NoDefenderPua) { Write-Skip 'Skipping Defender PUA protection'; return }
    Write-Step 'Blocking potentially unwanted applications (Defender PUA)'
    # PUA is the class Defender does NOT block by default on Windows Server:
    # adware, bundlers, coin miners, "optimizers" - not malware on paper, and
    # the most common way a box picks up code that runs with the user's (or
    # an installer's SYSTEM) rights. Two layers, on purpose:
    #   - the machine POLICY value (MpEnablePus under Policies\Microsoft\
    #     Windows Defender\MpEngine - what Group Policy writes): policy wins
    #     over the local preference and survives a Set-MpPreference reset;
    #   - the live PREFERENCE (Set-MpPreference -PUAProtection 1): the engine
    #     picks policy up on its own schedule, the preference flips the
    #     effective value NOW - and it is what Get-MpPreference reports, i.e.
    #     what verify and audit read.
    # 1 = Block. 2 = Audit only logs - the "we have a control" that changes
    # nothing. No Defender (a third-party AV owns the box) is a WARN, not a
    # failure: the policy value still lands for the day Defender is back.
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    Set-RegistryValue -Path $policy -Name 'MpEnablePus' -Value 1 `
        -Because 'PUA blocked by machine policy (survives preference resets)' | Out-Null
    try {
        $current = [int](Get-MpPreference -ErrorAction Stop).PUAProtection
    } catch {
        Write-Warn2 'Defender preferences unavailable (no Defender, or another AV owns the box) - policy written, live preference skipped'
        return
    }
    if ($current -eq 1) {
        Write-Ok 'Defender PUAProtection already 1 (Block)'
    } elseif ($DryRun) {
        Write-Warn2 "(dry-run) would set Defender PUAProtection = 1 (currently $current)"
    } else {
        try {
            Set-MpPreference -PUAProtection 1 -ErrorAction Stop
            $Script:ChangeCount++
            Write-Warn2 "set Defender PUAProtection = 1 (Block), was $current"
        } catch {
            Write-Warn2 "Set-MpPreference failed ($($_.Exception.Message.Trim())) - the policy value is written and the engine applies it on its next policy refresh"
        }
    }
    Write-Ok 'Adware, bundlers and miners are blocked, not just noticed'
}

# ---- Step 14: SMBv1 off -----------------------------------------------------

function Disable-Smb1 {
    if ($NoSmb1) { Write-Skip 'Skipping SMBv1 removal'; return }
    Write-Step 'Turning SMBv1 off (server dialect, client driver, optional feature)'
    # SMBv1 is the 1980s dialect behind EternalBlue, WannaCry and NotPetya:
    # no signing worth the name, no encryption, and a parser the world spent
    # 2017 patching. Nothing built this decade needs it; the clients that do
    # are the ones that should not be on the network. Three doors:
    #   - the SERVER dialect: LanmanServer\Parameters\SMB1 pinned to 0 (the
    #     registry method, works on every build) and read back through
    #     Get-SmbServerConfiguration - the effective config, the "sshd -T"
    #     of SMB. The CI plants the registry value to 1 so this step provably
    #     shuts a door instead of confirming a default;
    #   - the CLIENT redirector: the mrxsmb10 driver, so this box never
    #     speaks SMB1 outbound either (a downgrade attack needs a willing
    #     client). LanmanWorkstation lists it as a dependency, so that list
    #     is rewritten to the SMB2 driver alone - Microsoft's own procedure;
    #   - the optional FEATURE (SMB1Protocol), removed so neither can come
    #     back - a reboot may be needed to finish that removal.
    # Each door is skipped, not failed, when Windows says it is not there.
    # The registry pin is the method Microsoft documents for every build,
    # and the one that works whether or not the SMB1 payload is installed:
    # MEASURED on the CI image (SMB1 DisabledWithPayloadRemoved),
    # Set-SmbServerConfiguration -EnableSMB1Protocol fails with "The specified
    # service does not exist" in EITHER direction, because the SMB1 server
    # driver it toggles is not there. So: pin the value (a default is not a
    # decision), and use the cmdlet only as the LIVE toggle where the dialect
    # is currently negotiable.
    $srvParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Set-RegistryValue -Path $srvParams -Name 'SMB1' -Value 0 `
        -Because 'the server never negotiates the SMB1 dialect (pinned, payload or not)' | Out-Null
    $cfg = Get-SmbServerConfiguration
    if (-not $cfg.EnableSMB1Protocol) {
        Write-Ok 'SMB server refuses the SMB1 dialect (effective config)'
    } elseif ($DryRun) {
        Write-Warn2 '(dry-run) would disable the SMB1 dialect live (currently negotiable)'
    } else {
        try {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -Force -ErrorAction Stop
            $Script:ChangeCount++
            Write-Warn2 'SMB server no longer speaks SMB1, was negotiable'
        } catch {
            $Script:RebootNeeded += 'SMB1 server dialect (registry pin applies at the next LanmanServer start)'
            Write-Warn2 "live toggle unavailable ($($_.Exception.Message.Trim())) - the registry pin takes effect at the next LanmanServer start"
        }
    }
    $client = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue
    if ($null -eq $client) {
        Write-Ok 'SMB1 client driver (mrxsmb10) is not present'
    } elseif ($client.StartType -eq 'Disabled') {
        Write-Ok 'SMB1 client driver (mrxsmb10) already disabled'
    } elseif ($DryRun) {
        Write-Warn2 "(dry-run) would disable the SMB1 client driver mrxsmb10 (currently $($client.StartType))"
    } else {
        Set-Service -Name mrxsmb10 -StartupType Disabled
        & sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null
        $Script:ChangeCount++
        $Script:RebootNeeded += 'SMB1 client driver (mrxsmb10) disabled'
        Write-Warn2 "SMB1 client driver mrxsmb10 disabled, was $($client.StartType)"
    }
    $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($null -eq $feature -or "$($feature.State)" -like 'Disabled*') {
        Write-Ok "SMB1Protocol optional feature is not installed ($(if ($feature) { $feature.State } else { 'absent' }))"
    } elseif ($DryRun) {
        Write-Warn2 "(dry-run) would remove the SMB1Protocol optional feature (currently $($feature.State))"
    } else {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -WarningAction SilentlyContinue | Out-Null
        $Script:ChangeCount++
        $Script:RebootNeeded += 'SMB1Protocol optional feature removed'
        Write-Warn2 "SMB1Protocol optional feature removed, was $($feature.State)"
    }
    Write-Ok 'The 2017 attack surface is closed: this box neither serves nor speaks SMB1'
}

# ---- Step 15: Windows Script Host off ---------------------------------------

function Disable-ScriptHost {
    if ($NoScriptHost) { Write-Skip 'Skipping Windows Script Host removal'; return }
    Write-Step 'Turning Windows Script Host off (wscript / cscript)'
    # WSH is the engine behind .vbs, .js, .jse, .wsf and .wsh files - the
    # attachment that has opened more phishing chains than any Office macro,
    # because double-clicking it just RUNS. On a server there is no mail
    # client and no user double-clicking anything legitimate; admin automation
    # lives in PowerShell (which steps 6 and 9 already log). One machine-wide
    # value: HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0.
    # Absent means enabled (the default), so this is a real change everywhere.
    # Behavioural proof in verify: a fresh cscript.exe on a one-line .vbs must
    # refuse with "Windows Script Host access is disabled on this machine".
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' `
        -Name 'Enabled' -Value 0 -Because 'no .vbs/.js/.wsf runs on this box' | Out-Null
    Write-Ok 'The double-click-and-it-runs attachment has nothing to run in'
}

# ---- Step 16: event log capacity --------------------------------------------

function Set-EventLogCapacity {
    if ($NoEventLogSize) { Write-Skip 'Skipping event log capacity'; return }
    Write-Step 'Sizing the event logs so the evidence survives (Security 192 MB, System/Application 32 MB)'
    # Step 9 switched the events ON (4624/4625 logons, 4688 process creation
    # with its command line, 4719 audit-policy changes). This step makes sure
    # they are still THERE when someone needs them. Windows ships every log at
    # 20 MB, circular: a 4625 is about 1 KB, so a password spray at a modest
    # 50 attempts a second wraps the Security log in roughly seven minutes -
    # and the 4719 that recorded who switched auditing off goes with it.
    # CIS 18.10.25.x: Security 196608 KB (192 MB), Application and System
    # 32768 KB. Two layers, the audit-policy pattern: the POLICY value
    # (HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\<Log>\MaxSize, in KB)
    # so the size survives anyone "fixing" it in Event Viewer, and the LIVE
    # channel (wevtutil sl /ms:) so it applies now, not at the next service
    # start. Never shrinks: a log an admin made bigger stays bigger. Retention
    # stays circular (overwrite as needed) - "do not overwrite" stops logging
    # when full, which is exactly the outage an attacker would order.
    # Measured on the CI runner: the Security channel will not go below
    # 20 MB (a 1 MB request returns quietly, the effective size stays
    # 20971520) - the shipped size IS the floor, and a tenth of the target.
    $targets = [ordered]@{ Security = 196608; System = 32768; Application = 32768 }
    foreach ($log in $targets.Keys) {
        $kb = [int64]$targets[$log]
        $bytes = $kb * 1024
        $live = [int64](Get-WinEvent -ListLog $log -ErrorAction Stop).MaximumSizeInBytes
        if ($live -ge $bytes) {
            Write-Ok "$log log already holds $([math]::Round($live / 1MB)) MB (effective)"
        } elseif ($DryRun) {
            Write-Warn2 "(dry-run) would grow the $log log to $($kb / 1024) MB live (currently $([math]::Round($live / 1MB, 1)) MB)"
        } else {
            & wevtutil.exe sl $log /ms:$bytes
            if ($LASTEXITCODE -ne 0) { throw "wevtutil could not resize the $log log (exit $LASTEXITCODE)" }
            $Script:ChangeCount++
            Write-Warn2 "$log log grown to $($kb / 1024) MB live, was $([math]::Round($live / 1MB, 1)) MB"
        }
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log" `
            -Name 'MaxSize' -Value $kb -Because 'policy pin in KB - survives Event Viewer edits' | Out-Null
    }
    Write-Ok 'A brute force now has to run for hours, not minutes, to push its own trace out of the log'
}

# ---- Step 17: firewall logging ----------------------------------------------

function Set-FirewallLogging {
    if ($NoFirewallLogging) { Write-Skip 'Skipping firewall logging'; return }
    Write-Step 'Making the firewall write down what it drops and what it lets in (all profiles, 16 MB each)'
    # Step 5 made the firewall deny by default. A firewall that denies in
    # SILENCE is the Windows twin of the Linux siblings' drop-without-log:
    # the port scan and the brute force vanish, and the one connection an
    # attacker DID get is not written down either. CIS 9.x, per profile: log
    # dropped packets, log successful connections, and a log of at least
    # 16384 KB - the shipped 4096 KB is minutes of a scan. Read effective
    # from Get-NetFirewallProfile (GpoBoolean: True/False/NotConfigured, so
    # compared as text), set per profile only where something differs.
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $fw = Get-NetFirewallProfile -Name $profileName
        $needs = @()
        if ("$($fw.LogBlocked)" -ne 'True') { $needs += 'dropped packets' }
        if ("$($fw.LogAllowed)" -ne 'True') { $needs += 'successful connections' }
        if ([int]$fw.LogMaxSizeKilobytes -lt 16384) { $needs += "size $($fw.LogMaxSizeKilobytes) KB -> 16384 KB" }
        if ($needs.Count -eq 0) {
            Write-Ok "$profileName profile already logs dropped and allowed into $($fw.LogMaxSizeKilobytes) KB"
            continue
        }
        if ($DryRun) {
            Write-Warn2 "(dry-run) would fix $profileName logging: $($needs -join ', ') (currently dropped=$($fw.LogBlocked) allowed=$($fw.LogAllowed) size=$($fw.LogMaxSizeKilobytes) KB)"
            continue
        }
        Set-NetFirewallProfile -Name $profileName -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384
        $Script:ChangeCount++
        Write-Warn2 "$profileName profile now logs dropped and allowed into a 16 MB log, was dropped=$($fw.LogBlocked) allowed=$($fw.LogAllowed) size=$($fw.LogMaxSizeKilobytes) KB"
    }
    Write-Ok 'A scan or a brute force leaves a line per packet in pfirewall.log - and so does the connection that got through'
}

# ---- Step 18: SMB client - insecure guest logons off --------------------------

function Disable-SmbGuestLogons {
    if ($NoSmbGuest) { Write-Skip 'Skipping SMB insecure guest logons'; return }
    Write-Step 'Refusing insecure guest logons on the SMB client (CIS 18.6.8.1)'
    # A guest logon is a session with NO authentication - and with no
    # authentication there is no signing, no encryption and no identity on the
    # other end. It is how a rogue share (the "evil installer" share, the
    # spoofed file server after a name-poisoning win) gets mounted without a
    # single credential ever being challenged. Step 1 made the client require
    # signing, which already refuses guest sessions in practice; this step
    # closes the door by its own name so a future relaxation of signing does
    # not silently reopen it. Two layers, the SMB1 pattern: the POLICY value
    # (LanmanWorkstation\AllowInsecureGuestAuth = 0, what Group Policy
    # writes) and the LIVE client setting (Set-SmbClientConfiguration), read
    # back effective from Get-SmbClientConfiguration.
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' `
        -Name 'AllowInsecureGuestAuth' -Value 0 -Because 'policy pin: no unauthenticated SMB sessions' | Out-Null
    $cli = Get-SmbClientConfiguration
    if (-not $cli.EnableInsecureGuestLogons) {
        Write-Ok 'SMB client already refuses insecure guest logons (effective config)'
    } elseif ($DryRun) {
        Write-Warn2 '(dry-run) would disable insecure guest logons on the SMB client live (currently enabled)'
    } else {
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
        $Script:ChangeCount++
        Write-Warn2 'SMB client no longer accepts insecure guest logons, was enabled'
    }
    Write-Ok 'No share mounts without a credential being challenged - the spoofed file server gets nothing'
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
    if (-not $NoRdp) { Write-Host '    - RDP posture: NLA + TLS + high encryption (never toggles RDP itself)' }
    if (-not $NoAuditPolicy) { Write-Host '    - audit policy: logons, process creation (with command line), policy changes' }
    if (-not $NoAutoRun) { Write-Host '    - AutoRun/AutoPlay off for every drive type (incl. autorun.inf and non-volume devices)' }
    if (-not $NoServiceSurface) { Write-Host '    - attack-surface services stopped and disabled (Spooler, RemoteRegistry)' }
    if (-not $NoNullSessions) { Write-Host '    - null sessions locked down (no anonymous enumeration, exception lists emptied)' }
    if (-not $NoDefenderPua) { Write-Host '    - Defender PUA protection: adware/bundlers/miners blocked (policy + live preference)' }
    if (-not $NoSmb1) { Write-Host '    - SMBv1 off (server dialect, client driver, optional feature)' }
    if (-not $NoScriptHost) { Write-Host '    - Windows Script Host off (no .vbs/.js/.wsf execution)' }
    if (-not $NoEventLogSize) { Write-Host '    - event log capacity: Security 192 MB, System/Application 32 MB (policy + live, never shrinks)' }
    if (-not $NoFirewallLogging) { Write-Host '    - firewall logging: dropped and allowed connections, 16 MB per profile' }
    if (-not $NoSmbGuest) { Write-Host '    - SMB client: insecure guest logons refused (policy + live)' }
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
    Set-RdpPosture
    Set-AuditPolicy
    Disable-AutoRun
    Disable-AttackSurfaceServices
    Disable-NullSessions
    Enable-DefenderPua
    Disable-Smb1
    Disable-ScriptHost
    Set-EventLogCapacity
    Set-FirewallLogging
    Disable-SmbGuestLogons

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
