#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 23 (LimitBlankPasswordUse): can a local
    account with a BLANK password log on over the network?

.DESCRIPTION
    A throwaway local user is created with no password at all
    (New-LocalUser -NoPassword: the account is flagged "password not
    required", so the password policy of step 7 does not stand in the way -
    exactly how such accounts exist in the wild). Then a real SMB session is
    opened to this box's first non-loopback IPv4 as that user, with an empty
    password: `net use \\<ip>\IPC$ "" /user:<box>\<user>`. A network logon,
    the one LimitBlankPasswordUse confines to the console.

    Not the loopback: step 22 measured that this box does not treat
    \\127.0.0.1 as a remote caller. And through cmd.exe: Windows PowerShell
    5.1 drops an empty-string argument on its way to a native command, so the
    "" would never reach net.exe.

    Returns one object: Result = ALLOWED (the session opened), DENIED (the
    logon was refused: system error 1327, "account restrictions"), or
    SETUP-FAILED (the probe never got as far as asking - a FAILED proof, never
    a pass). Detail carries net.exe's answer. The user and the session are
    removed whatever happens; only that one \\<ip>\IPC$ connection is touched.

.NOTES
    ASCII ONLY (see harden.ps1).
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function New-ProbeResult {
    param([string]$Result, [string]$Detail)
    [pscustomobject]@{ Result = $Result; Detail = $Detail }
}

$ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
if (-not $ip) { return (New-ProbeResult 'SETUP-FAILED' 'no non-loopback IPv4 to open a network session to') }

$user = 'whBlank' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$target = "\\$ip\IPC$"
try {
    try {
        $null = New-LocalUser -Name $user -NoPassword -ErrorAction Stop
        Enable-LocalUser -Name $user -ErrorAction Stop
    } catch {
        return (New-ProbeResult 'SETUP-FAILED' "could not create a blank-password user: $($_.Exception.Message)")
    }
    $null = cmd.exe /c "net use $target /delete /y" 2>&1
    $out = (cmd.exe /c "net use $target `"`" /user:$env:COMPUTERNAME\$user 2>&1" | Out-String).Trim()
    $rc = $LASTEXITCODE
    $flat = ($out -replace '\s+', ' ')
    if ($rc -eq 0) { return (New-ProbeResult 'ALLOWED' "a blank password opened $target ($flat)") }
    if ($out -match '\b1327\b') { return (New-ProbeResult 'DENIED' "refused: $flat") }
    return (New-ProbeResult 'SETUP-FAILED' "unexpected answer from net use (rc $rc): $flat")
} finally {
    $null = cmd.exe /c "net use $target /delete /y" 2>&1
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
