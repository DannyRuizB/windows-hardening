#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 24 (DisableDomainCreds): will Credential
    Manager still SAVE a password for network authentication?

.DESCRIPTION
    `cmdkey /add:<target> /user:<DOMAIN>\<user> /pass:<pw>` stores a
    "Domain Password" credential - the kind Windows hands to SMB, RDP and
    every other network logon to <target> without asking, and the kind
    mimikatz `vault::cred` / `sekurlsa::credman` lift from the logon session.
    That is what DisableDomainCreds = 1 refuses. Measured on the runner
    (Server 2025): as shipped (an explicit 0) the credential is stored;
    with 1 - live, no reboot, no new logon - cmdkey exits 1 with
    "Credentials cannot be saved from this logon session" and the list for
    that target reads "* NONE *".

    Anchored on a GENERIC credential (`cmdkey /generic:`), which the policy
    leaves alone (measured: stored in both states): if that one cannot be
    saved either, the probe is not measuring the policy and says so.

    Returns one object: Result = ALLOWED (the domain credential was stored),
    DENIED (refused with the policy's message, nothing stored), or
    SETUP-FAILED (the probe never got as far as asking - a FAILED proof,
    never a pass). Detail names the identity it ran as and cmdkey's answer.
    Both throwaway targets are deleted whatever happens.

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

$who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
$domTarget = "wh-dom-$tag.invalid"
$genTarget = "wh-gen-$tag.invalid"
$pw = 'Probe-' + [guid]::NewGuid().ToString('N')
try {
    $gen = (cmd.exe /c "cmdkey /generic:$genTarget /user:probe /pass:$pw 2>&1" | Out-String).Trim()
    $genRc = $LASTEXITCODE
    $genList = (cmd.exe /c "cmdkey /list:$genTarget 2>&1" | Out-String)
    if ($genRc -ne 0 -or $genList -notmatch 'Generic') {
        return (New-ProbeResult 'SETUP-FAILED' "WHO=$who; even a generic credential could not be saved (rc $genRc): $($gen -replace '\s+', ' ')")
    }
    $dom = (cmd.exe /c "cmdkey /add:$domTarget /user:WHPROBE\probe /pass:$pw 2>&1" | Out-String).Trim()
    $domRc = $LASTEXITCODE
    $domList = (cmd.exe /c "cmdkey /list:$domTarget 2>&1" | Out-String)
    $flat = ($dom -replace '\s+', ' ')
    if ($domRc -eq 0 -and $domList -match 'Domain Password') {
        return (New-ProbeResult 'ALLOWED' "WHO=$who; a Domain Password credential for $domTarget was stored ($flat)")
    }
    if ($domRc -ne 0 -and $dom -match 'cannot be saved' -and $domList -match 'NONE') {
        return (New-ProbeResult 'DENIED' "WHO=$who; refused (rc $domRc): $flat")
    }
    return (New-ProbeResult 'SETUP-FAILED' "WHO=$who; unexpected answer from cmdkey (rc $domRc): $flat")
} finally {
    $null = cmd.exe /c "cmdkey /delete:$domTarget" 2>&1
    $null = cmd.exe /c "cmdkey /delete:$genTarget" 2>&1
}
