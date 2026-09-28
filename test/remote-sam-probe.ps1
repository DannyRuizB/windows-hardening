#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 22 (RestrictRemoteSAM): can a NON-admin,
    over a real network logon, enumerate this box's local accounts through
    SAMR?

.DESCRIPTION
    A throwaway local user (member of Users only) opens an SMB session to
    this very box (\\127.0.0.1\IPC$ with its real password - a network
    logon, the path a remote caller takes), then a CHILD process asks SAMR
    for the local users through ADSI WinNT over that session. The child
    reuses the session's credentials, so the SAM server sees the probe user,
    not the elevated account running this script.

    Returns one object: Result = ALLOWED (with the user count), DENIED
    (the SAM server refused: "Access is denied"), or SETUP-FAILED (the
    probe never got as far as asking - a FAILED proof, never a pass). The
    user and the IPC$ session are removed whatever happens.

    Only the \\127.0.0.1\IPC$ connection is touched - never other mappings.

.NOTES
    ASCII ONLY (see harden.ps1).
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$user = 'whSam' + [guid]::NewGuid().ToString('N').Substring(0, 8)
# Long and mixed, so it passes the step 7 password policy on a hardened box.
$pw = 'Rs!' + [guid]::NewGuid().ToString('N').Substring(0, 20) + 'aZ9'
$target = '\\127.0.0.1\IPC$'

function New-ProbeResult {
    param([string]$Result, [string]$Detail)
    [pscustomobject]@{ Result = $Result; Detail = $Detail }
}

$null = net use $target /delete /y 2>&1
try {
    $addOut = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe user: $addOut") }
    $useOut = (net use $target $pw /user:$user 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "the probe user's network logon failed: $useOut") }

    # A child process: no ADSI object cached in THIS session, and the
    # enumeration rides the IPC$ session opened above.
    $child = @'
try {
    $c = [ADSI]'WinNT://127.0.0.1,computer'
    $n = @($c.psbase.Children | Where-Object { $_.SchemaClassName -eq 'User' }).Count
    "ALLOWED|$n"
} catch {
    "ERROR|$($_.Exception.InnerException.Message) $($_.Exception.Message)"
}
'@
    # -EncodedCommand, not -Command: native argument passing strips the
    # inner double quotes of a multi-line -Command (measured on the runner:
    # "ALLOWED|$n" arrived as a pipeline and the child did not even parse).
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $out = (& powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1 | Out-String).Trim()
    if ($out -match '^ALLOWED\|(\d+)') {
        return (New-ProbeResult 'ALLOWED' "a non-admin listed $($Matches[1]) local account(s) over SAMR")
    }
    if ($out -match 'Access is denied|0x80070005') {
        return (New-ProbeResult 'DENIED' 'the SAM server refused the non-admin: Access is denied')
    }
    return (New-ProbeResult 'SETUP-FAILED' "unexpected answer from the SAMR call: $out")
} finally {
    $null = net use $target /delete /y 2>&1
    $null = net user $user /delete 2>&1
}
