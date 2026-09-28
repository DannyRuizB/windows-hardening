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
    for the local users (NetUserEnum against \\127.0.0.1) over that session. The child
    reuses the session's credentials, so the SAM server sees the probe user,
    not the elevated account running this script.

    Returns one object: Result = ALLOWED (with the user count), DENIED
    (the SAM server refused: access denied, rc 5), or SETUP-FAILED (the
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

    # A child process, so the call rides the IPC$ session opened above and
    # nothing is cached in THIS one. NetUserEnum against \\127.0.0.1 is a
    # remote SAMR call - the one RestrictRemoteSAM gates - with a crisp
    # answer: 0 = listed, 5 = ERROR_ACCESS_DENIED. (ADSI WinNT was the first
    # try: its Children walk enumerates every object on the box and hung the
    # runner.) -EncodedCommand, not -Command: native argument passing strips
    # the inner double quotes of a multi-line -Command (measured on the
    # runner: the child did not even parse). And a hard timeout: a probe
    # that hangs is a FAILED probe, not a stuck build.
    $child = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SamProbe {
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserEnum(string server, int level, int filter, out IntPtr buf,
        int prefmaxlen, out int entriesread, out int totalentries, ref int resume);
    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buf);
}
"@
$buf = [IntPtr]::Zero; $read = 0; $total = 0; $resume = 0
$rc = [SamProbe]::NetUserEnum('\\127.0.0.1', 0, 2, [ref]$buf, -1, [ref]$read, [ref]$total, [ref]$resume)
if ($buf -ne [IntPtr]::Zero) { [void][SamProbe]::NetApiBufferFree($buf) }
'RC=' + $rc + ' USERS=' + $total
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $outFile = [IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -PassThru -NoNewWindow `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
            -RedirectStandardOutput $outFile
        if (-not $proc.WaitForExit(60000)) {
            try { $proc.Kill() } catch { $null = $_ }
            return (New-ProbeResult 'SETUP-FAILED' 'the SAMR call did not answer within 60 s')
        }
        $out = (Get-Content -Raw -LiteralPath $outFile -ErrorAction SilentlyContinue)
        if ($null -eq $out) { $out = '' }
        $out = $out.Trim()
    } finally {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
    if ($out -match 'RC=0 USERS=(\d+)') {
        return (New-ProbeResult 'ALLOWED' "a non-admin listed $($Matches[1]) local account(s) over SAMR (NetUserEnum rc 0)")
    }
    if ($out -match 'RC=5 ') {
        return (New-ProbeResult 'DENIED' 'the SAM server refused the non-admin: NetUserEnum rc 5 (access denied)')
    }
    return (New-ProbeResult 'SETUP-FAILED' "unexpected answer from the SAMR call: $out")
} finally {
    $null = net use $target /delete /y 2>&1
    $null = net user $user /delete 2>&1
}
