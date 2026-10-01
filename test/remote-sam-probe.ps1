#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 22 (RestrictRemoteSAM): can a NON-admin,
    over the network, enumerate this box's local accounts through SAMR?

.DESCRIPTION
    A throwaway local user (member of Users only) is created. A CHILD
    process logs it on with LogonUser(LOGON32_LOGON_NETWORK_CLEARTEXT) -
    the "access this computer from the network" right a remote caller
    uses, and a token that still carries the password for the outbound
    hop - and, IMPERSONATING that token, asks SAMR for the local users with
    NetUserEnum against two network addresses of this very box: the
    loopback (\\127.0.0.1) and the first non-loopback IPv4. Neither is the
    computer name, so netapi does not short-circuit to a local call; it
    binds \pipe\samr over SMB as the probe user - the path a remote caller
    takes, and the one RestrictRemoteSAM gates.

    The child also reports whose token it called with; anything but the
    probe user is a FAILED probe. (That was the first version's flaw: the
    call ran with the runner's administrator token and was ALLOWED whatever
    the descriptor said. Start-Process -Credential was the second try: on
    the runner it fails with "The parameter is incorrect".)

    Returns one object: Result = ALLOWED (some target listed the accounts),
    DENIED (every target refused: rc 5, access denied), or SETUP-FAILED
    (the probe never got as far as asking - a FAILED proof, never a pass).
    Detail always lists every target's answer. The user is removed
    whatever happens.

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

function New-ProbeResult {
    param([string]$Result, [string]$Detail)
    [pscustomobject]@{ Result = $Result; Detail = $Detail }
}

$targets = @('\\127.0.0.1')
$ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
if ($ip) { $targets += "\\$ip" }

try {
    $addOut = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe user: $addOut") }

    # NetUserEnum has a crisp answer: 0 = listed, 5 = ERROR_ACCESS_DENIED.
    # (ADSI WinNT was the first try: its Children walk enumerates every
    # object on the box and hung the runner.) The logon, the impersonation
    # and the calls all happen inside one C# method, so they share a thread.
    # A child process, so a hang can be killed: a probe that hangs is a
    # FAILED probe, not a stuck build. -EncodedCommand, not -Command: native
    # argument passing strips the inner double quotes of a multi-line
    # -Command (measured on the runner: the child did not even parse).
    $child = @'
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class SamProbe {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    static extern int NetUserEnum(string server, int level, int filter, out IntPtr buf,
        int prefmaxlen, out int entriesread, out int totalentries, ref int resume);
    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buf);
    public static string[] Run(string user, string password, string[] targets) {
        List<string> lines = new List<string>();
        IntPtr token;
        // 8 = LOGON32_LOGON_NETWORK_CLEARTEXT, 0 = default provider
        if (!LogonUser(user, ".", password, 8, 0, out token)) {
            lines.Add("LOGON=" + Marshal.GetLastWin32Error());
            return lines.ToArray();
        }
        try {
            using (WindowsIdentity id = new WindowsIdentity(token))
            using (WindowsImpersonationContext ctx = id.Impersonate()) {
                lines.Add("WHO=" + WindowsIdentity.GetCurrent().Name);
                foreach (string t in targets) {
                    IntPtr buf; int read, total, resume = 0;
                    int rc = NetUserEnum(t, 0, 2, out buf, -1, out read, out total, ref resume);
                    if (buf != IntPtr.Zero) NetApiBufferFree(buf);
                    lines.Add("T=" + t + " RC=" + rc + " USERS=" + total);
                }
            }
        } finally { CloseHandle(token); }
        return lines.ToArray();
    }
}
"@
[SamProbe]::Run('__USER__', '__PW__', @(__TARGETS__))
'@
    $child = $child.Replace('__USER__', $user).Replace('__PW__', $pw)
    $child = $child.Replace('__TARGETS__', (($targets | ForEach-Object { "'$_'" }) -join ', '))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $outFile = [IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -PassThru -NoNewWindow `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
            -RedirectStandardOutput $outFile
        if (-not $proc.WaitForExit(90000)) {
            try { $proc.Kill() } catch { $null = $_ }
            return (New-ProbeResult 'SETUP-FAILED' 'the SAMR calls did not answer within 90 s')
        }
        $out = @(Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue)
    } finally {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
    if ($out.Count -eq 0) { return (New-ProbeResult 'SETUP-FAILED' "the child (exit $($proc.ExitCode)) wrote no answer") }

    $logon = ($out | Where-Object { $_ -like 'LOGON=*' } | Select-Object -First 1)
    if ($logon) { return (New-ProbeResult 'SETUP-FAILED' "the probe user's network logon failed (Win32 error $($logon.Substring(6)))") }
    $who = ($out | Where-Object { $_ -like 'WHO=*' } | Select-Object -First 1)
    if (-not $who -or $who -notlike "*\$user") { return (New-ProbeResult 'SETUP-FAILED' "the call did not run as the probe user ($who) - output: $($out -join ' | ')") }
    $answers = @($out | Where-Object { $_ -like 'T=*' })
    $detail = "as $($who.Substring(4)): " + ($answers -join '; ')
    if ($answers.Count -ne $targets.Count) { return (New-ProbeResult 'SETUP-FAILED' "missing answers - $detail") }
    if (@($answers | Where-Object { $_ -match ' RC=0 ' }).Count -gt 0) { return (New-ProbeResult 'ALLOWED' $detail) }
    if (@($answers | Where-Object { $_ -notmatch ' RC=5 ' }).Count -eq 0) { return (New-ProbeResult 'DENIED' $detail) }
    return (New-ProbeResult 'SETUP-FAILED' "unexpected answer - $detail")
} finally {
    $null = net user $user /delete 2>&1
}
