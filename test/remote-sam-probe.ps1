#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 22 (RestrictRemoteSAM): can a NON-admin,
    over the network, enumerate this box's local accounts through SAMR?

.DESCRIPTION
    A throwaway local user (member of Users only) is created and a CHILD
    process is started AS that user (Start-Process -Credential, so its
    token is the non-admin's own - nothing of the elevated account running
    this script rides along). The child asks SAMR for the local users with
    NetUserEnum against two network addresses of this very box: the
    loopback (\\127.0.0.1) and the first non-loopback IPv4. Neither is the
    computer name, so netapi does not short-circuit to a local call; it
    binds \pipe\samr over SMB, authenticating as the probe user - the path
    a remote caller takes, and the one RestrictRemoteSAM gates.

    The child also prints whose token it runs with; a child that is not the
    probe user is a FAILED probe (that was the first version's flaw: the
    child ran as the runner's administrator and was ALLOWED whatever the
    descriptor said).

    Returns one object: Result = ALLOWED (some target listed the accounts),
    DENIED (every target refused: rc 5, access denied), or SETUP-FAILED
    (the probe never got as far as asking - a FAILED proof, never a pass).
    Detail always lists every target's answer. The user, its profile and
    the scratch directory are removed whatever happens.

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

$scratch = Join-Path $env:SystemRoot ('Temp\' + $user)
try {
    $addOut = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe user: $addOut") }

    # The child runs as the probe user: it writes its answer into a scratch
    # directory that user is granted, not into the elevated account's TEMP.
    $null = New-Item -ItemType Directory -Path $scratch -Force
    $null = icacls $scratch /grant "${user}:(OI)(CI)M" 2>&1
    $outFile = Join-Path $scratch 'answer.txt'

    # NetUserEnum has a crisp answer: 0 = listed, 5 = ERROR_ACCESS_DENIED.
    # (ADSI WinNT was the first try: its Children walk enumerates every
    # object on the box and hung the runner.) -EncodedCommand, not -Command:
    # native argument passing strips the inner double quotes of a multi-line
    # -Command (measured on the runner: the child did not even parse).
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
$lines = @('WHO=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
foreach ($t in @(__TARGETS__)) {
    $buf = [IntPtr]::Zero; $read = 0; $total = 0; $resume = 0
    $rc = [SamProbe]::NetUserEnum($t, 0, 2, [ref]$buf, -1, [ref]$read, [ref]$total, [ref]$resume)
    if ($buf -ne [IntPtr]::Zero) { [void][SamProbe]::NetApiBufferFree($buf) }
    $lines += 'T=' + $t + ' RC=' + $rc + ' USERS=' + $total
}
Set-Content -LiteralPath '__OUT__' -Value $lines -Encoding ASCII
'@
    $child = $child.Replace('__TARGETS__', (($targets | ForEach-Object { "'$_'" }) -join ', '))
    $child = $child.Replace('__OUT__', $outFile)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))

    # Built char by char: the password is this script's own throwaway, and
    # ConvertTo-SecureString -AsPlainText is a PSScriptAnalyzer error.
    $secure = New-Object System.Security.SecureString
    foreach ($c in $pw.ToCharArray()) { $secure.AppendChar($c) }
    $cred = New-Object System.Management.Automation.PSCredential($user, $secure)
    try {
        # -LoadUserProfile: Add-Type compiles into the user's TEMP, which
        # only exists once the profile does. A hard timeout: a probe that
        # hangs is a FAILED probe, not a stuck build.
        $proc = Start-Process -FilePath 'powershell.exe' -PassThru -Credential $cred -LoadUserProfile `
            -WorkingDirectory $scratch -WindowStyle Hidden `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -ErrorAction Stop
    } catch {
        return (New-ProbeResult 'SETUP-FAILED' "could not start a process as the probe user: $($_.Exception.Message)")
    }
    if (-not $proc.WaitForExit(90000)) {
        try { $proc.Kill() } catch { $null = $_ }
        return (New-ProbeResult 'SETUP-FAILED' 'the SAMR calls did not answer within 90 s')
    }
    $out = @(Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue)
    if ($out.Count -eq 0) { return (New-ProbeResult 'SETUP-FAILED' "the child (exit $($proc.ExitCode)) wrote no answer") }

    $who = ($out | Where-Object { $_ -like 'WHO=*' } | Select-Object -First 1)
    if (-not $who -or $who -notlike "*\$user") { return (New-ProbeResult 'SETUP-FAILED' "the child did not run as the probe user ($who)") }
    $answers = @($out | Where-Object { $_ -like 'T=*' })
    $detail = "as $($who.Substring(4)): " + ($answers -join '; ')
    if ($answers.Count -ne $targets.Count) { return (New-ProbeResult 'SETUP-FAILED' "missing answers - $detail") }
    if (@($answers | Where-Object { $_ -match ' RC=0 ' }).Count -gt 0) { return (New-ProbeResult 'ALLOWED' $detail) }
    if (@($answers | Where-Object { $_ -notmatch ' RC=5 ' }).Count -eq 0) { return (New-ProbeResult 'DENIED' $detail) }
    return (New-ProbeResult 'SETUP-FAILED' "unexpected answer - $detail")
} finally {
    $null = net user $user /delete 2>&1
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -like "*\$user" } |
        Remove-CimInstance -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
