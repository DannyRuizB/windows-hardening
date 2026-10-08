#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 30 (autologon password): can a NON-admin
    read the automatic-logon password out of the registry?

.DESCRIPTION
    Automatic logon keeps the account's password in
    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword
    as plain text, and that key is readable by every local user. A
    throwaway local user (member of Users only) is created; a CHILD process
    logs it on with LogonUser(LOGON32_LOGON_NETWORK_CLEARTEXT) and,
    IMPERSONATING that token, opens the Winlogon key and reads the value -
    the step 22 probe's technique, so the read runs with the probe user's
    rights and not the runner administrator's. The child reports whose
    token it read with; anything but the probe user is a FAILED probe.

    The password itself NEVER leaves the child: it reports only whether a
    non-empty value was there and how long it is.

    Returns one object: Result = EXPOSED (the probe user read a non-empty
    password), NONE (no value, or an empty one), DENIED (the key refused
    the probe user) or SETUP-FAILED (never got as far as reading - a FAILED
    proof, never a pass). The user is removed whatever happens.

.NOTES
    ASCII ONLY (see harden.ps1).
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$user = 'whAal' + [guid]::NewGuid().ToString('N').Substring(0, 8)
# Long and mixed, so it passes the step 7 password policy on a hardened box.
$pw = 'Al!' + [guid]::NewGuid().ToString('N').Substring(0, 20) + 'aZ9'

function New-ProbeResult {
    param([string]$Result, [string]$Detail)
    [pscustomobject]@{ Result = $Result; Detail = $Detail }
}

try {
    $addOut = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe user: $addOut") }

    # The logon, the impersonation and the read happen inside one C# method,
    # so they share a thread. A child process, so a hang can be killed.
    $child = @'
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
public static class AutologonProbe {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    public static string[] Run(string user, string password) {
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
                try {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false)) {
                        if (k == null) { lines.Add("READ=nokey"); }
                        else {
                            object v = k.GetValue("DefaultPassword");
                            string s = v == null ? null : v.ToString();
                            // Only the length - the value itself never leaves this method.
                            lines.Add(string.IsNullOrEmpty(s) ? "READ=none" : ("READ=value LEN=" + s.Length));
                        }
                    }
                } catch (System.Security.SecurityException) { lines.Add("READ=denied"); }
                catch (UnauthorizedAccessException) { lines.Add("READ=denied"); }
            }
        } finally { CloseHandle(token); }
        return lines.ToArray();
    }
}
"@
[AutologonProbe]::Run('__USER__', '__PW__')
'@
    $child = $child.Replace('__USER__', $user).Replace('__PW__', $pw)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $outFile = [IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -PassThru -NoNewWindow `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
            -RedirectStandardOutput $outFile
        if (-not $proc.WaitForExit(90000)) {
            try { $proc.Kill() } catch { $null = $_ }
            return (New-ProbeResult 'SETUP-FAILED' 'the registry read did not answer within 90 s')
        }
        $out = @(Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue)
    } finally {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
    if ($out.Count -eq 0) { return (New-ProbeResult 'SETUP-FAILED' "the child (exit $($proc.ExitCode)) wrote no answer") }

    $logon = ($out | Where-Object { $_ -like 'LOGON=*' } | Select-Object -First 1)
    if ($logon) { return (New-ProbeResult 'SETUP-FAILED' "the probe user's network logon failed (Win32 error $($logon.Substring(6)))") }
    $who = ($out | Where-Object { $_ -like 'WHO=*' } | Select-Object -First 1)
    if (-not $who -or $who -notlike "*\$user") { return (New-ProbeResult 'SETUP-FAILED' "the read did not run as the probe user ($who) - output: $($out -join ' | ')") }
    $read = ($out | Where-Object { $_ -like 'READ=*' } | Select-Object -First 1)
    $detail = "as $($who.Substring(4)): $read"
    switch -Wildcard ($read) {
        'READ=value*' { return (New-ProbeResult 'EXPOSED' $detail) }
        'READ=none' { return (New-ProbeResult 'NONE' $detail) }
        'READ=denied' { return (New-ProbeResult 'DENIED' $detail) }
        default { return (New-ProbeResult 'SETUP-FAILED' "unexpected answer - $detail") }
    }
} finally {
    $null = net user $user /delete 2>&1
}
