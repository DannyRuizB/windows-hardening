#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 34 (UAC remote restrictions): does a LOCAL
    administrator who logs on over the network get a full admin token?

.DESCRIPTION
    A throwaway local administrator is created with a random password, and
    logs on over the network as that account:

      * SMB to this box's first non-loopback IPv4. IPC$ first - the anchor:
        it opens for any valid credential, so a refusal of the next two is
        about the token, not the password - then the administrative shares
        C$ and ADMIN$ (where PsExec-style tools copy their service).
      * WinRM (Invoke-Command to localhost, Negotiate), asking whether the
        session holds the Administrators group.

    Measured on the runner (Server 2025 and 2022, probe branch): as shipped
    (LocalAccountTokenFilterPolicy = 1) C$, ADMIN$ and a High-integrity
    WinRM session all opened; with 0, and with the value absent, C$ and
    ADMIN$ answered "System error 5 has occurred. Access is denied.", WinRM
    "Access is denied", and IPC$ still opened. Unlike SAM in step 22 the
    filter treats \\127.0.0.1 as a network logon too; the non-loopback
    address is used anyway, like the other probes.

    Returns one object: Result = FULL-TOKEN (an administrative share or an
    admin WinRM session opened), FILTERED (C$ and ADMIN$ refused with error
    5, no admin WinRM session, IPC$ opened), or SETUP-FAILED (no address, no
    account, IPC$ refused - a FAILED proof, never a pass). One NEW account
    per run: an SMB session already open would be reused, with the token
    computed back then. The account, its mappings and its server-side
    sessions are removed whatever happens.

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

# Built char by char: ConvertTo-SecureString -AsPlainText is a PSScriptAnalyzer
# error, and the password is a random throwaway that dies with the account.
function New-ProbeSecret {
    param([string]$Plain)
    $sec = New-Object System.Security.SecureString
    foreach ($ch in $Plain.ToCharArray()) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()
    $sec
}

$ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -First 1 -ExpandProperty IPAddress
if (-not $ip) { return (New-ProbeResult 'SETUP-FAILED' 'no non-loopback IPv4 to log on to over the network') }

$user = 'whTf' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$pw = 'Tf-' + [guid]::NewGuid().ToString('N') + '-a7Z!'
$shares = @('IPC$', 'C$', 'ADMIN$')
try {
    # net.exe like the other probes, /y for the long-password question.
    $out = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe administrator: $out") }
    $out = (net localgroup Administrators $user /add 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not make the probe user an administrator: $out") }

    $smb = @{}
    foreach ($share in $shares) {
        $target = "\\$ip\$share"
        $text = (cmd.exe /c "net use $target $pw /user:$env:COMPUTERNAME\$user 2>&1" | Out-String) -replace '\s+', ' '
        $smb[$share] = [pscustomobject]@{ Rc = $LASTEXITCODE; Text = $text.Trim() }
        $null = cmd.exe /c "net use $target /delete /y 2>nul"
    }
    if ($smb['IPC$'].Rc -ne 0) {
        return (New-ProbeResult 'SETUP-FAILED' "IPC`$ refused the account itself, so a refusal of the admin shares would prove nothing: $($smb['IPC$'].Text)")
    }

    $winrm = 'not running'
    $winrmAdmin = $false
    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        $cred = New-Object System.Management.Automation.PSCredential($user, (New-ProbeSecret $pw))
        try {
            $who = Invoke-Command -ComputerName localhost -Credential $cred -ErrorAction Stop -ScriptBlock {
                $id = [Security.Principal.WindowsIdentity]::GetCurrent()
                "$($id.Name)|$(([Security.Principal.WindowsPrincipal]$id).IsInRole('Administrators'))"
            }
            $name, $isAdmin = "$who".Split('|')
            if ($isAdmin -eq 'True') { $winrmAdmin = $true; $winrm = "admin session as $name" }
            else { $winrm = "session as $name without the Administrators group" }
        } catch {
            $winrm = "refused: $($_.Exception.Message.Split("`n")[0])"
        }
    }

    $detail = "IPC`$ rc $($smb['IPC$'].Rc), C`$ rc $($smb['C$'].Rc), ADMIN`$ rc $($smb['ADMIN$'].Rc) on \\$ip; WinRM $winrm"
    $openedAdmin = @($shares | Where-Object { $_ -ne 'IPC$' -and $smb[$_].Rc -eq 0 })
    if ($openedAdmin.Count -gt 0 -or $winrmAdmin) {
        return (New-ProbeResult 'FULL-TOKEN' "a local administrator's password is remote administration - $detail")
    }
    # Error 5 by number, not by the English words after it.
    if ($smb['C$'].Text -match '\b5\b' -and $smb['ADMIN$'].Text -match '\b5\b') {
        return (New-ProbeResult 'FILTERED' "$detail [C`$: $($smb['C$'].Text)]")
    }
    return (New-ProbeResult 'SETUP-FAILED' "the admin shares were refused, but not with error 5 - $detail [C`$: $($smb['C$'].Text)]")
} finally {
    foreach ($share in $shares) { $null = cmd.exe /c "net use \\$ip\$share /delete /y 2>nul" }
    Get-SmbSession -ErrorAction SilentlyContinue | Where-Object { $_.ClientUserName -like "*\$user" } |
        Close-SmbSession -Force -ErrorAction SilentlyContinue
    $null = net user $user /delete 2>&1
}
