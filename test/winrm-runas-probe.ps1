#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 32 (DisableRunAs): can a WinRM endpoint run a
    Remote Management Users member as an administrator whose password WinRM
    keeps?

.DESCRIPTION
    Two throwaway local accounts: an administrator, and a plain user in
    Remote Management Users. A session configuration is registered with
    -RunAsCredential of the administrator and the DEFAULT permissions (which
    let Remote Management Users in - measured), then the plain user connects
    to it and asks who it is.

    Returns one object: Result = ESCALATES (the plain user's commands ran as
    the administrator), REFUSED (registering a RunAs endpoint was refused by
    the "Disallow WinRM from storing RunAs credentials" policy - measured
    message), NOT-RUNNING (the WinRM service is stopped), or SETUP-FAILED
    (anything else - a FAILED proof, never a pass). The endpoint and both
    accounts are removed whatever happens. Registering and unregistering
    restart WinRM.

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
# error, and the passwords are random throwaways that die with the accounts.
function New-ProbeSecret {
    param([string]$Plain)
    $sec = New-Object System.Security.SecureString
    foreach ($ch in $Plain.ToCharArray()) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()
    $sec
}

$svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if (-not $svc) { return (New-ProbeResult 'SETUP-FAILED' 'no WinRM service on this box') }
if ($svc.Status -ne 'Running') { return (New-ProbeResult 'NOT-RUNNING' "WinRM service is $($svc.Status)") }

$tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
$admin = "whRaAdm$tag"
$plain = "whRaUsr$tag"
$endpoint = "whRunAs$tag"
$pwAdmin = 'Ra-' + [guid]::NewGuid().ToString('N') + '-a7Z!'
$pwPlain = 'Ru-' + [guid]::NewGuid().ToString('N') + '-a7Z!'
try {
    # net.exe like the other probes, /y for the long-password question.
    $out = (net user $admin $pwAdmin /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the administrator: $out") }
    $out = (net localgroup Administrators $admin /add 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not make it an administrator: $out") }
    $out = (net user $plain $pwPlain /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the plain user: $out") }
    $out = (net localgroup 'Remote Management Users' $plain /add 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not add the plain user to Remote Management Users: $out") }
    $credAdmin = New-Object System.Management.Automation.PSCredential($admin, (New-ProbeSecret $pwAdmin))
    $credPlain = New-Object System.Management.Automation.PSCredential($plain, (New-ProbeSecret $pwPlain))

    try {
        $null = Register-PSSessionConfiguration -Name $endpoint -RunAsCredential $credAdmin -Force -WarningAction SilentlyContinue -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message.Split("`n")[0]
        if ($msg -match 'RunAs credentials') { return (New-ProbeResult 'REFUSED' "registering a RunAs endpoint was refused: $msg") }
        return (New-ProbeResult 'SETUP-FAILED' "could not register the endpoint: $msg")
    }
    try {
        $who = Invoke-Command -ComputerName localhost -ConfigurationName $endpoint -Credential $credPlain -ErrorAction Stop -ScriptBlock {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            "$($id.Name)|$(([Security.Principal.WindowsPrincipal]$id).IsInRole('Administrators'))"
        }
    } catch {
        return (New-ProbeResult 'SETUP-FAILED' "the endpoint registered but the plain user could not use it: $($_.Exception.Message.Split("`n")[0])")
    }
    $name, $isAdmin = "$who".Split('|')
    if ($name -like "*\$admin" -and $isAdmin -eq 'True') {
        return (New-ProbeResult 'ESCALATES' "a Remote Management Users member ran as $name (administrator) through a RunAs endpoint with default permissions")
    }
    return (New-ProbeResult 'SETUP-FAILED' "the endpoint ran as '$who', not as the RunAs administrator")
} finally {
    Unregister-PSSessionConfiguration -Name $endpoint -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $null = net user $admin /delete 2>&1
    $null = net user $plain /delete 2>&1
}
