#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 31 (WinRM authentication): does any WinRM
    listener on this box accept the RIGHT password in a Basic header?

.DESCRIPTION
    A throwaway local administrator is created with a random password. Then,
    for every WinRM listener the box has (HTTP 5985 and HTTPS 5986 on the
    runner), a raw POST goes to http(s)://127.0.0.1:<port>/wsman carrying
    that password in an `Authorization: Basic` header and an empty SOAP
    envelope. Measured on the runner: an authenticated caller gets HTTP 500
    (the envelope is nonsense) and a refused one 401 - so the status code
    says whether the service took the password, without going through the
    WinRM client and its own (cached, per-process) configuration. The HTTPS
    certificate is not checked: the question is what the service accepts,
    not who it is.

    Then the same account connects with Invoke-Command and the default
    authentication (Negotiate). It must still get in: that proves the account
    and the service are fine, so a 401 above is about Basic and nothing else
    - and that hardening did not cut the administration channel.

    Returns one object: Result = REFUSED (every listener answered 401 to the
    right password, and Negotiate got in), ACCEPTED (some listener took the
    password - Detail names it), NOT-RUNNING (the WinRM service is stopped:
    nothing listens to take a header), or SETUP-FAILED (no listener, no user,
    or Negotiate failed too - a FAILED proof, never a pass). The user is
    removed and the certificate callback restored whatever happens.

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

$svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if (-not $svc) { return (New-ProbeResult 'SETUP-FAILED' 'no WinRM service on this box') }
if ($svc.Status -ne 'Running') { return (New-ProbeResult 'NOT-RUNNING' "WinRM service is $($svc.Status)") }

$listeners = @()
foreach ($l in @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue)) {
    $kv = @{}
    foreach ($i in @(Get-ChildItem -Path $l.PSPath -ErrorAction SilentlyContinue)) { $kv[$i.Name] = "$($i.Value)" }
    if ($kv['Transport'] -and $kv['Port']) { $listeners += [pscustomobject]@{ Transport = $kv['Transport']; Port = $kv['Port'] } }
}
if ($listeners.Count -eq 0) { return (New-ProbeResult 'SETUP-FAILED' 'WinRM is running with no listener - nothing to send a header to') }

$user = 'whWinRm' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$pw = 'Wr-' + [guid]::NewGuid().ToString('N') + '-a7Z!'
# Built char by char: ConvertTo-SecureString -AsPlainText is a PSScriptAnalyzer
# error, and the password is a random throwaway that dies with the account.
$sec = New-Object System.Security.SecureString
foreach ($ch in $pw.ToCharArray()) { $sec.AppendChar($ch) }
$sec.MakeReadOnly()
$oldCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    # net.exe like the other probes, /y for the long-password question.
    $addOut = (net user $user $pw /add /y 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not create the probe administrator: $addOut") }
    $grpOut = (net localgroup Administrators $user /add 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { return (New-ProbeResult 'SETUP-FAILED' "could not make the probe user an administrator: $grpOut") }
    [Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${user}:$pw"))
    $envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/><s:Body/></s:Envelope>'
    $answers = @()
    $took = @()
    foreach ($l in $listeners) {
        $scheme = if ($l.Transport -eq 'HTTPS') { 'https' } else { 'http' }
        $uri = "${scheme}://127.0.0.1:$($l.Port)/wsman"
        $code = $null
        try {
            $resp = Invoke-WebRequest -Uri $uri -Method Post -Headers @{ Authorization = "Basic $basic" } `
                -ContentType 'application/soap+xml;charset=UTF-8' -Body $envelope -UseBasicParsing -ErrorAction Stop
            $code = [int]$resp.StatusCode
        } catch {
            try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = $null }
            if ($null -eq $code) {
                return (New-ProbeResult 'SETUP-FAILED' "no HTTP answer from $uri - $($_.Exception.Message.Split("`n")[0])")
            }
        }
        $answers += "$($l.Transport) $($l.Port): HTTP $code"
        if ($code -ne 401) { $took += "$($l.Transport) $($l.Port) (HTTP $code)" }
    }
    $cred = New-Object System.Management.Automation.PSCredential($user, $sec)
    $who = $null
    $neg = 'no output from whoami'
    try {
        $who = Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami } -ErrorAction Stop
    } catch {
        $neg = $_.Exception.Message.Split("`n")[0]
    }
    if ($took.Count -gt 0) {
        return (New-ProbeResult 'ACCEPTED' "the right password in a Basic header was taken on $($took -join ', ') [$($answers -join '; ')]")
    }
    if (-not $who) {
        return (New-ProbeResult 'SETUP-FAILED' "every listener said 401, but Negotiate failed too, so the 401s prove nothing about Basic: $neg")
    }
    return (New-ProbeResult 'REFUSED' "Basic refused with the right password [$($answers -join '; ')]; Negotiate still gets in as $who")
} finally {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
    [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
    $null = net user $user /delete 2>&1
}
