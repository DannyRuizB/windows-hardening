#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 25 (SMB encryption): does a NEW SMB session
    to this box travel encrypted?

.DESCRIPTION
    A throwaway share is created on a throwaway directory, every SMB session
    on the box is closed (measured on the runner: a session opened BEFORE the
    server switched to EncryptData kept going unencrypted - the client reuses
    it - so a probe that does not start fresh measures the past), and a real
    session is opened to this box's first non-loopback IPv4 with
    `net use \\<ip>\<share>`. `Get-SmbConnection` then says whether that
    session is Encrypted. Measured on Server 2025: as shipped Encrypted=False
    (Signed=True); with EncryptData=True, set live, Encrypted=True.

    Returns one object: Result = ENCRYPTED, PLAINTEXT, or SETUP-FAILED (the
    session never opened - a FAILED proof, never a pass). Detail carries the
    dialect and the Encrypted/Signed flags. The share, its directory and the
    connection are removed whatever happens.

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
if (-not $ip) { return (New-ProbeResult 'SETUP-FAILED' 'no non-loopback IPv4 to open a session to') }

$share = 'whEnc' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$dir = Join-Path $env:TEMP $share
$target = "\\$ip\$share"
try {
    try {
        $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop
        $null = New-SmbShare -Name $share -Path $dir -ReadAccess Everyone -ErrorAction Stop
    } catch {
        return (New-ProbeResult 'SETUP-FAILED' "could not create the throwaway share: $($_.Exception.Message)")
    }
    $null = cmd.exe /c "net use * /delete /y 2>nul"
    Get-SmbSession -ErrorAction SilentlyContinue | Close-SmbSession -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $out = (cmd.exe /c "net use $target 2>&1" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        return (New-ProbeResult 'SETUP-FAILED' "net use $target failed: $($out -replace '\s+', ' ')")
    }
    $conn = Get-SmbConnection -ErrorAction SilentlyContinue | Where-Object { $_.ShareName -eq $share } | Select-Object -First 1
    if (-not $conn) { return (New-ProbeResult 'SETUP-FAILED' "no SMB connection to $target after net use") }
    $flags = "dialect $($conn.Dialect), Encrypted=$($conn.Encrypted), Signed=$($conn.Signed)"
    if ($conn.Encrypted) { return (New-ProbeResult 'ENCRYPTED' "a fresh session to $target is encrypted ($flags)") }
    return (New-ProbeResult 'PLAINTEXT' "a fresh session to $target is NOT encrypted ($flags)")
} finally {
    $null = cmd.exe /c "net use $target /delete /y 2>nul"
    Remove-SmbShare -Name $share -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
}
