#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural probe for step 9's SCENoApplyLegacyAuditPolicy: can a LEGACY
    category audit policy still overwrite the subcategories step 9 sets?

.DESCRIPTION
    Step 9 audits logons by SUBCATEGORY (success AND failure: events 4624 and
    4625). The older 9-category policy - what a basic-audit GPO or a secedit
    template carries - is a second way to say the same thing, and with
    SCENoApplyLegacyAuditPolicy = 0 it wins. Measured on Server 2022 and
    2025: a template saying "logon events: success" turned the Logon
    subcategory into Success only, and a failed logon wrote NO 4625 - a
    password spray goes unrecorded. With the value at 1, or absent (what
    Windows ships), the subcategory held and the 4625 landed. (A template
    saying "no auditing", AuditLogonEvents = 0, was never applied at all - a
    trap that needs a template that DEFINES something.)

    The probe backs up the whole audit policy (auditpol /backup), applies
    exactly that template with `secedit /configure` (the SECURITYPOLICY area
    only), reads the Logon subcategory by GUID (auditpol localizes the
    names), then makes one failed network logon against this box's own IPC$
    with a unique user name and looks for it in event 4625 - the effect, not
    just the setting. Whatever happened, the backup is restored at the end
    (auditpol /restore): on a box where the template DID win, the failure
    auditing it took away - and the rest of the Logon/Logoff category - is
    put back, so running verify on an unhardened box does not leave it
    blinder than it found it.

    Returns one object: Result = HELD (failure auditing survived AND the
    4625 landed), OVERRIDDEN (the template took failure auditing away AND no
    4625 landed), INCONSISTENT (the setting and the event disagree), or
    SETUP-FAILED (secedit or auditpol did not run - a FAILED proof, never a
    pass). Restored says whether the audit policy was put back from the
    backup. Detail says what was seen. The template, its database and the
    backups are removed whatever happens.

.NOTES
    ASCII ONLY (see harden.ps1). 'Continue', like every probe here: under
    'Stop', Windows PowerShell 5.1 turns the stderr of `net use ... 2>&1`
    (the failed logon IS the probe) into a terminating error.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$logonGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
$tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
$inf = Join-Path $env:TEMP "wh-legacy-audit-$tag.inf"
$db = Join-Path $env:TEMP "wh-legacy-audit-$tag.sdb"
$csv = Join-Path $env:TEMP "wh-legacy-audit-$tag.csv"
$before = Join-Path $env:TEMP "wh-legacy-audit-$tag-before.csv"

function New-Result([string]$Result, [string]$Detail) {
    [pscustomobject]@{ Result = $Result; Detail = $Detail; Restored = $false }
}

function Invoke-LegacyAuditProbe {
    # The legacy category policy, as a basic-audit GPO would carry it:
    # logon events, SUCCESS only (1). Not 0 - "no auditing" was measured to
    # be ignored even when the legacy policy is allowed to win.
    @(
        '[Unicode]', 'Unicode=yes',
        '[Version]', 'signature="$CHICAGO$"', 'Revision=1',
        '[Event Audit]', 'AuditLogonEvents = 1'
    ) | Set-Content -LiteralPath $inf -Encoding Unicode
    $out = secedit /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        return New-Result 'SETUP-FAILED' "secedit /configure rc $LASTEXITCODE - $(($out | Out-String).Trim())"
    }

    $null = auditpol /backup /file:"$csv"
    if ($LASTEXITCODE -ne 0) { return New-Result 'SETUP-FAILED' "auditpol /backup rc $LASTEXITCODE" }
    $setting = -1
    foreach ($line in Get-Content -LiteralPath $csv) {
        $cols = $line -split ','
        if ($cols.Count -ge 7 -and $cols[3] -eq $logonGuid) { $setting = [int]$cols[6] }
    }
    if ($setting -lt 0) { return New-Result 'SETUP-FAILED' 'the Logon subcategory is not in the auditpol backup' }
    $failureAudited = ($setting -band 2) -eq 2

    # One failed network logon, unique name, loopback IPC$: nothing leaves the
    # host, nothing is created, and the attempt cannot succeed.
    $user = "whLegacy$tag"
    $null = net use '\\127.0.0.1\IPC$' WrongPass123x /user:$user 2>&1
    $landed = $false
    foreach ($attempt in 1..10) {
        Start-Sleep -Milliseconds 700
        $evts = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddMinutes(-5)
        } -MaxEvents 300 -ErrorAction SilentlyContinue
        if ($evts | Where-Object { $_.Message -like "*$user*" }) { $landed = $true; break }
    }

    $seen = "after a legacy 'logon events: success' template the Logon subcategory is $setting " +
        "(failure audited: $failureAudited) and the failed logon of $user " +
        $(if ($landed) { 'landed in 4625' } else { 'wrote no 4625' })
    if ($failureAudited -and $landed) { return New-Result 'HELD' $seen }
    if (-not $failureAudited -and -not $landed) { return New-Result 'OVERRIDDEN' $seen }
    return New-Result 'INCONSISTENT' $seen
}

# The backup comes first: without it the probe would change a policy it
# cannot put back, so it does not run at all.
$null = auditpol /backup /file:"$before"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $before)) {
    New-Result 'SETUP-FAILED' "auditpol /backup of the current policy rc $LASTEXITCODE - nothing was changed"
    return
}

try {
    $result = Invoke-LegacyAuditProbe
} catch {
    $result = New-Result 'SETUP-FAILED' $_.Exception.Message
} finally {
    $null = auditpol /restore /file:"$before"
    $restoreRc = $LASTEXITCODE
    Remove-Item -LiteralPath $inf, $db, $csv, $before -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$db.log", ($db -replace '\.sdb$', '.jfm') -ErrorAction SilentlyContinue
}
$result.Restored = ($restoreRc -eq 0)
if (-not $result.Restored) {
    $result.Detail += " - WARNING: auditpol /restore rc $restoreRc, the audit policy was NOT put back"
}
$global:LASTEXITCODE = 0
$result
