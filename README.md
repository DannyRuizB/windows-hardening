# windows-hardening

[![lint](https://github.com/DannyRuizB/windows-hardening/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/windows-hardening/actions/workflows/lint.yml)
[![e2e](https://github.com/DannyRuizB/windows-hardening/actions/workflows/e2e.yml/badge.svg)](https://github.com/DannyRuizB/windows-hardening/actions/workflows/e2e.yml)

A **baseline security hardening script for Windows Server / Windows 10-11**, in
PowerShell — with a harness that proves it. CI takes a disposable Windows Server
runner, **hardens it for real**, runs the script again to prove idempotence,
verifies every promise (including four behavioural proofs) and scores the box
against a CIS-style checklist.

Sibling of [debian-hardening](https://github.com/DannyRuizB/debian-hardening)
(Bash) and [debian-hardening-ansible](https://github.com/DannyRuizB/debian-hardening-ansible)
(Ansible): same discipline, the other operating system.

```powershell
.\harden.ps1 -DryRun        # show what would change, change nothing
.\harden.ps1                # apply, with a confirmation prompt
.\harden.ps1 -Yes           # apply unattended (CI)
.\harden.ps1 -NoFirewall -Yes
.\test\verify.ps1           # assert every promise
.\test\audit.ps1            # score against the checklist
```

Run elevated. `-DryRun` and the per-step `-No*` switches are honoured by every
step, and the script reports the number of changes it made — a correct second
run reports **0**.

## What it hardens, and why that specific thing

| Step | What and why |
|---|---|
| **SMB signing** | Signs every SMB session, server *and* client. An **unsigned** SMB session is what makes NTLM relay work: the attacker sits in the middle, forwards the victim's authentication to a third host and lands a session there. Every relay tutorial starts by checking whether signing is required — measured on the CI runner, it was **not**. |
| **WDigest** | Pins `UseLogonCredential = 0` so LSASS stops keeping **cleartext passwords in memory** for a 2008-era protocol. This single value is the difference between a credential dump handing over passwords and handing over hashes. Windows 8.1+ defaults to off, but on a fresh box the value is **absent** — and absent means "whatever this build decided", which a GPO or an application can flip back. |
| **LLMNR + NetBIOS** | Both protocols broadcast *"who is FILESRV?"* to the whole segment and believe **whoever answers first**. That is exactly what Responder answers, collecting an NTLM exchange to crack or relay. DNS needs neither. NetBIOS is **per interface**, and `NetbiosOptions = 0` means "use the DHCP setting" (usually on) — all five interfaces on the runner shipped `0`. |
| **NTLM policy** | `LmCompatibilityLevel = 5` (NTLMv2 only, refuse LM and NTLMv1) plus `NoLMHash = 1`. An LM hash has no salt, uppercases the password and splits it into two 7-byte halves — it falls to brute force in minutes. |
| **Firewall posture** | All three profiles enabled with an **explicit inbound `Block`** and dropped-packet logging. Measured: the profiles were on but their default inbound action was `NotConfigured` — and "not configured" is not a policy, it means the answer comes from elsewhere and can change without anyone touching this machine. |
| **PowerShell logging** | Script-block (event **4104**) and module logging. An attacker's PowerShell never has to touch disk: it arrives over the network and runs from memory, so file-based forensics find nothing. Script-block logging records the code **after** any decoding or de-obfuscation. Both keys were absent on the runner: no logging at all. |
| **Password & lockout policy** | Minimum length 14, history 24, lockout after 5 attempts in a 15-minute window. Measured on the runner: **minimum length 0 and history 0** — a local account could have no password and reuse it forever. |
| **RDP posture** | NLA required (`UserAuthentication = 1`), TLS transport (`SecurityLayer = 2`), high encryption (`MinEncryptionLevel = 3`). **Without NLA, anyone who can reach 3389 talks to the pre-auth attack surface** — the logon screen renders and the BlueKeep class of bugs lived exactly there; with it, the client authenticates *before* any session exists. Whether RDP should be reachable at all is a business decision the script never makes — `fDenyTSConnections` is left alone; the step makes the session safe *when* the port answers. |
| **Audit policy** | Logons (success **and** failure — events 4624/4625), process creation **with the full command line** (4688 plus `ProcessCreationIncludeCmdLine_Enabled`, because a 4688 without arguments names the actor but not the act), and changes to the audit policy itself (4719 — the log records who turns the log off). `SCENoApplyLegacyAuditPolicy = 1` so the subcategories can't be silently overridden by legacy category policy. Steps 1–8 shrink the attack surface; this one makes whatever still happens **visible**. Subcategories are addressed **by GUID, never by name** — `auditpol` localizes the names, so `/subcategory:"Logon"` breaks on a non-English box — and read back through the backup CSV, the only interface with a numeric, locale-proof `Setting Value` column. |
| **AutoRun / AutoPlay** | The oldest trick on this list and still alive: a prepared USB stick, ISO or network share offering to run what's on it. Three machine-level policy values close the family: `NoDriveTypeAutoRun = 0xFF` (bit per drive type, **all eight set** — the OS default leaves several clear), `NoAutorun = 1` (autorun.inf is **never parsed** — the file that made the Conficker era), `NoAutoplayfornonVolume = 1` (no autoplay for MTP phones and cameras, the modern edge the two classics miss). The CI plants the classic weak `0x91` so the step provably tightens it, not just fills an absence. |
| **Attack-surface services** | Two services whose job description *is* the attack story, **stopped and disabled** — either alone leaks: a stopped service with StartType Automatic returns at the next boot, a disabled-but-running one keeps serving until then. **Print Spooler** runs as SYSTEM, accepts driver packages from callers, and gave the world PrintNightmare (CVE-2021-34527) — a server that never prints runs it anyway, because it ships enabled. **RemoteRegistry** hands a remote caller this machine's registry: reconnaissance as a service, on a box that has WinRM and PowerShell for real administration. The CI plants **both running with StartType Automatic** before hardening, and verify proves the lock behaviourally: `Start-Service` against the disabled Spooler must *throw*, and no `spoolsv.exe` process survives. Graded WARN (not FAIL) in the audit — a real print server is the legitimate niche. |

### Deliberately *not* in the baseline

Being explicit about the gaps is part of the design — `audit.ps1` grades these
so they stay visible, but the script never applies them silently:

- **UAC admin consent prompt** (`ConsentPromptBehaviorAdmin = 2`). Correct on an
  interactive workstation; on a machine with **no interactive session** (a CI
  runner, an unattended server) raising the prompt can hang anything that needs
  elevation. Same reasoning that keeps `noexec /tmp` out of the Bash sibling.
- **LSASS as a protected process** (`RunAsPPL`). A genuinely good control that
  needs a reboot and can break legacy SSO or AV agents — a decision for the
  admin, not a baseline default.
- **Defender real-time protection.** A CI image ships it off for build speed;
  forcing it there fights the platform. On a real server the audit's WARN is a
  real to-do.
- **SMBv1 removal.** The script grades it, but the CI image has it
  `DisabledWithPayloadRemoved`, so the harness **cannot plant the offender** and
  a check would only confirm a default. Said out loud rather than dressed up.

## How it's tested

The CI does what a reviewer would want to see done:

1. **Prints the starting posture** — the weak values are in the log, so the
   "after" means something.
2. **Plants the offenders that would otherwise be tautological.** Most are
   natural (SMB signing off, LLMNR on, no logging, password length 0), but two
   knobs already held a good value, so the CI sets `NoLMHash = 0` and
   `WDigest UseLogonCredential = 1` first — and the Azure-built runner image
   provisions RDP already configured, so the three RDP knobs are planted weak
   too, the three audit subcategories are planted to *No Auditing*, and
   `NoDriveTypeAutoRun` is planted at the classic weak `0x91`.
   A check that passes without the step doing anything proves nothing.
3. **Dry run changes nothing** — asserted against the planted values.
4. **First pass** hardens for real.
5. **Second pass must report `Changes applied: 0`** — the idempotence contract,
   machine-checked.
6. **`verify.ps1`** asserts the effective state (what the cmdlets and the OS
   report, not the files we wrote) plus two behavioural checks:
   - a **fresh** PowerShell process emits a unique marker and it must appear in
     event 4104. The engine reads the logging policy at startup, so an
     in-process check would be a lie;
   - three linked probes against a throwaway local account: creating it with
     **no** password must be refused (the 14-character minimum bites), the
     same account **with** a compliant password must be accepted, and
     changing that password to a 7-character one must be refused again —
     proving the policy is enforced at the point of use, not merely recorded;
   - a spawned process whose command line carries a unique marker must land
     in Security event **4688** *with the marker in the arguments* — one
     match proving both the subcategory and the command-line inclusion;
   - one deliberately failed network logon (a unique nonexistent user
     against `IPC$` on loopback — it *cannot* succeed and nothing leaves the
     host) must land in event **4625**.
7. **`audit.ps1`** scores the box; it fails the build only on `FAIL`, never on
   `WARN` (a warning is a to-do, not a broken build).
8. **Flag behaviour**: `-NoWDigest` must leave its planted offender alone while
   the rest of the baseline still applies.

`lint.yml` parses every script (the PowerShell equivalent of `bash -n`), runs
PSScriptAnalyzer, and enforces **pure ASCII**.

### Gotchas this harness caught on its first day

**A comment broke the parser.** This repo's very first CI run failed on a UTF-8
em dash *inside a comment*: Windows PowerShell 5.1 reads a `.ps1` without a BOM
as the system ANSI codepage, the character became mojibake and swallowed the
closing quote. Every script is pure ASCII now and the lint job fails on any byte
above 127, so it stays that way.

**A one-letter variable ate the score.** `audit.ps1` counted results in
`$Script:P` / `$Script:W` / `$Script:F` — and the firewall section's innocent
`$fwProfile = Get-NetFirewallProfile` was originally `$p`. PowerShell variable
names are **case-insensitive**, so `$p` *is* `$Script:P`: the PASS counter became
a CIM object, every later PASS threw *"The '++' operator works only on numbers"*,
and the final line printed `Score: MSFT_NetFirewallProfile (...) PASS, 4 WARN, 0
FAIL -> % compliant`. **The job still went green**, because the audit only fails
on `FAIL` — a green tick would have hidden it if nobody read the log. Fixed with
spelled-out counter names, and a type guard that now throws if a counter is not
an integer, so it can never fail quietly again.

**`net.exe` asks questions.** A 16-character probe password made `net user`
prompt *"Computers with Windows prior to Windows 2000 will not be able to use
this account. Continue? (Y/N)"*, and with no interactive stdin that surfaced as
`No valid response was provided` — indistinguishable, at a glance, from a policy
refusal. Fixed with a password of exactly 14 characters *and* `/y`, so neither
belt alone has to hold.

**The hardening broke its own test, and that became the test.** The first
`verify.ps1` created its throwaway probe account with a plain `net user /add`
— which makes an account with *no* password, exactly what the 14-character
minimum we had just applied refuses. The check failed because the policy
worked, so the refusal is now the first of three linked assertions.

**The probe that must fail poisoned the exit code.** Step 9's behavioural check
*needs* `net use` to fail — the failed logon **is** the check. But GitHub's
`powershell` shell appends `exit $LASTEXITCODE` to every step, so the probe's
non-zero rc outlived its own assertion: the run printed **"All checks passed"
and exited 1**. Both test scripts now end with an explicit `exit 0` — the exit
code is the script's verdict, never whatever the last native command left
behind. Same family as the two lessons below.

**`Write-Host` is not capturable.** The first e2e run failed its idempotence gate
while the script was *perfectly* idempotent — every step reported "already" and
the summary said `Changes applied: 0`. The bug was in the check: `Write-Host`
writes straight to the host and never enters the pipeline, so `$out = .\harden.ps1`
captured nothing and the regex matched nothing. The summary line now goes through
`Write-Output` as the script's machine-readable contract. Same family as the Linux
siblings' lesson about capturing the real exit code instead of the pipe's.

## Ground truth before promises

Every step above was designed against **measured behaviour** on a real Windows
Server 2025 runner, not assumptions: a probe job reported what the box actually
allows (registry writes, `Get-SmbServerConfiguration`, `auditpol`, `secedit`,
firewall cmdlets, Defender) and the current value of every candidate knob. That
evidence is what decided which steps are real, which offenders need planting,
and which candidates were dropped as unprovable here.

## Status

Early but honest: 11 steps, 39 verify checks (eight of them behavioural), a scored
audit, a scenario suite covering every `-No*` switch, and CI that hardens a real
Windows box on every push.

Current score on a freshly hardened CI runner:

```
 Score: 31 PASS, 4 WARN, 0 FAIL  ->  94% compliant
```

**94%, not 100%, on purpose.** The four warnings are the controls this baseline
declines to apply on a machine it does not own: LSASS protected process, Defender
real-time protection and PUA (off by design in the CI image), and the UAC consent
prompt. Padding the score by applying them blindly would make the number prettier
and the tool worse. On the roadmap: Defender PUA.

`test/scenarios.ps1` closes what used to be here: every `-No<Step>` switch is
proven twice — the skipped step leaves its knob exactly as planted, the rest of
the baseline still applies — and one closing full run repairs every planted
offender, so each step's reconcile-over-real-drift is exercised and the box
leaves as hardened as it arrived.

## License

MIT
