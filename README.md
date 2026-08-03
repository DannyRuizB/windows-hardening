# windows-hardening

[![lint](https://github.com/DannyRuizB/windows-hardening/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/windows-hardening/actions/workflows/lint.yml)
[![e2e](https://github.com/DannyRuizB/windows-hardening/actions/workflows/e2e.yml/badge.svg)](https://github.com/DannyRuizB/windows-hardening/actions/workflows/e2e.yml)

A **baseline security hardening script for Windows Server / Windows 10-11**, in
PowerShell — with a harness that proves it. CI takes a disposable Windows Server
runner, **hardens it for real**, runs the script again to prove idempotence,
verifies every promise (including two behavioural checks) and scores the box
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
   `WDigest UseLogonCredential = 1` first. A check that passes without the step
   doing anything proves nothing.
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
     proving the policy is enforced at the point of use, not merely recorded.
7. **`audit.ps1`** scores the box; it fails the build only on `FAIL`, never on
   `WARN` (a warning is a to-do, not a broken build).
8. **Flag behaviour**: `-NoWDigest` must leave its planted offender alone while
   the rest of the baseline still applies.

`lint.yml` parses every script (the PowerShell equivalent of `bash -n`), runs
PSScriptAnalyzer, and enforces **pure ASCII**.

### Two gotchas this harness caught on its first run

**A comment broke the parser.** This repo's very first CI run failed on a UTF-8
em dash *inside a comment*: Windows PowerShell 5.1 reads a `.ps1` without a BOM
as the system ANSI codepage, the character became mojibake and swallowed the
closing quote. Every script is pure ASCII now and the lint job fails on any byte
above 127, so it stays that way.

**The hardening broke its own test, and that became the test.** The first
`verify.ps1` created its throwaway probe account with a plain `net user /add`
— which makes an account with *no* password, exactly what the 14-character
minimum we had just applied refuses. The check failed because the policy
worked, so the refusal is now the first of three linked assertions.

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

Early but honest: 7 steps, a verify suite with two behavioural checks, a scored
audit, and CI that hardens a real Windows box on every push. On the roadmap:
advanced audit policy (`auditpol` subcategories), AutoRun/AutoPlay, RDP posture
(NLA + encryption level), Defender PUA, and a dedicated scenario script for the
`-No*` switches.

## License

MIT
