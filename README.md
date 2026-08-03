# windows-hardening

A **baseline hardening script for Windows Server / Windows 10-11 in PowerShell**,
with a test harness that proves it: CI hardens a real, disposable Windows runner,
runs the script twice to prove idempotence, and then verifies every promise from
the outside.

Sibling of [debian-hardening](https://github.com/DannyRuizB/debian-hardening)
(Bash) and [debian-hardening-ansible](https://github.com/DannyRuizB/debian-hardening-ansible)
(Ansible) — same discipline, the other operating system.

> Status: **bootstrapping.** The `probe` workflow is measuring what the runner
> actually allows before any step is written; every hardening step in this repo
> is designed against measured behaviour, never assumptions.
