# Linux security audit — <hostname>

**Date:** <YYYY-MM-DD>  **Distro/kernel:** <os> / <kernel>  **Role:** <what this host does>
**Collected as:** root | non-root (*checks marked NA were not determinable at this privilege level*)
**Baseline:** <CIS L1 / user's hardening guide / KSPP+CIS composite>
**Raw evidence:** `<path to collector output>`

## Summary

Two or three sentences: overall posture, the single most important thing to fix, and whether
anything suggests active compromise. No hedging — if the host is in decent shape, say so.

| Severity | Count |
|---|---|
| Critical | |
| High | |
| Medium | |
| Low | |
| Policy decision | |

## Immediate attention

Only if present: indicators of existing compromise or a directly exploitable exposure
(unauthenticated database/Docker API on a public IP, non-empty `/etc/ld.so.preload`, unknown UID-0
account, unexplained SUID binary, unknown cron entry, modified system binary). These are
*investigate now*, not *harden later* — say what to check next, not just what to change.

## Collection quality — read before the findings

State the mode and its limits, because they decide which verdicts are trustworthy:

| | |
|---|---|
| Mode | live root / live non-root / `--root <path>` offline / container |
| Checks by method | `static` N, `runtime` N, `active` N |
| `NA` count | N — **these are undetermined, not passes** |

A `FAIL` from this collector means *checked and wrong*. A check whose prerequisite was missing
emits `NA` with the reason instead. If any check carries `:degraded` in its method field, or the
run was non-root or offline, **verify those specific findings against the target before reporting
them** — a manufactured finding costs more credibility than a missed one.

Known blind spots by mode: non-root cannot read `/etc/sudoers`, `/etc/shadow` or the firewall
ruleset; `--root` cannot see sysctls, listeners, processes, loaded modules or live TLS; a container
sees the host's kernel, not its own.

## Findings

Ranked by exploitability **on this host**, not checklist order. One block each:

### <N>. <Title> — <Critical|High|Medium|Low>

- **Observed:** what the collector found, quoted, with the section it came from.
- **Why it matters here:** the concrete attack this enables, given what this host actually does.
  Not the generic textbook reason.
- **Fix:**
  ```bash
  # exact commands or config
  ```
- **Blast radius:** what this may break, and how to test before committing.
- **Rollback:** one line.
- **Verification:** the command that proves it worked.

## Policy decisions

Controls with a real cost, where the answer depends on how this host is used. Present the
trade-off and a recommendation — do not report these as plain failures.

| Control | Current | Benefit | Cost | Recommendation |
|---|---|---|---|---|
| `net.ipv4.icmp_echo_ignore_all` | | hides host from ping sweeps | breaks ICMP monitoring, MTU diagnosis | |
| `nosmt=force` / CPU mitigations | | closes cross-thread side channels | ~50% of logical CPUs | |
| `ipv6.disable=1` | | removes a whole unfirewalled stack | breaks anything using IPv6 | |
| `kernel.modules_disabled=1` | | blocks LKM rootkits | one-way; no module loading until reboot | |
| `noexec` on `/tmp`, `/var` | | blocks drop-and-run payloads | breaks Java, installers, Docker, some package hooks | |
| `module.sig_enforce` / `lockdown` | | root can no longer alter the kernel | breaks DKMS, perf, hibernation | |

## Already in good shape

Short list of controls verified present. This tells the reader what not to redo and keeps the
report honest.

## Not assessed

What this audit did not cover and why — e.g. kernel `CONFIG_*` build options (needs
`kernel-hardening-checker`), external TLS grading (needs `testssl.sh`/SSL Labs from outside),
application-level authorisation logic, provider-side firewall/security groups, backup restore
integrity, physical security. Plus anything that returned `NA` for lack of privilege.

## Suggested order of work

1. Immediate-attention items.
2. Zero-cost / zero-risk hardening (Phase 1 in `remediation.md`).
3. Application-affecting changes, tested individually.
4. Lockout-risk changes, with a second session open.
5. Boot-risk changes, scheduled with console access available.
