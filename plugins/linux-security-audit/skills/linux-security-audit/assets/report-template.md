# Linux security audit: <hostname>

**Date:** <YYYY-MM-DD>  **Distro/kernel:** <os> / <kernel>  **Role:** <what this host does>
**Collected as:** root | non-root (*checks marked NA were not determinable at this privilege level*)
**Baseline:** <CIS L1 / user's hardening guide / KSPP+CIS composite>
**Raw evidence:** `<path to collector output>`

## Summary

Two or three sentences: overall posture, the single most important thing to fix, and whether
anything suggests active compromise. No hedging: if the host is in decent shape, say so.

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
*investigate now*, not *harden later*: say what to check next, not just what to change.

## Collection quality; read before the findings

State the mode and its limits, because they decide which verdicts are trustworthy:

Every row below is printed by the collector in its `RUN_SUMMARY` section. Copy the values from
there rather than counting by hand or quoting a figure from the documentation, which drifts.

| | |
|---|---|
| Mode | live root / live non-root / `--root <path>` offline / container |
| Collector version | `collector_version` + `collector_sha256`: pins the report to a check set |
| Elapsed | `elapsed_seconds`, and `slowest_sections` if anything ran long |
| Checks by method | `method_counts`: `static` N, `runtime` N, `active` N |
| Undetermined | `undetermined_pct`: **NA is not a pass** |
| Truncated evidence | any raw list at exactly its cap (`head -N`) is incomplete; say which |

A `FAIL` from this collector means *checked and wrong*. A check whose prerequisite was missing
emits `NA` with the reason instead. If any check carries `:degraded` in its method field, or the
run was non-root or offline, **verify those specific findings against the target before reporting
them**: a manufactured finding costs more credibility than a missed one.

Known blind spots by mode: non-root cannot read `/etc/sudoers`, `/etc/shadow` or the firewall
ruleset; `--root` cannot see sysctls, listeners, processes, loaded modules or live TLS; a container
sees the host's kernel, not its own.

Under `--root`, `undetermined_pct` is typically well over half. That is the expected shape of an
offline audit, not a defect, but it means the report must lead with what was **not** covered. An
image that passes every check it was possible to run offline has not been shown to be hardened; it
has been shown not to be misconfigured in the ways a filesystem can reveal. Say that explicitly,
and pair the image audit with a run against a booted instance before signing anything off.

## Findings

Ranked by exploitability **on this host**, not checklist order. One block each:

### <N>. <Title>: <Critical|High|Medium|Low>

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
trade-off and a recommendation; do not report these as plain failures.

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

What this audit did not cover and why: e.g. kernel `CONFIG_*` build options (needs
`kernel-hardening-checker`), external TLS grading (needs `testssl.sh`/SSL Labs from outside),
application-level authorisation logic, provider-side firewall/security groups, backup restore
integrity, physical security. Plus anything that returned `NA` for lack of privilege.

## Suggested order of work

1. Immediate-attention items.
2. Zero-cost / zero-risk hardening (Phase 1 in `remediation.md`).
3. Application-affecting changes, tested individually.
4. Lockout-risk changes, with a second session open.
5. Boot-risk changes, scheduled with console access available.
