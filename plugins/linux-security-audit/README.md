# linux-security-audit

A Claude Code plugin that audits how hardened a Linux system is and produces a
risk-ranked report — what to fix, in what order, with the exact change and its blast radius.

It is an auditing tool, not a hardening script. It changes nothing by default.

## Install

```
/plugin marketplace add jonaslejon/linux-security-audit-plugin
/plugin install linux-security-audit
```

Then ask Claude to audit a host, or point it at an image.

## What it looks at

249 checks across 31 areas, including:

- **Kernel** — sysctls, boot parameters, module blacklists, lockdown, CPU mitigations
- **Filesystem** — mount options (`nosuid`/`noexec`/`nodev`), SUID/SGID, capabilities, world-writable paths
- **Access control** — SELinux/AppArmor *confinement* (not just "enforcing"), sudoers, PAM, password and lockout policy
- **Privilege escalation** — `sudo` GTFOBins-capable grants and `env_keep`, writable systemd units, writable `PATH`, NFS `no_root_squash`, exposed credentials
- **Boot and service-start trust chain** — everything root reads on the way up: `EnvironmentFile`, `ld.so` search paths, udev `RUN`, plus what root processes currently hold open
- **Network** — firewall policy per direction including **egress**, listener/rule reconciliation, bind-address discipline, exposed services
- **TLS** — cipher and protocol validation by active probe, and whether mutual TLS is *enforced* rather than merely requested
- **Services** — SSH (public-key-only enforcement, forwarding channels, `Match` block overrides), web servers, databases, and insecure-by-default daemons
- **Secrets** — cleartext credentials and private keys on disk, **reported with values redacted**
- **Images and templates** — SSH host keys or entropy seeds baked into a golden image
- **Drift** — where persisted config and running kernel disagree, and in which direction

## Three collection modes

| Mode | How | What is valid |
|---|---|---|
| Live host | run it directly | everything |
| Mounted image | `--root /mnt` | configuration only; runtime checks report `NA` |
| Container | run inside it | container-level checks; host-owned ones report `NA` |

## The verdict model

Output is one line per check:

```
CHECK|<id>|<PASS|FAIL|WARN|INFO|NA>|<observed>|<why it matters>|<static|runtime|active>
```

Two rules the tool holds to:

- **`FAIL` means "checked, and it is wrong"** — never "could not determine". When a
  prerequisite is missing the check emits `NA` with the reason. A manufactured finding costs
  more credibility than a missed one.
- **`NA` is not a pass.** It is undetermined, and the report says so.

The method tag matters too: *not active* does not mean *works offline*. Roughly two thirds of
checks need a booted system.

## Side effects

Writes nothing by default. No config is modified, no service restarted, no package installed.

- Active checks open loopback connections (a TLS ClientHello, an HTTP HEAD to `127.0.0.1`) and
  query NTP peers. These appear in the audited service's own logs. `--passive` removes them.
- `--apt-update` is opt-in and off by default; it is the only thing that writes anything.
- Filesystem walks do read I/O proportional to disk size — use `--quick` on large storage.

A separate script, `lsa-trace.sh`, observes what root processes actually open at boot and
service start. It runs a preflight first and refuses rather than half-working when hardening
blocks it, because on a properly hardened host `ptrace_scope=3` and kernel lockdown are
supposed to stop exactly this.

## Relationship to CIS and STIG

Strong technical overlap, but this is **not a compliance tool** and emits no control IDs.
CIS and STIG produce pass/fail against a numbered control list for an auditor; this produces a
prioritised fix list. For compliance *evidence*, use OpenSCAP with the real datastream and run
this alongside for what a benchmark does not model — exploitability ranking, drift, secrets,
image hygiene, and local privilege-escalation chains.

## Licence

MIT — see [LICENSE](LICENSE).
