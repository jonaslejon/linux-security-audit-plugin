---
name: linux-security-audit
description: Audit a Linux host's security hardening posture and produce a risk-ranked report of what to fix. Covers the kernel and boot chain, filesystems and mount options, SELinux/AppArmor, accounts and sudo, SSH, firewall and exposed ports, TLS and mutual-TLS enforcement, web servers, insecure-by-default services, packages, logging and auditd, containers, and cleartext secrets on disk, combining passive config inspection, live runtime state and optional active probing. Use when asked to security-audit, hardening-review, CIS-check or harden a Linux server or web server, locally, over SSH, in a container, or against a mounted image, or to verify a specific hardening control is in place.
---

# Linux Security Audit

Audits how hardened a Linux system is and reports what to fix, in risk order, with the exact
change and its blast radius. Auditing is the default; **changing the system is a separate,
explicitly approved step**.

## What this does to the system

Designed to be run against production, so here is the precise inventory rather than a blanket
warning — an overstated caution just gets ignored.

**`scripts/lsa-collect.sh` writes nothing by default.** No config is modified, no service is
started, stopped or reloaded, no package is installed. Two side effects worth knowing:

- **Active checks open loopback connections** — a TLS ClientHello to each listening port and an
  HTTP HEAD to `127.0.0.1`, plus NTP peer queries. Harmless, but they appear in the audited
  service's *own logs* as connections from localhost. `--passive` removes them entirely.
- **`--apt-update` is opt-in and off by default.** It is the only thing that writes anything
  (refreshing `/var/lib/apt/lists`), and it exists only because verifying that every repo is
  signed requires it.

Load, not risk, is the real production consideration: the whole-filesystem walks (SUID,
world-writable, secrets) and package checksum verification (`dpkg --verify`, `rpm -Va`) do read I/O
proportional to disk size, and on a large host the package pass alone can run for minutes. Use
`--quick` to skip both on large or slow storage. The output header reports total elapsed time and
the slowest sections, so quote those rather than guessing.

**`scripts/lsa-trace.sh` is different and is deliberately kept separate.** `--live` is read-only,
but `--unit` restarts a service and `--boot arm` writes audit rules and needs a reboot. Every mode
runs `--preflight` first, prints exactly what it will do, and requires `--yes`. It refuses outright
rather than half-working when hardening blocks it.

So: run the collector on production. Run the tracer on a staging clone unless you have a specific
reason not to.

## Rules of engagement

1. **Read-only by default.** `scripts/lsa-collect.sh` changes nothing. Never apply hardening as
   part of an audit — collect, analyse, report, then ask.
2. **Confirm the target before touching it.** Name the host(s) and get a go-ahead before SSH-ing
   into anything the user did not explicitly point you at. Production hosts especially.
3. **No exploitation.** This is a configuration audit. Do not attempt privilege escalation,
   password cracking, or exploiting anything found.
4. **Know the execution context.** In a container the collector reports host-owned controls as
   `NA` with the reason, rather than describing the host and calling it the container. That covers
   `BOOT`, `KERNEL_MODULES`, `DISK_ENCRYPTION`, `USB` and `DRIFT`, and also the controls a container
   cannot implement at all: mount layout, firewall, time sync, file-integrity monitoring, core dump
   handling, and the interactive-login family (`TMOUT`, banners, password ageing, `cron.allow`).
   Measured on three production images, those alone were 49 of 55 non-`PASS` lines, which buried
   the three that were actionable.

   The same reasoning applies to hardware. `system.platform` reports physical, virtual or unknown,
   and the `USB` section is scored against it: a missing device policy is a `FAIL` on bare metal,
   a `WARN` on a guest that has a USB bus, and `NA` where there is no bus to defend. Do not
   reinstate a suppressed USB finding against a cloud instance because the control is missing;
   check `usb.context` first. Where the platform is `unknown` the finding is reported at `WARN`
   rather than dropped, and that one is worth resolving by hand, because an unrecognised machine
   is often a physical one running a distribution without `systemd-detect-virt`.

   When it is physical, recommend controls in the order that matches how they fail. **An
   allow-list beats a deny-list**, so `usb.restriction_present` only passes on a default-deny
   control: USBGuard with `ImplicitPolicyTarget=block` plus rules, `authorized_default=0`,
   `deny_new_usb`, or `nousb`. A `modprobe.d` blacklist is worth keeping as depth but is not the
   control, because it is only ever as complete as the list and a BadUSB device chooses which
   class it presents. Do not report a blacklisted host as hardened, and do not stop at "USBGuard
   is installed" either: check `usb.usbguard_rule_scope`, since an allow-list that admits an
   entire interface class has the same weakness as the deny-list it replaced.

   It further distinguishes **two kinds of container**, reported in `container.context`:

   - **workload** — PID 1 is the application. This is a deployed container, so its seccomp profile,
     `no_new_privs`, rootfs mode and namespaced sysctls are real findings about the deployment.
   - **inspection** — PID 1 is a shell, so the container exists only to read an image (`docker run
     -i <image> bash -s < collector`). Runtime posture here belongs to *your* `docker run`, not to
     the image, so it reports `NA`. What survives is genuinely image-level: `USER`, SUID binaries,
     baked `ENV` secrets, repo trust, package surface.

   When auditing an image, report the image-level findings and say explicitly that runtime posture
   was not assessed and must be read from the compose/swarm/k8s manifest instead.
5. **Never lock the user out.** Firewall, SSH, PAM, `noexec`, GRUB-password and `module.sig_enforce`
   changes can end a session or brick a boot. Every proposed change carries a rollback and a
   "test before you commit" step. See `references/remediation.md` → *Lockout-risk changes*.
6. **A missing control is a finding, not a failure of the machine.** Report what is true; state
   privilege limits plainly (a non-root run reports `NA`, which is not `PASS`).
7. **Confirm a finding before you report it.** The collector is a script, not an oracle. Spend one
   command checking a `FAIL` against the system rather than copying it into a report, because the
   cost of a manufactured finding is not the wasted hour, it is that the next real finding gets
   ignored. This is the single most productive habit when using this skill: it is how essentially
   every defect in the tool has been found. See *Verifying a finding* below for the classes that
   misfire and how to check each one.

## Workflow

### 1. Scope

Establish: which host(s), is root/sudo available, is it production, and is there a baseline to
audit against (CIS Level 1/2, a site-specific standard, "everything"). Default baseline is
`references/checklist.md`, which merges KSPP, CIS and madaidan's Linux hardening guide with
practitioner hardening practice.

### 2. Collect

Run the collector. It is one self-contained bash script — prefer it over dozens of ad-hoc
commands, both for speed and so nothing is silently skipped.

Locate the collector rather than assuming a path: it moves depending on whether the skill was
installed as a plugin, cloned as a marketplace, or dropped into `~/.claude/skills`.

```bash
# -L follows symlinks: a skill installed by symlinking into ~/.claude/skills is invisible without it
SK="$(find -L "${CLAUDE_PLUGIN_ROOT:-$HOME/.claude}" "$HOME/.claude/plugins" "$HOME/.claude/skills" \
        -name lsa-collect.sh -path '*linux-security-audit*' 2>/dev/null | head -1)"
[ -n "$SK" ] || echo 'collector not found — check the plugin is installed'

OUT=/tmp/lsa-<host>-$(date +%Y%m%d).txt      # or any working directory
```

```bash
# local
sudo bash "$SK" > "$OUT"

# remote (preferred: pipe the script in, leave nothing behind on the target)
ssh -p <port> <user>@<host> 'sudo bash -s -- ' < "$SK" > "$OUT"
# without sudo (many checks degrade to NA — say so in the report)
ssh -p <port> <user>@<host> 'bash -s' < "$SK" > "$OUT"

# container image. --entrypoint is required: without it, `bash` is passed as an ARGUMENT to the
# image's own entrypoint, which usually rejects it and exits 0, so you get a success and a report
# full of that program's usage text. --network none keeps the audit off the network.
docker run --rm -i --entrypoint bash --network none <image> -s -- --passive < "$SK" > "$OUT"

# a RUNNING container (its posture, not just its image)
docker exec -i <container> bash -s -- --passive < "$SK" > "$OUT"
```

The collector reports which of those two it is in `container.context`. Running an image gives an
*inspection* container: seccomp, `no_new_privs`, rootfs mode and namespaced sysctls then describe
the container you just started, not the image, so they report `NA`. Use `docker exec` against a
real workload when you need those.

```bash
# golden image / ISO / unbooted system — mount it and point --root at the mountpoint
mount -o loop,ro image.raw /mnt
sudo bash "$SK" --root /mnt > "$OUT"
```

**Use `--root`, never `chroot`, for an offline tree.** Inside a `chroot` the collector cannot tell
that it is offline: `systemctl`, `sudo -l`, `apachectl` and `/proc` reads return "absent" or "not
set" rather than failing, and the collector turns that into `FAIL` on controls that are actually
correct. `--root` makes the offline context explicit, so every check that needs a running kernel
reports `NA` instead. This is the difference between a thin report and a wrong one.

Flags: `--root PATH` audits a mounted filesystem offline and forces `--passive`. `--quick` skips
the whole-filesystem walks (SUID/SGID, world-writable, capabilities, package checksums) on big or
slow disks. `--passive` (alias `--no-probe`) disables every active check. `--out FILE` writes to a
file on the target instead of stdout. `--apt-update` opts in to refreshing the APT lists.

### Passive and active checks

The collector uses both, and tags every `CHECK` line with which produced it:

- **`static`** — reads files on disk only. These are the checks that work under `--root` against a
  mounted image: sudoers, secrets, module blacklists, log retention, cron, SSH config, package and
  repo trust.
- **`runtime`** — reads live kernel and process state: `/proc/sys` sysctls, `/proc/cmdline`,
  `lsmod`, `ps`, `ss`, `systemctl is-active`, `/proc/<pid>/fd`, or queries an installed binary
  (`nginx -V`). Safe on production and it touches no service, **but it is meaningless on an offline
  image** — under `--root` these report `NA`, they do not pass.
- **`active`** — interacts with a service or the network: local TLS handshakes, an HTTP request to
  loopback, `apt-get update`, NTP source queries, `sudo -l`. Suppressed by `--passive`.

The run's actual distribution is printed in the output header (`method_counts=`) along with total
elapsed time and per-section timings. Quote those numbers in the report rather than any figure from
this file, which will drift as checks are added.

**"Not active" does not mean "works offline."** Most of the check set needs a booted system, so an
image audit produces verdicts only for the `static` share. Say that in the report rather than
presenting a thin pass list as full coverage. Two consequences worth knowing: the `DRIFT` section
compares persisted config against running kernel and reports which way they disagree, so read it
before trusting any other `PASS`; and TLS cipher/protocol negotiation and genuine mutual-TLS
*enforcement* cannot be established from config at all, so under `--passive` mark those unverified
rather than passing. Both are covered in `references/checklist.md` and `references/tls-and-mtls.md`.

Always save raw output to a working directory and cite line numbers from it as evidence. Multiple
hosts: collect them all first, then compare — drift between supposedly-identical hosts is itself
a finding.

### 3. Analyse

The output has two kinds of content:

- `CHECK|<id>|<PASS|FAIL|WARN|INFO|NA>|<observed>|<note>|<static|runtime|active>` — deterministic
  checks. Grep these first: `grep '^CHECK|' $OUT | grep -v '|PASS|'`. Every record has exactly six
  fields: a `|` occurring inside a value is emitted as `%7C` so `awk -F'|'` stays correct. Linux
  `core_pattern` is the common case, since a leading `|` there means "pipe to this handler".
- `===== SECTION X =====` blocks of raw evidence — these need judgement (firewall rules, SUID
  list, running services, cron contents, sudoers). Read them; do not just count `FAIL` lines.

Statuses: `FAIL` = control absent or wrong. `WARN` = weaker than recommended or needs a human
call. `INFO` = reported for judgement, no verdict. `NA` = not applicable on this kernel/distro, or
not determinable at the privilege level used — **never report `NA` as compliant**.

`POLICY` in a note means the control has a real cost and the right answer depends on the host's
job. Do not report these as flat failures; report them as a decision with the trade-off stated.
The common ones: `icmp_echo_ignore_all` (breaks ping-based monitoring), `tcp_timestamps=0`,
`nosmt=force` (~big CPU loss on hyper-threaded hosts), `ipv6.disable=1`, `ip_forward` (required on
routers/NAT gateways/container hosts), `accept_ra=0` (breaks SLAAC-configured hosts),
`oops=panic`, `module.sig_enforce=1` (breaks DKMS/out-of-tree drivers), `lockdown=confidentiality`.

Consult the reference files for anything you are not certain about rather than guessing at what a
value means — several of these settings mean different things on different distros and kernel
versions (see `references/sysctl.md` → *Distro and version traps*).

### Verifying a finding

Before a `FAIL` or `WARN` goes in the report, confirm it. Some check classes misfire in ways that
look exactly like real findings, and each has a one-command test:

| Finding looks like | Why it misfires | Confirm with |
|---|---|---|
| A permission on `/bin`, `/sbin`, `/lib` or any path that may be a symlink | Every symlink is mode 0777; a check that does not dereference reports the link, not the target | `ls -ld <path>; stat -L -c '%a %U:%G' <path>`, then actually try to write as a non-root user |
| "X is not installed" or "no Y configured" | The tool may be looking on the wrong machine (offline mode), or the subsystem may not exist in this context at all | `command -v X` on the target itself; check `container.context` and whether the section should be `NA` here |
| A count taken from a command's output | An error message on the command's output stream gets counted as data | Re-run the command by hand and look at what it actually printed |
| A secret or credential | Key-name matching hits commented-out examples and public key material (a `GPG_KEY` in a base image is a published fingerprint, not a secret) | Open the file at the reported line. Is the line commented? Is the value a public fingerprint or digest? |
| A file mode reported as wrong | Stricter-than-expected modes are sometimes flagged because a check lists exact values instead of a rule (`0` is `000`, and `0550` is stricter than `0700`) | Reason about who actually gains access, not whether the mode matches a template |
| Anything about users, groups or homes | Group-readable is not exposure when the group is the user's own private group with no other members | `stat -c '%U %G' <home>; getent group <group>` |

If a check is wrong, say so in the report instead of quietly dropping it (silence teaches the
reader nothing), and open an issue at the repository. A misfiring check that nobody reports stays
misfiring for everyone.

### Triaging a container or image report

Findings from a container fall into three groups, and saying which is most of the value:

- **Image** — fixed in the `Dockerfile` and shipped by a rebuild: `container.runs_as_root` (add a
  `USER`), `container.suid_binaries`, `container.env_secrets`, `repo.*`, `packages.*`,
  `system.base_os*`, `perm.*`, `secrets.*`.
- **Deployment** — fixed in the compose file, swarm service or pod spec, and *not* defects in the
  image: `container.no_new_privs`, `container.readonly_rootfs`, `container.mac`,
  `container.privileged`, `container.seccomp`, and every namespaced `sysctl.*`. When the collector
  ran in inspection mode these are `NA`, because they described the container you started to read
  the image with.
- **Host or orchestrator** — reported `NA` with the reason: mount layout, firewall, time sync,
  auditd, remote logging, kernel currency, and the interactive-login family.

Say plainly which group each finding is in. "Your image runs as root" and "your deployment does not
set `no_new_privs`" go to different people and different files.

Then look for what the collector cannot judge alone:

- Correlate: `noexec` on `/tmp` + a service that writes executables to `/tmp`; a firewall that is
  "active" but has an `ACCEPT` default policy; `auditd` running with zero rules; AIDE installed
  with a database older than the last package update.
- Reconcile the listening-socket list against the firewall. Every `exposed.<port>` FAIL is only a
  real finding once you check whether a firewall or provider security group covers it — and every
  port the firewall *does* leave open should appear in the listener list. A service that could bind
  `127.0.0.1` instead is a better fix than a firewall rule.
- For web servers, the highest-yield questions are not header flags: is the document root writable
  by the worker user (webshell persistence), is `.git`/`.env`/a database dump sitting in the
  webroot, does `real_ip_header` lack `set_real_ip_from` (forgeable client IP defeats every
  rate limit and allowlist), and is the PHP/nginx/Apache version still supported.
- For TLS, separate *encrypted* from *authenticated*. An internal listener with no client-certificate
  requirement, `--tls` without `--tlsverify`, rsyslog `StreamDriverAuthMode` other than `x509/name`,
  `proxy_ssl_verify` left at its off default, or a `curl -k` in a cron job are all "TLS is on" and
  "nobody is authenticated" at the same time. `tls.*.mtls|WARN` — requested but not enforced — is
  the one people misread as compliant.
- For root processes, the finding is not the count. It is the specific process that is both root
  and reachable (`proc.root_listeners`), or the application daemon with no reason to be root
  (`proc.root_unexpected`). Name them individually with the least-privilege fix — `User=` or
  `DynamicUser=yes` in a unit drop-in, `CAP_NET_BIND_SERVICE` or socket activation instead of root
  for a low port.
- For logging, read retention and readability together. `logret.*` gives three independent limits
  (journald, logrotate, auditd) and the **shortest one wins** — quote the computed number of days,
  not the config. `logperm.logrotate_create|FAIL` explains why a previously "fixed" permission is
  wrong again: the mode reverts at every rotation. And members of `adm`/`systemd-journal` read every
  log without `sudo`, so they leave no sudo trail doing it.
- With SELinux enforcing, `mac.selinux_unconfined` matters more than the enforcing status itself:
  a process in `unconfined_t` gets no confinement at all, so "SELinux is on" and "this daemon is
  protected" are different claims. Same for `semanage permissive -l` domains, which are exempt while
  the system still reports Enforcing, and for AppArmor's unprofiled processes.
- Attack paths, not just missing settings. A world-writable script in `/etc/cron.d`, an unusual
  SUID binary, a `NOPASSWD` sudo rule, or docker-group membership each convert local access to
  root — say so explicitly and rank accordingly.
- Anything that looks like existing compromise (non-empty `/etc/ld.so.preload`, unexplained SUID
  binaries in `/tmp` or `/var`, unknown UID-0 accounts, recently modified system binaries) goes to
  the top of the report and gets flagged as *investigate now*, not *harden later*.

### 4. Report

Use `assets/report-template.md`. Rank by exploitability on this host, not by checklist order.
Every finding needs: what was observed (with evidence), why it matters here, the exact fix, and
what the fix might break. Include a short "already in good shape" list — it tells the user what
not to re-do, and it makes the report honest.

### 5. Remediate — only when asked

Get explicit approval, then work from `references/remediation.md`. Apply in the order given
there (lowest lockout risk first), keep every change in a drop-in file under `/etc/*.d/` rather
than editing distro-managed files, back up anything you overwrite, and re-run the collector
afterwards to prove the delta. For anything that only takes effect at boot (cmdline, fstab,
modprobe, GRUB password), state clearly that it is unverified until a reboot — and that a reboot
is the risky moment.

## Reference files

Load these on demand, not upfront:

- `references/checklist.md` — the full check catalogue: what each control does, how to verify it
  by hand, expected value, and its caveats. The authority for interpreting collector output.
- `references/sysctl.md` — every sysctl, what it defends against, and the distro/version traps.
- `references/boot-and-modules.md` — kernel cmdline parameters, module blacklisting, lockdown,
  Secure Boot, CPU mitigations.
- `references/webserver-and-ports.md` — listening-port exposure and the ports that must never be
  public; NTP/NTS security both as client and as a potential reflector; nginx, Apache, PHP, TLS
  certificate and webroot hardening.
- `references/tls-and-mtls.md` — cipher and protocol policy, why it needs active testing, and the
  per-service table of *which setting actually enforces peer verification* for mutual TLS.
- `references/services-ssh-logging.md` — SSH server/client hardening, systemd unit sandboxing,
  remote logging, auditd, file-integrity monitoring.
- `references/remediation.md` — ready-to-apply config templates and the safe order to apply them.
- `scripts/lsa-trace.sh` — runtime tracing of what root actually opens: `--live <secs>` (passive,
  bpftrace/opensnoop/fatrace), `--unit <name>` (restarts one service), `--boot arm`/`--boot report`
  (temporary auditd rules across a reboot). Not run automatically — the last two are disruptive.
- `assets/report-template.md` — report structure.
- `references/tooling-and-scope.md` — what else to run alongside (Lynis, OpenSCAP, `testssl.sh`,
  `kernel-hardening-checker`), the relationship to CIS and STIG, how this differs from Lynis and
  linPEAS, and the known coverage gaps to name in a report's *Not assessed* section.

**This is not a compliance tool and must not be presented as one.** It emits no control IDs, and
no check should be labelled with a CIS or STIG number: numbering varies by benchmark version and
distro, so asserting one from memory would be wrong too often. Use OpenSCAP with a real datastream
when the deliverable is an audit artifact. Details, and the comparison to other tools, are in
`references/tooling-and-scope.md`.

## Where this skill lives

Home, updates and issues: <https://github.com/jonaslejon/linux-security-audit-plugin>

Installed with `/plugin marketplace add jonaslejon/linux-security-audit-plugin` then
`/plugin install linux-security-audit`. If a check misfires — especially a `FAIL` that should
have been `NA` — that is worth reporting there, because a manufactured finding is the failure
mode this skill cares most about avoiding.
