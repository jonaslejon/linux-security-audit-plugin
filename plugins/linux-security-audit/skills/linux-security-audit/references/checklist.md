# Check catalogue

The authority for interpreting collector output. Each entry: **what** the control does, **why** it
matters, **verify** by hand, **expect**, and caveats. Sections match the collector's
`===== SECTION =====` names.

Severity below is a *starting* rank. Adjust for the host: a missing GRUB password is near-irrelevant
on a cloud VM with no console access and critical on a laptop or colo box; `ip_forward=1` is a
finding on a web server and correct on a NAT gateway.

---

## SYSTEM

| Check | Why | Verify |
|---|---|---|
| Distro + version supported | An EOL release gets no security updates at all — this outranks every other finding | `cat /etc/os-release`, compare against distro EOL dates |
| Kernel version | Old kernels carry known local-privesc CVEs; the kernel is the one thing every other control depends on | `uname -r` vs distro's current |
| Reboot pending | Patched packages on disk ≠ patched code in memory. Livepatch is the exception | `/var/run/reboot-required`, `needrestart -b` |
| Kernel taint | Non-zero can mean out-of-tree/unsigned modules loaded | `cat /proc/sys/kernel/tainted` |

---

## FILESYSTEMS

**Mount options.** `nosuid` neutralises SUID/SGID bits on that filesystem, `noexec` blocks
executing files from it, `nodev` blocks device nodes. Together they remove the standard
post-exploitation pattern of *drop a payload in a writable directory and run it*.

Recommended `/etc/fstab` (from the user's guide; `/tmp` and `/var` shown as bind mounts, which is
what you use when they are not separate physical partitions):

```
/        /          ext4    defaults                              1 1
/home    /home      ext4    defaults,nosuid,noexec,nodev          1 2
/tmp     /tmp       ext4    defaults,bind,nosuid,noexec,nodev     1 2
/var     /var       ext4    defaults,bind,nosuid                  1 2
/boot    /boot      ext4    defaults,nosuid,noexec,nodev          1 2
proc     /proc      proc    nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
```

Also cover `/var/tmp`, `/dev/shm` (`nosuid,noexec,nodev` — a very common payload drop location),
`/var/log`, `/var/log/audit`, `/srv`.

Caveats worth stating in the report:
- `noexec` on `/var` breaks a lot (package hooks, Docker's `/var/lib/docker`, many app deploys) —
  which is why the baseline is `nosuid` only for `/var`.
- `noexec` on `/tmp` breaks Java, some installers, `pip`/`npm` builds, and `apt` hook scripts.
  Test, don't assume.
- `noexec` is not a hard boundary: an interpreter still runs a script (`sh /tmp/x.sh`,
  `python /tmp/x.py`), and `ld.so /tmp/binary` can bypass it. It raises cost, not a wall.
- Not having a separate filesystem at all is a real finding: without one, these options cannot be
  applied, and a full `/var/log` takes down the whole host.

**`/proc` with `hidepid`.** Without it, every local user reads every process's command line,
environment (`/proc/*/environ` — where secrets passed as env vars live), and open FDs.
`hidepid=2`/`invisible` hides other users' processes entirely; `gid=proc` exempts a monitoring
group. `hidepid=invisible` is the kernel ≥5.8 spelling; `hidepid=2` is still accepted. On systemd
≥247 the per-unit equivalent is `ProtectProc=invisible`.
Caveat: breaks tools that expect to see all PIDs (some monitoring agents, `pkill` behaviour for
non-root, systemd's own session tracking on old versions). Red Hat advises against it on RHEL7+.
Add monitoring users to the `proc` group rather than dropping the option.

---

## SYSCTL

See `sysctl.md` for the full table with rationale and distro traps. Note that a correct *running*
value with nothing in `/etc/sysctl.d/` means the setting is lost at reboot — check both:

```bash
sysctl -a 2>/dev/null | grep -E 'kptr_restrict|dmesg_restrict|...'   # running
grep -rhE '^\s*[a-z]' /etc/sysctl.conf /etc/sysctl.d/                 # persisted
```

**Core dumps** need all three mechanisms, because each covers a different path:

| Mechanism | Setting |
|---|---|
| kernel | `kernel.core_pattern=\|/bin/false` and `fs.suid_dumpable=0` |
| systemd | `/etc/systemd/coredump.conf.d/disable.conf` → `[Coredump]` / `Storage=none` |
| PAM limits | `/etc/security/limits.conf` → `* hard core 0` |

Why: a core dump of a privileged process writes its memory — private keys, credentials, decrypted
data — to disk as a world-readable-ish file, and `systemd-coredump` will happily ship it to the
journal. Cost: you lose crash forensics for your own debugging.

---

## BOOT

Kernel command line, GRUB password, Secure Boot, lockdown, CPU mitigations: see
`boot-and-modules.md`.

Quick manual verification: `cat /proc/cmdline`, `cat /sys/kernel/security/lockdown`,
`mokutil --sb-state`, `grep -r password_pbkdf2 /etc/grub.d/`.

**GRUB password.** Without it, anyone at the console/KVM/IPMI/serial adds `init=/bin/bash` and has
root without a password, or boots single-user. Only meaningful when physical or out-of-band console
access is possible — which includes cloud provider web consoles. Set `set superusers` plus
`password_pbkdf2` (generate with `grub-mkpasswd-pbkdf2`), and prefer `--unrestricted` on the normal
boot entry so a password is needed to *edit* but not to *boot* — otherwise unattended reboots hang.
systemd-boot equivalent: `editor no` in `loader.conf`.

**Disk encryption.** Protects data at rest against disk seizure, RMA'd drives, and (for cloud) a
snapshot or a compromised hypervisor storage layer. It does *not* protect a running system, and it
does not protect `/boot` without verified boot. Check for LUKS (`lsblk -o NAME,FSTYPE`), and check
swap separately — plaintext swap can page out keys.

---

## KERNEL_MODULES

`kernel.modules_disabled=1` blocks all further module loading and unloading, permanently, until
reboot. This is the single strongest anti-rootkit control on a Linux box: LKM rootkits (REPTILE,
Diamorphine, and the toolkits Mandiant documented for UNC3886) load as modules. Set it *last* in
boot, after every needed module is loaded, and understand it is one-way — no new hardware, no
DKMS rebuild, no `modprobe` until reboot.

Blacklisting (`install <mod> /bin/false` in `/etc/modprobe.d/`) covers the rest: obscure network
protocols and filesystems that are auto-loaded on demand by a packet or a mount and have a poor
CVE history. Full list and rationale in `boot-and-modules.md`.

Note the difference: `blacklist X` only stops *automatic* loading (a direct `modprobe X` still
works); `install X /bin/false` stops both. Use `install`.

---

## MAC_LSM

SELinux `Enforcing` or AppArmor with enforcing profiles. Without a MAC layer, a compromised daemon
has every right its UID has. `Permissive` is not protection — it logs and allows.

Verify: `getenforce` / `sestatus`, `aa-status`, `cat /sys/kernel/security/lsm`.

**"Enforcing" is not the same as "confined".** Three ways a system reports Enforcing while giving a
given process no protection at all — check all three:

1. **Unconfined domains.** A process running as `unconfined_t`, `unconfined_service_t` or
   `initrc_t` is permitted essentially everything DAC allows. This is the normal fate of anything
   started outside the targeted policy — a custom daemon, a hand-written unit, a binary in
   `/opt` with no file context. `ps -eZ` shows it; `ps -eZ | awk 'NR>1{n=split($1,a,":"); print a[3]}'
   | sort | uniq -c` gives the domain breakdown. The fix is a targeted policy module
   (`audit2allow`/`sepolicy generate`) or labelling the binary with a confined type — not
   switching to Permissive.
2. **Permissive domains.** `semanage permissive -l` lists domains individually exempted from
   enforcement. These usually survive from troubleshooting and are invisible in `getenforce`.
3. **Config vs runtime.** `/etc/selinux/config` may say `permissive` or `disabled` while the
   running system is Enforcing — the mode then does not survive reboot.

AppArmor's equivalent is a process with no profile attached. A stock Ubuntu enforces profiles for
only a handful of daemons, so custom applications are typically unconfined; `aa-status` reports the
count directly, and `/proc/<pid>/attr/current` reads `unconfined` per process. Profiles in
*complain* mode log violations and block nothing.

Report which network-facing services are actually confined — that is the question that matters, not
the global status line.

---

## SUID_SGID_CAPS

Every SUID-root binary is a potential local privesc. Audit the list against a known baseline, and
treat as findings: anything outside `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`; anything not owned by
a package (`dpkg -S <path>` / `rpm -qf <path>` returning nothing); and anything on
[GTFOBins](https://gtfobins.github.io/) that isn't needed (`pkexec`, `at`, `mount`, `umount`,
`chsh`, `chfn`, `newgrp`, `wall`, `write`).

Removing the SUID bit is usually done with `chmod u-s`; `dpkg-statoverride` (Debian) makes it
survive package upgrades.

File capabilities (`getcap -r /`) are the modern equivalent and are frequently missed — `cap_setuid`
or `cap_dac_override` on a binary is as good as SUID root.

World-writable directories without the sticky bit let any user delete or replace another's files.
World-writable files owned by root, and files with no owner (`-nouser`), are both classic
persistence footholds.

---

## PERMISSIONS

- `/root` → `700`. Home directories → `700` (default `755` on many distros lets every local user
  read every other user's files, SSH configs, and `.bash_history`).
- `/boot`, `/usr/src`, `/lib/modules` → `700` (madaidan's guide; hides kernel version/config detail
  used for exploit targeting). Low severity, low cost.
- `/etc/shadow` → `640 root:shadow` or stricter; `/etc/passwd` → `644 root:root`;
  `/etc/sudoers` → `440 root:root`.
- Default `umask 077` (or `027` where group collaboration is needed). Set in `/etc/login.defs`
  (`UMASK`), `/etc/profile`, and — for services — `UMask=` in the unit. `umask` in a shell rc only
  affects interactive shells.
- Sticky bit on `/tmp`, `/var/tmp`, `/dev/shm` (`1777`).

---

## USERS_AUTH

| Check | Expect |
|---|---|
| UID 0 accounts | exactly one (`root`) |
| Empty passwords | none (`awk -F: '$2==""' /etc/shadow`) |
| Root login | locked (`passwd -l root`) or key-only; `PermitRootLogin no` |
| Password hashes | yescrypt or sha512 with high rounds; flag md5/`$1$` |
| Shells | service accounts on `/usr/sbin/nologin` |
| `sudoers` | no `NOPASSWD` unless justified; `Defaults use_pty`, `Defaults logfile=`; no wildcards that expand to arbitrary commands; visudo-validated |
| Group membership | `docker`, `lxd`, `wheel`/`sudo` membership is root-equivalence — enumerate it |
| PAM | `pam_pwquality` (minlen ≥ 14), `pam_faillock`/`pam_tally2` lockout, `pam_wheel use_uid` on `su` |
| Aging | `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` in `/etc/login.defs` |
| Stale accounts | logins that no longer correspond to a person; check `last`, `lastlog` |

`docker` group membership deserves an explicit callout: `docker run -v /:/host` is trivially root
on the host. It is not "sudo-lite".

---

## SSH

See `services-ssh-logging.md`. The high-value items: key-only auth, no root login, a restrictive
`AllowUsers`/`AllowGroups`, modern KEX/cipher/MAC lists, weak DH moduli filtered
(`awk '$5 >= 3071' /etc/ssh/moduli`), and **distinct host keys per server** — cloned images that
share a host key mean one stolen key impersonates every host, and host-key pinning stops detecting
MITM. Compare fingerprints across hosts; identical ones are a finding.

Always read the *effective* config (`sshd -T`), not the file — drop-ins in `sshd_config.d/` and
`Match` blocks change the answer, and on Debian/Ubuntu the first matching directive wins so an
`Include` at the top of the file overrides everything below it.

---

## FIREWALL

Check that one is active *and* what its default policy is — an "active" firewall with
`-P INPUT ACCEPT` and no rules protects nothing. Enumerate what is allowed from where, and
reconcile it against the listening-socket list: anything listening on a public interface that the
firewall does not restrict is live attack surface.

Cloud hosts: local firewall and provider security group are two layers; audit both, and note when
the host relies entirely on the provider's ACL (works, but one console mistake removes it).

`fail2ban` (or equivalent) matters for anything with a public SSH/web login.

---

## NETWORK

Every non-loopback listener is attack surface. For each: which process, does it need to be public,
could it bind `127.0.0.1` instead. Databases, admin panels, metrics exporters, container APIs and
`docker.sock` over TCP are the usual offenders. The collector emits an `exposed.<port>` FAIL for a
list of services that should essentially never face the internet — see
`webserver-and-ports.md` → *Listening ports* for that list and what each exposure leads to.

IPv6: either configure and firewall it, or disable it (`ipv6.disable=1` as a boot parameter is the
thorough way; the `net.ipv6.conf.all.disable_ipv6` sysctl leaves the stack loaded). The failure
mode to look for is IPv6 *up and reachable* but the firewall rules only written for IPv4.

---

## SERVICES

- What is running, what is enabled, and can any of it be removed. Unused daemons are pure risk.
- `systemd-analyze security <unit>` scores each unit's sandboxing 0.0–10.0; anything critical
  scoring `UNSAFE`/`EXPOSED` is worth hardening (see `services-ssh-logging.md` for the directive
  set). The score is a heuristic about *systemd settings only* — it says nothing about the
  application's own security.

### Process privilege audit

Every process should run as the least-privileged user that still works. Root is the default that
nobody revisited, and each root process is a full-host compromise if it is exploited.

Exclude kernel threads (`ppid` 2, or a bracketed name) — they are root by definition and are not
findings. Of what remains:

- **Standard root infrastructure** — `systemd` and its helpers, `udevd`, `sshd`'s privileged
  listener, `cron`, `auditd`, `dbus`, `containerd`/`dockerd`, agents that genuinely need host-wide
  access. Expected; note and move on.
- **Application daemons running as root** — the actual finding. A web app, worker, script, exporter
  or vendor agent almost never needs it. The fixes, in order of preference: `User=`/`Group=` in a
  systemd drop-in; `DynamicUser=yes` for stateless daemons (systemd allocates a transient UID);
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` or socket activation instead of root for a port below
  1024; `CapabilityBoundingSet=` to strip everything else.
- **Root *and* network-facing** — rank this highest. A remote bug in a root-owned listener is
  immediate root, with no escalation step. Cross-reference the listener list against process owners.
- **Capabilities and `NoNewPrivs`** — `/proc/<pid>/status` shows `CapEff` and `NoNewPrivs` per
  process (`capsh --decode=<CapEff>` to read it). A non-root process holding `CAP_SYS_ADMIN`,
  `CAP_DAC_OVERRIDE` or `CAP_SETUID` is effectively root; a root process that has dropped to a
  minimal `CapEff` is genuinely reduced.

Report named processes with their specific fix, not a count.
- Containers: privileged containers, host networking, host PID namespace, `/var/run/docker.sock`
  mounted into a container (= container escape to root), unauthenticated Docker TCP socket.

---

## PACKAGES

Minimise: every installed package is attack surface and patch burden. Enumerate with
`dpkg-query -W` / `rpm -qa` / `apk info` and question anything not needed on a server — compilers
and interpreters, X11/desktop, `telnet`, `rsh`, `tftp`, `xinetd`, NIS, `avahi`, `cups`, an FTP
server, a second web server.

Patch state matters more than package count: pending *security* updates are a live finding, with
the specific CVEs where you can get them (`debsecan`, `dnf updateinfo list security`). Check
whether unattended/automatic security updates are configured, since that determines whether this
finding recurs.

### Repository signature verification

The package manager installs code that runs as root. If signatures are not verified, a compromised
mirror, a hijacked vendor domain, or an on-path attacker gets root on every host that runs an
update — and the machine does it willingly, on a schedule. This is a supply-chain control, and it
belongs near the top of any audit.

**RPM / dnf / yum** — inspect `/etc/yum.repos.d/*.repo` and confirm `gpgcheck=1` for **every**
repository, not just globally:

```bash
grep -rn 'gpgcheck\|^\[' /etc/yum.repos.d/            # per-repo, the value that actually applies
grep -E '^\s*(gpgcheck|localpkg_gpgcheck|repo_gpgcheck)' /etc/dnf/dnf.conf /etc/yum.conf
rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION} %{SUMMARY}\n'   # who is trusted to sign
```

Key points:
- **Per-repo `gpgcheck` overrides the `[main]` value.** A correct global setting proves nothing —
  a single third-party repo with `gpgcheck=0` reopens the whole hole. The collector reports each
  section separately and flags only *enabled* repos with `gpgcheck=0`.
- `gpgcheck=1` verifies **package** signatures. `repo_gpgcheck=1` additionally verifies the
  repository *metadata* signature, which is what stops metadata replay/downgrade; enable it where
  the repo signs its metadata.
- `localpkg_gpgcheck=1` covers manually supplied `.rpm` files, which default to unverified.
- A repo with no `gpgkey=` can only verify if its key is already in the RPM keyring — check it is.
- `sslverify=0` on a repo disables TLS validation of the mirror.
- Every imported `gpg-pubkey` is a party trusted to ship root-run code on this host. Remove keys
  for repos no longer in use.

**APT / Debian / Ubuntu** — the equivalents of `gpgcheck=0` are:
- `deb [trusted=yes] …` in a `.list` file, or `Trusted: yes` in a deb822 `.sources` file — this
  disables signature verification for that source entirely.
- `APT::Get::AllowUnauthenticated "true"` or `Acquire::AllowInsecureRepositories "true"` in
  `/etc/apt/apt.conf.d/` — disables it globally.
- `Acquire::https::Verify-Peer "false"` — disables TLS validation.
- A third-party source **without** `signed-by=` : its key sits in the global keyring (or the
  deprecated `/etc/apt/trusted.gpg`) and is therefore trusted to sign *any* package from *any*
  repository — so that vendor can silently replace a core distro package. Every third-party source
  should pin its key: `deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://…`.
- Expired repository keys cause updates to fail silently or be skipped; check key expiry.

**Update servers must be `https://`.** Signatures protect *integrity*, so plaintext is not remote
code execution on its own — but that is the only thing signatures buy you here, and two real
attacks remain:

- **Inventory disclosure.** An on-path observer reads the exact package and version list the host
  fetches, which is a ready-made map of which CVEs apply to it. That is reconnaissance handed over
  for free, and on a shared or hostile network it is passive.
- **Freeze / replay.** An attacker who can serve a stale but still-validly-signed `Release` file
  withholds security updates — the host keeps reporting "no updates available" while remaining
  vulnerable. `Valid-Until` bounds the window but does not close it, and `Check-Valid-Until "false"`
  removes even that bound.

Every major distro serves HTTPS on its official mirrors, so there is no cost to switching. Use
HTTPS **and** signature verification — neither substitutes for the other. Also confirm
`Acquire::https::Verify-Peer` has not been set to `false`, which turns the HTTPS back into
unauthenticated transport.

---

## TLS

Cipher suites, protocol versions, certificate quality, and mutual-TLS enforcement on internal
tunnels: see `tls-and-mtls.md`. The key distinction when reading results is *encrypted* versus
*authenticated* — an internal endpoint that does not require a client certificate, or a client with
verification switched off, is encrypted against a passive eavesdropper and open to an active one.

This section is where passive and active checks diverge most: what a server actually negotiates
cannot be read off its config, and "requests a client certificate" cannot be distinguished from
"requires one" without connecting.

## WEBSERVER

nginx, Apache, PHP, TLS certificates, security headers and webroot exposure: see
`webserver-and-ports.md`. Audit the **effective** config (`nginx -T`, `apachectl -S` + `-M`), not
the vhost file — includes and drop-ins are where the surprises are.

The ranking that matters: an EOL PHP/nginx/Apache version and a webroot writable by the worker user
outrank every missing response header. `.git/` or `.env` in the docroot is fully automated by
scanners and should be treated as urgent.

## TIME

Wrong time invalidates certificate checks, TOTP, Kerberos, and — critically for an audit — the
ordering and credibility of logs. Check a sync daemon is active *and synchronised*
(`timedatectl show -p NTPSynchronized`). Prefer NTS (authenticated NTP, chrony `nts` option); plain
NTP is spoofable by anyone on the path. Separately, check the host is not itself an open NTP server
answering control queries — see `webserver-and-ports.md` → *NTP security* for both directions.

---

## LOGGING

Local-only logs are deleted by whoever gets root. Off-host forwarding is what makes an incident
reconstructable. Check: forwarding configured, destination reachable, and the transport
authenticated + encrypted (rsyslog `omfwd` with `StreamDriver="gtls"` and
`StreamDriverAuthMode="x509/name"`, or syslog-ng TLS). Also check retention, log file permissions,
and that the journal is persistent (`Storage=persistent`) rather than lost on reboot.

`auditd` gives syscall-level attribution (execve, file access, privilege change). Running with an
empty ruleset is a common false comfort — verify `auditctl -l` returns rules, and that
`-e 2` (immutable) is used where appropriate.

### Retention — how far back can an incident be reconstructed?

Breaches are typically discovered weeks to months after the fact. Retention shorter than the
detection gap means the evidence is already deleted when you go looking. Three independent
mechanisms each impose their own limit, and the shortest one wins:

| Mechanism | Setting | Trap |
|---|---|---|
| **journald** | `MaxRetentionSec`, `SystemMaxUse`, `SystemMaxFileSize`, `MaxFileSec` | With `MaxRetentionSec` unset (the default) retention is bounded by **size, not time** — so the window silently shrinks exactly when the system gets noisy, which is during an attack. `Storage=volatile` (or a missing `/var/log/journal`) means the journal lives in `/run` and is **erased at every reboot** |
| **logrotate** | `rotate N` × frequency, `maxage` | Effective days = `N` × (1/7/30/365 for daily/weekly/monthly/yearly), capped by `maxage`. Debian's default `weekly` + `rotate 4` is **28 days**. Per-file blocks in `/etc/logrotate.d/` override the global, so check `auth.log` specifically rather than trusting `/etc/logrotate.conf` |
| **auditd** | `num_logs` × `max_log_file`, `max_log_file_action` | A **byte budget, not a time period**. `max_log_file_action=ROTATE` deletes the oldest log when full — so a high-volume attack overwrites the record of itself. `ignore`/`suspend` are worse: auditing stops silently and an attacker can blind auditd by generating volume. `keep_logs` retains everything, provided the partition cannot fill |

Compute the number and compare it against policy. Common floors: 90 days as a practical minimum,
PCI DSS 1 year with 3 months immediately available. Also check `wtmp`/`btmp` (login history), which
rotate on their own schedule.

The retention that ultimately matters is the **collector's**, not the host's — anyone with root
deletes local logs regardless of these settings. This cannot be verified from the audited host;
confirm it separately and say so in the report.

### Who can read the logs?

Logs are reconnaissance material even when they hold no credentials: usernames, source IPs,
internal hostnames, file paths, software versions, and cron command lines. And they frequently do
hold credentials — a password typed at a username prompt is recorded verbatim in `auth.log`/`btmp`.
A compromised low-privilege service account reading these gets a map of the host and often a
working login.

Check:

- **World-readable files under `/var/log`** (`find /var/log -type f -perm -004`). Use POSIX `-print`,
  not GNU `-printf` — a find that lacks `-printf` returns nothing and produces a false pass.
- **The sensitive ones specifically**: `auth.log`/`secure`, `sudo.log`, `btmp`, and
  `audit/audit.log` (which should be `0600 root:root`).
- **`logrotate`'s `create` mode.** This sets the permissions of every *future* rotated file, so a
  `create 0644` line silently reverts any manual `chmod` at the next rotation. This is the usual
  reason "we fixed that" doesn't stick.
- **`rsyslog`'s `$FileCreateMode`.** Unset means `0644` — world-readable by default.
- **Group membership**: members of `adm` and `systemd-journal` read all system logs without `sudo`,
  and therefore without leaving a sudo audit trail. Enumerate and justify each account.
- **journald ACLs** on `/var/log/journal` (`getfacl`) — these grant read access beyond the file mode.
- **Application logs outside `/var/log`.** A `.log` file inside a webroot is both world-readable and
  *servable over HTTP*, which is strictly worse.

---

## INTEGRITY

### Package file verification

The cheapest tamper check on a packaged system: every distro records a checksum for each file it
ships, so ask the package manager whether the files on disk still match.

| Distro | Command | Notes |
|---|---|---|
| Debian/Ubuntu | `dpkg --verify` | **Built into dpkg ≥1.17 — no extra package needed.** Flags `??5??????`, `c` marks a conffile |
| Debian/Ubuntu | `debsums -c` | Cross-check. Covers only packages that shipped md5sums — `debsums -l` lists the ones that did not, which is a real coverage gap |
| RHEL/Fedora | `rpm -Va` | `S`ize `M`ode `5`digest `D`evice `L`ink `U`ser `G`roup `T`ime `P`capabilities |
| Alpine | `apk audit --system` | |

**Split config drift from binary tampering — this is what makes the output usable.** A modified
conffile under `/etc` is ordinary administration and will be present on every real host; reporting
those as findings buries the one that matters. A modified file under `/usr/bin`, `/usr/sbin`,
`/lib`, `/usr/lib`, `/lib64` or `/boot` is a **possibly backdoored binary until explained**.

For a changed binary, investigate before repairing: compare against a freshly downloaded package
(`apt-get download <pkg>`, `dnf download <pkg>`), check the file mtime against the package install
time, and check whether the package was legitimately reinstalled or locally patched. **Do not just
reinstall the package** — that destroys the evidence.

Also report separately:
- **Missing packaged files** — a broken upgrade, a manual deletion, or an attacker removing
  something inconvenient (an auditd rule, a log, a binary replaced at a different path).
- **Mode / owner / capability changes** (`rpm -Va` `M`/`U`/`G`/`P` flags) — content unchanged but a
  setuid bit or file capability was added or removed on a packaged binary.

**Trust boundary, and say it in the report:** verification reads the same package database an
attacker with root can rewrite (`/var/lib/dpkg/info/*.md5sums`, the rpm DB). A clean result proves
the absence of *opportunistic* tampering, not the absence of a competent intruder. Closing that gap
needs an off-host AIDE database, dm-verity, or comparison against freshly downloaded packages.

Verification is I/O-bound (it hashes every packaged file), so it is skipped under `--quick`.

AIDE / Tripwire / Samhain / OSSEC-Wazuh: detects a modified binary, a new SUID file, an altered
config. Two things make or break it: the database must be **rebuilt after legitimate changes and
stored off-host or read-only** (an attacker with root updates it otherwise), and the reports must
actually be read by someone. An AIDE install whose DB predates the last `apt upgrade` produces
noise nobody reads — report that as ineffective, not as present.

---

## SCHEDULED_TASKS

A root cron job is a scheduled root shell. It does not need to *execute* something a user
controls — reading, sourcing or archiving it is enough. Four distinct routes, all checked:

1. **The script is writable.** Obvious, and usually the only thing people check.
2. **A directory on the script's path is writable.** The script itself can be root-owned `0644`
   and still be trivially replaced if any parent directory is writable — delete and recreate. The
   audit walks the whole path and reports the *most severe* issue found on it, because a weak
   signal on the file (non-root owner) would otherwise mask a world-writable parent.
3. **The job reads or sources data a user controls.** A root job that does `. /opt/app/env.conf`
   or `awk -f /srv/x.awk` executes whatever is in that file. The audit follows one level into
   referenced scripts to find what *they* source.
4. **Glob expansion in a user-writable directory.** `tar cf backup.tar *` in a directory a user can
   write becomes argument injection — they create a file named `--checkpoint-action=exec=sh x.sh`
   and tar runs it as root. Same class for `rsync -e`, `chown --reference`, `find`.

Plus: cron's own `PATH` (a writable or relative element hijacks any command called by bare name),
the permissions of `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}` and
`/var/spool/cron` (write access to any of these schedules a root command outright), unknown or
`@reboot` entries as compromise indicators, and `/etc/cron.allow` existing as an allow-list rather
than relying on the `cron.deny` deny-list. `systemctl list-timers --all` covers the systemd
equivalents — a timer whose unit has no `User=` runs as root and gets the same analysis.

## INSECURE_SERVICES

Services that are cleartext by design, or that ship with an insecure default most installs never
change. Each is reported as **installed / enabled / listening / listening-public** — an installed
but inert package is a different finding from a live listener, and saying so keeps the report
honest.

Cleartext and legacy: `telnet`, `rsh`/`rlogin`/`rexec`, `ftp`, `tftp`, `finger`, `talk`, NIS,
`rpcbind`, `avahi`, `cups`, `xinetd`/`inetd`, `squid`, `snmpd`, `memcached`, VNC, `dhcpd`. For the
super-servers, check what they actually start: `disable = no` in `/etc/xinetd.d/*` and the enabled
lines in `/etc/inetd.conf`, plus active systemd `.socket` units.

**rsync daemon** — the highest-yield of these and almost never audited. Per module, check:
- `read only = no` with **no `auth users`** → anonymous write into that path from anyone who can
  reach tcp/873. If the path is served by a web server or read by a cron job, that is RCE; if
  `uid = root`, it is arbitrary file write as root.
- No `auth users` at all → the module is world-readable; the daemon protocol is unauthenticated by
  default.
- No `hosts allow` → no source restriction.
- `uid = root` → every operation is root-level.
- `use chroot = no` → symlinks inside the module escape it.
- `secrets file` must be `0600` (it holds cleartext passwords).

**FTP** — `anonymous_enable`, and especially `anon_upload_enable`/`anon_mkdir_write_enable`
(unauthenticated file upload); `ssl_enable` without `force_local_logins_ssl`/`force_local_data_ssl`
means TLS is available but not required, so clients still send credentials in the clear;
`chroot_local_user` off lets authenticated users browse the whole filesystem. proftpd:
`<Anonymous>` blocks, `TLSEngine on`, `DefaultRoot ~`.

**TFTP** — no authentication and no encryption at all. The `-c`/`--create` option additionally
allows unauthenticated *upload*.

**Samba** — `guest ok`/`public = yes`, `map to guest = bad user` (unknown users silently become
guest instead of being rejected), `min protocol` allowing SMB1/NT1 (the EternalBlue protocol),
`null passwords = yes`, signing not mandatory (SMB relay), and no `hosts allow`.

**Mail** — `mynetworks` containing `0.0.0.0/0` is an open relay and will be found within hours;
`smtpd_sasl_auth_enable` without `smtpd_tls_auth_only` offers SMTP AUTH over cleartext. Dovecot:
`disable_plaintext_auth = yes` and `ssl = required`.

**Others** — LDAP anonymous bind, BIND `recursion yes` with no `allow-recursion` (open resolver:
amplification DDoS plus cache poisoning) and `allow-transfer { any; }` (full zone AXFR = a map of
your infrastructure), Squid `http_access allow all` (open proxy used to pivot and to launder
traffic through your IP), memcached without `-U 0` (>50000x UDP amplification) or not
loopback-bound (no authentication by design), mosquitto `allow_anonymous true`, and an X server
listening on tcp/6000.

---

## PRIVESC_PATHS

The chain from "code execution as a normal user or a service account" to root. This is what an
attacker enumerates immediately after a web shell, so it is what the audit should enumerate first.

**sudo.** Beyond `NOPASSWD`, four configuration details each hand out root outright:
- `env_keep` containing `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5LIB` or `RUBYLIB` —
  the caller loads their own library into a root process. Unconditional root shell.
- Missing `env_reset`, or missing `secure_path` — sudo then uses the caller's `PATH`, so a
  writable directory in it becomes root code execution.
- Command specs pointing at anything on [GTFOBins](https://gtfobins.github.io/) — `find`, `vi`,
  `less`, `awk`, `env`, `python`, `systemctl` all spawn a shell. Granting them equals granting `ALL`.
- Negation rules (`ALL, !/bin/su`) — bypassed by copying or symlinking the binary. They restrict
  nothing while looking restrictive.
- Also record the sudo **version** against CVE-2021-3156 (Baron Samedit, <1.9.5p2), CVE-2019-14287
  (`Runas -1`, <1.8.28), CVE-2023-22809 (sudoedit `EDITOR`), CVE-2025-32463 (chroot, <1.9.17p1).

**sudoers hygiene**, separately from the grants: `/etc/sudoers` and every `sudoers.d` file must be
`0440 root:root` (writable = direct root grant); `visudo -c` must pass; and these `Defaults` each
weaken authentication — `timestamp_timeout=-1` (credential cache never expires), `!tty_tickets`
(the timestamp is shared across the user's terminals, so another process in another TTY inherits
the authentication), `pwfeedback` (CVE-2019-18634, a stack overflow reachable by any local user on
sudo < 1.8.31), and `rootpw`/`targetpw` (which usually means a shared root password).

**GTFOBins grants.** The audit groups matched commands by *escalation primitive*, so the report can
say why each is root rather than just naming it:

| Group | Examples | Why it is root |
|---|---|---|
| shell | `sh`, `env`, `nice`, `timeout`, `xargs`, `find`, `screen`, `tmux`, `socat`, `make` | spawns or wraps a shell directly |
| editor/pager | `vi`, `less`, `more`, `man`, `sed`, `ed`, `jq` | escapes to a shell (`:!sh`) |
| interpreter | `python`, `perl`, `ruby`, `awk`, `lua`, `node`, `php`, `gdb` | executes arbitrary code by definition |
| file write | `dd`, `tee`, `cp`, `tar`, `rsync`, `openssl`, `curl`, `wget`, `xxd` | overwrite `/etc/shadow`, `/etc/sudoers`, a cron file or a unit. `tar`/`rsync` also execute via `--checkpoint-action` / `-e` |
| admin | `systemctl`, `service`, `docker`, `apt`, `git`, `mount`, `chmod`, `chown`, `pkexec` | run other programs as root (hooks, `-exec`) or change privilege state directly |

Also flag: wildcards in the argument list (`systemctl restart *` takes a path, `../` traverses),
`SETENV:` (caller sets any environment variable for the root command), and a grant ending in `/`,
which matches every executable in that directory.

**PATH.** A writable, world-writable, empty (`::`) or relative (`.`) element means an attacker
plants a binary that a higher-privileged user later runs by name.

**Writable systemd units and their binaries.** A group- or world-writable `.service` file — or a
writable `ExecStart` binary, or either not owned by root — is root at the next start or reboot.
Same logic as writable cron scripts, and more often missed.

**NFS exports.** `no_root_squash` is a one-line total compromise: any client that can mount the
export writes files as real root, so they mount it, drop a SUID root shell, and run it. Also flag
exports to `*` and the `insecure` option. On the client side, check what this host mounts.

**Credentials at rest.** Private keys (`~/.ssh/id_*`), `.netrc`, `.pgpass`, `.git-credentials`,
`~/.aws/credentials`, `~/.docker/config.json`, `~/.kube/config` — anything not `600`/`400` is
readable by other local accounts. Note which SSH private keys are **unencrypted** (no passphrase),
since those are usable the moment they are copied. `.rhosts`/`hosts.equiv` are host-based trust
without authentication and should not exist.

**Shell history.** Two different findings live here. `~/.bash_history` symlinked to `/dev/null`, or
`HISTFILE=/dev/null`/`HISTSIZE=0` in a profile, is deliberate anti-forensics — treat it as a
compromise indicator until explained. Separately, history files routinely contain passwords passed
on the command line; count pattern matches rather than printing the values.

**binfmt_misc.** Registered handlers map a file signature to an interpreter that runs on `execve`.
Legitimate for qemu/wine, but also a quiet execution and persistence vector.

**Compilers.** `gcc`/`clang` on a production server let an attacker build a local privesc exploit
in place. Remove, or restrict to a group.

## DATA_SERVICES_AUTH

The `TLS` section covers whether the transport is protected. This covers whether anything checks
*who is connecting* — the two are independent, and encrypted-but-unauthenticated is the common
result.

| Service | The finding |
|---|---|
| **Redis** | No `requirepass` and no `aclfile`. An unauthenticated Redis is a reliable RCE: set `dir`/`dbfilename` and write an SSH key or cron entry. Also check `protected-mode no`, a non-loopback `bind`, and whether `CONFIG` has been renamed |
| **MongoDB** | `authorization` not `enabled` — full read/write of every database to anyone who connects. The single most-ransomed database misconfiguration |
| **MySQL/MariaDB** | `skip-grant-tables` (all authentication off), `local-infile=1` (turns SQLi into arbitrary file read), a world-readable `.my.cnf`/`debian.cnf` containing a password |
| **PostgreSQL** | `trust` in `pg_hba.conf` — any connection is accepted as any user with no password. Prefer `scram-sha-256` over `md5` |
| **Elasticsearch** | `xpack.security.enabled` not true — every index readable and writable |
| **SNMP** | `rocommunity public` / `rwcommunity private`. Community strings are passwords and the defaults are the first thing any scanner tries; v1/v2c sends them in cleartext. `rwcommunity` allows reconfiguring the device |

## SECRETS

**Values are never printed.** The collector reports file, line, key name and value *length* only.
Its output is written to a file and pasted into reports, so dumping live credentials into it would
create a second copy of the problem. Keep that property in anything you add.

Cleartext credentials in application config are normal and not by themselves a finding. What makes
them a finding are three multipliers, each checked separately:

1. **Readability** — a world-readable `.env` or `config.php` is available to every local account,
   including a compromised service account. `secrets.world_readable`.
2. **Location** — a credential file *inside a document root* is downloadable the moment the
   interpreter does not run it: a handler change, a `.env.save` left by an editor, or a
   `config.php.bak`. Scanners request `/.env` on every host they touch. `secrets.in_webroot`.
3. **Reuse** — the same credential in git history, a backup, or on another host. Not detectable
   locally; call it out for the operator to confirm.

Detection is by three independent routes, because each catches what the others miss:

- **Key name** — an assignment whose name says credential (`*PASSWORD`, `*SECRET`, `*API_KEY`,
  `DB_PASS`, `JWT_SECRET`, …). Values matching `${VAR}`, `changeme`, `{{ }}` or empty are annotated
  as placeholders/references so a CI file full of `${{ secrets.X }}` does not read as a breach.
- **Provider token formats** — self-identifying prefixes, so a match is a real credential rather
  than a guess: `AKIA`/`ASIA` (AWS), `ghp_`/`gho_`/`github_pat_`, `xox[baprse]-` (Slack),
  `sk_live_`/`pk_live_` (Stripe), `AIza`/`ya29.` (Google), `glpat-`, `dop_v1_`, `npm_`, `hf_`,
  `gsk_` (Groq), `r8_` (Replicate), `pplx-`, `xai-`, `shpat_`, `sq0atp-`, `AGE-SECRET-KEY-1`, JWTs,
  and the AI-provider keys — **`sk-ant-api03-` / `sk-ant-admin01-` (Anthropic)**, `sk-proj-` /
  `sk-svcacct-` / `sk-[48 chars]` (OpenAI).
- **Connection URIs** — `scheme://user:pass@host`. Note the username may be **empty**
  (`redis://:password@host` is the common form), so the pattern must not require one.

**Private key material** is found two ways. By file (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`,
`*.p12`, `*.pfx`, `privkey*`) confirmed by reading the header — a name-bounded list first, because
a recursive content grep over `/opt` and `/home` is unbounded and can take minutes. And **embedded
in config files**: a deploy key pasted into a YAML block, JSON string or environment variable is
invisible to a filename-based search. Covers PKCS#1/PKCS#8/EC/DSA/OpenSSH/PGP headers.

For each key found, record permissions and whether it is **passphrase-protected**. An unencrypted
key is usable the instant it is copied; that is normal for automation keys, but it means file
permissions and backup handling are the only thing protecting it. A private key inside a document
root is its own finding — request it over HTTP to confirm, then rotate.

Also check the places people forget: `Environment=` lines in systemd units (unit files are
world-readable and `systemctl show` exposes the values to any local user — use `EnvironmentFile=`
pointing at a `0600` file, or `LoadCredential=`), `/etc/environment` and profile scripts, cron
entries using `curl -u` / `MYSQL_PWD` / `PGPASSWORD`, `credentials=`/`password=` in `/etc/fstab`,
NetworkManager connection files (PSKs in cleartext, must be `0600`), a `.git` directory inside the
webroot (history retains every credential ever committed and later removed), and editor/backup
leftovers (`*.bak`, `*.save`, `*~`, `*.orig`, `.env.*`).

Limitation to state in the report: this is pattern- and key-name-based, with no entropy analysis.
A secret in an unusual key name or a bare high-entropy string will not be caught. For thorough
coverage — especially of git history — recommend `gitleaks` or `trufflehog`.

## USB_PERIPHERALS

**A machine that accepts arbitrary USB devices has an unauthenticated hardware input.** Anyone with
brief physical access gets: mass storage for exfiltration, a keyboard for BadUSB keystroke
injection (the device claims to be an HID and types), or a network adapter that becomes the default
route and captures traffic. None of this needs a login, and none of it is stopped by disk
encryption on a running machine.

**USBGuard is the control to require** — it is the only one that restricts devices by *identity*
(vendor/product/serial/interface class) rather than blanket-disabling a driver:

```bash
usbguard generate-policy > /etc/usbguard/rules.conf   # allow-list what is plugged in now
# /etc/usbguard/usbguard-daemon.conf:
#   ImplicitPolicyTarget=block      <- unknown devices denied; without this it only logs
#   PresentDevicePolicy=apply-policy
#   InsertedDevicePolicy=apply-policy
#   IPCAllowedGroups=usbguard       <- who may change policy
systemctl enable --now usbguard
```

Two failure modes to check for specifically: the daemon **installed but not running**, and the
daemon running with **`ImplicitPolicyTarget=allow`**, which enumerates devices and blocks nothing.
Both look like "we have USBGuard".

Other mechanisms, roughly in order of coverage:

| Control | Covers | Notes |
|---|---|---|
| USBGuard with `ImplicitPolicyTarget=block` | Everything, per device | The recommendation |
| `authorized_default=0` via udev on each `usb*` controller | New devices at bus level | No extra software; coarse |
| `kernel.deny_new_usb=1` | All new devices after boot | `linux-hardened` kernels only; one-way until reboot |
| `nousb` boot parameter | USB entirely | Headless hosts only |
| `install usb_storage /bin/false`, `uas` | Mass storage | Does not stop HID or network devices |
| `install usbnet /bin/false`, `cdc_ether`, `rndis_host`, `cdc_ncm` | Rogue USB network adapters | Frequently forgotten; this is the traffic-hijack path |
| `install usbhid /bin/false` | BadUSB keystroke injection | **Disables real keyboards** — headless only |
| IOMMU (`intel_iommu=on`/`amd_iommu=on`) + Thunderbolt authorization | DMA attacks | Thunderbolt/FireWire read memory directly, bypassing all of the above |

Scope the finding honestly: on a cloud VM with no USB controller the practical risk is low —
report it as such rather than as a flat failure — but on any bare-metal host, laptop, kiosk, or
colocated server this is a real, cheap-to-exploit gap.

---

## MISC

- `/etc/ld.so.preload` non-empty → verify every entry; this is classic userland-rootkit persistence.
- `LD_PRELOAD` / `LD_LIBRARY_PATH` set globally in `/etc/environment` or profile scripts.
- Ctrl-Alt-Del reboot disabled on servers (`systemctl mask ctrl-alt-del.target`).
- Legal/warning banner in `/etc/issue.net` if the org requires it (compliance, not security).
- `prelink` installed → weakens ASLR; remove.

## BOOT_CHAIN — what root reads on the way up

A root process that reads, sources, execs or maps a file an unprivileged user can write is a
privilege-escalation path that fires **automatically** at boot or on the next service start. No
attacker interaction is needed — they plant the file and wait for the reboot.

Three levels of evidence, in increasing cost:

**1. Static (always run, passive).** Parse every root-owned systemd unit for the directives that
name a file, and apply the same ancestor-walking writability test used for cron:
`EnvironmentFile=`, all `Exec*=` variants, `Condition*/Assert*`, `WorkingDirectory=`, `PIDFile=`,
`LoadCredential=`, `BindPaths=`, `RootImage=`, and for `.path`/`.mount` units `PathExists=`/`What=`.
Units with `User=` set to a non-root account are skipped — they cannot escalate this way.

`EnvironmentFile=` is the one that matters most: a writable `/etc/default/<service>` injects
environment variables into a root process at every start.

Beyond units, the same test covers the rest of the boot chain: SysV init scripts and `rc.local`,
`/etc/ld.so.conf.d/` search paths (**a writable library directory is code execution in every root
binary that starts** — the broadest local escalation there is), udev `RUN+=` targets, root shell
profile scripts, PAM files, initramfs hooks, systemd generators, `logrotate` `postrotate` blocks,
and writable unit drop-in directories (`foo.service.d/`), where an added `.conf` overrides
`ExecStart`.

**2. Live snapshot (always run, passive).** Static analysis misses what a long-running daemon has
*already* opened. Walk `/proc/<pid>/fd` for every root process and flag targets that fail the
writability test, and walk `/proc/<pid>/maps` for `.so` files loaded from non-root-owned paths —
replacing one of those gives code execution inside a root process at its next start.

**3. Runtime tracing (`scripts/lsa-trace.sh`, explicitly invoked).** The only way to see what root
*actually* opens, including transient reads during startup that no config file mentions:

- `--live <secs>` — passive, system-wide, changes nothing. Uses `bpftrace`, `opensnoop` (bcc), or
  `fatrace`, in that order of preference. Start here.
- `--unit <name>` — traces one service across a restart. **Restarts the service**, so it is a brief
  outage; requires confirmation.
- `--boot arm` / `--boot report` — boot cannot be traced after the fact from userspace, so this
  installs a temporary auditd rule keyed `lsa_boot`, you reboot, and `report` reads back what root
  opened during boot and then removes the rule. This is the only mode that modifies configuration.

Correctness note for anyone extending this: **sticky world-writable directories are not a replace
risk.** `/tmp`, `/var/tmp` and `/dev/shm` are `1777`; the sticky bit stops non-owners deleting or
renaming entries, so an ancestor walk must not report them, or every path under `/tmp` becomes a
false positive. The file itself being writable is still a finding.

## DRIFT — static intent vs runtime reality

Many controls exist twice: as intent in a config file and as reality in the kernel. Auditing one
side only is how both of the failures below get missed, and they mean **opposite** things — so the
direction of the disagreement is the finding, not the disagreement itself.

| Verdict | Meaning | Why a single-sided audit gets it wrong |
|---|---|---|
| `RUNTIME-ONLY` | Applied now, not persisted | Reverts at the next reboot. A grep-the-config audit calls it FAIL; a `sysctl -a` audit calls it PASS. Both are wrong |
| `CONFIG-ONLY` | Persisted, not applied | **The dangerous direction.** The file says compliant and the kernel disagrees. Every checklist-by-grep audit scores this as a pass |
| `MISMATCH` | Both present, different values | Override ordering, or something changed it at runtime — `tuned`, a container runtime, a config-management run, or an attacker making a change a reboot would undo |

Cross-checked pairs:

- **sysctl** — `/proc/sys/*` vs the *effective* persisted value. Computing that requires reproducing
  `systemd-sysctl`'s precedence: files merge by **basename** across `/usr/lib/sysctl.d`,
  `/run/sysctl.d` and `/etc/sysctl.d` (`/etc` wins for the same basename), applied in lexicographic
  basename order, with `/etc/sysctl.conf` last. Two real traps this catches: a cloud image's
  `99-cloudimg-*.conf` sorting *after* your `50-hardening.conf` and silently winning, and
  `vm.mmap_rnd_bits` set above the architecture maximum so the write fails and the file still reads
  as compliant. Confirm with `journalctl -b -u systemd-sysctl`.
- **Kernel cmdline** — `/proc/cmdline` vs `GRUB_CMDLINE_LINUX*` in `/etc/default/grub`. A parameter
  present in the file but absent from the running kernel means `update-grub` was never run, or the
  running kernel predates the edit. The hardening is not in effect, and a reboot is when you find
  out whether it even boots.
- **Mount options** — live options vs `/etc/fstab`. `CONFIG-ONLY` here is a *pending* change that
  applies at next boot, which is also when it may break the service — test it now with
  `mount -o remount,...`.
- **Modules** — a module blacklisted in `/etc/modprobe.d` but present in `lsmod`. Usually the
  blacklist was added after boot or the module comes from the initramfs (rebuild it).
- **Firewall** — live rule count vs a saved ruleset. `RUNTIME-ONLY` (rules loaded, nothing saved) is
  the single most common way a host silently loses its firewall at reboot; `CONFIG-ONLY` (saved but
  not loaded) means it is unprotected *now* behind a correct-looking config.
- **Services** — `is-active` vs `is-enabled`. Running-but-not-enabled loses the control at reboot;
  enabled-but-not-running means an auditd or firewall that reads as configured while providing
  nothing.
- **SELinux** — `getenforce` vs `/etc/selinux/config`.
- **IPv6** — `ipv6.disable=1` on the cmdline *and* `net.ipv6.*` entries in `sysctl.d` conflict: with
  the stack disabled those tunables do not exist, so they fail to apply and log errors every boot.

Resolve drift before trusting any other PASS in the report — it is precisely where a config-based
and a runtime-based audit disagree.

## CONTAINER — and what "auditing a container" can actually mean

Three different targets, with different valid check sets:

| Target | How | What is valid |
|---|---|---|
| **Running host** | run the collector directly | everything |
| **Image / ISO / unbooted system** | mount + `chroot`, `--passive` | the `static` third only |
| **Running container** | `docker exec` or `docker run -i <image> bash -s <` | container-level checks; host-level ones are NA |

The trap that makes this worth stating: **inside a container, `/proc/sys`, `/proc/cmdline`, `lsmod`
and `/sys` are the HOST's.** A collector that reports them as findings about the container is
simply wrong — it would describe the host's kernel hardening as though it were the image's. The
collector therefore detects the context (`/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`,
`systemd-detect-virt -c`, PID 1 not being an init) and marks those checks `NA` with an explanation.
Only `net.*`, `kernel.shm*/msg*/sem*` and `fs.mqueue.*` are namespaced and therefore meaningful.

Container-level controls actually worth checking, in rough order of value:

- **Runs as root** — no `USER` in the Dockerfile. Root in a container is root on the host the
  moment any boundary fails.
- **Runtime socket mounted in** (`docker.sock`, `containerd.sock`) — an immediate, complete host
  takeover: start a new container with the host filesystem mounted. No configuration makes it safe.
- **Privileged / full capability set** — `CapEff` of `0000003fffffffff` means it can load modules
  and access all devices; it is not a boundary at all. Individually, `CAP_SYS_ADMIN`,
  `CAP_SYS_MODULE`, `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` are each close to an escape.
- **Seccomp disabled** (`Seccomp: 0` in `/proc/1/status`) — every syscall is reachable, including
  the ones used for escapes. Means `--privileged` or `seccomp=unconfined` was used.
- **Shared namespaces** — a visible host process table means `--pid=host`.
- **Writable host bind mounts**, `/host` style mounts, host `/etc` files bind-mounted in.
- **Secrets in the environment** — readable via `/proc/<pid>/environ`, captured by `docker inspect`,
  and baked into image metadata when set with `ENV`.
- Image hygiene: SUID binaries (a container needs none — `chmod a-s` them at build), a package
  manager and shells present in the runtime image, writable root filesystem.

## PACKAGES — attack-surface inventory

Package *count* is a weak signal on its own; use it to prompt the question. Reference points:
debootstrap minbase ~120, minimal server ~350, default server install ~600, anything with a desktop
>1200.

The stronger findings are about provenance and purpose:

- **Packages with no repository candidate** (`apt-cache policy` returning `Candidate: (none)`, or
  `dnf repoquery --extras`). Installed from a local `.deb`, or from a PPA/vendor repo that has since
  been removed. **These receive no security updates and no CVE feed covers them** — they are
  permanently frozen at whatever version was installed.
- **Held packages** (`apt-mark showhold`) — explicitly excluded from security updates.
- **Removed but not purged** (`rc` state) — configuration left behind, sometimes with credentials.
- **Manually installed** (`apt-mark showmanual`, `dnf repoquery --userinstalled`) — the deliberate
  additions. This is the list to review, not the base system.
- **Prohibited on a hardened production host** — compilers and toolchains (`gcc`, `g++`, `clang`,
  `make`, `binutils`, `dkms`, `libc6-dev`, kernel headers, `build-essential`), packet capture
  (`tcpdump`, `dumpcap`, `wireshark`, `tshark`), and network/debug tooling (`nmap`, `masscan`,
  `netcat`, `socat`, `gdb`, `strace`, `ltrace`, `sqlmap`, `hydra`). **Baseline is absence, not
  restriction**, and this is a FAIL rather than a judgement call:
  - A compiler plus headers lets an attacker build a local privilege-escalation exploit *in place*,
    against the exact running kernel, instead of having to smuggle in a version-matched binary.
  - `tcpdump`/`wireshark` parse attacker-supplied network data in a privileged process and carry a
    long CVE history of their own — libpcap and the Wireshark dissectors especially. The tool is
    both a capability handed to the attacker and an attack surface in its own right.
  - Restriction is weaker than removal: file modes and capabilities can be restored by root and are
    reset by a package upgrade. **A package that is not installed cannot be re-enabled, cannot carry
    a CVE, and does not need patching.** CIS and DISA STIG both require removal of compilers on
    hardened profiles.
  - Also flag any of these present as a **binary with no owning package** — copied in by hand, so
    it is invisible to the package manager, gets no updates, and survives `apt purge`.

  The objection is always "how do we debug then", so put the answer in the report next to the
  finding: capture from a sidecar or ephemeral container sharing the network namespace
  (`--net=container:<id>`, `kubectl debug`), from a switch SPAN/mirror port, or from the hypervisor;
  use `ss -tulpn`, `/proc/net/*` and `conntrack` for connection state without capture; compile on a
  build host or in CI and ship the artifact — for DKMS modules build once elsewhere and install the
  signed `.ko`, which also composes with `module.sig_enforce=1`; and if something is genuinely
  needed, install on demand and purge in the same maintenance window rather than leaving it resident.

  Capability state (`getcap` showing `cap_net_raw+ep` on `tcpdump`, setuid bits, group delegation)
  is reported separately as an *aggravating* detail — it makes the tool usable by non-root users
  too — but it does not change the baseline finding, which is that the package should not be there.

- **Second software channels** — snap and flatpak update on their own schedule outside apt/dnf, so
  distro patch reporting does not cover them. Same for globally installed pip/npm/gem packages.

## IMAGE_HYGIENE — what must never be baked into a template

Any secret or identity shipped inside a golden image, ISO, AMI, VM template or container image is
**identical on every machine ever cloned from it**, including ones built years later by people who
never saw the image contents. That converts a per-host secret into a fleet-wide one.

### SSH host keys — the canonical case

Host keys must be generated at **first boot**, never shipped. When they are baked in, one
compromised host lets an attacker impersonate the entire fleet; recorded sessions using a
non-forward-secret KEX can be decrypted; and host-key pinning stops working — a MITM no longer
produces the warning that is the whole point of pinning.

Two independent checks, because they catch it at different stages:

1. **In a template** (machine-id empty): shipping `/etc/ssh/ssh_host_*_key` at all is the finding.
2. **On a running clone**: compare mtimes. If the host key file is **older than `/etc/machine-id`**,
   the key predates this instance's own identity, so it did not come from first boot — it came from
   the image. This detects the problem on hosts already in production, which is where it usually
   gets discovered.

Then check a regeneration mechanism actually exists: cloud-init `ssh_deletekeys: true` (explicitly
`false` is its own finding), RHEL's `sshd-keygen@.service`, or a firstboot unit running
`ssh-keygen -A` guarded by `ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key`. The classic failure
is a mechanism that only fires when the keys are *absent*, combined with an image that ships them —
so it never fires. Remediation on an affected host:

```bash
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A            # or: dpkg-reconfigure openssh-server
systemctl restart sshd   # clients will warn once — that is the pinning working
```

...then fix the image, or every future instance repeats it.

### The rest of the per-instance set

- **`/var/lib/systemd/random-seed`** — easy to miss and genuinely serious: every clone starts with
  **identical early-boot entropy**, which can repeat across machines in key generation, session IDs
  and ASLR before the pool is reseeded. Delete during image prep; systemd rewrites it at shutdown.
- **`/etc/machine-id`** — must be **empty, not deleted**. An empty file is systemd's documented
  first-boot trigger; a missing one can leave read-only-`/etc` setups without an identity. Also
  ensure `/var/lib/dbus/machine-id` is a symlink to it rather than a second copy.
- **`/var/lib/cloud/`** — cloud-init state present in a template means it believes it has already
  run and will **skip first-boot tasks, including host-key regeneration**. Clean with
  `cloud-init clean --logs --seed`.
- **Enrolment material and agent identities** — Puppet/Salt/Chef client certs, kubelet client certs,
  Wazuh/OSSEC `client.keys`, Zabbix PSK, Consul/Vault tokens, snapd state, NetworkManager
  `secret_key`, iSCSI initiator name, DHCP leases and DUIDs. Duplicated identity across a fleet.
- **`authorized_keys`** baked into `/root` or a user home — grants its holder access to every
  machine built from the image.
- **Build leftovers** — `/root/.bash_history` (frequently holds credentials typed during the build),
  a populated `/var/log` carrying hostnames, IPs and build-environment credentials, and
  `known_hosts`.
- **TLS certificates and private keys** for services — same argument as SSH host keys.

The natural place to run this is the passive image workflow: mount the image, `chroot`, run with
`--passive`. It also runs on live hosts, where the mtime comparison is what surfaces a fleet that
was built from a bad template.

## Relationship to CIS Benchmarks and DISA STIG

**This is not a compliance tool, and it should not be presented as one.** CIS and STIG produce a
pass/fail verdict against a numbered control list, for an auditor. This produces a risk-ranked fix
list, for whoever has to fix it. Different output, different purpose — and the difference matters
when someone asks "are we CIS compliant?"

Specifically, this skill **does not emit control IDs** and no check should ever be labelled with
one. CIS numbering varies between benchmark versions and distributions; asserting "this is CIS
5.2.1" from memory would be wrong often enough to be worse than saying nothing. If a finding needs
a control reference, look it up in the actual benchmark for that exact distro and version.

### Where coverage is strong

Filesystem mount options, kernel module blacklisting, the network and kernel sysctl sets, SSH
server configuration, sudo, password quality and lockout parameters, password aging, umask, core
dumps, auditd, remote logging, AIDE, SELinux/AppArmor, firewall policy, time synchronisation,
repository GPG verification, bootloader password, banners, legacy NIS entries, world-writable and
unowned files, SUID/SGID inventory, cron permissions, USBGuard, FIPS mode and fapolicyd.

### Where the benchmarks still go further

- **Exhaustive per-file permission enumeration.** STIG in particular lists dozens of individual
  files with required mode and owner. This checks the security-relevant subset, not the full list.
- **Individual auditd rules.** CIS enumerates roughly forty specific rules; this checks coverage by
  *event class* instead, which is more useful for judging whether an investigation is possible but
  is not a control-by-control match.
- **Desktop/GDM controls** — not covered; out of scope for servers.
- **Formal evidence.** No XCCDF/ARF output, no signed result, no control mapping.

**If the deliverable is compliance evidence, use OpenSCAP with the real datastream** — `oscap
xccdf eval --profile <cis|stig> --results-arf arf.xml <ds.xml>`, with content from
[ComplianceAsCode](https://github.com/ComplianceAsCode/content) (STIG content is public; CIS
benchmark documents are licensed). Run this skill alongside it for the things a benchmark does not
model: exploitability ranking, static-vs-runtime drift, secrets, image hygiene, and the local
privilege-escalation chains.

### Where this goes beyond both

Active TLS cipher and mutual-TLS *enforcement* probing; the boot and service-start trust chain;
root cron reading user-writable data; cleartext secret scanning with redaction; image and template
hygiene (baked host keys, entropy seeds); webroot writability and loaded-but-unused web server
modules; static-vs-runtime drift; container-context awareness; package provenance; and GTFOBins-aware
sudo analysis. None of these are modelled as CIS or STIG controls.
