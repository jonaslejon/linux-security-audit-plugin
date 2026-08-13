# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Check counts quoted in earlier entries were taken from the development machine, which runs
almost none of the audited subsystems and therefore emits close to the *minimum*, not the
maximum. The tool implements 450+ distinct checks across 33 areas; how many a given host emits
depends on what it actually runs, with absent subsystems collapsing to a single `NA`.

## [1.4.0] — 2026-08-13

Offline mode did not work. `--root` was wired into two sections and nowhere else, so 270 of the
277 filesystem path operands read the machine running the audit instead of the mounted image.
The section worst affected was `IMAGE_HYGIENE`, whose entire purpose is finding SSH host keys
baked into a golden template: it reported on the auditor's own keys.

This release also closes a redaction leak that put a live API key in the report, makes argument
handling fail closed, and adds the CI and regression tests that would have caught all of it.
Everything here was reported by Patrik Solsten, who cloned the repo and actually ran it.

### Fixed

- **`--root` now resolves every path read against the mounted tree.** All 277 operands go through
  `rf()` (or `"$LSA_ROOT"` where a glob must still expand). Verified against a fixture root: every
  `FAIL` is now a property of the fixture, where previously 9 of 32 described the auditing host.
- **Runtime and active checks can no longer produce a verdict offline.** Enforced centrally in
  `chk()` rather than at each call site, because a guard that must be remembered 270 times gets
  missed, and the failure mode of missing one is a manufactured finding.
- **Whole-filesystem walks no longer scan the auditing host offline.** `SCANDIRS` consulted
  `findmnt`, a runtime tool, so `--root` walked the auditor's entire disk. This also made the run
  appear to hang: it never completed rather than taking a long time.
- **Binary-presence checks resolve inside the target.** `have` searches the auditor's `PATH`, so
  `packages.prohibited` and `hardening.compilers` reported the auditor's toolchain as the image's.
  New `have_target` looks inside the tree offline.
- **Docker section no longer triggers on the auditor's socket.** Auditing an image from a
  workstation running Docker Desktop produced a full set of daemon findings about the workstation.
- **`perm./etc/shadow` emits `NA` when the file is absent or unreadable**, instead of `FAIL` on an
  empty mode. This violated the collector's own `statmode` contract.
- **`umask.effective` and `privesc.path` retagged `runtime`.** Both read the auditing shell's own
  environment, so offline they described the auditor entirely.
- **The orphaned-package check no longer forks once per package.** It ran up to 800 sequential
  `apt-cache policy` invocations, unbounded and not covered by `--quick`, which is enough to make
  a run look like it has hung; it now passes the list through `xargs` under a timeout. The dnf
  equivalent ran its slowest query twice, once without a timeout.
- **Three checks asserted a control was in place after reading nothing.** `users.uid0` reported
  "1 UID-0 account" when `/etc/passwd` was unreadable, `users.shadow_group` reported the group
  empty when the group database was absent (and queried the auditing host's NSS rather than the
  image), and `bootchain.ld_so_path` reported the linker search path clean when there was no
  `ld.so.conf` to enumerate. All three now emit `NA`. Found by the new empty-tree assertion.
- **`image.logs_in_image` measured the auditing host's `/var/log`**, so an image audit reported
  the auditor's log volume as the template's.
- **Paths containing spaces are no longer skipped.** Loops over discovered file lists split on the
  default `IFS`, so a private key under `/home/anna karlsson/.ssh/` was passed over without a
  trace. Newline-only `IFS` is now scoped to those loops specifically; the many loops that iterate
  space-separated scalars (mount options, module names, ports) keep default splitting.
- **`--out` no longer merges stderr into the record stream.** `stat` and `grep` warnings landed
  between `CHECK|` records and broke the `grep '^CHECK|'` contract. Diagnostics go to
  `<file>.stderr`.
- **Metadata agreed nowhere.** `marketplace.json` claimed 249 checks across 31 areas, the README
  claimed 450+ across 33, and the collector implements 457 across 33. All three are now synced and
  asserted in CI. `plugin.json` gained `license`, `homepage`, `repository` and `keywords`.
- **`rp_filter`**: the reference table claimed a per-interface value overrides `all`. The effective
  value is `max(all, <iface>)`, as the same document's traps section already said correctly.

### Security

- **A secret could be printed into the report.** Redaction of systemd `Environment=` lines used a
  `sed` anchored on the last `=`, so a unit carrying two variables masked only the second:
  `Environment=API_KEY=abc123 DB_SECRET=hunter2` published the API key verbatim. Replaced with a
  redactor that masks every value on the line and collapses the whole remainder when a quoted
  value could hide a token boundary. A regression test now plants a two-variable secret and fails
  if either value reaches the output.
- **Unknown flags no longer fall through to the defaults.** A typo'd `--pasive` left active
  probing enabled, so a run intended to touch nothing opened TLS handshakes and HTTP requests to
  production services without a warning. Unknown options now exit 2.
- **`--root` with a missing or invalid argument is fatal.** It previously left the prefix empty
  while still setting offline mode, so the report was headed `MODE: OFFLINE` and then described
  the running host. Silently auditing the wrong machine under an offline banner is the worst
  outcome this tool has.

### Fixed (found by the new CI on its first run against a real Linux host)

- **A `|` inside a value broke the record contract.** Linux `core_pattern` begins with a literal
  `|` meaning "pipe to this handler", which produced a seven-field `CHECK` record and silently
  mis-parsed under the `awk -F'|'` consumers the skill itself documents. Delimiters inside values
  are now percent-encoded, and CI asserts every record has exactly six fields.
- **Offline package verification ran against the auditing host.** `dpkg --verify` and `rpm -Va`
  ignored the `--admindir`/`--dbpath` options the query paths already used, so auditing an image
  from a Debian host checksummed the auditor's own packages under a 600-second timeout. That is
  both a wrong answer and what made an offline run appear to hang. Now uses the image's database,
  or reports `NA` when the tree has none.
- **`tr '_' '[_-]'` was not doing anything.** `tr` maps characters, not strings, so the USB module
  blacklist check turned `_` into `[` and GNU `tr` rejected the reversed range outright, printing
  an error per module. It never matched a `-` separated module name. Now a `sed` character class.

### Added

- **CI, tests and a security policy.** There were none, which for a tool run as root on production
  is the largest single reason not to trust it. Added `.github/workflows/ci.yml` (shellcheck,
  syntax, manifest validation, both test suites, and a live collection on a real Linux runner),
  `tests/offline-regression.sh`, `tests/metadata-consistency.sh`, `SECURITY.md` and
  `CONTRIBUTING.md`. The live smoke job matters most: until now nothing had exercised the
  collector on a booted Linux host as part of the build.
- **`cap` replaces `head -N` on 119 evidence lists.** Truncation was silent, so a host with 213
  SUID binaries reported 80 and read as a complete list. Lists now state how many were dropped,
  and `truncated_lists` appears in the run summary. Five lists were being truncated on the
  development machine alone.

### Changed

- **`SKILL.md` no longer instructs `chroot` for offline trees.** It taught the one approach the
  collector's own header calls finding-fabricating, while never mentioning `--root` at all. Inside
  a `chroot` the collector cannot tell it is offline, so runtime tools return "absent" and become
  `FAIL` on controls that are correct.
- **The collector locates itself.** `SKILL.md` and the README both hardcoded paths that do not
  exist after `/plugin install`.
- **New `RUN_SUMMARY` section** reports collector version and SHA, elapsed time, the five slowest
  sections, the verdict spread, and the real `static`/`runtime`/`active` distribution. The
  hardcoded "~31%/~66%/~3%" in `SKILL.md` was wrong (measured: 41/59) and would have drifted again.
- **The conservative sysctl baseline is split into unconditional and conditional blocks.** It
  previously shipped `perf_event_paranoid=3`, `legacy_tiocsti=0` and `mmap_rnd_bits=32` unmarked,
  each of which fails to apply on the wrong kernel, in a file the same document warns will produce
  `systemd-sysctl` boot errors. `yama.ptrace_scope=2` is now marked as breaking in-place debugging.
- **`SKILL.md` frontmatter description cut from 295 words to 3 sentences.** It had grown into the
  full check catalogue, which belongs in `checklist.md`; a wall of text makes skill matching worse,
  not better, and costs context in every session where the skill is considered.
- Report template gained collector version/SHA, elapsed time and truncation rows, and now states
  that a high `undetermined_pct` under `--root` is the expected shape of an offline audit.

## [1.3.0] — 2026-08-12

### Added

- **Dependency-free `/proc` backend for `lsa-trace.sh --live`.** Every tracing backend
  previously required `bpftrace`, `opensnoop`, `fatrace` or `strace` — which is precisely what
  a hardened image strips, and which this project's own `packages.prohibited` check reports as
  a finding when present. Requiring one in order to run the tracer was self-defeating, and
  installing one is a persistent change to the audited host.

  The new backend samples every root process's open file descriptors (`/proc/PID/fd`) and
  mapped files (`/proc/PID/maps`) for the requested window and feeds them through the existing
  `path_risk()`. It needs nothing but a readable `/proc` as root, so it works where every other
  backend is unavailable. `--preflight` advertises it instead of refusing.

  Its limitation is printed rather than left implicit: polling *samples*, so a file opened and
  closed entirely between two samples is missed. Confidence is partial, unlike the
  event-driven backends.

  Contributed patch, adjusted before merge: sampling interval raised from 0.3s to 1s (at 0.3s
  on a host with ~400 processes the poller issues roughly 6.4M `readlink()` calls per minute,
  which is real load on a production box, and a warning now fires above 250 processes with a
  sub-second interval); fractional `sleep` is a GNU/BSD extension so the interval is probed
  once and falls back to 1s, because busybox and POSIX `sleep` take integers and a minimal
  hardened image is exactly where busybox lives; and the ASCII conversion was completed across
  the whole file rather than only the added lines.

### Fixed

- `v1.1.2` was tagged without a changelog entry, and its three false-positive fixes were
  written up under `1.2.0` — attributing them to a release they did not ship in. Each version
  now has a matching entry.

## [1.2.0] — 2026-08-12

### Added

- **eBPF section.** eBPF executes attacker-reachable code in the kernel *without loading a
  module*, so `kernel.modules_disabled=1` — the strongest anti-LKM-rootkit control this audit
  recommends — does not constrain it at all. Published eBPF rootkits (TripleCross, ebpfkit,
  boopkit) hook syscalls, hide processes and files, and implement backdoor triggers this way.
  Coverage: `unprivileged_bpf_disabled` semantics (0/1/2), JIT hardening, loaded programs by
  type with the syscall/packet/LSM-hooking types called out, programs with no owning process,
  maps, cgroup attachments, BPF LSM programs, pinned objects in `bpffs` (persistence with no
  process and no file on disk), XDP attachments (which see and can rewrite packets before the
  network stack, including before tcpdump), tc BPF filters, `CAP_BPF`/`CAP_PERFMON` holders,
  and the kernel-lockdown interaction that actually constrains all of it.
  Loaded programs are not treated as inherently suspicious — Cilium, Calico, Falco, Datadog
  and systemd all load them legitimately — so the section enumerates and attributes rather
  than alarms.

## [1.1.2] — 2026-08-12

### Fixed

Three false-positive classes, all found during a live EL8 audit and all of which manufactured
findings that did not exist:

- **Symlinks judged by their own mode.** A symlink's mode is always `0777` and carries no
  information, so `/bin -> usr/bin` reported as `WORLD-WRITABLE /bin (777)` on every Linux
  host. The same inflated `web.config_writable` (`/etc/httpd/{run,modules,logs,state}` are all
  symlinks) and `bootchain.unit_inputs`. `path_risk` now dereferences and judges the target,
  dangling links are skipped, and the writability scans no longer match symlinks at all.
- **Non-TLS ports probed as TLS endpoints.** OpenSSL prints `Cipher : 0000` when no handshake
  occurred, which the endpoint test accepted as a valid cipher — so SSH on 22 and plaintext
  HTTP on 80 were treated as TLS and given a full battery of bogus weak-cipher `FAIL`s. A named
  cipher is now required.
- **Weak-cipher probes bounded by the local openssl.** Families the local build cannot offer
  were reported `ACCEPTED`, recording the client's inability to ask as the server's answer.
  Each family is now pre-checked with `openssl ciphers` and reported `NA` when untestable, and
  a completed handshake must negotiate a cipher *inside* the tested family before it counts —
  which also catches `-cipher` failing to constrain and the server picking something modern.

## [1.1.1] — 2026-08-12

### Fixed

- **`PATH` missing the sbin directories.** A non-login shell — which is what
  `ssh host 'sudo bash -s' < script` produces, the invocation this project documents — usually
  has no `/sbin` or `/usr/sbin`. `have()` therefore returned false for `iptables`, `nft`, `ss`,
  `sshd`, `auditctl`, `lsmod`, `sysctl` and `findmnt`, and every dependent check reported the
  control as **absent on hosts where it was installed and running**. Reported in the field as
  `firewall.active` returning `FAIL "none detected"` on a host with a live iptables ruleset;
  the firewall was the visible symptom of a much broader silent degradation. The collector now
  prepends the sbin directories itself.
- **iptables detection ignored default policies.** A host whose entire ruleset was
  `-P INPUT DROP` with no explicit rules was reported as having no firewall. Rules and
  non-ACCEPT default policies are now both counted, and `ip6tables` is checked as well.
- Replaced the `grep -qv` idiom, whose exit status is not portable between grep
  implementations, with a positive match.

### Added

- `collect.missing_tools` — reports absent collection tools once and explicitly, so a missing
  binary can no longer masquerade as a missing control.
- **Refuses to run on a non-Linux kernel.** Previously it would emit a full report on, say,
  macOS, where nearly every check degrades to absent — output that reads like findings and is
  really just "wrong operating system". `--force` overrides, for development only.

## [1.1.0] — 2026-08-12

### Added

- **Docker daemon and container posture, audited from the host** (`DOCKER_HOST`, 32nd section).
  Previously the tool only inspected containers from the *inside*; the daemon itself and the
  containers it runs were not examined.
  - Daemon configuration from `/etc/docker/daemon.json` and `docker info`: `userns-remap`,
    `icc`, `no-new-privileges` default, `live-restore`, `userland-proxy`, `default-ulimits`,
    log-driver rotation, `insecure-registries`, rootless mode, default seccomp profile.
  - Running containers via `docker inspect`: privileged, `docker.sock` mounted in, host
    networking, running as root, missing memory/PID limits, writable root filesystem,
    `cap_drop: ALL`, `no-new-privileges`, ports published on `0.0.0.0`, and images referenced
    by tag rather than digest.
  - Credentials baked into image layers, via `docker history`, reported with values redacted.
  - Presence of supply-chain tooling (Trivy, Grype, Syft, Cosign, docker-bench-security).
- Project home referenced from `SKILL.md`, so a misfiring check can be reported upstream.

### Scope note

Build-time supply chain is deliberately **not** implemented: image CVE scanning, SBOM
generation, signature verification and admission control belong to a different lifecycle stage
and to purpose-built tools. Their presence is reported rather than reimplemented.

## [1.0.0] — 2026-08-12

Initial release. 249 checks across 31 areas.

### Collection

- Three modes: live host, mounted image (`--root <path>`), and container, with the execution
  context detected automatically. Host-owned checks report `NA` inside a container rather than
  describing the host and calling it the container.
- Every check is tagged `static` (files on disk), `runtime` (live kernel and process state) or
  `active` (probes a running service). *Not active* does not mean *works offline* — roughly two
  thirds of checks need a booted system, and the tag makes that visible.
- `--passive` disables all active checks; `--quick` skips whole-filesystem walks;
  `--apt-update` is opt-in and is the only thing that writes anything.

### Verdict model

- `FAIL` means *checked, and it is wrong*. A check whose prerequisite is unavailable emits `NA`
  with the reason. `NA` is never reported as a pass.

### Coverage

- Kernel: sysctls, boot parameters, module blacklists, lockdown, Secure Boot, CPU mitigations.
- Filesystem: mount options, SUID/SGID, file capabilities, world-writable paths, home directory
  permissions including the default applied to newly created accounts.
- Access control: SELinux/AppArmor *confinement* rather than just enforcement status,
  unconfined and permissive domains, sudoers, PAM, password quality and lockout parameters.
- Privilege escalation: GTFOBins-capable sudo grants, `env_keep`, writable systemd units,
  writable `PATH`, NFS `no_root_squash`, exposed credentials, shell-history anti-forensics.
- Boot and service-start trust chain: `EnvironmentFile` and `Exec*` paths, `ld.so` search
  paths, udev `RUN` targets, plus files currently open in and libraries mapped into root
  processes.
- Scheduled tasks: root cron reading, sourcing or globbing user-writable data.
- Network: firewall policy per direction including egress, firewall/listener reconciliation,
  bind-address discipline, exposed services.
- TLS: cipher and protocol validation by active probe, and whether mutual TLS is *enforced*
  rather than merely requested.
- SSH: public-key-only enforcement via `AuthenticationMethods`, every forwarding channel, and
  `Match` block overrides that `sshd -T` does not show.
- Services: web servers including loaded-but-unused modules, databases, SNMP, and
  insecure-by-default daemons.
- Secrets: cleartext credentials, API tokens and private keys on disk, reported with values
  redacted.
- Packages: repository GPG verification, provenance, prohibited tooling on hardened hosts,
  and checksum verification via `dpkg --verify` / `debsums` / `rpm -Va`.
- Image and template hygiene: SSH host keys or entropy seeds baked into a golden image,
  uninitialised `machine-id`, cloud-init state, per-instance enrolment material.
- Drift: where persisted configuration and running kernel disagree, and in which direction.

### Known limitations

- Developed and tested on macOS against fixtures. The GNU-specific collection paths
  (`findmnt`, `ss`, `stat -c`, `sshd -T`, `nginx -T`, `rpm -Va`, `dpkg --verify`) have not yet
  been exercised end-to-end on a booted Linux host.
- Not a compliance tool: no control IDs are emitted, and none should be inferred.

[1.3.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.3.0
[1.2.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.2.0
[1.1.2]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.1.2
[1.1.1]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.1.1
[1.1.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.1.0
[1.0.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.0.0
