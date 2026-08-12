# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Check counts quoted in earlier entries were taken from the development machine, which runs
almost none of the audited subsystems and therefore emits close to the *minimum*, not the
maximum. The tool implements 450+ distinct checks across 33 areas; how many a given host emits
depends on what it actually runs, with absent subsystems collapsing to a single `NA`.

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
