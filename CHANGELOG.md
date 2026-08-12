# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Counts quoted below are the checks emitted on a host where every subsystem is present;
a given host emits fewer, and reports the rest as `NA`.

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

[1.1.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.1.0
[1.0.0]: https://github.com/jonaslejon/linux-security-audit-plugin/releases/tag/v1.0.0
