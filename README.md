# linux-security-audit

A Claude Code plugin that audits how hardened a Linux system is and produces a
risk-ranked report — what to fix, in what order, with the exact change and its blast radius.

It is an auditing tool, not a hardening script. It changes nothing by default.

**Requires Linux.** The collector refuses to run on any other kernel rather than emit a report
full of controls that only look absent because `/proc`, `/sys` and the GNU userland are missing.
Run it on the host, over SSH, or against a mounted Linux filesystem with `--root`.

## Install

```
/plugin marketplace add jonaslejon/linux-security-audit-plugin
/plugin install linux-security-audit
```

Then ask Claude to audit a host, or point it at an image.

## What it looks at

**459 distinct checks across 33 areas.** The number a given host emits is a subset — sections
for subsystems it does not run collapse to a single `NA`, and a host with Docker, a web server,
TLS listeners and eBPF programs loaded emits far more than a minimal one. Coverage includes:

- **Kernel** — sysctls, boot parameters, module blacklists, lockdown, CPU mitigations
- **Filesystem** — mount options (`nosuid`/`noexec`/`nodev`), SUID/SGID, capabilities, world-writable paths
- **Access control** — SELinux/AppArmor *confinement* (not just "enforcing"), sudoers, PAM, password and lockout policy
- **Privilege escalation** — `sudo` GTFOBins-capable grants and `env_keep`, writable systemd units, writable `PATH`, NFS `no_root_squash`, exposed credentials
- **Boot and service-start trust chain** — everything root reads on the way up: `EnvironmentFile`, `ld.so` search paths, udev `RUN`, plus what root processes currently hold open
- **Network** — firewall policy per direction including **egress**, listener/rule reconciliation, bind-address discipline, exposed services
- **TLS** — cipher and protocol validation by active probe, and whether mutual TLS is *enforced* rather than merely requested
- **eBPF** — loaded programs by type, unattributed and pinned objects, XDP and tc attachments, BPF LSM programs, and `CAP_BPF` holders. `modules_disabled=1` does not constrain eBPF, so an in-kernel implant needs no module
- **Services** — SSH (public-key-only enforcement, forwarding channels, `Match` block overrides), web servers, databases, and insecure-by-default daemons
- **Secrets** — cleartext credentials and private keys on disk, **reported with values redacted**
- **Containers and Docker** — daemon hardening (`userns-remap`, `icc`, default `no-new-privileges`), running-container posture (privileged, mounted `docker.sock`, missing memory/PID limits, writable rootfs), and credentials baked into image layers
- **Images and templates** — SSH host keys or entropy seeds baked into a golden image
- **Drift** — where persisted config and running kernel disagree, and in which direction

## Three collection modes

| Mode | How | What is valid |
|---|---|---|
| Live host | run it directly | everything |
| Mounted image | `--root /mnt` | configuration only; runtime checks report `NA` |
| Container | run inside it | container-level checks; host-owned ones report `NA` |

In a container, controls that belong to the host or the orchestrator report `NA` with the reason
rather than as findings against the image: mount layout, firewall, time, file-integrity monitoring
and the interactive-login family. The collector also distinguishes a **workload** container (PID 1
is the application, so runtime posture is a real finding) from an **inspection** container (PID 1
is a shell, so the collector is reading an image and the seccomp profile, rootfs mode and
namespaced sysctls belong to your `docker run`, not to the image). `container.context` reports
which. Auditing a stock image this way yields single-digit findings instead of ~55.

Use `--root` for an offline tree, never `chroot`. Inside a `chroot` the collector cannot tell it
is offline: `systemctl`, `sudo -l` and `/proc` reads return "absent" rather than failing, and a
check that turns a failed read into a `FAIL` has manufactured a finding. `--root` makes the
context explicit, so those checks report `NA` instead.

Every run ends with a `RUN_SUMMARY` section giving the collector version and hash, elapsed time,
the slowest sections, the verdict spread and the real `static`/`runtime`/`active` split. Quote
those figures in a report rather than any number written down here.

## Running it

The plugin drives this for you, but the collector is a standalone script with no dependencies
beyond a POSIX shell and the tools it audits:

```bash
# the plugin install path varies; locate the collector rather than guessing
S="$(find -L "$HOME/.claude" -name lsa-collect.sh -path '*linux-security-audit*' 2>/dev/null | head -1)"

# a live host, over SSH, leaving nothing behind on the target
ssh -p 22 user@host 'sudo bash -s' < "$S" > report.txt

# locally
sudo bash "$S" > report.txt

# a mounted image or golden template — configuration only
sudo bash "$S" --root /mnt/image > image-report.txt

# a container image
docker run --rm -i <image> bash -s < "$S" > image-report.txt
```

| Flag | Effect |
|---|---|
| `--quick` | Skip whole-filesystem walks (SUID, world-writable, secrets) and package checksum verification. Use on large or slow storage |
| `--passive` (`--no-probe`) | Disable every active check — no loopback connections, no NTP queries |
| `--root PATH` | Offline mode against a mounted filesystem; runtime checks report `NA` |
| `--apt-update` | Also run `apt-get update` to test repo signatures. **The only thing that writes anything** |
| `--out FILE` | Write to a file on the target instead of stdout |
| `--force` | Run on a non-Linux kernel anyway. Development only; results are not meaningful |

Runtime observation of what root actually opens at boot and service start is a separate script.
Start with the preflight, which changes nothing and reports which backends this host allows:

```bash
sudo bash lsa-trace.sh --preflight      # what is possible here, without changing anything
sudo bash lsa-trace.sh --live 60        # passive; falls back to /proc polling if no tracer
sudo bash lsa-trace.sh --unit nginx     # restarts that service; asks first
```

## What the output looks like

One `CHECK` line per control, plus raw evidence blocks for the things needing human judgement.
Illustrative — the note field carries the reasoning, which is what makes a finding report-ready:

```
CHECK|sudo.env_keep|FAIL|env_keep += "LD_PRELOAD"|preserving the dynamic-linker environment
  across sudo lets any sudo-capable user load their own library into a root process - a direct,
  unconditional root shell|static
CHECK|firewall.policy_output|FAIL|OUTPUT=ACCEPT|UNRESTRICTED EGRESS. Inbound filtering only stops
  the first step; with open egress a compromised process can reach any C2 endpoint, exfiltrate to
  any destination, pull a second stage, and open a reverse shell outbound|runtime
CHECK|tls.443.mtls|WARN|requested but NOT enforced|the server asks for a client certificate yet
  completed the handshake without one - permissive mTLS authenticates nobody|active
CHECK|sudo.policy_readable|NA|/etc/sudoers could not be read|0440 root:root - re-run as root. No
  sudo verdict is issued, because an empty read is not an absent rule|static
```

(Wrapped here for width; each check is a single line.)

Grep it: `grep '^CHECK|' report.txt | grep -v '|PASS|'`

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
service start. It uses `bpftrace`, `opensnoop` or `fatrace` when present, and otherwise falls
back to a dependency-free `/proc` snapshot poller that needs no tracer installed — which matters,
because a hardened image strips exactly those tools. It runs a preflight first and refuses rather than half-working when hardening
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
