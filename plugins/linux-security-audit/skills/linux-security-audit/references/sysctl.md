# sysctl reference

What each tunable defends against, and where it lies to you.

Read both the running value (`/proc/sys/...`) and the persisted one (`/etc/sysctl.conf`,
`/etc/sysctl.d/*.conf`, `/usr/lib/sysctl.d/`, `/run/sysctl.d/`). A correct running value with no
config file is lost at the next reboot. Later-sorting filenames win; `/etc/sysctl.d/` beats
`/usr/lib/sysctl.d/`; `/etc/sysctl.conf` is applied last on most distros.

---

## Kernel self-protection

| Tunable | Want | Defends against |
|---|---|---|
| `kernel.kptr_restrict` | `2` | Kernel pointer leaks via `/proc` and `dmesg` that defeat KASLR. `1` hides from unprivileged users only; `2` hides from everyone |
| `kernel.dmesg_restrict` | `1` | Unprivileged reads of the kernel ring buffer (leaks addresses, hardware detail, crash traces) |
| `kernel.printk` | `3 3 3 3` | Console leakage of the same information |
| `kernel.unprivileged_bpf_disabled` | `1` | eBPF has been a repeated source of local privesc; this removes it from unprivileged users. `2` (newer kernels) is "disabled until first `CAP_BPF` use" |
| `net.core.bpf_jit_harden` | `2` | JIT spraying — constant blinding for all users |
| `dev.tty.ldisc_autoload` | `0` | Auto-loading arbitrary TTY line disciplines (a historically fruitful bug class) |
| `dev.tty.legacy_tiocsti` | `0` | `TIOCSTI` keystroke injection into the parent terminal (sandbox/`sudo` escape). Kernel ≥6.2 |
| `kernel.kexec_load_disabled` | `1` | Booting a new, unsigned kernel from a compromised running one. One-way until reboot |
| `vm.unprivileged_userfaultfd` | `0` | `userfaultfd()` is the standard tool for winning kernel use-after-free races |
| `kernel.sysrq` | `4` | Magic SysRq — `4` keeps only the secure attention key (`0` disables entirely) |
| `kernel.perf_event_paranoid` | `3` | The perf subsystem; a long CVE history. `3` requires a patched kernel on many distros (see traps) |
| `kernel.randomize_va_space` | `2` | Full ASLR (heap included). Anything less is a serious finding |
| `kernel.yama.ptrace_scope` | `1`–`3` | Process A reading process B's memory (credential theft from browsers, agents, `ssh-agent`). `1` = descendants only, `2` = root only, `3` = nobody, ever (irreversible until reboot) |
| `kernel.modules_disabled` | `1` | LKM rootkits. Irreversible until reboot — apply after boot completes |
| `kernel.kexec_load_disabled`, `kernel.modules_disabled` | | Both one-way switches; set them at the *end* of the boot sequence |
| `kernel.oops_limit` / `kernel.warn_limit` | `1` | Attackers probing memory corruption by repeatedly triggering oopses/warnings (kernel ≥6.2). Panics instead of letting them iterate |
| `kernel.panic_on_oops` | `1` | Same idea, older mechanism |
| `kernel.core_pattern` | `\|/bin/false` | Core dumps writing process memory (keys, secrets) to disk |
| `fs.suid_dumpable` | `0` | Core dumps of SUID processes specifically |

## User-space protection

| Tunable | Want | Defends against |
|---|---|---|
| `vm.mmap_rnd_bits` | `32` (x86_64) | Weak mmap ASLR entropy. Max is arch-dependent — `32` on x86_64, `33` on some arm64. Setting above the arch max fails silently at boot |
| `vm.mmap_rnd_compat_bits` | `16` | Same for 32-bit compat processes |
| `fs.protected_symlinks` | `1` | Symlink-following attacks in world-writable dirs (`/tmp` races) |
| `fs.protected_hardlinks` | `1` | Hardlinking to a file you cannot read, then having a privileged process act on it |
| `fs.protected_fifos` | `2` | FIFO-in-`/tmp` attacks |
| `fs.protected_regular` | `2` | Regular-file equivalent |
| `vm.swappiness` | `1` | Secrets being paged to (usually unencrypted) swap. `1` minimises without disabling |
| `vm.max_map_count` | `1048576` | Not security — needed by hardened allocators and some apps |
| `kernel.deny_new_usb` | `1` | New USB devices after boot. `linux-hardened` only |

## User namespaces

The single most distro-divergent control. Unprivileged user namespaces let a normal user obtain
capabilities inside a namespace, which is how most kernel local-privesc exploits of the last decade
reached their vulnerable code path. Disabling them is high value and breaks: rootless containers
(Podman/Docker rootless), Flatpak/Snap/bubblewrap sandboxes, Chrome's sandbox, `unshare`.

- **Debian / Arch / linux-hardened**: `kernel.unprivileged_userns_clone=0` (a patch, not mainline).
- **Mainline / RHEL**: `user.max_user_namespaces=0` — blunter; also affects root's ability to
  create namespaces in that userns, and breaks systemd's own sandboxing (`PrivateUsers=`).
- **Ubuntu 23.10+ (default-on in 24.04)**: `kernel.apparmor_restrict_unprivileged_userns=1` — allows
  userns only for AppArmor-confined programs that declare a `userns` rule. Note that bypasses of
  this mechanism have been published; treat it as a speed bump, not a boundary.

Report which mechanism the host actually supports, not a generic FAIL for the absent one.

## Network

| Tunable | Want | Notes |
|---|---|---|
| `net.ipv4.tcp_syncookies` | `1` | SYN flood resilience |
| `net.ipv4.tcp_rfc1337` | `1` | Drops RST packets for sockets in TIME-WAIT |
| `net.ipv4.conf.{all,default}.rp_filter` | `1` | Reverse-path filtering — drops spoofed sources. **`1` (strict) breaks asymmetric routing and multi-homed/VPN hosts**; `2` (loose) is the safe choice there. Modern kernels also honour a per-interface value that overrides `all` |
| `net.ipv4.conf.{all,default}.accept_redirects` | `0` | ICMP redirects rewriting your routing table |
| `net.ipv6.conf.{all,default}.accept_redirects` | `0` | |
| `net.ipv4.conf.{all,default}.secure_redirects` | `0` | |
| `net.ipv4.conf.{all,default}.send_redirects` | `0` | Only relevant on routers; harmless to set everywhere |
| `net.ipv4.conf.{all,default}.accept_source_route` | `0` | Source routing lets a sender pick the return path |
| `net.ipv6.conf.{all,default}.accept_source_route` | `0` | |
| `net.ipv6.conf.{all,default}.accept_ra` | `0` | Router advertisements can reconfigure the host. **Breaks any host that gets its IPv6 address via SLAAC** — check before setting |
| `net.ipv4.icmp_echo_ignore_all` | `1` | **POLICY.** Stops ping. Breaks uptime monitoring, MTU discovery aids, and troubleshooting. Real-world value is low (a port scan finds the host anyway). Recommend only if the org's monitoring does not use ICMP |
| `net.ipv4.tcp_timestamps` | `0` | **POLICY.** Removes an uptime/host-fingerprint side channel; costs PAWS and RTT estimation on high-bandwidth long-fat links |
| `net.ipv4.ip_forward` | `0` | **POLICY.** Must be `1` on routers, NAT gateways, Docker/Kubernetes hosts, and WireGuard hubs |
| `net.ipv4.conf.all.log_martians` | `1` | Logs impossible source addresses — useful signal, some noise |
| `net.ipv4.conf.all.arp_ignore` / `arp_announce` | `1` / `2` | ARP-level source-address hygiene on multi-homed hosts |
| `net.ipv4.tcp_sack` / `tcp_dsack` / `tcp_fack` | `0` in madaidan's guide | **Not recommended generally** — SACK is important for throughput on lossy links. Only worth it during an active SACK-panic CVE window |
| `net.ipv6.conf.{all,default}.use_tempaddr` | `2` | IPv6 privacy addresses — for clients, not servers |

---

## Distro and version traps

- **`kernel.unprivileged_userns_clone` does not exist on mainline kernels.** Its absence on RHEL or
  a vanilla kernel is `NA`, not a failure. See the user-namespace section above.
- **`kernel.perf_event_paranoid=3`** is only meaningful with the Debian/Arch/hardened patch.
  Mainline caps at `2`; writing `3` may be accepted and behave as `2`, so a `PASS` on the read-back
  is not proof.
- **`vm.mmap_rnd_bits`** above `CONFIG_ARCH_MMAP_RND_BITS_MAX` makes the boot-time sysctl apply
  fail — check `systemd-sysctl` errors in the journal, not just the current value.
- **`rp_filter`**: the effective value is `max(all, <iface>)`, so setting `all=1` while an interface
  has `0` still yields strict filtering on that interface. Setting `all=0` does not disable it if
  the per-interface value is `1`.
- **`net.ipv6.*` tunables vanish** when IPv6 is disabled at boot (`ipv6.disable=1`), so
  `/etc/sysctl.d/` entries for them cause `systemd-sysctl` failures at boot. Pick one approach.
- **`dev.tty.legacy_tiocsti`** exists only on kernel ≥6.2; older kernels have no equivalent.
- **`kernel.deny_new_usb`** exists only on `linux-hardened`.
- **Container/VM guests**: many `kernel.*` tunables are read-only inside a container (they belong to
  the host namespace). Auditing a container image against this list produces meaningless failures —
  audit the host.
- **Cloud images** often ship their own `/etc/sysctl.d/99-cloudimg-*.conf` that re-enables things;
  check ordering before concluding a setting is applied.

---

## A conservative persisted baseline

Server-safe subset — high value, low breakage. Drop into `/etc/sysctl.d/99-hardening.conf`, then
`sysctl --system` and check for errors. The POLICY items above are deliberately excluded; add them
only after deciding the trade-off per host.

```ini
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
kernel.kexec_load_disabled = 1
vm.unprivileged_userfaultfd = 0
kernel.sysrq = 4
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 2
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.swappiness = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
```

`kernel.modules_disabled = 1` is deliberately **not** in this file: applied at sysctl time it can
run before every needed module has loaded. Set it from a late-boot unit instead — see
`remediation.md`.
