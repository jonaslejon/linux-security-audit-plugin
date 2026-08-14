# Boot parameters, kernel modules, lockdown

## Kernel command line

Verify with `cat /proc/cmdline`. Persist in `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`
(then `update-grub` / `grub2-mkconfig -o …`), or `/etc/kernel/cmdline` on systemd-boot/UKI setups.

### Memory and allocator hardening: low risk, apply broadly

| Parameter | Effect | Cost |
|---|---|---|
| `slab_nomerge` | Stops merging slab caches of similar size, which otherwise lets an attacker groom an unrelated object into a freed slot | Slightly more memory |
| `init_on_alloc=1` | Zeroes newly allocated pages: kills uninitialised-memory info leaks | ~1–3% |
| `init_on_free=1` | Zeroes freed pages: sharply reduces the value of use-after-free | ~2–5%, more on alloc-heavy loads |
| `page_alloc.shuffle=1` | Randomises the page allocator freelist | Negligible |
| `randomize_kstack_offset=on` | Per-syscall randomisation of the kernel stack offset | ~1% |
| `hardened_usercopy=1` | Keeps usercopy bounds checking on | Negligible |
| `vsyscall=none` | Removes the legacy fixed-address vsyscall page (a reliable ROP gadget source) | Breaks pre-2013 static binaries only |
| `vdso32=0` | Disables the 32-bit vDSO | 32-bit userspace only |

### Attack surface removal

| Parameter | Effect | Cost |
|---|---|---|
| `debugfs=off` | Removes debugfs, which exposes broad kernel internals | Breaks some tracing/debug tooling |
| `ia32_emulation=0` | Disables the entire 32-bit syscall ABI (kernel ≥6.7). Large, low-attention, historically buggy surface | Breaks all 32-bit binaries |
| `nousb` | No USB at all | Physical machines only |
| `ipv6.disable=1` | IPv6 stack not loaded at all | **POLICY**; verify nothing needs IPv6 first, and remove IPv6 sysctls from `/etc/sysctl.d/` or boot will log failures |
| `random.trust_cpu=off` / `random.trust_bootloader=off` | Do not seed the RNG from RDRAND/bootloader alone | Slower boot-time entropy availability; can stall early boot on entropy-poor VMs |
| `efi=disable_early_pci_dma` | Blocks pre-boot DMA from PCI devices | UEFI only |
| `intel_iommu=on` / `amd_iommu=on`, `iommu.passthrough=0`, `iommu.strict=1` | DMA protection from Thunderbolt/PCIe peripherals | Small I/O cost |
| `proc_mem.force_override=never` | Blocks `/proc/<pid>/mem` writes | Breaks some debuggers |

### One-way / high-impact; read the cost column carefully

| Parameter | Effect | Cost |
|---|---|---|
| `pti=on` | Forces Kernel Page Table Isolation (Meltdown, some KASLR bypasses) | 5–30% on syscall-heavy workloads |
| `module.sig_enforce=1` | Only signed modules load | **Breaks DKMS, VirtualBox, NVIDIA, ZFS, out-of-tree drivers.** Can make the machine unbootable if a needed module is unsigned |
| `lockdown=confidentiality` | Root can no longer read or modify the running kernel: no `/dev/mem`, no unsigned modules, no kexec, no `bpf` on kernel memory, no hibernation | Breaks perf-based profiling, some debuggers, hibernation, and any tool needing raw kernel access. `lockdown=integrity` is the milder tier. Normally requires Secure Boot to be meaningful |
| `oops=panic` | Panic instead of surviving a kernel oops, so attackers cannot iterate on memory-corruption probes | **A buggy driver now reboots the box.** Pair with a watchdog and console logging |
| `mce=0` | Panic on uncorrected machine check | Same trade-off |
| `quiet loglevel=0` | Suppresses boot console output | Makes boot troubleshooting harder |
| `hash_pointers=always` | Forces pointer hashing in kernel output (≥6.17) | Debug output less useful |

### CPU vulnerability mitigations: POLICY, measure before applying

`mitigations=auto,nosmt` is the KSPP recommendation and enables the defaults *plus* disables SMT
where a vulnerability needs it. The explicit form:

```
spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt \
mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force
```

`nosmt=force` halves logical CPU count on hyper-threaded hardware. On a dedicated single-tenant
server running only trusted code, the cross-thread side channels these address are largely
unreachable and the cost is not obviously worth it; on a shared/multi-tenant host or anything
running untrusted code (CI runners, container platforms, browsers, sandboxed scanners) it is.
State which case the host is in rather than recommending blindly.

Always cross-check the actual outcome against `/sys/devices/system/cpu/vulnerabilities/*`: those
files report what the kernel *achieved*, including microcode-dependent parts, which the command
line alone does not tell you. `mitigations=off` anywhere is a serious finding.

### Verifying lockdown and Secure Boot

```bash
cat /sys/kernel/security/lockdown      # [none] integrity confidentiality
mokutil --sb-state                     # SecureBoot enabled/disabled
[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS
```

Kernel lockdown without Secure Boot is bypassable (an attacker with root modifies the bootloader
or kernel image), so report them together.

---

## Module blacklisting

`/etc/modprobe.d/*.conf`. Use `install <module> /bin/false`: `blacklist <module>` only prevents
*automatic* loading, and an explicit `modprobe` still works. Reserve `/bin/true` for modules whose
absence should not produce an error (network filesystems that something might optionally probe).

After changing, rebuild the initramfs (`update-initramfs -u` / `dracut -f`) or modules baked into it
still load.

### Obscure network protocols

Auto-loaded when a socket of that family is created, so an unprivileged local program can load any
of them on demand. Repeatedly a source of privesc CVEs.

```
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
```

Check first: SCTP is used by some telecom/SIP and Kubernetes services; TIPC by some clusters; CAN by
automotive/embedded.

### Rare filesystems

Auto-loaded on mount attempt, including from an attacker-supplied image or a removable device.
These drivers are largely unmaintained and fuzz badly.

```
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
```

**`squashfs` breaks Snap** (all snaps are squashfs images): on Ubuntu this disables everything
installed via snap, including `lxd` and often the `core` runtime. Check before applying.
`udf` breaks optical media. `cramfs` is used by some initramfs setups.

### Network filesystems (`/bin/true`: absent, not an error)

```
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true
```

Only if the host neither mounts nor serves them. `ksmbd` in particular has had a bad run of
pre-auth RCEs and should be blocked unless deliberately in use.

### Hardware / drivers

```
install vivid /bin/false          # test-only V4L2 driver, has yielded local privesc CVEs
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false       # USB webcams
install firewire-core /bin/false  # DMA-capable
install thunderbolt /bin/false    # DMA-capable
install usb-storage /bin/false    # blocks USB mass storage (physical hosts)
```

Servers should have Bluetooth, webcam, FireWire and Thunderbolt blocked as a matter of course:
zero cost, since nothing uses them. On laptops these are real functionality; ask.

### Checking what is actually loaded

```bash
lsmod
# a module in the blacklist that is currently loaded means the blacklist was added
# after boot, or it is pulled in from the initramfs: both need a reboot to take effect
```

---

## `kernel.modules_disabled=1`

The strongest single anti-rootkit setting: after it is set, no module can be loaded or unloaded for
the rest of the uptime. LKM rootkits: REPTILE, Diamorphine, and the tooling Mandiant attributed to
UNC3886: all depend on module loading.

It is **one-way**. Once set: no new hardware requiring a driver, no DKMS build, no `modprobe`, no
`wg`/`nf_tables`/filesystem module loading on demand. Apply it late in boot, after everything else
has loaded:

```ini
# /etc/systemd/system/disable-modules.service
[Unit]
Description=Disable kernel module loading
DefaultDependencies=no
After=multi-user.target network-online.target
Requires=multi-user.target

[Service]
Type=oneshot
ExecStart=/sbin/sysctl -q kernel.modules_disabled=1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Before enabling it on a production host, boot once with everything running and record `lsmod`, then
confirm nothing loads later (containers starting `overlay`/`br_netfilter`, WireGuard bringing up
`wireguard`, a backup job loading a filesystem module). Docker and Kubernetes hosts in particular
load modules well after boot.
