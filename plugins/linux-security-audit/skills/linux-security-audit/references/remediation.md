# Remediation

Only after explicit approval. Auditing and changing are separate steps.

## Ground rules

1. **Drop-in files, never vendor files.** `/etc/sysctl.d/99-hardening.conf`,
   `/etc/modprobe.d/99-blacklist.conf`, `/etc/ssh/sshd_config.d/99-hardening.conf`,
   `systemctl edit <unit>`. Distro upgrades overwrite the originals; drop-ins survive and are
   trivially reversible by deleting one file.
2. **Back up anything you overwrite**, with a timestamp: `cp -a f f.bak.$(date +%F-%H%M)`.
3. **One change class at a time, then verify.** Batching a firewall change with an SSH change means
   you cannot tell which one locked you out.
4. **Anything that only takes effect at boot is unverified until reboot** — and the reboot is the
   risky moment. Schedule it, have console/KVM access ready, and know the recovery path.
5. **Re-run the collector afterwards** and show the before/after delta as evidence.

## Order of application — lowest risk first

| Phase | Changes | Risk |
|---|---|---|
| 1 | sysctl (non-POLICY subset), module blacklists for hardware you don't have, file permissions, umask, core dumps, package removal, banner | Low — reversible, effective immediately |
| 2 | Web server + PHP hardening, security headers, TLS versions, NTP config, log forwarding, auditd rules, AIDE install, systemd unit sandboxing | Medium — can break an application; test each |
| 3 | SSH hardening, firewall rules, PAM/faillock | **Lockout risk** — see below |
| 4 | fstab mount options, kernel cmdline, GRUB password, `module.sig_enforce`, `lockdown`, `kernel.modules_disabled` | **Boot risk** — only takes effect on reboot, and a mistake means console recovery |

## Lockout-risk changes

**Before touching SSH or the firewall, open a second, independent session and keep it open.** Test
the new config in the second session; if it fails, the first session is still there to revert.

```bash
# validate before restarting — never restart on an unvalidated config
sshd -t                     # syntax
sshd -T | grep -iE 'permitrootlogin|passwordauth|allowusers'   # effective result
systemctl reload sshd       # reload keeps existing sessions alive; restart is fine too but reload is safer
# then, from a NEW terminal, prove you can still log in before closing the old one
```

Firewall: apply with a dead-man switch so a mistake self-heals.

```bash
# schedule a revert, apply rules, verify connectivity, then cancel the revert
echo 'ufw --force reset && ufw --force enable' | at now + 10 minutes
# ... apply rules, confirm you can still connect ...
atrm <job>
```

`nft`/`iptables`: always ensure `ESTABLISHED,RELATED` accept and an explicit SSH-port accept rule
exist *before* setting the default policy to DROP.

PAM: keep a root shell open. A broken `/etc/pam.d/common-auth` locks out every login including the
console.

## Boot-risk changes

- **fstab**: `mount -a` after editing catches syntax errors while the system is still up. A bad
  fstab drops the machine into emergency mode on reboot. Test `noexec` on `/tmp` and `/var` against
  the actual workload first — package hooks, Java, Docker and CI runners commonly break.
- **GRUB password**: after `update-grub`, confirm the entry uses `--unrestricted` if unattended
  reboots must work without a password, or the host will hang at the menu.
- **`module.sig_enforce=1`**: verify every needed module is signed first (`modinfo <mod> | grep
  signature`). DKMS modules (NVIDIA, VirtualBox, ZFS, WireGuard on old kernels) are typically not.
- **`lockdown=confidentiality`**: only meaningful with Secure Boot; breaks perf, hibernation, and
  some debuggers.
- **`kernel.modules_disabled=1`**: apply from a late-boot unit (see `boot-and-modules.md`), never
  from `/etc/sysctl.d/`. Confirm nothing loads modules after boot (Docker, Kubernetes, WireGuard,
  on-demand filesystem mounts).

## Templates

### sysctl

`/etc/sysctl.d/99-hardening.conf` — use the conservative baseline in `sysctl.md`, then:

```bash
sysctl --system 2>&1 | grep -i 'cannot\|error'   # catches unsupported keys and out-of-range values
```

An error here means the setting is *not* applied, even though the file exists — a silent
false-positive in any audit that only reads config files.

### Module blacklist

`/etc/modprobe.d/99-blacklist-hardening.conf` — lists in `boot-and-modules.md`. Then:

```bash
update-initramfs -u        # Debian/Ubuntu
dracut -f                  # RHEL/Fedora
```

Skip `squashfs` if snaps are in use; skip network filesystems the host actually mounts.

### Core dumps

```bash
mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/disable.conf
printf '* hard core 0\n* soft core 0\n' > /etc/security/limits.d/99-coredump.conf
# plus kernel.core_pattern=|/bin/false and fs.suid_dumpable=0 in the sysctl drop-in
systemctl daemon-reload
```

### SSH

`/etc/ssh/sshd_config.d/99-hardening.conf` — settings in `services-ssh-logging.md`. On Debian and
Ubuntu confirm the main file's `Include /etc/ssh/sshd_config.d/*.conf` line is present and comes
first, then verify with `sshd -T`, not by reading the file.

### GRUB password

```bash
grub-mkpasswd-pbkdf2                      # produces grub.pbkdf2.sha512....
cat >> /etc/grub.d/40_custom <<'EOF'
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.<hash>
EOF
# keep unattended boot working: add --unrestricted to the default menuentry
update-grub
```

### Mount options

```bash
cp -a /etc/fstab /etc/fstab.bak.$(date +%F-%H%M)
# edit, then:
mount -a && findmnt -lo TARGET,OPTIONS --real
# apply without reboot where possible:
mount -o remount,nosuid,nodev,noexec /tmp
```

### Web server

Put hardening in an included file (`/etc/nginx/conf.d/99-hardening.conf`,
`/etc/apache2/conf-available/99-hardening.conf` + `a2enconf`) rather than editing the vhost, then:

```bash
nginx -t && systemctl reload nginx
apachectl -t && systemctl reload apache2
```

`reload` does not drop live connections; `restart` does. Reload after every single change and check
the site still serves before moving on — security headers and TLS-version changes are the ones that
most often break a client.

### Remote logging (rsyslog over TLS)

```
# /etc/rsyslog.d/99-remote.conf
global(DefaultNetstreamDriver="gtls"
       DefaultNetstreamDriverCAFile="/etc/ssl/certs/log-ca.pem")
action(type="omfwd" target="logs.example.net" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="logs.example.net"
       queue.type="LinkedList" queue.filename="fwdq" queue.saveOnShutdown="on"
       action.resumeRetryCount="-1")
```

The disk-assisted queue matters: without it, log lines are dropped whenever the collector is
unreachable — which is exactly when you need them.

### Repository signature verification

RPM — set the global default and fix every offending repo (per-repo wins):

```bash
# global
grep -q '^gpgcheck' /etc/dnf/dnf.conf || echo 'gpgcheck=1' >> /etc/dnf/dnf.conf
sed -i 's/^gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf
echo 'localpkg_gpgcheck=1' >> /etc/dnf/dnf.conf

# per repo — review each hit before changing; a repo that genuinely has no signing key
# should be removed or replaced, not silently forced to gpgcheck=1
grep -rn 'gpgcheck\s*=\s*0' /etc/yum.repos.d/
sed -i.bak.$(date +%F) 's/^gpgcheck\s*=\s*0/gpgcheck=1/' /etc/yum.repos.d/<repo>.repo

# verify: an unsigned package must now be refused
dnf --setopt=gpgcheck=1 check-update
```

APT — remove `trusted=yes`, pin third-party keys with `signed-by`, retire the legacy keyring:

```bash
# move a vendor key out of the global keyring into a scoped one
gpg --dearmor < vendor.asc > /etc/apt/keyrings/vendor.gpg
chmod 644 /etc/apt/keyrings/vendor.gpg
# then rewrite the source line:
#   deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://apt.vendor.example.com bookworm main
apt-get update      # must complete with no NO_PUBKEY / "not signed" / EXPKEYSIG warnings
```

If a repo genuinely cannot be verified, the fix is to stop using it — not to keep `trusted=yes`.

### USB device restriction

```bash
apt install usbguard || dnf install usbguard
usbguard generate-policy > /etc/usbguard/rules.conf     # allow-list what is currently attached
sed -i 's/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=block/' /etc/usbguard/usbguard-daemon.conf
systemctl enable --now usbguard
usbguard list-devices                                    # confirm expected devices show "allow"
```

**Generate the policy while every device you need is plugged in**, and keep a console session open —
on a machine whose keyboard is USB, a policy generated without it can lock you out of the console.
Add `IPCAllowedGroups=usbguard` so an admin can adjust policy without root.

Without USBGuard, the no-extra-software option:

```bash
# /etc/udev/rules.d/10-usb-deny-default.rules
ACTION=="add", SUBSYSTEM=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"
```

### Dropping a service off root

```bash
systemctl edit myapp.service
```
```ini
[Service]
User=myapp
Group=myapp
# or, for a stateless daemon with no files of its own:
# DynamicUser=yes
# needed only if it binds a port below 1024:
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
```

Then fix ownership of its state, log and runtime directories (`StateDirectory=`, `LogsDirectory=`
and `RuntimeDirectory=` create them with the right owner automatically). Restart and confirm with
`ps -o user= -p $(systemctl show -p MainPID --value myapp)`.

### Confining an unconfined SELinux domain

```bash
ausearch -m AVC -ts recent | audit2allow -M myapp_local   # from a Permissive-domain run, not a Permissive system
semodule -i myapp_local.pp
semanage permissive -d myapp_t                            # remove the exemption once the policy is right
restorecon -Rv /opt/myapp
```

Put the single domain in permissive (`semanage permissive -a myapp_t`) while tuning — never the
whole system — and remove the exemption afterwards. Verify with `ps -eZ | grep myapp`.

### AIDE

```bash
apt install aide && aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# copy the DB off-host, and re-run `aide --update` after every planned change
```

## Rollback

Every drop-in file can be removed and the service reloaded. Keep a one-line rollback per change in
the report:

| Change | Rollback |
|---|---|
| sysctl drop-in | `rm /etc/sysctl.d/99-hardening.conf && sysctl --system` |
| modprobe drop-in | `rm /etc/modprobe.d/99-blacklist-hardening.conf && update-initramfs -u` |
| sshd drop-in | `rm /etc/ssh/sshd_config.d/99-hardening.conf && sshd -t && systemctl reload sshd` |
| nginx/apache include | remove the file, `nginx -t`/`apachectl -t`, reload |
| fstab | restore the `.bak`, `mount -a` |
| kernel cmdline | edit at the GRUB menu for one boot (`e`), then fix `/etc/default/grub` |
| `kernel.modules_disabled` | reboot — there is no other way back |
| GRUB password | boot from rescue media, edit `/etc/grub.d/40_custom` |
