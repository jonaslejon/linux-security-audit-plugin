# SSH, service sandboxing, logging, integrity

## SSH server

**`Match` blocks are the blind spot.** `sshd -T` prints the *global* configuration, so a `Match
Group devs` block re-enabling `PasswordAuthentication` or `AllowTcpForwarding` is invisible to it —
and to any check that reads only the global result. Grep the config for `Match` and inspect each
block, then confirm per-context with `sshd -T -C user=<u>,group=<g>,addr=<a>`.

Client side (`/etc/ssh/ssh_config`) matters too: `ForwardAgent yes` there means this host forwards
its agent to *every* server it connects to, so any of them can authenticate onward as its user.

Always audit the **effective** configuration: `sshd -T` (or `sshd -T -C user=x,host=y,addr=z` to
resolve `Match` blocks). Reading `sshd_config` alone is unreliable — drop-ins under
`/etc/ssh/sshd_config.d/` are included (on Debian/Ubuntu the `Include` sits at the *top* of the
file, and **the first occurrence of a keyword wins**, so a drop-in silently overrides everything
below it in the main file).

### Core settings

| Directive | Want | Why |
|---|---|---|
| `PermitRootLogin` | `no` (or `prohibit-password` where automation requires it) | Removes the one account name every attacker already knows |
| `PasswordAuthentication` | `no` | Ends credential-stuffing and brute force outright |
| `KbdInteractiveAuthentication` | `no` | The other password path — disabling only `PasswordAuthentication` while leaving this on is a common mistake |
| `PermitEmptyPasswords` | `no` | |
| `PubkeyAuthentication` | `yes` | |
| `AllowUsers` / `AllowGroups` | explicit list | Without it, every account with a shell may attempt SSH. This is the single highest-value line in the file |
| `MaxAuthTries` | `3` | |
| `LoginGraceTime` | `20`–`30` | Limits unauthenticated connection slots (the pre-auth surface that CVE-2024-6387 lived in) |
| `MaxStartups` | `10:30:60` | Pre-auth connection flooding |
| `X11Forwarding` | `no` | |
| `DisableForwarding` | `yes` where forwarding is not required | One directive kills TCP, X11, agent, tunnel and unix-socket forwarding together, and no future default can partially undo it |
| `AllowTcpForwarding` | `no` | **Defaults to `yes`.** Any SSH user can `ssh -L`/`-D` and reach anything this host can reach — private-network databases, cloud metadata, other segments. Firewall segmentation is bypassed by anyone with a shell here. The most consequential forwarding setting on a bastion |
| `AllowAgentForwarding` | `no` | **Defaults to `yes`.** A forwarded agent socket lets root on the intermediate host authenticate onward *as the connecting user*, with no prompt and no record. Use `ProxyJump`, which never exposes the agent to the middle host |
| `AllowStreamLocalForwarding` | `no` | **Defaults to `yes`.** Unix-socket forwarding reaches local sockets — including `/var/run/docker.sock`, which is host root |
| `GatewayPorts` | `no` | `yes` makes remote-forwarded ports bind all interfaces, so a user's `ssh -R` publishes an internal service to the network |
| `PermitTunnel` | `no` | Layer 2/3 tunnelling — a full VPN into the network for anyone who can log in |
| `PermitOpen` | scoped host:port list | If forwarding must stay on, this bounds where a tunnel may terminate — keeps a jump host useful without making it a universal pivot |
| `X11Forwarding` | `no` | The X11 protocol assumes a trusted client: a malicious server can capture keystrokes and read the connecting workstation's display. If on, require `X11UseLocalhost yes` and never `ForwardX11Trusted` |
| `PermitUserEnvironment` | `no` | `~/.ssh/environment` can set `LD_PRELOAD` |
| `GSSAPIAuthentication` | `no` unless Kerberos | Pre-auth code path |
| `ClientAliveInterval` / `ClientAliveCountMax` | `300` / `2` | Reaps abandoned sessions |
| `UsePAM` | `yes` | Needed for account/session policy and `pam_faillock` |
| `LogLevel` | `VERBOSE` | Records the key fingerprint used for each login — essential for attributing an incident to a key |

Changing the port is obscurity, not security: it cuts log noise substantially and stops nothing
targeted. Say so rather than presenting it as a control.

### Algorithms

Restrict KEX/ciphers/MACs to modern primitives. Preferring `chacha20-poly1305@openssh.com`,
`aes*-gcm` and `curve25519-sha256` guarantees forward secrecy and AEAD:

```
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
```

Note the trade-off: an explicit allow-list opts you out of future improvements OpenSSH adds. Since
OpenSSH 7.5 you can instead subtract from the default with a leading `-`
(`Ciphers -*cbc,*-sha1`), which stays current automatically. Either is defensible; prefer
subtraction on hosts you will not revisit often, and include `sntrup761x25519` (post-quantum
hybrid KEX, default since OpenSSH 9.0) where the client base supports it.

**DH moduli.** `awk '$5 < 3071' /etc/ssh/moduli | wc -l` — any result > 0 means weak groups are
offered for `diffie-hellman-group-exchange-sha256`. Fix:

```bash
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && mv /etc/ssh/moduli.safe /etc/ssh/moduli
```

**Host keys.** Every host must have its own. Cloned VM images and golden templates routinely ship
with identical host keys — one stolen key then impersonates the whole fleet, and host-key pinning
(the thing that would detect a MITM) becomes meaningless. Compare
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` across hosts; identical fingerprints are a
finding. Regenerate with `rm /etc/ssh/ssh_host_*; dpkg-reconfigure openssh-server` (and expect
every client to warn once). Prefer Ed25519; remove DSA entirely.

**authorized_keys.** Audit for: keys that no longer belong to anyone, `ssh-rsa`/`ssh-dss` keys,
file/dir permissions (`700` on `.ssh`, `600` on the file, owned by the user — sshd refuses
otherwise), and whether automation keys are constrained with
`command="…",restrict` / `from="10.0.0.0/8"`. An unconstrained automation key is a full shell.

### SSH client

For outbound connections — relevant when the audited host is a jump box or CI runner:
`/etc/ssh/ssh_config` should set `HashKnownHosts yes`, `StrictHostKeyChecking ask` (never `no`),
`ForwardAgent no`, and the same restricted algorithm lists. Check `~/.ssh/config` for
`StrictHostKeyChecking no` or `UserKnownHostsFile /dev/null` — both disable MITM detection entirely
and are common in scripts.

Grade the result from outside with `ssh-audit <host>` — it tests what is actually offered rather
than what the config says.

---

## systemd unit sandboxing

`systemd-analyze security` scores every unit 0.0–10.0 (lower = more constrained) and labels it
`OK`/`MEDIUM`/`EXPOSED`/`UNSAFE`. It only measures *systemd directives* — it says nothing about the
application's own security — but it is the fastest way to find a network-facing daemon running with
no confinement at all.

Harden with a drop-in (`systemctl edit <unit>`), never by editing the vendor unit:

```ini
[Service]
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077
ReadWritePaths=/var/lib/myservice /var/log/myservice
```

Apply incrementally and test after each group — `ProtectSystem=strict` and `SystemCallFilter` are
the two that most often break a service. `MemoryDenyWriteExecute=true` breaks anything with a JIT
(Java, Node, PHP with JIT, Python with some extensions). `ProtectHome=true` breaks services that
legitimately read user home directories.

---

## Logging

**Off-host forwarding is the control that survives compromise.** Whoever gets root on the host owns
every local log; the copy on another machine is what makes an incident reconstructable.

Check three things, not one:
1. Forwarding is configured (rsyslog `omfwd` / `*.* @@host:port`, syslog-ng destination, journald
   `ForwardToSyslog`, or an agent — Vector, Filebeat, Fluent Bit, CloudWatch, Loki).
2. The transport is **encrypted and authenticated** — rsyslog with
   `DefaultNetstreamDriver gtls`, `StreamDriverMode 1`, `StreamDriverAuthMode x509/name` and a CA
   file. `@@host` alone is TCP in cleartext, which leaks the log contents and lets anyone inject
   forged entries.
3. It is actually working — check the queue/error stats, not just the config.

### Retention and readability

State retention in **time**, not bytes. The defaults do not:

```ini
# /etc/systemd/journald.conf.d/retention.conf
[Journal]
Storage=persistent      # otherwise the journal is in /run and dies at reboot
MaxRetentionSec=90day   # without this, retention is a size cap that shrinks when volume rises
SystemMaxUse=2G         # ceiling so the journal cannot fill /var
Compress=yes
```

```
# /etc/logrotate.d/rsyslog  — daily x 90 = 90 days, and 0640 so rotated files stay unreadable
daily
rotate 90
create 0640 root adm
compress
delaycompress
notifempty
```

auditd retains by byte budget only (`num_logs` × `max_log_file`). Set
`max_log_file_action = keep_logs` where the evidence matters more than the disk — with `ROTATE`, an
attacker who generates volume overwrites the record of their own activity — and give
`/var/log/audit` its own filesystem so filling it cannot take the host down.

For readability, three settings decide it and they are easy to get half-right:

```
$FileCreateMode 0640          # rsyslog default is 0644 — world-readable
create 0640 root adm          # logrotate: sets the mode of every FUTURE rotated file
chmod 0600 /var/log/audit/audit.log
```

A manual `chmod` on a log file reverts at the next rotation unless the `create` line is fixed too.
Then audit who is in `adm` and `systemd-journal` — those accounts read every system log without
`sudo`, so they leave no sudo trail when they do.

**auditd** provides syscall-level attribution that syslog cannot: who executed what, who read which
file, who changed a privilege. The common failure is auditd running with an empty ruleset — verify
`auditctl -l` returns rules. A reasonable baseline logs: `execve`, changes to `/etc/passwd`,
`/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`; module load/unload; `mount`; time changes;
and privilege escalation. Consider `-e 2` (immutable ruleset until reboot) on high-value hosts.
Start from the [Neo23x0 auditd ruleset](https://github.com/Neo23x0/auditd) rather than writing from
scratch, and tune for volume — an unusable audit log is not a control.

---

## File integrity monitoring

AIDE, Tripwire, Samhain, Wazuh/OSSEC, or `rpm -Va` on RPM systems. Detects a replaced binary, a new
SUID file, a modified config, an added cron entry.

Two things determine whether it is real or theatre:
- **Database freshness and location.** The DB must be regenerated after legitimate changes
  (package updates) and stored off-host or on read-only media. A DB an attacker with root can
  update is worthless, and one that predates the last `apt upgrade` produces thousands of
  legitimate diffs nobody reads.
- **Somebody reads the report.** Check that the cron/timer exists, that it mails or ships the
  report somewhere monitored, and that the last report was actually delivered.

Report an installed-but-stale AIDE as *ineffective*, not as present. `rkhunter`/`chkrootkit` are
signature-based and catch only known kits; treat them as a cheap supplement, not coverage.
