# Other tooling, and where this sits

Background rather than procedure. Load it when the user asks what else to run, whether this
replaces a compliance scanner, or how it compares to the well-known tools.

## Complementary tooling

The collector is deliberately dependency-free. When deeper coverage is wanted and the user agrees
to install tooling, suggest: `lynis audit system` (broad, opinionated, no agent),
`oscap`/OpenSCAP with a CIS or STIG datastream (formal compliance evidence),
`ssh-audit` and `testssl.sh` (SSH and TLS algorithm grading: both must run from *outside* the
host to test what is actually offered, which a config read cannot establish),
[`kernel-hardening-checker`](https://github.com/a13xp0p0v/kernel-hardening-checker) (kernel
`CONFIG_*` vs KSPP: the one thing the collector genuinely cannot cover, since it inspects build
config), `debsecan` / `dnf updateinfo` (CVE exposure of installed packages), `debsums` / `rpm -Va`
(verify installed files against their packages), and `systemd-analyze security` (already sampled by
the collector).

### Relationship to CIS and STIG

Strong technical overlap, but **this is not a compliance tool and must not be presented as one**:
it emits no control IDs, and no check should ever be labelled with a CIS or STIG number (numbering
varies by benchmark version and distro; asserting one from memory would be wrong too often). For
compliance *evidence*, use OpenSCAP with the real datastream and run this alongside for what a
benchmark does not model. Full comparison in `references/checklist.md`.

### Where this sits relative to the well-known tools

The check set was diffed against [Lynis](https://github.com/CISOfy/lynis)'s `tests.db`,
[linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration),
[LinEnum](https://github.com/rebootuser/LinEnum)/linPEAS, and the CIS benchmarks. Deliberate
differences:

- **Lynis** is broader on platform coverage (BSD/Solaris/AIX/macOS) and on service inventory
  (Squid, CUPS, printers, mail, LDAP, DNS). It reports mostly *suggestions* without exploitability
  ranking, and it does not actively probe TLS ciphers or mutual-TLS enforcement. Run it alongside
  for breadth; it is packaged, agentless and fast.
- **linPEAS / LSE** are attacker-perspective and unprivileged-user oriented; they enumerate what
  the *current user* can escalate through. The `PRIVESC_PATHS` section here covers the same ground
  from the defender's side (whole-host, with root), but they will find user-context things this
  does not, running tmux/screen sessions, ssh-agent sockets, cached Kerberos tickets, credentials
  in running process command lines.
- **CIS / OpenSCAP** produce formal, numbered compliance evidence with a pass/fail per control.
  Use `oscap` with a CIS datastream when the deliverable is an audit artifact rather than a
  prioritised fix list.

Known gaps in this skill, worth naming in a report's *Not assessed* section: kernel `CONFIG_*`
build options, mail/DNS/print/proxy server hardening beyond exposure, BSD and Solaris,
user-context credential theft (agent sockets, tmux, Kerberos), and anything requiring an external
vantage point (`testssl.sh`, `ssh-audit`, external port scan).