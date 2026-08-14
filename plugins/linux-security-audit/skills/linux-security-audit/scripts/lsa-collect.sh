#!/usr/bin/env bash
# lsa-collect.sh: Linux Security Audit collector.  LINUX ONLY.
LSA_VERSION="1.7.0"
#
# SIDE EFFECTS: the complete list. This is designed to be run against production, so the
# honest inventory matters more than a blanket warning:
#   * Writes nothing to the audited system by default. No config is modified, no service is
#     started, stopped or reloaded, no package is installed.
#   * ACTIVE checks open loopback TCP connections (a TLS ClientHello to each listening port,
#     an HTTP HEAD to 127.0.0.1) and query NTP peers. These appear in the audited service's
#     OWN LOGS as connections from localhost. Disable with --passive.
#   * --apt-update (opt-in, off by default) is the ONLY thing that writes: it refreshes
#     /var/lib/apt/lists.
#   * Whole-filesystem walks (SUID, world-writable, secrets) cause read I/O proportional to
#     disk size. Use --quick on large or slow storage.
#   * Reads credential-bearing files to classify them, but NEVER prints their values.
#   * Creates one temporary file under $TMPDIR to tally verdicts and section timings, removed
#     on exit. If mktemp is unavailable the tally is skipped rather than the run failing.
# Every check degrades gracefully when a tool or file is absent.
#
# Usage:  ./lsa-collect.sh [--quick] [--no-fs-scan] [--no-probe] [--out FILE]
#   --quick        skip slow whole-filesystem scans (SUID, world-writable, caps)
#   --no-fs-scan   same as --quick for the filesystem walks only
#   --no-probe     PASSIVE MODE (alias: --passive). Skip every active check: local TLS
#   --passive      handshakes, HTTP requests to localhost, `apt-get update`, and NTP
#                  source queries. What remains is pure inspection of config and state,
#                  which is what you want when auditing a golden image, an unbooted
#                  system, or a host whose services must not be touched.
#   --root PATH    OFFLINE MODE for a mounted image/template. Resolves config paths under PATH,
#                  reads the package DB with rpm --dbpath / dpkg --root, and marks every check
#                  that needs a running kernel (sysctls, listeners, processes, loaded modules,
#                  firewall state, live TLS) as NA rather than inventing a verdict from the
#                  auditing host's state. Preferred over chroot, which silently lets runtime
#                  tools return "absent" and manufactures FAILs.
#   --apt-update   also run 'apt-get update' to test repo signatures (writes the apt cache)
#   --force        run on a non-Linux kernel anyway (development only; results are not meaningful)
#   --out FILE     write to FILE instead of stdout
#
# PASSIVE vs ACTIVE
#   Passive checks read configuration files and kernel state (/proc, /sys). They work on a
#   mounted image or ISO: mount it, `chroot` in, and run this script: file-based checks
#   resolve against the image, and runtime checks correctly report NA because /proc is absent.
#   Active checks require the service to be running and answering: TLS cipher and mutual-TLS
#   enforcement in particular CANNOT be determined from config alone, because what a server
#   actually negotiates depends on its TLS library version, build options and defaults.
#   Every CHECK line is tagged with which method produced it.
#
# Output format:
#   CHECK|<id>|<PASS|FAIL|WARN|INFO|NA>|<observed value>|<note>|<passive|active>
#   ===== SECTION <name> =====   followed by raw evidence blocks
#
# Exit code is always 0: findings are in the output, not the exit status.

LC_ALL=C
export LC_ALL
# A non-login shell, which is exactly what `ssh host 'sudo bash -s' < script` gives you,
# typically has no /sbin or /usr/sbin on PATH. Without them have() returns false for iptables,
# nft, ss, sshd, auditctl, lsmod, sysctl and findmnt, and every check that depends on one
# silently reports "not present" on a host where it is installed and running.
case ":$PATH:" in *:/usr/sbin:*) ;; *) PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH" ;; esac
export PATH
QUICK=0
PROBE=1
APTUPDATE=0
OUT=""
LSA_ROOT=""   # --root prefix; empty = live system
OFFLINE=0

die() { printf 'lsa-collect: %s\n' "$1" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --quick|--no-fs-scan) QUICK=1 ;;
    --no-probe|--passive) PROBE=0 ;;
    --apt-update) APTUPDATE=1 ;;
    --force) FORCE_NON_LINUX=1 ;;
    # A missing or bad argument here used to leave LSA_ROOT empty with OFFLINE=1, which labels
    # the report "OFFLINE" and then describes the running host. Silently auditing the wrong
    # machine under an offline banner is the worst failure this tool has, so it is fatal.
    --root)
      [ -n "$2" ] || die "--root requires a path to a mounted filesystem"
      case "$2" in -*) die "--root requires a path, got the flag '$2'" ;; esac
      [ -d "$2" ] || die "--root: '$2' is not a directory"
      LSA_ROOT="${2%/}"; OFFLINE=1; PROBE=0; shift ;;
    --out)
      [ -n "$2" ] || die "--out requires a filename"
      OUT="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    # Unknown flags were ignored silently, so a typo'd --pasive left active probing ON and
    # opened TLS handshakes and HTTP requests to production services with no warning.
    *) die "unknown option '$1' (see --help). Refusing to run rather than fall back to defaults, because the default is to probe" ;;
  esac
  shift
done
# stdout carries the machine-readable CHECK| contract. Merging stderr into it put stat and grep
# warnings between the records and broke `grep '^CHECK|'`, so diagnostics go to a sidecar file.
if [ -n "$OUT" ]; then
  exec >"$OUT" 2>"${OUT}.stderr"
fi

have() { command -v "$1" >/dev/null 2>&1; }
# cap <n>: print at most n lines and SAY SO when there were more. `head -n` drops the remainder
# without a trace, so a host with 213 SUID binaries reports 80 and reads as a complete list. That
# is a missed finding dressed up as coverage, which is the same failure as a manufactured one:
# the report claims to know something it does not. Truncations are counted into the run summary.
cap() {
  awk -v n="$1" -v tally="${LSA_TALLY:-}" '
    { c++; if (c<=n) print }
    END {
      if (c>n) {
        printf "  [truncated: showing %d of %d, re-run a targeted query for the rest]\n", n, c
        if (tally != "") print "T 1" >> tally
      }
    }'
}
# redact_env: mask the VALUE of every assignment on a line, keeping the variable names.
# A single `sed 's/=\([^=]*\)$/=<redacted>/'` only masks after the LAST '=', so a unit line
# carrying two variables ("Environment=API_KEY=abc DB_SECRET=xyz") printed the first value
# verbatim into the report. Redaction that is wrong on multi-assignment lines is worse than
# no redaction, because the output claims to be safe to paste into a ticket.
redact_env() {
  awk '{
    pfx=""
    if (match($0, /^[[:space:]]*[A-Za-z_]+=/)) { pfx=substr($0,1,RLENGTH); $0=substr($0,RLENGTH+1) }
    # A quoted value may contain spaces, so token-splitting cannot find where it ends. Rather
    # than risk printing the tail of one, collapse the whole remainder. Losing a variable name
    # is cheap; printing half a secret is not.
    if ($0 ~ /[\047"]/) { sub(/=.*/, "=<redacted>", $0); print pfx $0; next }
    line=$0; out=""
    while (match(line, /[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*/)) {
      tok=substr(line,RSTART,RLENGTH); eq=index(tok,"=")
      out = out substr(line,1,RSTART-1) substr(tok,1,eq) "<redacted>"
      line=substr(line,RSTART+RLENGTH)
    }
    print pfx out line
  }'
}
# have_target <binary>: is it installed on the TARGET? Live that is the running PATH; offline it
# must be looked for inside the mounted tree. `have` alone would resolve against the AUDITOR's PATH
# and report their toolchain as the image's.
have_target() {
  [ "$OFFLINE" = "1" ] || { have "$1"; return; }
  for _hd in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin; do
    [ -x "${LSA_ROOT}${_hd}/$1" ] && return 0
  done
  return 1
}
raw()  { printf '\n--- %s ---\n' "$1"; }
# CHECK|id|status|value|note|method
#   static: reads files on disk only. Works against a mounted image or chroot.
#   runtime: reads LIVE kernel/process state (/proc, /sys, ps, ss, lsmod, systemctl) or queries
#             an installed binary. Safe on production, but meaningless on an offline image.
#   active: interacts with a service or the network (TLS handshake, HTTP request, apt update,
#             NTP query, sudo -l). Suppressed entirely by --passive.
# The distinction matters: "not active" does NOT mean "works offline", and conflating the two
# would make the offline-image workflow silently useless for the runtime checks.
METHOD=static
SECTION_DEFAULT=static
# Offline, a runtime or active check has nothing to read but the AUDITING host, so any verdict it
# reaches describes the wrong machine. Enforced here, at the single choke point, rather than at
# each call site: a guard that has to be remembered 200 times is a guard that gets missed, and the
# failure mode of missing one is a manufactured finding, which is the thing this tool must not do.
# Verdict and timing tally. Written to a temp file rather than shell variables because many checks
# run inside pipelines and `while read` loops, whose subshells would discard an incremented counter.
# Absent mktemp, the tally is skipped and the run still completes.
LSA_T0="$(date +%s 2>/dev/null || echo 0)"
LSA_TALLY=""
if have mktemp; then
  LSA_TALLY="$(mktemp "${TMPDIR:-/tmp}/lsa-tally.XXXXXX" 2>/dev/null)" || LSA_TALLY=""
fi
[ -n "$LSA_TALLY" ] && trap 'rm -f "$LSA_TALLY"' EXIT HUP INT TERM
LSA_SECT=""; LSA_SECT_T0="$LSA_T0"

# ---------------- container profile ----------------
# A container image cannot implement a host control, and reporting one as a defect buries the
# findings that ARE actionable. Measured on three production images: 49 of 55 non-PASS lines were
# host controls, leaving 3 real ones. These become NA with the reason, never silent suppression.
ctr_host_owned() {
  case "$1" in
    mount/*|mount.*)
      CTR_WHY="the image is a single layered filesystem; separate mounts and their nosuid/noexec/nodev options are set by the host or the orchestrator (tmpfs mounts, volume options, --mount), not in the image" ;;
    firewall.*)
      CTR_WHY="a container has no netfilter of its own; ingress and egress filtering belong to the host, the orchestrator network policy, or the cloud security group" ;;
    time.*)
      CTR_WHY="the clock is the host kernel's; NTP configuration inside an image has no effect and no ntpd runs here" ;;
    integrity.fim)
      CTR_WHY="file-integrity monitoring is the wrong control for an immutable image: drift is prevented by rebuilding and by a read-only rootfs, not detected after the fact" ;;
    session.tmout|banner.*|users.password_reuse|users.inactive_lock|users.single_user_auth|cron.allow)
      CTR_WHY="an interactive-login control; this container has no console, no getty and no sshd, so there is no login session for it to govern" ;;
    coredump.limits)
      CTR_WHY="core dump handling is kernel-wide and set on the host; a container cannot change it" ;;
    logging.auditd|logging.auditd_rules|logging.auditd_coverage|logret.auditd*)
      CTR_WHY="the kernel audit subsystem is not namespaced and a container cannot run auditd meaningfully; audit the host, and collect container events there" ;;
    logging.remote|logging.*_forward|logret.journal*|logging.journal*)
      CTR_WHY="a container writes to stdout/stderr and the runtime log driver ships it; journald retention and remote forwarding are configured on the host or in the logging sidecar" ;;
    misc.running_newest|kernel.*)
      CTR_WHY="the kernel is the host's; a container has no kernel of its own to update" ;;
    system.platform)
      CTR_WHY="whether the machine is physical or virtual is a property of the host, and an image can be deployed to either. It decides whether the USB and DMA controls apply, so determine it on the host" ;;
    proc.hidepid)
      CTR_WHY="/proc is mounted into the container by the runtime; hidepid is set with a --mount option or the pod spec, not from inside the image" ;;
    *) return 1 ;;
  esac
  return 0
}
# Properties of how THIS container was started, not of the image. When the collector is the
# workload (an inspection container), they describe the throwaway container it is running in.
ctr_runtime_posture() {
  case "$1" in
    container.privileged|container.seccomp|container.mac|container.no_new_privs|\
    container.readonly_rootfs|container.socket.*|container.host_mount*|container.host_sensitive_mount)
      return 0 ;;
    sysctl.net.*|sysctl.kernel.*|sysctl.vm.*|sysctl.fs.*|sysctl.dev.*) return 0 ;;
    umask.effective) return 0 ;;
  esac
  return 1
}

chk()  {
  _cid="$1"; _cst="$2"; _cob="$3"; _cnt="$4"; _cm="${5:-$METHOD}"
  if [ -n "${CTR:-}" ] && ctr_host_owned "$_cid"; then
    _cst=NA; _cob="container: control belongs to the host"; _cnt="$CTR_WHY"
  elif [ -n "${CTR:-}" ] && [ "${CTR_MODE:-}" = "inspection" ] && ctr_runtime_posture "$_cid"; then
    # PID 1 is a shell, so this container was started to inspect an image. Its seccomp profile,
    # rootfs mode and netns sysctls are this throwaway container's, and say nothing about how the
    # image is deployed. Reporting them as image findings is describing the wrong thing.
    _cst=NA; _cob="inspection container: reflects this run, not the image"
    _cnt="started to inspect the image, so runtime posture and namespaced sysctls here are docker's defaults for this command. Audit the deployed service (compose/swarm/k8s manifest) for these"
  elif [ -n "${CTR:-}" ] && [ "${CTR_MODE:-}" = "workload" ] && ctr_runtime_posture "$_cid"; then
    case "$_cid" in
      sysctl.*) _cnt="${_cnt} [container: namespaced sysctls cannot be set from the image; fix with --sysctl, a sysctls: block in the pod spec, or on the host]" ;;
    esac
  fi
  if [ "$OFFLINE" = "1" ]; then
    case "$_cm" in
      runtime*|active*)
        _cst=NA
        _cob="offline (--root): not determinable from a mounted image"
        _cnt="needs a running kernel or a live service; audit the booted instance for this control"
        ;;
    esac
  fi
  # The delimiter must never appear inside a field. Linux core_pattern starts with a literal '|'
  # (pipe-to-handler), which silently produced a 7-field record and broke every documented
  # `awk -F"|"` consumer. Percent-encoded so the value stays readable and reversible.
  _cob="${_cob//|/%7C}"; _cnt="${_cnt//|/%7C}"
  _cob="${_cob//$'\n'/ }";  _cnt="${_cnt//$'\n'/ }"
  printf 'CHECK|%s|%s|%s|%s|%s\n' "$_cid" "$_cst" "$_cob" "$_cnt" "$_cm"
  [ -n "$LSA_TALLY" ] && printf 'V %s %s\n' "$_cst" "${_cm%%:*}" >> "$LSA_TALLY"
  return 0
}
active_on()  { [ "$PROBE" = "1" ] && METHOD=active; return 0; }
active_off() { METHOD="$SECTION_DEFAULT"; return 0; }
runtime_on() { METHOD=runtime; return 0; }
static_on()  { METHOD=static; return 0; }
method_reset() { METHOD="$SECTION_DEFAULT"; return 0; }

# ---------------- determinability guards (field feedback §1) ----------------
# A FAIL must mean "checked, and it is wrong", never "could not determine". Any check whose
# prerequisite is missing must emit NA with the reason. The inverse of the NA-is-not-PASS rule,
# and the more damaging one: a FAIL invented from a failed read manufactures findings.
DEGRADED=""
degrade() { DEGRADED="$1"; METHOD="${METHOD}:degraded"; }   # mark the next check as low-confidence
undegrade() { DEGRADED=""; METHOD="${METHOD%%:degraded}"; }
# readable <file...>: true only if at least one exists AND is readable by us
readable() { for _f in "$@"; do [ -r "$_f" ] && return 0; done; return 1; }
# rf <path>: resolve a path under --root. All FILE reads should go through this so the same
# check works live and offline. Runtime interfaces (/proc, /sys) are deliberately NOT resolved:
# they belong to the auditing host and must be reported NA offline, never read by accident.
rf() { printf '%s%s' "$LSA_ROOT" "$1"; }
# offline_na <id> <what>: in --root mode, emit NA for a check that needs a running system
offline_na() {
  [ "$OFFLINE" = "1" ] || return 1
  chk "$1" NA "offline (--root): $2" "requires a running kernel or a live service; not determinable from a mounted image. Audit the booted instance for this control"
  return 0
}
# any_readable_in <dir...>: true if a directory exists and we can list it
dir_readable() { for _d in "$@"; do [ -d "$_d" ] && [ -r "$_d" ] && return 0; done; return 1; }
# statmode <file>: mode only, empty if stat is unavailable or fails. Callers MUST treat
# empty as "unknown" and emit NA, never as a permissive default.
statmode() { stat -L -c '%a' "$1" 2>/dev/null || stat -L -f '%Lp' "$1" 2>/dev/null; }
statown()  { stat -L -c '%u:%g' "$1" 2>/dev/null || stat -L -f '%u:%g' "$1" 2>/dev/null; }
# need <id> <what-is-missing>: emit NA and return 1 so the caller can skip its check
need() { chk "$1" NA "prerequisite unavailable: $2" "not determinable in this collection mode: this is NOT a pass and NOT a failure"; return 1; }
# Section defaults: the dominant acquisition method for that section. Individual checks that
# differ call runtime_on/static_on around themselves.
sec() {
  _snow="$(date +%s 2>/dev/null || echo 0)"
  if [ -n "$LSA_SECT" ] && [ -n "$LSA_TALLY" ]; then
    printf 'S %s %s\n' "$LSA_SECT" "$((_snow - LSA_SECT_T0))" >> "$LSA_TALLY"
  fi
  LSA_SECT="$1"; LSA_SECT_T0="$_snow"
  printf '\n===== SECTION %s =====\n' "$1"
  case "$1" in
    SYSTEM|FILESYSTEMS|SYSCTL|BOOT|DISK_ENCRYPTION|MAC_LSM|FIREWALL|NETWORK|SERVICES|\
    USB_PERIPHERALS|MISC|TIME) SECTION_DEFAULT=runtime ;;
    KERNEL_MODULES|INSECURE_SERVICES|WEBSERVER|TLS)   SECTION_DEFAULT=runtime ;;
    *)                                                SECTION_DEFAULT=static ;;
  esac
  METHOD="$SECTION_DEFAULT"
}
# tmo <secs> CMD...: bounded execution even where GNU `timeout` is absent
# stderr is NOT merged into stdout. It used to be, and that turned every diagnostic into data:
# `dnf repoquery --extras` with no network printed "Error: Failed to download metadata..." to
# stderr, which arrived on stdout, was counted as one line, and became
# "packages.orphaned FAIL: 1 package(s) not provided by any repo" on an image that had none.
# Call sites that want the diagnostic in the report add 2>&1 themselves.
tmo() {
  _s="$1"; shift
  if have timeout; then timeout "$_s" "$@"; return; fi
  "$@" & _p=$!
  ( sleep "$_s"; kill -9 "$_p" 2>/dev/null ) >/dev/null 2>&1 & _w=$!
  wait "$_p" 2>/dev/null; _r=$?
  kill -9 "$_w" >/dev/null 2>&1
  return $_r
}
# run CMD with a timeout, never hang the audit
run()  { tmo 25 "$@"; }

# Reports the MOST SEVERE insecure element anywhere on a path: the file itself or any
# ancestor directory. Walks the whole path rather than returning on the first hit, because
# a weak signal on the file (non-root owner) would otherwise mask a world-writable parent,
# and write access to a parent directory is enough to replace the file entirely.
path_risk() {
  _p="$1"; _w=""; _g=""; _o=""; _depth=0
  while [ -n "$_p" ] && [ "$_p" != "/" ] && [ "$_p" != "." ]; do
    if [ -e "$_p" ] || [ -L "$_p" ]; then
      # A SYMLINK'S OWN MODE IS ALWAYS 0777 and carries no information: /bin -> usr/bin is
      # lrwxrwxrwx on every Linux host. Evaluating it directly reports "/bin is world-writable",
      # which is alarming and wrong. Follow the link and judge the target; what actually governs
      # replaceability is the target's mode and the writability of the parent directories, which
      # this walk already covers.
      if [ -L "$_p" ]; then
        _tgt="$(readlink -f "$_p" 2>/dev/null)"
        if [ -n "$_tgt" ] && [ -e "$_tgt" ]; then
          _s="$(stat -L -c '%a %U %G' "$_p" 2>/dev/null)"
        else
          _s=""   # dangling symlink: nothing to evaluate
        fi
      else
        _s="$(stat -c '%a %U %G' "$_p" 2>/dev/null)"
      fi
      if [ -n "$_s" ]; then
        _m="${_s%% *}"; _own="$(printf '%s' "$_s" | awk '{print $2}')"; _grp="$(printf '%s' "$_s" | awk '{print $3}')"
        # Sticky world-writable ANCESTOR directories (/tmp, /var/tmp, /dev/shm = 1777) are not a
        # replace risk: the sticky bit stops non-owners deleting or renaming entries.
        _sticky=0
        if [ "${#_m}" = "4" ]; then case "$_m" in 1*|3*|5*|7*) _sticky=1 ;; esac; fi
        _skipw=0
        [ "$_sticky" = "1" ] && [ "$_depth" -gt 0 ] && [ -d "$_p" ] && _skipw=1
        if [ "$_skipw" = "0" ]; then
          case "$_m" in *[2367]) [ -z "$_w" ] && _w="WORLD-WRITABLE $_p ($_s)" ;; esac
          case "$_m" in ?[2367]?) [ "$_grp" != "root" ] && [ -z "$_g" ] && _g="GROUP-WRITABLE-BY-$_grp $_p ($_s)" ;; esac
        fi
        [ "$_own" != "root" ] && [ -z "$_o" ] && _o="OWNED-BY-$_own $_p ($_s)"
      fi
    fi
    _depth=$((_depth+1))
    _p="$(dirname "$_p")"
  done
  [ -n "$_w" ] && { printf '%s' "$_w"; return 0; }
  [ -n "$_g" ] && { printf '%s' "$_g"; return 0; }
  [ -n "$_o" ] && { printf '%s' "$_o"; return 0; }
  return 1
}
trim() { printf '%s' "$1" | tr -s ' \t' ' ' | sed 's/^ *//;s/ *$//'; }

# ---------------------------------------------------------------- OS GATE
# This audits Linux. On any other kernel almost every check degrades to "absent": /proc and
# /sys are missing, the userland is BSD, and the collection tools are not there, which produces
# a long list of FAIL and NA that reads like findings and is really just "wrong operating
# system". Refuse rather than emit a misleading report.
KERNEL_NAME="$(uname -s 2>/dev/null)"
if [ "$KERNEL_NAME" != "Linux" ]; then
  printf 'ERROR: this collector audits Linux. Detected kernel: %s\n\n' "${KERNEL_NAME:-unknown}"
  printf 'Almost every check would report the control as absent, not because it is missing,\n'
  printf 'but because /proc, /sys and the GNU userland this relies on are not present. That\n'
  printf 'output would look like findings and would be wrong.\n\n'
  printf 'Run it on the Linux host instead:\n'
  printf '    ssh -p <port> <user>@<host> \047sudo bash -s\047 < %s > report.txt\n' "$(basename "$0")"
  printf 'or against a mounted Linux filesystem:\n'
  printf '    %s --root /mnt/image\n\n' "$(basename "$0")"
  printf 'Pass --force to run anyway (development only: results are not meaningful).\n'
  [ "${FORCE_NON_LINUX:-0}" = "1" ] || exit 2
  printf '\n--force given; continuing on a non-Linux kernel. RESULTS ARE NOT MEANINGFUL.\n\n'
fi

AM_ROOT=0
[ "$(id -u)" = "0" ] && AM_ROOT=1

# ---------------------------------------------------------------- EXECUTION CONTEXT
# Critical for correctness: inside a container, /proc/sys, /proc/cmdline, lsmod, /sys and
# the kernel itself belong to the HOST, not to the thing being audited. Reporting those as
# findings about the container would be simply wrong, so detect the context first and
# downgrade host-owned checks to NA with an explanation.
CTR=""; CTRTYPE=""
[ -f /.dockerenv ] && CTR=1 && CTRTYPE=docker
[ -f /run/.containerenv ] && CTR=1 && CTRTYPE=podman
[ -n "${container:-}" ] && CTR=1 && CTRTYPE="${CTRTYPE:-$container}"
if [ -r /proc/1/cgroup ]; then
  grep -qE '(docker|libpod|containerd|kubepods|lxc|garden)' /proc/1/cgroup 2>/dev/null && { CTR=1; CTRTYPE="${CTRTYPE:-cgroup-match}"; }
fi
if have systemd-detect-virt; then
  _dv="$(systemd-detect-virt -c 2>/dev/null)"
  [ -n "$_dv" ] && [ "$_dv" != "none" ] && { CTR=1; CTRTYPE="$_dv"; }
fi
# a container's PID 1 is not systemd/init
[ -z "$CTR" ] && [ -r /proc/1/comm ] && case "$(cat /proc/1/comm 2>/dev/null)" in
  systemd|init|openrc-init|runit) ;; *) [ -d /proc/1 ] && CTR=1 && CTRTYPE="${CTRTYPE:-pid1-not-init}" ;;
esac
# Which kind of container: a deployed workload, or one started just to inspect an image?
# PID 1 tells us. A workload's PID 1 is the application; an inspection container's is the shell
# the collector was piped into. The distinction decides whether runtime posture is a finding.
CTR_MODE=""
if [ -n "$CTR" ]; then
  CTR_MODE=workload
  case "$(cat /proc/1/comm 2>/dev/null)" in
    sh|bash|dash|ash|zsh|ksh|busybox|lsa-collect.sh) CTR_MODE=inspection ;;
  esac
fi

host_owned() { # true when a host-level check cannot describe this execution context
  [ -n "$CTR" ]
}

# ---- physical or virtual ------------------------------------------------------------------
# Controls that defend a physical port (USB device policy, DMA protection) only mean something
# where such a port exists. "usbguard not installed" against a cloud instance with no USB bus is
# noise, and noise is what gets a report skimmed instead of read. Conversely a machine somebody
# can walk up to needs those controls, so the platform decides the severity, not the tester.
PLATFORM=unknown; VIRT=unknown; PLATFORM_WHY=""; CHASSIS=""
detect_platform() {
  if have systemd-detect-virt; then
    # Authoritative, and the only source that reliably reports "none" for bare metal.
    VIRT="$(systemd-detect-virt -v 2>/dev/null)"; [ -z "$VIRT" ] && VIRT=none
    PLATFORM_WHY="systemd-detect-virt"
  elif [ -r /sys/hypervisor/type ]; then
    VIRT="$(cat /sys/hypervisor/type 2>/dev/null)"; PLATFORM_WHY="/sys/hypervisor/type"
  elif grep -qE '^flags[[:space:]]*:.* hypervisor( |$)' /proc/cpuinfo 2>/dev/null; then
    # CPUID hypervisor bit: set by every mainstream hypervisor, and not distro-dependent.
    VIRT=hypervisor-bit; PLATFORM_WHY="hypervisor flag in /proc/cpuinfo"
  else
    _dmi=""
    for _f in sys_vendor product_name board_vendor; do
      [ -r "/sys/class/dmi/id/$_f" ] && _dmi="$_dmi $(cat "/sys/class/dmi/id/$_f" 2>/dev/null)"
    done
    case "$_dmi" in
      *QEMU*|*KVM*|*VMware*|*VirtualBox*|*innotek*|*Xen*|*Bochs*|*Parallels*|*oVirt*|\
      *OpenStack*|*"Virtual Machine"*|*"Virtual Platform"*|*"Google Compute Engine"*)
        VIRT=dmi-match; PLATFORM_WHY="DMI:${_dmi}" ;;
      *)
        if [ -r /proc/device-tree/model ]; then
          # No DMI and no hypervisor bit usually means ARM, where a board is described by its
          # device tree. An SBC (Raspberry Pi and friends) is as physical as hardware gets and
          # tends to have the most exposed USB ports in the estate. But a guest has a device tree
          # too: QEMU's virt machine calls itself "linux,dummy-virt" and Xen's is "xen,xenvm", so
          # match those before concluding that a device tree means real hardware.
          _dt="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
          [ -d /proc/device-tree/hypervisor ] && _dt="$_dt $(tr -d '\0' < /proc/device-tree/hypervisor/compatible 2>/dev/null)"
          case "$_dt" in
            # Anchored on the identifiers hypervisors actually publish. A bare *xen* substring
            # would also swallow a board called Xenon and report real hardware as a guest.
            *dummy-virt*|*QEMU*|*qemu*|*XENVM*|*xen,xen*|*xen,dom*|*KVM*|*kvm*|*VMware*|*virtio,*)
              VIRT=dt-match; PLATFORM_WHY="device-tree: $_dt" ;;
            *)
              VIRT=none; PLATFORM_WHY="device-tree: $_dt" ;;
          esac
        elif [ -n "$_dmi" ]; then
          VIRT=none; PLATFORM_WHY="DMI:${_dmi}"
        fi ;;
    esac
  fi
  case "$VIRT" in
    none)       PLATFORM=physical ;;
    unknown|"") PLATFORM=unknown ;;
    *)          PLATFORM=virtual ;;
  esac
  # SMBIOS chassis type. A machine that leaves the building is a different USB threat model
  # from one bolted into a rack in a datacentre with badge access.
  if [ -r /sys/class/dmi/id/chassis_type ]; then
    case "$(cat /sys/class/dmi/id/chassis_type 2>/dev/null)" in
      3|4|5|6|7|13|15|16)     CHASSIS=desktop ;;
      8|9|10|11|14|30|31|32)  CHASSIS=portable ;;
      17|22|23|28|29)         CHASSIS=server ;;
    esac
  fi
}
[ -z "$CTR" ] && [ "$OFFLINE" != "1" ] && detect_platform

printf '===== LINUX SECURITY AUDIT COLLECTOR =====\n'
printf 'collected_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
printf 'hostname=%s\n' "$(hostname 2>/dev/null)"
printf 'running_as_root=%s\n' "$AM_ROOT"
printf 'PATH=%s\n' "$PATH"
printf 'quick_mode=%s\n' "$QUICK"
[ "$OFFLINE" = "1" ] && printf 'MODE: OFFLINE (--root %s). Config is read from the mounted tree; every check needing a running\n      kernel or live service reports NA rather than describing the auditing host.\n' "$LSA_ROOT"
[ "$AM_ROOT" = "0" ] && printf 'NOTE: not root: several checks will report NA (insufficient privilege), not PASS.\n'

# ---------------------------------------------------------------- 1. SYSTEM
sec SYSTEM
raw "os-release"
[ -r "$(rf /etc/os-release)" ] && cat "$(rf /etc/os-release)"
# Provenance, emitted as a single comparable string. Drift between images that are supposed to
# share a base is invisible until you line them up: two of three images audited on the same day
# were Debian 13 and the third was Debian 12, which nothing in the report surfaced.
static_on   # both read files from the tree, so they work against a mounted image
OSID="$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' "$(rf /etc/os-release)" 2>/dev/null)"
OSVER="$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2; exit}' "$(rf /etc/os-release)" 2>/dev/null)"
if [ -n "$OSID" ]; then
  chk system.base_os INFO "${OSID}-${OSVER:-unknown}" "quote this when comparing images or hosts that are supposed to be identical; a base-image difference explains findings that otherwise look like drift"
else
  chk system.base_os NA "no /etc/os-release" "the distribution and release could not be identified"
fi

# End-of-life, established from EVIDENCE rather than a date table. A hardcoded EOL list is wrong
# the moment it goes stale, and asserting "this release is unsupported" from memory is the same
# error as asserting a CIS control number from memory. What IS observable: the distributions move
# past-EOL releases to a different host, so a repository pointing there is proof, not a guess.
EOLEV="$( { cat "$(rf /etc/apt/sources.list)" 2>/dev/null
            cat "$LSA_ROOT"/etc/apt/sources.list.d/*.list "$LSA_ROOT"/etc/apt/sources.list.d/*.sources 2>/dev/null
            cat "$LSA_ROOT"/etc/yum.repos.d/*.repo 2>/dev/null; } \
          | grep -ioE '(archive\.debian\.org|old-releases\.ubuntu\.com|vault\.centos\.org|vault\.almalinux\.org)' | sort -u | tr '\n' ' ')"
if [ -n "$EOLEV" ]; then
  chk system.base_os_eol FAIL "repositories point at ${EOLEV}" "distributions move a release to these hosts once it stops receiving security updates, so this is direct evidence the base is past end of life. No patch is coming for any CVE in it: rebuild on a supported release"
else
  # No archive evidence. Fall back to a dated table, reported as WARN and never FAIL, because a
  # date table is stale the day it ships. The as-of date is printed so a reader can judge how much
  # to trust it, and the instruction is to verify rather than to act on this alone. This is the
  # same reasoning that keeps CIS control numbers out of the output: state the basis, or say NA.
  EOL_ASOF="2026-08"
  EOLTAB=""
  case "${OSID}-${OSVER%%.*}" in
    debian-8|debian-9|debian-10)                   EOLTAB="Debian ${OSVER}" ;;
    ubuntu-14|ubuntu-16|ubuntu-18|ubuntu-19|ubuntu-21|ubuntu-23) EOLTAB="Ubuntu ${OSVER}" ;;
    centos-6|centos-7|centos-8)                    EOLTAB="CentOS ${OSVER}" ;;
    rhel-6|rhel-7)                                 EOLTAB="RHEL ${OSVER}" ;;
  esac
  case "${OSID}-${OSVER}" in
    ubuntu-20.04) EOLTAB="Ubuntu 20.04 (standard support ended; security updates require Ubuntu Pro/ESM)" ;;
  esac
  if [ -n "$EOLTAB" ]; then
    chk system.base_os_eol WARN "${EOLTAB} is past end of standard support (as of ${EOL_ASOF})" "no archived-release repository is configured, so this is from the collector's own table rather than from evidence on the host, and that table goes stale. Confirm against the vendor lifecycle page before acting. If it is correct, no patch is coming for any CVE in this base and the fix is a rebuild, not a package update"
  else
    chk system.base_os_eol PASS "no archived-release repositories configured" "this shows the release has not been moved to an archive host, and it is not in the collector's table of releases known past support as of ${EOL_ASOF}. Neither is proof of support: check the vendor's lifecycle page for ${OSID:-this distribution} ${OSVER:-}"
  fi
fi
method_reset
raw "kernel"
uname -a
raw "virtualisation / platform"
have systemd-detect-virt && systemd-detect-virt 2>/dev/null
[ -r /sys/class/dmi/id/product_name ] && cat /sys/class/dmi/id/product_name 2>/dev/null
raw "uptime"
uptime 2>/dev/null

KREL="$(uname -r)"
chk kernel.release INFO "$KREL" ""
# Physical or virtual decides whether the port-level controls further down are findings or
# noise, so it is stated once, up front, with the evidence it was decided on.
chk system.platform INFO "$PLATFORM (virt=${VIRT}${CHASSIS:+, chassis=$CHASSIS})" \
  "${PLATFORM_WHY:+determined from $PLATFORM_WHY. }a physical machine has ports somebody can plug into, so USB device policy and DMA protection apply to it; on a virtual instance those same controls are usually unenforceable and are reported as not applicable rather than as defects"
# If a collection tool is missing, every check that needs it degrades. Say so once, loudly,
# rather than letting each dependent check report a misleading absence.
MISSING_TOOLS=""
for t in ss iptables nft systemctl lsmod sysctl findmnt stat awk sed grep; do
  have "$t" || MISSING_TOOLS="$MISSING_TOOLS $t"
done
if [ -n "$MISSING_TOOLS" ]; then
  chk collect.missing_tools WARN "$MISSING_TOOLS" "on a Linux host these are almost certainly present but not on PATH, so every check depending on one reports NA or a degraded result, NOT an absent control. If this includes iptables/nft/ss on a host that plainly has them, PATH is missing /sbin and /usr/sbin: re-run with 'sudo -i' or an explicit PATH"
else
  chk collect.missing_tools PASS "all core collection tools present" ""
fi
# End-of-life / very old kernels are their own finding; compare against distro current.
if have needrestart; then
  raw "needrestart (reboot required?)"
  run needrestart -b 2>/dev/null | cap 30
fi
if [ -f "$(rf /var/run/reboot-required)" ] || [ -f /run/reboot-required ]; then
  chk kernel.reboot_pending FAIL "yes" "kernel/libs updated but not rebooted, running code is not the patched code"
else
  chk kernel.reboot_pending PASS "no" ""
fi

# ------------------------------------------------------------ 2. FILESYSTEMS
sec FILESYSTEMS
raw "/etc/fstab"
[ -r "$(rf /etc/fstab)" ] && grep -vE '^\s*#' "$(rf /etc/fstab)" | grep -vE '^\s*$'
raw "findmnt (real mounts)"
if have findmnt; then run findmnt -lo TARGET,SOURCE,FSTYPE,OPTIONS --real; else mount; fi

mopts() { # mopts <mountpoint> -> option string, empty if not a mountpoint
  if have findmnt; then findmnt -no OPTIONS "$1" 2>/dev/null | head -1
  else awk -v m="$1" '$2==m{print $4; exit}' /proc/mounts 2>/dev/null; fi
}
is_mp() { if have mountpoint; then mountpoint -q "$1"; else grep -qE " $1 " /proc/mounts; fi; }

for mp in /home /tmp /var /var/tmp /var/log /var/log/audit /boot /dev/shm /srv /opt; do
  if is_mp "$mp"; then
    o="$(mopts "$mp")"
    miss=""
    case "$mp" in
      /var|/var/log|/var/log/audit) want="nosuid nodev" ;;
      *)                            want="nosuid noexec nodev" ;;
    esac
    for w in $want; do case ",$o," in *",$w,"*) ;; *) miss="$miss $w" ;; esac; done
    if [ -n "$miss" ]; then chk "mount$mp" FAIL "$o" "missing:$miss"
    else chk "mount$mp" PASS "$o" ""; fi
  else
    chk "mount$mp" WARN "not-a-separate-mount" "no separate filesystem: cannot enforce nosuid/noexec/nodev, and cannot bound disk exhaustion"
  fi
done

PO="$(mopts /proc)"
chk mount/proc INFO "$PO" ""
case "$PO" in *hidepid=2*|*hidepid=invisible*) chk proc.hidepid PASS "$PO" "" ;;
  *hidepid=1*|*hidepid=noaccess*) chk proc.hidepid WARN "$PO" "hidepid=1 only hides file contents; use 2/invisible" ;;
  *) chk proc.hidepid FAIL "${PO:-unknown}" "every user can read every process cmdline/env" ;; esac
for o in nosuid nodev noexec; do
  case ",$PO," in *",$o,"*) ;; *) chk "proc.$o" FAIL "$PO" "missing $o on /proc" ;; esac
done

raw "disk usage"
df -hT 2>/dev/null | grep -vE 'tmpfs|devtmpfs|overlay|squashfs'

# ---------------------------------------------------------------- 3. SYSCTL
sec SYSCTL
# id|expected|severity-hint  ('*' expected = report value only)
SYSCTLS='
kernel.kptr_restrict|2|HIGH
kernel.dmesg_restrict|1|MEDIUM
kernel.printk|3 3 3 3|LOW
kernel.unprivileged_bpf_disabled|1|HIGH
net.core.bpf_jit_harden|2|MEDIUM
dev.tty.ldisc_autoload|0|MEDIUM
dev.tty.legacy_tiocsti|0|MEDIUM
kernel.kexec_load_disabled|1|HIGH
vm.unprivileged_userfaultfd|0|MEDIUM
kernel.sysrq|4|MEDIUM
kernel.unprivileged_userns_clone|0|POLICY
user.max_user_namespaces|*|POLICY
kernel.apparmor_restrict_unprivileged_userns|1|POLICY
kernel.perf_event_paranoid|3|MEDIUM
kernel.randomize_va_space|2|HIGH
kernel.yama.ptrace_scope|3|HIGH
kernel.modules_disabled|1|HIGH
kernel.oops_limit|1|LOW
kernel.warn_limit|1|LOW
kernel.panic_on_oops|1|LOW
vm.mmap_rnd_bits|32|MEDIUM
vm.mmap_rnd_compat_bits|16|LOW
vm.swappiness|1|LOW
vm.max_map_count|*|INFO
fs.protected_symlinks|1|MEDIUM
fs.protected_hardlinks|1|MEDIUM
fs.protected_fifos|2|MEDIUM
fs.protected_regular|2|MEDIUM
fs.suid_dumpable|0|HIGH
kernel.deny_new_usb|1|POLICY
net.ipv4.tcp_syncookies|1|MEDIUM
net.ipv4.tcp_rfc1337|1|LOW
net.ipv4.conf.all.rp_filter|1|MEDIUM
net.ipv4.conf.default.rp_filter|1|MEDIUM
net.ipv4.conf.all.accept_redirects|0|MEDIUM
net.ipv4.conf.default.accept_redirects|0|MEDIUM
net.ipv4.conf.all.secure_redirects|0|MEDIUM
net.ipv4.conf.default.secure_redirects|0|MEDIUM
net.ipv6.conf.all.accept_redirects|0|MEDIUM
net.ipv6.conf.default.accept_redirects|0|MEDIUM
net.ipv4.conf.all.send_redirects|0|MEDIUM
net.ipv4.conf.default.send_redirects|0|MEDIUM
net.ipv4.icmp_echo_ignore_all|1|POLICY
net.ipv4.conf.all.accept_source_route|0|MEDIUM
net.ipv4.conf.default.accept_source_route|0|MEDIUM
net.ipv6.conf.all.accept_source_route|0|MEDIUM
net.ipv6.conf.default.accept_source_route|0|MEDIUM
net.ipv6.conf.all.accept_ra|0|POLICY
net.ipv6.conf.default.accept_ra|0|POLICY
net.ipv4.conf.all.log_martians|1|LOW
net.ipv4.icmp_echo_ignore_broadcasts|1|MEDIUM
net.ipv4.icmp_ignore_bogus_error_responses|1|LOW
net.ipv4.ip_forward|0|POLICY
net.ipv4.tcp_timestamps|0|POLICY
net.ipv4.conf.all.arp_ignore|1|LOW
net.ipv4.conf.all.arp_announce|2|LOW
'
printf '%s\n' "$SYSCTLS" | while IFS='|' read -r key want sevhint; do
  [ -z "$key" ] && continue
  path="/proc/sys/$(printf '%s' "$key" | tr '.' '/')"
  if [ ! -e "$path" ]; then
    chk "sysctl.$key" NA "absent" "tunable not present on this kernel/distro ($sevhint)"
    continue
  fi
  got="$(trim "$(cat "$path" 2>/dev/null)")"
  # In a container only net.*, kernel.shm*/msg*/sem* and fs.mqueue.* are namespaced; every
  # other tunable is the host's, read-only, and not a property of what is being audited.
  if [ "$OFFLINE" = "1" ]; then
    chk "sysctl.$key" NA "offline (--root)" "/proc/sys belongs to the auditing host, not the image. The PERSISTED intent is still checked from ${LSA_ROOT}/etc/sysctl.d; see the DRIFT notes"
    continue
  fi
  if [ -n "$CTR" ]; then
    case "$key" in
      net.*|kernel.shm*|kernel.msg*|kernel.sem*|fs.mqueue.*) ;;
      *) chk "sysctl.$key" NA "$got (host value)" "this tunable is not namespaced: inside a $CTRTYPE container it reflects the HOST kernel and cannot be set here. Audit the host for this control"
         continue ;;
    esac
  fi
  if [ "$want" = "*" ]; then
    chk "sysctl.$key" INFO "$got" "$sevhint"
  elif [ "$got" = "$(trim "$want")" ]; then
    chk "sysctl.$key" PASS "$got" ""
  else
    chk "sysctl.$key" FAIL "$got" "want=$want sev=$sevhint"
  fi
done

# core dumps: three independent mechanisms, all must agree
CP="$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
case "$CP" in
  '|/bin/false'|'|/bin/true'|core|'') chk coredump.core_pattern PASS "$CP" "" ;;
  *systemd-coredump*)  chk coredump.core_pattern WARN "$CP" "systemd-coredump active; check Storage= below" ;;
  *)                   chk coredump.core_pattern FAIL "$CP" "core dumps are being written/piped somewhere" ;;
esac
static_on   # the two checks below read files, not /proc
CDS="$(grep -rhiE '^\s*Storage\s*=' "$(rf /etc/systemd/coredump.conf)" "$(rf /etc/systemd/coredump.conf.d/)" 2>/dev/null | tail -1)"
if [ -n "$CDS" ]; then
  case "$CDS" in *none*) chk coredump.systemd PASS "$CDS" "" ;; *) chk coredump.systemd FAIL "$CDS" "want Storage=none" ;; esac
else
  have systemd-coredump && chk coredump.systemd FAIL "unset(default=external)" "no [Coredump] Storage=none drop-in" \
    || chk coredump.systemd NA "systemd-coredump not present" ""
fi
if grep -rqE '^\s*\*\s+hard\s+core\s+0' "$(rf /etc/security/limits.conf)" "$(rf /etc/security/limits.d/)" 2>/dev/null; then
  chk coredump.limits PASS "* hard core 0" ""
else
  chk coredump.limits FAIL "absent" "no '* hard core 0' in limits.conf/limits.d"
fi
runtime_on
raw "ulimit -c (current shell)"; ulimit -c 2>/dev/null

static_on
raw "sysctl config files on disk (persistence)"
ls -la "$(rf /etc/sysctl.conf)" "$(rf /etc/sysctl.d/)" "$(rf /usr/lib/sysctl.d/)" /run/sysctl.d/ 2>/dev/null
raw "hardening-relevant lines in sysctl config"
grep -rhE '^\s*[a-z]' "$(rf /etc/sysctl.conf)" "$(rf /etc/sysctl.d/)" 2>/dev/null | sed 's/  */ /g'

# --------------------------------------------------- 4. BOOT / KERNEL CMDLINE
sec BOOT
if [ -n "$CTR" ] || [ "$OFFLINE" = "1" ]; then
  chk boot.container_context NA "running inside a $CTRTYPE container" "kernel command line, Secure Boot, lockdown and CPU mitigations are properties of the HOST kernel; audit the host for this section"
else
raw "/proc/cmdline"
cat /proc/cmdline 2>/dev/null
CMD=" $(cat /proc/cmdline 2>/dev/null) "
want_param() { # want_param <token> <severity> <note>
  case "$CMD" in *" $1 "*) chk "cmdline.$1" PASS "present" "" ;;
                 *) chk "cmdline.$1" FAIL "absent" "$2: $3" ;; esac
}
want_param "slab_nomerge"              MEDIUM "slab merging aids heap-spray exploitation"
want_param "init_on_alloc=1"           MEDIUM "uninitialised heap memory leaks/UAF primitives"
want_param "init_on_free=1"            MEDIUM "freed memory not zeroed"
want_param "page_alloc.shuffle=1"      LOW    "page allocator freelist is predictable"
want_param "pti=on"                    HIGH   "Meltdown/KASLR-bypass protection not forced"
want_param "randomize_kstack_offset=on" MEDIUM "kernel stack offset predictable"
want_param "vsyscall=none"             MEDIUM "legacy vsyscall page is a fixed-address ROP source"
want_param "debugfs=off"               MEDIUM "debugfs exposes kernel internals"
want_param "oops=panic"                POLICY "oops-based exploit probing not stopped (may cause reboots)"
want_param "module.sig_enforce=1"      HIGH   "unsigned kernel modules can be loaded (rootkit vector)"
want_param "lockdown=confidentiality"  HIGH   "no kernel lockdown: root can read/modify kernel memory"
want_param "mce=0"                     LOW    ""
want_param "spectre_v2=on"             POLICY "CPU side-channel mitigation not forced"
want_param "spec_store_bypass_disable=on" POLICY ""
want_param "tsx=off"                   POLICY ""
want_param "l1tf=full,force"           POLICY ""
want_param "mds=full,nosmt"            POLICY ""
want_param "nosmt=force"               POLICY "SMT/hyper-threading enabled: cross-thread side channels"
want_param "kvm.nx_huge_pages=force"   POLICY ""
want_param "ia32_emulation=0"          MEDIUM "32-bit syscall ABI reachable (large, low-attention attack surface; kernel 6.7+)"
want_param "ipv6.disable=1"            POLICY "IPv6 stack loaded"
want_param "random.trust_cpu=off"      POLICY ""
want_param "efi=disable_early_pci_dma" POLICY "pre-boot DMA attack surface"
case "$CMD" in *" mitigations="*) chk cmdline.mitigations INFO "$(printf '%s' "$CMD" | tr ' ' '\n' | grep '^mitigations=')" "" ;; esac
case "$CMD" in *"mitigations=off"*) chk cmdline.mitigations_off FAIL "mitigations=off" "ALL CPU vulnerability mitigations disabled" ;; esac

raw "CPU vulnerability status (/sys/devices/system/cpu/vulnerabilities)"
for f in /sys/devices/system/cpu/vulnerabilities/*; do
  [ -r "$f" ] && printf '%-28s %s\n' "$(basename "$f")" "$(cat "$f" 2>/dev/null)"
done
raw "SMAP / SMEP / other CPU security flags"
CPUFLAGS="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2-)"
printf '%s' " $CPUFLAGS " | tr ' ' '\n' | grep -E '^(smap|smep|umip|pti|ibrs|ibpb|stibp|ssbd|md_clear|user_shstk|la57|nx)$' | tr '\n' ' '
echo
for f in smap smep umip; do
  case " $CPUFLAGS " in
    *" $f "*) chk "cpu.$f" PASS present "" ;;
    *)        chk "cpu.$f" WARN absent "CPU/hypervisor does not expose $f: kernel cannot block supervisor access/execution of user pages" ;;
  esac
done

static_on
raw "bootloader config presence + permissions"
ls -la "$(rf /boot/grub/grub.cfg)" "$(rf /boot/grub2/grub.cfg)" "$LSA_ROOT"/boot/efi/EFI/*/grub.cfg "$(rf /boot/loader/loader.conf)" 2>/dev/null
ls -la "$(rf /etc/grub.d/)" 2>/dev/null
GP=0
grep -rqs 'password_pbkdf2\|password_pbkdf' "$(rf /etc/grub.d/)" "$(rf /boot/grub/grub.cfg)" "$(rf /boot/grub2/grub.cfg)" "$(rf /etc/grub.d/40_custom)" 2>/dev/null && GP=1
grep -rqs 'GRUB2_PASSWORD' "$(rf /boot/grub2/user.cfg)" 2>/dev/null && GP=1
if [ "$GP" = "1" ]; then chk boot.grub_password PASS "password_pbkdf2 found" ""
else chk boot.grub_password FAIL "absent" "anyone with console/KVM/IPMI can edit cmdline and boot to a root shell (init=/bin/bash)"; fi
grep -rqs 'set superusers' "$(rf /etc/grub.d/)" "$(rf /boot/grub/grub.cfg)" "$(rf /boot/grub2/grub.cfg)" 2>/dev/null \
  && chk boot.grub_superusers PASS present "" || chk boot.grub_superusers INFO absent ""
if [ -r "$(rf /boot/loader/loader.conf)" ]; then
  grep -qE '^\s*editor\s+no' "$(rf /boot/loader/loader.conf)" && chk boot.sdboot_editor PASS "editor no" "" \
    || chk boot.sdboot_editor FAIL "editor not disabled" "systemd-boot allows cmdline editing at boot"
fi

raw "Secure Boot / lockdown state"
have mokutil && run mokutil --sb-state
[ -r /sys/kernel/security/lockdown ] && cat /sys/kernel/security/lockdown
[ -d /sys/firmware/efi ] && echo "firmware=UEFI" || echo "firmware=BIOS/legacy"

# ------------------------------------------------------------ 5. DISK CRYPTO
fi

sec DISK_ENCRYPTION
if [ -n "$CTR" ] || [ "$OFFLINE" = "1" ]; then
  chk disk_encryption.container_context NA "running inside a $CTRTYPE container" "block devices and LUKS belong to the HOST; audit the host for this section"
else
raw "block devices"
have lsblk && run lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE
CRYPTN=0
if have lsblk; then CRYPTN="$(lsblk -o FSTYPE 2>/dev/null | grep -c crypto_LUKS)"; fi
if [ "${CRYPTN:-0}" -gt 0 ]; then chk disk.luks PASS "$CRYPTN LUKS volume(s)" ""
else chk disk.luks WARN "none" "no LUKS volumes: data at rest unprotected if disk/snapshot/backing store is seized or cloned"; fi
raw "crypttab"
[ -r "$(rf /etc/crypttab)" ] && grep -vE '^\s*#|^\s*$' "$(rf /etc/crypttab)"
raw "swap"
cat /proc/swaps 2>/dev/null
if grep -q '^/' /proc/swaps 2>/dev/null; then
  if grep -qs 'swap' "$(rf /etc/crypttab)" 2>/dev/null; then chk disk.swap_encrypted PASS "crypttab entry" ""
  else chk disk.swap_encrypted WARN "plaintext swap" "memory (keys, secrets) can be paged to unencrypted disk"; fi
else
  chk disk.swap_encrypted INFO "no swap active" ""
fi

# ---------------------------------------------------------------- 6. MODULES
fi

sec KERNEL_MODULES
if [ -n "$CTR" ] || [ "$OFFLINE" = "1" ]; then
  chk kernel_modules.container_context NA "running inside a $CTRTYPE container" "the module list and modprobe policy belong to the HOST kernel; a container shares it and cannot change it; audit the host for this section"
else
chk modules.disabled_runtime "$( [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" = "1" ] && echo PASS || echo FAIL )" \
    "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" "1 blocks all further module load/unload: blocks LKM rootkits (e.g. REPTILE / UNC3886)"
raw "loaded modules (count + list)"
lsmod 2>/dev/null | wc -l
lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort | tr '\n' ' '
echo
static_on
raw "/etc/modprobe.d contents"
ls -la "$(rf /etc/modprobe.d/)" 2>/dev/null
grep -rhE '^\s*(install|blacklist)' "$(rf /etc/modprobe.d/)" "$(rf /usr/lib/modprobe.d/)" 2>/dev/null | sed 's/  */ /g' | sort -u

BLACKLIST_NET='dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm'
BLACKLIST_FS='cramfs freevxfs jffs2 hfs hfsplus squashfs udf'
BLACKLIST_NETFS='cifs nfs nfsv3 nfsv4 ksmbd gfs2'
BLACKLIST_HW='vivid bluetooth btusb uvcvideo firewire-core thunderbolt usb-storage'
MPD="$(grep -rhE '^\s*(install|blacklist)\s' "$(rf /etc/modprobe.d/)" "$(rf /usr/lib/modprobe.d/)" 2>/dev/null)"
for grp in NET FS NETFS HW; do
  eval "list=\$BLACKLIST_$grp"
  missing=""; present=""
  for m in $list; do
    if printf '%s' "$MPD" | grep -qE "^\s*install\s+$m\s+/bin/(false|true)" || printf '%s' "$MPD" | grep -qE "^\s*blacklist\s+$m\s*$"; then
      present="$present $m"
    else
      missing="$missing $m"
    fi
  done
  [ -n "$missing" ] && chk "modblacklist.$grp" FAIL "missing:$missing" "loadable on demand by any packet/mount/USB event" \
                    || chk "modblacklist.$grp" PASS "all covered" ""
done
# loaded despite being on the risky list?
for m in $BLACKLIST_NET $BLACKLIST_FS $BLACKLIST_HW; do
  lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$(printf '%s' "$m" | tr '-' '_')" && chk "modloaded.$m" WARN loaded "risky module currently loaded"
done

# ---------------------------------------------------------------- 7. MAC / LSM
fi

sec MAC_LSM
# Offline the runtime state belongs to the auditing host, but the CONFIGURED state is a plain
# file and is exactly what an image audit should report. Do that instead of a blanket NA.
if [ "$OFFLINE" = "1" ]; then
  raw "MAC configuration (offline: configured state, not runtime)"
  grep -hE '^\s*(SELINUX|SELINUXTYPE)\s*=' "$(rf /etc/selinux/config)" 2>/dev/null
  SELCFG_O="$(awk -F= '/^\s*SELINUX\s*=/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$(rf /etc/selinux/config)" 2>/dev/null)"
  AAPROF_O="$(ls "$(rf /etc/apparmor.d)" 2>/dev/null | grep -c .)"
  if [ -n "$SELCFG_O" ]; then
    case "$SELCFG_O" in
      enforcing) chk mac.configured PASS "SELINUX=enforcing in /etc/selinux/config" "configured state; the running mode cannot be read from an image" ;;
      *) chk mac.configured FAIL "SELINUX=$SELCFG_O" "the image is configured to boot with SELinux $SELCFG_O: every instance from it starts unprotected" ;;
    esac
  elif [ "${AAPROF_O:-0}" -gt 0 ]; then
    chk mac.configured INFO "${AAPROF_O} AppArmor profile(s) present" "enforcement mode is a runtime property; verify on a booted instance"
  else
    chk mac.configured FAIL "no SELinux config and no AppArmor profiles in the image" "no mandatory access control is installed at all, so no instance built from this image will have one"
  fi
else
raw "active LSMs"
[ -r /sys/kernel/security/lsm ] && cat /sys/kernel/security/lsm
if have getenforce; then
  SEL="$(getenforce 2>/dev/null)"
  case "$SEL" in Enforcing) chk mac.selinux PASS "$SEL" "" ;;
    Permissive) chk mac.selinux FAIL "$SEL" "SELinux logs but does not block" ;;
    *) chk mac.selinux FAIL "${SEL:-Disabled}" "" ;; esac
  raw "sestatus"; run sestatus
  raw "SELinux policy and config"
  grep -hE '^\s*(SELINUX|SELINUXTYPE)\s*=' "$(rf /etc/selinux/config)" 2>/dev/null
  SELCFG="$(awk -F= '/^\s*SELINUX\s*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$(rf /etc/selinux/config)" 2>/dev/null)"
  [ -n "$SELCFG" ] && [ "$SELCFG" != "enforcing" ] && chk mac.selinux_persist FAIL "config SELINUX=$SELCFG" "even if currently enforcing, the mode is not persistent across reboot"

  # --- unconfined domains: a process in an unconfined domain is NOT protected by policy ---
  raw "process security contexts (ps -eZ)"
  run ps -eZ 2>/dev/null | cap 60
  raw "processes running in UNCONFINED domains"
  ps -eZ 2>/dev/null | awk 'NR>1' \
    | grep -E 'unconfined_t|unconfined_service_t|initrc_t|kernel_t\b' \
    | grep -vE '\[' | cap 40
  UNCONF="$(ps -eZ 2>/dev/null | awk 'NR>1' | grep -cE 'unconfined_t|unconfined_service_t|initrc_t')"
  if [ "${UNCONF:-0}" -gt 0 ]; then
    chk mac.selinux_unconfined FAIL "${UNCONF} process(es) in an unconfined domain" "SELinux is enforcing but these processes run under unconfined_t/unconfined_service_t/initrc_t, which permits essentially everything the DAC layer allows: for them SELinux provides no confinement at all. Confine each with a targeted policy module, or run it from a unit whose binary is labelled with a confined type"
  else
    chk mac.selinux_unconfined PASS "no unconfined domains running" ""
  fi
  raw "breakdown of running domains"
  ps -eZ 2>/dev/null | awk 'NR>1{n=split($1,a,":"); print a[3]}' | sort | uniq -c | sort -rn | cap 25

  # --- permissive domains silently exempt themselves even when the system is Enforcing ---
  if have semanage; then
    raw "permissive domains (exempt from enforcement)"
    run semanage permissive -l 2>/dev/null | cap 20
    PERMD="$(semanage permissive -l 2>/dev/null | grep -cE '^[a-z_]+_t$')"
    [ "${PERMD:-0}" -gt 0 ] && chk mac.selinux_permissive_domains FAIL "${PERMD} permissive domain(s)" "these domains are exempt from enforcement even though the system reports Enforcing, usually left over from troubleshooting"
  fi
  raw "SELinux denials in the recent audit log (tuning signal, and evidence policy is live)"
  [ "$AM_ROOT" = "1" ] && have ausearch && run ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | tail -25
  [ "$AM_ROOT" = "1" ] && have journalctl && run journalctl -q --no-pager -n 15 -g 'avc:  denied' 2>/dev/null
  raw "booleans that weaken policy if on"
  have getsebool && run getsebool -a 2>/dev/null | grep -E 'allow_execheap|allow_execmem|allow_execmod|allow_execstack|httpd_execmem|httpd_can_network_connect|httpd_enable_cgi|secure_mode_insmod|selinuxuser_execmod|domain_kernel_load_modules|nis_enabled' | cap 20
  raw "file contexts pending relabel"
  [ -e /.autorelabel ] && echo "/.autorelabel present: filesystem relabel scheduled at next boot"
elif have aa-status || [ -d /sys/kernel/security/apparmor ]; then
  raw "apparmor status"
  if [ "$AM_ROOT" = "1" ] && have aa-status; then run aa-status; else cat /sys/kernel/security/apparmor/profiles 2>/dev/null | cap 50; fi
  ENF="$(grep -c '(enforce)' /sys/kernel/security/apparmor/profiles 2>/dev/null)"
  CMPL="$(grep -c '(complain)' /sys/kernel/security/apparmor/profiles 2>/dev/null)"
  if [ "${ENF:-0}" -gt 0 ]; then chk mac.apparmor PASS "${ENF} enforcing / ${CMPL:-0} complain" ""
  else chk mac.apparmor FAIL "no enforcing profiles" ""; fi
  [ "${CMPL:-0}" -gt 0 ] && chk mac.apparmor_complain WARN "${CMPL} profile(s) in complain mode" "complain mode logs violations but blocks nothing"
  # AppArmor's equivalent of "unconfined": a running process with no profile attached
  raw "processes and their AppArmor confinement"
  if [ "$AM_ROOT" = "1" ] && have aa-status; then
    run aa-status 2>/dev/null | sed -n '/processes are in/,$p' | cap 30
    UNCONF="$(aa-status 2>/dev/null | awk '/processes are unconfined/{print $1; exit}')"
    [ -n "$UNCONF" ] && [ "$UNCONF" != "0" ] \
      && chk mac.apparmor_unconfined WARN "${UNCONF} unconfined process(es)" "these run with no AppArmor profile: on Ubuntu/Debian only a handful of daemons ship profiles, so custom applications are typically unconfined and get no MAC protection at all" \
      || chk mac.apparmor_unconfined PASS "no unconfined processes reported" ""
  else
    # /proc/<pid>/attr/current reads "unconfined" for unprofiled processes
    N=0; U=0
    for pid in $(ps -eo pid= 2>/dev/null | head -200); do
      c="$(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null)"
      [ -n "$c" ] || continue
      N=$((N+1)); case "$c" in unconfined*) U=$((U+1)) ;; esac
    done
    [ "$N" -gt 0 ] && chk mac.apparmor_unconfined INFO "${U} of ${N} sampled processes unconfined" "run as root with aa-status for the authoritative figure"
  fi
  raw "network-facing processes and their profile"
  if have ss; then
    ss -tulpnH 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | while read -r pid; do
      printf '  pid=%-7s %-28s %s\n' "$pid" "$(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null)" "$(ps -o args= -p "$pid" 2>/dev/null | cut -c1-50)"
    done | cap 20
  fi
elif [ -r "$(rf /etc/selinux/config)" ] || dir_readable "$(rf /etc/apparmor.d)"; then
  # tooling absent but configuration present; report the configuration, not "no MAC"
  SELCFG2="$(awk -F= '/^\s*SELINUX\s*=/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$(rf /etc/selinux/config)" 2>/dev/null)"
  chk mac.any WARN "${SELCFG2:+SELINUX=$SELCFG2 configured, }status tools unavailable" "getenforce/aa-status are not present, so the RUNNING mode could not be read. Reporting the configured state only; do not record this as either enforcing or absent"
elif [ -e /sys/kernel/security/lsm ] || [ -d /sys/module/apparmor ] || [ -d /sys/fs/selinux ]; then
  chk mac.any FAIL "no SELinux and no AppArmor active" "kernel LSM interfaces are readable and show no MAC in force: a compromised daemon runs with its full DAC rights"
else
  chk mac.any NA "no LSM interface and no MAC tooling or config found" "cannot determine whether mandatory access control is present: this is undetermined, not an absence"
fi
fi

# --------------------------------------------------------- 8. SUID / SGID / CAPS
sec SUID_SGID_CAPS
if [ "$QUICK" = "1" ]; then
  chk suid.scan NA skipped "--quick mode"
else
  # Offline, the only tree that belongs to the target is the mounted one. findmnt is a runtime
  # tool and would hand back the AUDITING host's mounts, so the walk must never consult it here.
  if [ "$OFFLINE" = "1" ]; then
    SCANDIRS="$LSA_ROOT"
  else
    SCANDIRS="$( { have findmnt && findmnt -lno TARGET,FSTYPE --real 2>/dev/null | awk '$2 ~ /^(ext2|ext3|ext4|xfs|btrfs|f2fs|zfs|jfs|reiserfs)$/{print $1}'; } | sort -u )"
    [ -z "$SCANDIRS" ] && SCANDIRS="/"
  fi
  raw "SUID/SGID files"
  _oifs=$IFS; IFS=$'\n'
  for d in $SCANDIRS; do
    find "$d" -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %g %s %p\n' 2>/dev/null
  done | sort -u
  IFS=$_oifs
  raw "file capabilities"
  if have getcap; then for d in $SCANDIRS; do getcap -r "$d" 2>/dev/null; done | sort -u; else echo "getcap not installed"; fi
  raw "world-writable directories missing sticky bit"
  for d in $SCANDIRS; do find "$d" -xdev -type d -perm -0002 ! -perm -1000 -printf '%M %u %g %p\n' 2>/dev/null; done | cap 50
  raw "world-writable files"
  for d in $SCANDIRS; do find "$d" -xdev -type f -perm -0002 -printf '%M %u %g %p\n' 2>/dev/null; done | cap 80
  raw "files/dirs with no owner or no group"
  for d in $SCANDIRS; do find "$d" -xdev \( -nouser -o -nogroup \) -printf '%M %u %g %p\n' 2>/dev/null; done | cap 40
fi

# ------------------------------------------------------- 9. PERMISSIONS / UMASK
sec PERMISSIONS
raw "home + sensitive directory permissions"
ls -ld "$(rf /root)" "$(rf /home)" "$LSA_ROOT"/home/* "$(rf /boot)" "$(rf /usr/src)" "$(rf /lib/modules)" "$(rf /usr/lib/modules)" "$(rf /etc)" /tmp "$(rf /var/tmp)" /dev/shm 2>/dev/null
# ---- /root ----
ROOTMODE="$(statmode "$(rf /root)")"
if [ -z "$ROOTMODE" ]; then
  chk perm./root NA "stat failed for /root" "mode not determinable, not a failure"
else
  OTH="$(printf '%s' "$ROOTMODE" | sed 's/.*\(.\)/\1/')"
  GRP="$(printf '%s' "$ROOTMODE" | sed 's/.*\(.\)./\1/')"
  ROOTGRP="$(stat -L -c '%G' "$(rf /root)" 2>/dev/null)"
  case "$ROOTMODE" in
    # Anything with no world bits and a root-owned group exposes nothing. Red Hat ships 0550,
    # which is stricter than 0700 for group and other, and failing it was simply wrong.
    700|0700|750|0750|500|0500|550|0550|000|0|00|400|0400|600|0600)
      if [ "$OTH" = "0" ] && { [ -z "$ROOTGRP" ] || [ "$ROOTGRP" = "root" ]; }; then
        chk perm./root PASS "$ROOTMODE" ""
      else
        chk perm./root WARN "$ROOTMODE (group $ROOTGRP)" "no world access, but a non-root group can read root's files"
      fi ;;
    *) if [ "$OTH" != "0" ]; then
         chk perm./root FAIL "$ROOTMODE" "/root must be 0700. Other local users can list or read it: root's shell history, .ssh, kubeconfigs, cloud credentials and anything left there during maintenance"
       else
         chk perm./root FAIL "$ROOTMODE" "/root must be 0700; group bits are set ($ROOTMODE), so members of its group can read root's files"
       fi ;;
  esac
fi

# ---- home directories, taken from /etc/passwd rather than globbing /home ----
# A user whose home is /srv/app or /var/lib/foo is invisible to a /home/* glob, and those are
# exactly the service accounts whose homes tend to be created by hand with default modes.
raw "home directory permissions (all real accounts, wherever their home is)"
HOMEBAD=0; HOMEOK=0
awk -F: '/^[^#]/ && NF>=7 && $3+0>=1000 && $3+0<65534 && $6!="" && $6!="/" && $6!="/nonexistent" {print $1" "$6}' \
  "$(rf /etc/passwd)" 2>/dev/null | while read -r u h; do
    hp="$(rf "$h")"
    [ -d "$hp" ] || { printf '  MISSING  %-16s %s\n' "$u" "$h"; continue; }
    m="$(statmode "$hp")"; o="$(statown "$hp")"
    [ -z "$m" ] && { printf '  UNKNOWN  %-16s %s (stat failed)\n' "$u" "$h"; continue; }
    g="$(printf '%s' "$m" | sed 's/.*\(.\)./\1/')"; ot="$(printf '%s' "$m" | sed 's/.*\(.\)/\1/')"
    if [ "$m" = "700" ] || [ "$m" = "0700" ]; then printf '  ok       %-16s %s %s\n' "$u" "$m" "$h"
    elif [ "$ot" = "0" ]; then printf '  GROUP    %-16s %s %s (uid:gid %s)\n' "$u" "$m" "$h" "$o"
    else printf '  OTHER    %-16s %s %s (uid:gid %s)\n' "$u" "$m" "$h" "$o"; fi
  done
# counts in a second pass so they survive the subshell
HOMES="$(awk -F: '/^[^#]/ && NF>=7 && $3+0>=1000 && $3+0<65534 && $6!="" && $6!="/" {print $6}' "$(rf /etc/passwd)" 2>/dev/null)"
# priv_group <user> <groupname>: true when the group is that user's own private group, i.e. named
# after them and with no other members. Debian and Ubuntu both ship USERGROUPS_ENAB yes, so a 0750
# home is group-readable only by its owner and exposes nothing. Counting that as a finding would
# flag the vendor default of the two most widely deployed distributions for an exposure that does
# not exist. It is still a finding the moment somebody else joins the group.
priv_group() {
  [ "$1" = "$2" ] || return 1
  _members="$(awk -F: -v g="$2" '$1==g{print $4}' "$(rf /etc/group)" 2>/dev/null)"
  case ",${_members}," in
    ,,|,"$1",) return 0 ;;
    *) return 1 ;;
  esac
}
NOTHER=0; NGROUP=0; NTOT=0; NPRIV=0
_oifs=$IFS; IFS=$'\n'
for h in $HOMES; do
  hp="$(rf "$h")"; [ -d "$hp" ] || continue
  m="$(statmode "$hp")"; [ -z "$m" ] && continue
  NTOT=$((NTOT+1))
  ot="$(printf '%s' "$m" | sed 's/.*\(.\)/\1/')"; g="$(printf '%s' "$m" | sed 's/.*\(.\)./\1/')"
  [ "$ot" != "0" ] && NOTHER=$((NOTHER+1))
  if [ "$ot" = "0" ] && [ "$g" != "0" ]; then
    _hu="$(stat -L -c '%U' "$hp" 2>/dev/null)"; _hg="$(stat -L -c '%G' "$hp" 2>/dev/null)"
    if priv_group "$_hu" "$_hg"; then NPRIV=$((NPRIV+1)); else NGROUP=$((NGROUP+1)); fi
  fi
done
IFS=$_oifs
if [ "$NTOT" = "0" ]; then
  chk perm.home_dirs NA "no home directories found or readable" "undetermined"
elif [ "$NOTHER" -gt 0 ]; then
  chk perm.home_dirs FAIL "${NOTHER} of ${NTOT} home(s) readable by other users" "every local account, including a compromised service account, can read these users' files: SSH private keys, .bash_history, cloud credential files, application configs. Set 0700 on each, and fix the default below or the next account created repeats it"
elif [ "$NGROUP" = "0" ] && [ "$NPRIV" -gt 0 ]; then
  chk perm.home_dirs PASS "${NPRIV} of ${NTOT} home(s) 0750 with a per-user private group" "group-readable, but the group is the owner's own and has no other members, so nothing is exposed. This stops being true the moment another account joins that group, so it is worth an alert on group membership changes rather than a permission change"
elif [ "$NGROUP" -gt 0 ]; then
  chk perm.home_dirs WARN "${NGROUP} of ${NTOT} home(s) group-readable" "acceptable only if the group is deliberate and its membership is controlled; 0700 otherwise"
else
  chk perm.home_dirs PASS "all ${NTOT} home director(ies) are 0700" ""
fi

# ---- the default that decides NEW accounts ----
# Fixing existing homes does not stop the next useradd creating a world-readable one. This is
# the same class as logrotate's create mode: correct the generator, not just the output.
raw "default mode for newly created home directories"
HOMEMODE="$(grep -hE '^\s*HOME_MODE' "$(rf /etc/login.defs)" 2>/dev/null | awk '{print $2}' | tail -1)"
LDUMASK="$(grep -hE '^\s*UMASK' "$(rf /etc/login.defs)" 2>/dev/null | awk '{print $2}' | tail -1)"
DIRMODE="$(grep -hE '^\s*DIR_MODE' "$(rf /etc/adduser.conf)" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
printf '  login.defs HOME_MODE=%s  login.defs UMASK=%s  adduser.conf DIR_MODE=%s\n' \
  "${HOMEMODE:-unset}" "${LDUMASK:-unset}" "${DIRMODE:-unset}"
if [ -n "$HOMEMODE" ]; then
  case "$HOMEMODE" in
    0700|700) chk perm.home_default PASS "HOME_MODE=$HOMEMODE" "new accounts get a private home" ;;
    0750|750)
      if [ "$(grep -hiE '^[[:space:]]*USERGROUPS_ENAB' "$(rf /etc/login.defs)" 2>/dev/null | awk '{print tolower($2)}' | tail -1)" = "yes" ]; then
        chk perm.home_default PASS "HOME_MODE=$HOMEMODE with USERGROUPS_ENAB yes" "useradd gives each account its own group, so a 0750 home is readable only by its owner. This is Ubuntu's default and is equivalent to 0700 in practice, as long as nobody is added to a user's private group"
      else
        chk perm.home_default WARN "HOME_MODE=$HOMEMODE, USERGROUPS_ENAB not yes" "new homes are group-readable and accounts share a common group, so every member of that group can read them"
      fi ;;
    *) chk perm.home_default FAIL "HOME_MODE=$HOMEMODE" "every account created from now on gets a home readable by other users. Set HOME_MODE 0700 in /etc/login.defs" ;;
  esac
elif [ -n "$LDUMASK" ]; then
  # with HOME_MODE unset, useradd derives the home mode from UMASK
  case "$LDUMASK" in
    077|0077) chk perm.home_default PASS "HOME_MODE unset, UMASK=$LDUMASK -> homes created 0700" "" ;;
    027|0027) chk perm.home_default WARN "HOME_MODE unset, UMASK=$LDUMASK -> homes created 0750" "group-readable" ;;
    *) chk perm.home_default FAIL "HOME_MODE unset, UMASK=$LDUMASK -> homes created world-readable" "with HOME_MODE unset, useradd derives the home mode from UMASK. Set HOME_MODE 0700 explicitly rather than relying on it" ;;
  esac
elif readable "$(rf /etc/login.defs)"; then
  chk perm.home_default FAIL "neither HOME_MODE nor UMASK set in login.defs" "new home directories fall back to the built-in default (0755 on most distros): world-readable"
else
  chk perm.home_default NA "/etc/login.defs not present or not readable" "the default home mode is not determinable here"
fi
[ -n "$DIRMODE" ] && case "$DIRMODE" in
  0700|700) chk perm.adduser_dirmode PASS "DIR_MODE=$DIRMODE" "" ;;
  *) chk perm.adduser_dirmode FAIL "DIR_MODE=$DIRMODE" "Debian's adduser uses DIR_MODE from /etc/adduser.conf and it overrides HOME_MODE for accounts created with adduser rather than useradd; set it to 0700 as well, or the two tools disagree" ;;
esac

# ---- the sensitive subdirectories, regardless of the home's own mode ----
raw "~/.ssh and dotfile directory permissions"
_oifs=$IFS; IFS=$'\n'
for h in $HOMES /root; do
  hp="$(rf "$h")"; [ -d "$hp/.ssh" ] || continue
  m="$(statmode "$hp/.ssh")"
  printf '  %s %s/.ssh\n' "${m:-?}" "$h"
  case "$m" in 700|0700) ;; ""|*) [ -n "$m" ] && chk "perm.ssh_dir$h" FAIL "$m $h/.ssh" "sshd refuses to use keys from a group- or world-writable .ssh, and a readable one exposes private keys and authorized_keys" ;; esac
done
IFS=$_oifs

raw "critical file permissions"
ls -l "$(rf /etc/passwd)" "$(rf /etc/shadow)" "$(rf /etc/gshadow)" "$(rf /etc/group)" "$(rf /etc/sudoers)" "$(rf /etc/ssh/sshd_config)" "$(rf /etc/crontab)" 2>/dev/null
SH="$(stat -c '%a %U %G' "$(rf /etc/shadow)" 2>/dev/null)"
# An unreadable or absent file yields an empty mode. Reporting that as FAIL would invent a
# permissions finding out of a failed read, so it is NA with the reason.
case "$SH" in
  "") if [ -e "$(rf /etc/shadow)" ]; then
        chk perm./etc/shadow NA "mode unreadable" "the file exists but stat could not read its mode at this privilege level"
      else
        chk perm./etc/shadow NA "/etc/shadow not present" "no shadow file in this tree; on a live host this would itself be a finding, offline it usually means the image stores accounts elsewhere"
      fi ;;
  "640 root shadow"|"600 root root"|"640 root root"|"400 root root"|\
  "0 root root"|"00 root root"|"000 root root") chk perm./etc/shadow PASS "$SH" "" ;;
  *) chk perm./etc/shadow FAIL "$SH" "want 640 root:shadow or stricter" ;;
esac
raw "umask configuration"
grep -rhsE '^\s*(UMASK|umask)' "$(rf /etc/login.defs)" "$(rf /etc/profile)" "$(rf /etc/bashrc)" "$(rf /etc/bash.bashrc)" "$(rf /etc/profile.d/)" "$(rf /etc/pam.d/common-session)" 2>/dev/null
# `umask` reports the auditing shell's value, which is a property of how the collector was invoked,
# not of the target. Offline it describes the auditor's machine entirely.
runtime_on
UM="$(umask)"
case "$UM" in 0077|077|0027|027) chk umask.effective PASS "$UM" "" ;; *) chk umask.effective FAIL "$UM" "want 077 (or 027): new files are readable by others" ;; esac
method_reset
raw "sticky bit on /tmp /var/tmp /dev/shm"
stat -c '%a %n' /tmp "$(rf /var/tmp)" /dev/shm 2>/dev/null

# ---------------------------------------------------------- 10. USERS / AUTH
sec USERS_AUTH
raw "UID 0 accounts"
awk -F: '$3==0{print $1" shell="$7}' "$(rf /etc/passwd)" 2>/dev/null
UID0="$(awk -F: '$3==0' "$(rf /etc/passwd)" 2>/dev/null | wc -l | tr -d ' ')"
if ! readable "$(rf /etc/passwd)"; then
  chk users.uid0 NA "/etc/passwd not readable" "the UID-0 account count is not determinable without it; this is NOT a pass"
elif [ "${UID0:-0}" -gt 1 ]; then
  chk users.uid0 FAIL "$UID0 accounts with UID 0" "only root should have UID 0"
elif [ "${UID0:-0}" -eq 0 ]; then
  chk users.uid0 NA "no UID-0 account found in /etc/passwd" "a passwd file with no root entry means the read failed or the tree is incomplete, not that the host is hardened"
else
  chk users.uid0 PASS "1" ""
fi
raw "accounts with a login shell"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$3":"$7}' "$(rf /etc/passwd)" 2>/dev/null

# ---- account database consistency (CIS staples; inconsistencies hide backdoor accounts) ----
raw "passwd/group/shadow consistency"
DUPUID="$(awk -F: '/^[^#]/ && NF>=7 && $3!="" {print $3}' "$(rf /etc/passwd)" 2>/dev/null | sort | uniq -d | tr '\n' ' ')"
[ -n "$DUPUID" ] && chk users.duplicate_uid FAIL "$DUPUID" "two accounts sharing a UID are the same user to the kernel: file ownership and audit attribution become ambiguous, and it is a classic way to hide a second root" \
                 || chk users.duplicate_uid PASS "no duplicate UIDs" ""
DUPGID="$(awk -F: '/^[^#]/ && NF>=3 && $3!="" {print $3}' "$(rf /etc/group)" 2>/dev/null | sort | uniq -d | tr '\n' ' ')"
[ -n "$DUPGID" ] && chk users.duplicate_gid FAIL "$DUPGID" "duplicate GIDs" || chk users.duplicate_gid PASS "no duplicate GIDs" ""
DUPNAME="$(awk -F: '/^[^#]/ && NF>=7 && $1!="" {print $1}' "$(rf /etc/passwd)" 2>/dev/null | sort | uniq -d | tr '\n' ' ')"
[ -n "$DUPNAME" ] && chk users.duplicate_name FAIL "$DUPNAME" "duplicate account names"
DUPGN="$(awk -F: '/^[^#]/ && NF>=3 && $1!="" {print $1}' "$(rf /etc/group)" 2>/dev/null | sort | uniq -d | tr '\n' ' ')"
[ -n "$DUPGN" ] && chk users.duplicate_groupname FAIL "$DUPGN" "duplicate group names"
# groups referenced in passwd that do not exist in group
# only meaningful where /etc/group is actually the group source (not LDAP/Open Directory);
# if GID 0 does not resolve, getent is not backed by the local files and the result is noise
if [ "$OFFLINE" = "1" ] && ! readable "$(rf /etc/group)"; then
  chk users.missing_groups NA "no /etc/group in the mounted tree" "primary GIDs cannot be resolved against the image; the auditing host's group database would answer for the wrong machine"
elif [ "$OFFLINE" = "1" ] || getent group 0 >/dev/null 2>&1; then
  # Offline the group database must come out of the tree. getent consults the AUDITOR's NSS.
  MISSG="$(awk -F: '/^[^#]/ && NF>=7 && $4 ~ /^[0-9]+$/ {print $4}' "$(rf /etc/passwd)" 2>/dev/null | sort -u | while read -r g; do
    if [ "$OFFLINE" = "1" ]; then
      awk -F: -v g="$g" '$3==g{f=1} END{exit !f}' "$(rf /etc/group)" 2>/dev/null || printf '%s ' "$g"
    else
      getent group "$g" >/dev/null 2>&1 || printf '%s ' "$g"
    fi; done)"
  [ -n "$MISSG" ] && chk users.missing_groups WARN "$MISSG" "primary GIDs referenced in /etc/passwd with no matching group" \
                  || chk users.missing_groups PASS "all primary GIDs resolve" ""
else
  chk users.missing_groups NA "group source is not local files" ""
fi
# the shadow group must be empty: membership grants read of /etc/shadow
if [ "$OFFLINE" = "1" ]; then
  SHG_SEEN=0; readable "$(rf /etc/group)" && SHG_SEEN=1
  SHG="$(awk -F: '$1=="shadow"{print $4}' "$(rf /etc/group)" 2>/dev/null)"
else
  SHG_SEEN=0; getent group >/dev/null 2>&1 && SHG_SEEN=1
  SHG="$(getent group shadow 2>/dev/null | cut -d: -f4)"
fi
if [ "$SHG_SEEN" = "0" ]; then
  chk users.shadow_group NA "group database not readable" "membership of the shadow group is not determinable here"
elif [ -n "$SHG" ]; then
  chk users.shadow_group FAIL "$SHG" "members of the shadow group can read every password hash"
else
  chk users.shadow_group PASS "shadow group empty or absent" ""
fi
if [ "$AM_ROOT" = "1" ]; then
  have pwck && { raw "pwck -r"; run pwck -r 2>&1 | cap 15; }
  have grpck && { raw "grpck -r"; printf '' | run grpck -r 2>&1 | cap 15; }
fi
# home directories that do not exist or are not owned by their user
raw "home directory ownership anomalies"
awk -F: '/^[^#]/ && NF>=7 && $3+0>=1000 && $3+0<65534 {print $1" "$6}' "$(rf /etc/passwd)" 2>/dev/null | while read -r u h; do
  [ -d "$h" ] || { printf '  MISSING  %s (%s)\n' "$h" "$u"; continue; }
  o="$(stat -c '%U' "$h" 2>/dev/null)"
  [ "$o" = "$u" ] || printf '  NOT-OWNED-BY-USER %s owned by %s (user %s)\n' "$h" "$o" "$u"
done | cap 15
# ---- CIS/STIG parity: parameter-level password policy, not just presence ----
raw "PASSWORD POLICY PARAMETERS"
PWQ="$( { cat "$(rf /etc/security/pwquality.conf)" 2>/dev/null; cat "$(rf /etc/security/pwquality.conf.d)"/*.conf 2>/dev/null;
          grep -RhsE 'pam_pwquality\.so|pam_cracklib\.so' "$(rf /etc/pam.d)" "$(rf /etc/authselect)" 2>/dev/null; } )"
printf '%s\n' "$PWQ" | grep -vE '^\s*#|^\s*$' | cap 20
pwq_get() { printf '%s\n' "$PWQ" | grep -oE "$1[[:space:]]*=[[:space:]]*-?[0-9]+" | tail -1 | grep -oE '\-?[0-9]+$'; }
if [ -z "$PWQ" ]; then
  chk password.quality NA "no pwquality/cracklib configuration found or readable" "undetermined, not absent"
else
  MINLEN="$(pwq_get minlen)"
  if [ -n "$MINLEN" ]; then
    [ "$MINLEN" -ge 14 ] 2>/dev/null && chk password.minlen PASS "minlen=$MINLEN" "" \
      || chk password.minlen FAIL "minlen=$MINLEN" "shorter than the 14-character minimum CIS and STIG both require"
  else chk password.minlen FAIL "minlen not set" "password length is unconstrained beyond the pam_unix default"; fi
  for cr in dcredit ucredit lcredit ocredit; do
    v="$(pwq_get "$cr")"
    [ -n "$v" ] && { [ "$v" -le -1 ] 2>/dev/null && chk "password.$cr" PASS "$cr=$v" "" \
      || chk "password.$cr" WARN "$cr=$v" "a non-negative credit makes that character class optional rather than required"; }
  done
  printf '%s' "$PWQ" | grep -q 'enforce_for_root' && chk password.enforce_for_root PASS present "" \
    || chk password.enforce_for_root WARN absent "root can set a password that violates the policy"
fi

raw "ACCOUNT LOCKOUT PARAMETERS"
FLK="$( { cat "$(rf /etc/security/faillock.conf)" 2>/dev/null;
          grep -RhsE 'pam_faillock\.so|pam_tally2\.so' "$(rf /etc/pam.d)" "$(rf /etc/authselect)" 2>/dev/null; } )"
printf '%s\n' "$FLK" | grep -vE '^\s*#|^\s*$' | cap 12
if [ -z "$FLK" ]; then
  chk lockout.configured FAIL "no pam_faillock/pam_tally2 configuration found" "failed logins are unlimited: password guessing is bounded only by network speed. Both CIS and STIG require lockout after a small number of failures"
else
  DENY="$(printf '%s\n' "$FLK" | grep -oE 'deny[[:space:]]*=[[:space:]]*[0-9]+' | tail -1 | grep -oE '[0-9]+$')"
  UNLK="$(printf '%s\n' "$FLK" | grep -oE 'unlock_time[[:space:]]*=[[:space:]]*[0-9]+' | tail -1 | grep -oE '[0-9]+$')"
  if [ -n "$DENY" ]; then
    [ "$DENY" -le 5 ] 2>/dev/null && chk lockout.deny PASS "deny=$DENY" "" || chk lockout.deny WARN "deny=$DENY" "more attempts than the 3-5 both benchmarks expect"
  else chk lockout.deny FAIL "deny not set" "pam_faillock is referenced but no failure threshold is configured"; fi
  [ -n "$UNLK" ] && { [ "$UNLK" -ge 900 ] 2>/dev/null && chk lockout.unlock_time PASS "unlock_time=$UNLK" "" \
      || chk lockout.unlock_time WARN "unlock_time=$UNLK" "shorter than the 900s both benchmarks expect"; }
  printf '%s' "$FLK" | grep -qE 'even_deny_root|root_unlock_time' && chk lockout.root PASS "root lockout configured" "" \
    || chk lockout.root WARN "root not subject to lockout" "even_deny_root unset: the root account can be brute-forced without limit wherever it is reachable"
fi

raw "FIPS MODE"
FIPSPROC="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)"
printf '  /proc/sys/crypto/fips_enabled=%s\n' "${FIPSPROC:-n/a}"
have fips-mode-setup && run fips-mode-setup --check 2>/dev/null
if [ "$OFFLINE" = "1" ]; then
  grep -qs 'fips=1' "$(rf /etc/default/grub)" 2>/dev/null \
    && chk crypto.fips INFO "fips=1 in bootloader config" "configured; runtime state not determinable offline" \
    || chk crypto.fips INFO "no fips=1 in bootloader config" "only relevant where FIPS 140 validation is required"
elif [ "$FIPSPROC" = "1" ]; then
  chk crypto.fips PASS "FIPS mode enabled" ""
elif [ -e /proc/sys/crypto/fips_enabled ]; then
  chk crypto.fips INFO "FIPS mode disabled" "a DISA STIG requirement and a FedRAMP/FIPS-140 obligation; irrelevant otherwise. Enabling restricts every crypto consumer to validated algorithms and WILL break non-compliant SSH/TLS settings; fix those first, then 'fips-mode-setup --enable' and reboot"
fi

FAPO=""
have fapolicyd && FAPO="installed"
have systemctl && systemctl is-active fapolicyd >/dev/null 2>&1 && FAPO="active"
[ -d "$(rf /etc/fapolicyd)" ] && FAPO="${FAPO:-config present}"
case "$FAPO" in
  active) chk exec.allowlisting PASS "fapolicyd active" "execution restricted to an allowlist" ;;
  "")     chk exec.allowlisting INFO "no application allowlisting" "STIG requires fapolicyd on RHEL 8/9. It blocks execution of anything not on the allowlist, which stops a dropped payload even where noexec does not. Real operational cost; expect to tune it" ;;
  *)      chk exec.allowlisting WARN "fapolicyd $FAPO but not active" "installed and not enforcing" ;;
esac

TMOUT_V="$(grep -RhsE '^[[:space:]]*(export[[:space:]]+)?TMOUT=' "$(rf /etc/profile)" "$(rf /etc/profile.d)" "$(rf /etc/bashrc)" "$(rf /etc/bash.bashrc)" 2>/dev/null | grep -oE '[0-9]+' | head -1)"
if [ -n "$TMOUT_V" ]; then
  [ "$TMOUT_V" -le 900 ] 2>/dev/null && chk session.tmout PASS "TMOUT=$TMOUT_V" "" || chk session.tmout WARN "TMOUT=$TMOUT_V" "longer than the 900s both benchmarks expect"
else
  chk session.tmout WARN "TMOUT not set" "idle shells stay authenticated indefinitely: an unattended session on a console-accessible or shared host stays usable. Both benchmarks require an idle timeout"
fi

PLUS=""
for f in "$(rf /etc/passwd)" "$(rf /etc/shadow)" "$(rf /etc/group)"; do
  [ -r "$f" ] && grep -q '^+' "$f" 2>/dev/null && PLUS="$PLUS $(basename "$f")"
done
[ -n "$PLUS" ] && chk users.legacy_plus FAIL "$PLUS" "legacy NIS '+' entries: historically these defer the file to a network map and on some implementations grant access to anyone the NIS server names" \
               || chk users.legacy_plus PASS "no legacy + entries" ""

for b in "$LSA_ROOT"/etc/issue "$LSA_ROOT"/etc/issue.net "$LSA_ROOT"/etc/motd; do
  f="$(rf $b)"
  if [ -r "$f" ]; then
    if grep -qiE '\\[smrvn]|Ubuntu [0-9]|Debian GNU|Red Hat|CentOS|kernel' "$f" 2>/dev/null; then
      chk "banner.$(basename $b)" WARN "leaks OS/kernel detail" "the banner reveals distribution and kernel version to anyone who connects, before authentication. Replace the \\escape sequences with a plain notice"
    else
      chk "banner.$(basename $b)" PASS "present, no version disclosure" ""
    fi
  fi
done

# password policy details CIS checks that a simple pam grep misses
raw "password reuse / inactivity / aging policy"
grep -RhE 'pam_(unix|pwhistory)\.so.*remember=' "$(rf /etc/pam.d/)" 2>/dev/null | head -3
grep -RqsE 'remember=[0-9]+' "$(rf /etc/pam.d/)" "$(rf /etc/security/pwhistory.conf)" "$(rf /etc/authselect/)" 2>/dev/null \
  && chk users.password_reuse PASS "remember= configured" "" \
  || chk users.password_reuse WARN "no password-reuse restriction" "users can cycle straight back to a known-compromised password"
INACT="$(useradd -D 2>/dev/null | awk -F= '/INACTIVE/{print $2}')"
case "$INACT" in
  -1|"") chk users.inactive_lock WARN "INACTIVE=${INACT:-unset}" "accounts are never auto-locked after the password expires; set to 30 or less" ;;
  *) [ "$INACT" -le 45 ] 2>/dev/null && chk users.inactive_lock PASS "INACTIVE=$INACT" "" || chk users.inactive_lock WARN "INACTIVE=$INACT" "longer than the usual 30-45 day window" ;;
esac
# single-user / emergency mode must require the root password
raw "single-user and emergency mode authentication"
grep -hE 'ExecStart' "$(rf /usr/lib/systemd/system/rescue.service)" "$(rf /usr/lib/systemd/system/emergency.service)" \
     /lib/systemd/system/rescue.service /lib/systemd/system/emergency.service 2>/dev/null
if grep -hqE 'ExecStart=.*sulogin' "$(rf /usr/lib/systemd/system/rescue.service)" "$(rf /lib/systemd/system/rescue.service)" 2>/dev/null; then
  chk users.single_user_auth PASS "rescue.service uses sulogin" ""
else
  chk users.single_user_auth WARN "sulogin not confirmed in rescue.service" "without sulogin, booting to rescue/emergency gives a root shell with no password: combine with a missing GRUB password and console access is instant root"
fi
raw "empty-password accounts (shadow)"
if [ "$AM_ROOT" = "1" ]; then
  EMPT="$(awk -F: '($2==""){print $1}' "$(rf /etc/shadow)" 2>/dev/null)"
  [ -n "$EMPT" ] && chk users.empty_password FAIL "$EMPT" "login with no password" || chk users.empty_password PASS none ""
  raw "password hash algorithms in use"
  awk -F: '$2 ~ /^\$/ {split($2,a,"$"); print $1" $"a[2]}' "$(rf /etc/shadow)" 2>/dev/null
  raw "root account lock state"
  passwd -S root 2>/dev/null
  raw "accounts never expiring / stale"
  awk -F: '$2!~/^[!*]/ {print $1" last_change="$3" max="$5}' "$(rf /etc/shadow)" 2>/dev/null
else
  chk users.empty_password NA "need root" ""
fi
raw "sudoers"
if readable "$(rf /etc/sudoers)"; then
  [ -r "$(rf /etc/sudoers)" ] && grep -vE '^\s*#|^\s*$' "$(rf /etc/sudoers)" 2>/dev/null
  grep -hvE '^\s*#|^\s*$' "$LSA_ROOT"/etc/sudoers.d/* 2>/dev/null
  if grep -RqsE 'NOPASSWD' "$(rf /etc/sudoers)" "$(rf /etc/sudoers.d/)" 2>/dev/null; then
    chk sudo.nopasswd WARN present "NOPASSWD rules: any code running as that user escalates to root silently"
  else chk sudo.nopasswd PASS absent ""; fi
  grep -RqsE '^\s*[^#]*ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL' "$(rf /etc/sudoers)" 2>/dev/null && chk sudo.blanket INFO present "unrestricted sudo entries exist"
  grep -RqsE 'Defaults\s+.*use_pty' "$(rf /etc/sudoers)" "$(rf /etc/sudoers.d/)" 2>/dev/null && chk sudo.use_pty PASS present "" \
    || chk sudo.use_pty WARN absent "no 'Defaults use_pty': sudo sessions can be hijacked via TTY pushback"
  grep -RqsE 'Defaults\s+.*logfile' "$(rf /etc/sudoers)" "$(rf /etc/sudoers.d/)" 2>/dev/null && chk sudo.logfile PASS present "" \
    || chk sudo.logfile INFO absent ""
else
  chk sudo.nopasswd NA "/etc/sudoers not readable" "0440 root:root: needs root on the target. An empty read is not an absent rule, so no NOPASSWD/use_pty/logfile verdict is issued"
fi
raw "group membership: sudo/wheel/admin/docker"
for g in sudo wheel admin adm docker lxd; do getent group "$g" 2>/dev/null; done
if getent group docker 2>/dev/null | grep -q ':.*[a-z]'; then
  chk users.docker_group WARN "$(getent group docker | cut -d: -f4)" "docker group membership == root equivalence"
fi
raw "PAM: pwquality / faillock / wheel"
grep -RhsE 'pam_(pwquality|cracklib|faillock|tally2|wheel|faildelay|unix)\.so' "$(rf /etc/pam.d/)" "$(rf /etc/authselect/)" 2>/dev/null | sed 's/  */ /g' | sort -u
raw "login.defs key settings"
grep -hsE '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD|SHA_CRYPT_MIN_ROUNDS|UMASK|FAILLOG_ENAB)' "$(rf /etc/login.defs)" 2>/dev/null
raw "/etc/securetty"
[ -e "$(rf /etc/securetty)" ] && wc -l < "$(rf /etc/securetty)"
raw "last logins / failed logins (recent)"
run last -n 15
have lastb && [ "$AM_ROOT" = "1" ] && run lastb -n 15

# ------------------------------------------------------------ 11. SSH SERVER
sec SSH
raw "sshd version"
have sshd && run sshd -V 2>&1 | head -3
ssh -V 2>&1 | head -1
raw "effective sshd config (sshd -T)"
if [ "$AM_ROOT" = "1" ] && have sshd; then run sshd -T 2>/dev/null | sort; else
  echo "(need root for sshd -T; showing file)"; grep -vE '^\s*#|^\s*$' "$(rf /etc/ssh/sshd_config)" 2>/dev/null
  grep -rhvE '^\s*#|^\s*$' "$(rf /etc/ssh/sshd_config.d/)" 2>/dev/null
fi
sshd_get() { if [ "$AM_ROOT" = "1" ] && have sshd; then sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1)==k{print $2; exit}'; else
  grep -rhiE "^\s*$1\s" "$(rf /etc/ssh/sshd_config)" "$(rf /etc/ssh/sshd_config.d/)" 2>/dev/null | head -1 | awk '{print tolower($2)}'; fi; }
for pair in "pubkeyauthentication:yes" "hostbasedauthentication:no" "challengeresponseauthentication:no" \
            "permitrootlogin:no" "passwordauthentication:no" "permitemptypasswords:no" \
            "x11forwarding:no" "allowtcpforwarding:no" "usepam:yes" "kbdinteractiveauthentication:no" \
            "gssapiauthentication:no" "permituserenvironment:no" "logingracetime:30" "maxauthtries:3" "clientaliveinterval:300"; do
  k="${pair%%:*}"; wantv="${pair#*:}"; got="$(sshd_get "$k")"
  if [ -z "$got" ]; then chk "ssh.$k" INFO "unset(default)" "want $wantv"
  elif [ "$got" = "$wantv" ]; then chk "ssh.$k" PASS "$got" ""
  else chk "ssh.$k" FAIL "$got" "want $wantv"; fi
done
# ---- IS PUBLIC-KEY THE *ONLY* ACCEPTED METHOD? ----
# The per-method toggles above each close one door. AuthenticationMethods is the directive
# that states positively which methods are acceptable, and it is the only one that cannot be
# undone by a method defaulting back on after an upgrade or a distro config change.
raw "AUTHENTICATION METHOD ENFORCEMENT"
# Same guard class as sudoers (field feedback §1): if we could not read the config at all,
# every directive reads as "unset" and the pubkey verdict below would be invented from
# nothing. sshd -T is authoritative; the file fallback needs the file to be readable.
SSH_READ=1
if [ "$AM_ROOT" = "1" ] && have sshd && [ "$OFFLINE" = "0" ]; then :
elif readable "$(rf /etc/ssh/sshd_config)"; then :
else SSH_READ=0; fi
if [ "$SSH_READ" = "0" ]; then
  chk ssh.config_readable NA "sshd config not readable and sshd -T unavailable" "no SSH auth verdict is issued: every directive would read as 'unset', and unset is not the same as absent"
fi
if [ "$SSH_READ" = "1" ]; then
AM="$(sshd_get authenticationmethods)"
PWA="$(sshd_get passwordauthentication)"; KBD="$(sshd_get kbdinteractiveauthentication)"
PKA="$(sshd_get pubkeyauthentication)"; GSS="$(sshd_get gssapiauthentication)"
HBA="$(sshd_get hostbasedauthentication)"
printf '  AuthenticationMethods=%s pubkey=%s password=%s kbdinteractive=%s gssapi=%s hostbased=%s\n' \
  "${AM:-unset}" "${PKA:-default yes}" "${PWA:-?}" "${KBD:-?}" "${GSS:-?}" "${HBA:-?}"
case "$AM" in
  publickey) chk ssh.pubkey_only PASS "AuthenticationMethods publickey" "public key is positively the only accepted method: this survives a method silently defaulting back on" ;;
  *publickey*)
    chk ssh.pubkey_only WARN "AuthenticationMethods=$AM" "public key is required but not alone. Comma-separated entries mean MULTI-FACTOR (all must succeed, which is stronger); space-separated alternatives mean ANY of them is sufficient (weaker). Confirm which this is: 'publickey,keyboard-interactive' is 2FA, 'publickey keyboard-interactive' is a fallback to keyboard-interactive" ;;
  "")
    if [ "$PWA" = "no" ] && [ "$KBD" = "no" ] && [ "$HBA" = "no" ] && [ "${GSS:-no}" = "no" ]; then
      chk ssh.pubkey_only WARN "every other method disabled individually, AuthenticationMethods unset" "effectively public-key only today, but stated as a set of negatives. Each depends on a default staying put across upgrades and distro config changes. Set 'AuthenticationMethods publickey' to state it positively"
    else
      ON=""
      [ "$PWA" != "no" ] && ON="$ON password"; [ "$KBD" != "no" ] && ON="$ON keyboard-interactive"
      [ "$HBA" != "no" ] && [ -n "$HBA" ] && ON="$ON hostbased"; [ "${GSS:-no}" != "no" ] && ON="$ON gssapi"
      chk ssh.pubkey_only FAIL "still accepted:$ON" "logins are not public-key-only. Password and keyboard-interactive are what credential-stuffing and brute force target, and keyboard-interactive is the one people miss, disabling PasswordAuthentication alone leaves it open on a PAM-enabled sshd, which is the usual bypass"
    fi ;;
  *) chk ssh.pubkey_only FAIL "AuthenticationMethods=$AM (does not require publickey)" "a method other than public key is sufficient on its own" ;;
esac

# ---- Match blocks: sshd -T prints the GLOBAL config only ----
# A Match block can re-enable password auth for a user, group or address range, and none of
# the checks above would see it. This is a false-negative the global read cannot catch.
# ---- FORWARDING: every channel an SSH account can open beyond a shell ----
# Forwarding is what turns "a user has SSH" into "a user has network access to everything this
# host can reach". On a bastion or jump host: precisely the machine whose job is to be a
# boundary: it is the control that decides whether the boundary exists.
raw "SSH FORWARDING CHANNELS"
DISFWD="$(sshd_get disableforwarding)"
TCPF="$(sshd_get allowtcpforwarding)"; AGF="$(sshd_get allowagentforwarding)"
X11F="$(sshd_get x11forwarding)"; X11LH="$(sshd_get x11uselocalhost)"
GWP="$(sshd_get gatewayports)"; TUN="$(sshd_get permittunnel)"
SLF="$(sshd_get allowstreamlocalforwarding)"; POPEN="$(sshd_get permitopen)"
printf '  DisableForwarding=%s AllowTcpForwarding=%s AllowAgentForwarding=%s X11Forwarding=%s\n' \
  "${DISFWD:-unset}" "${TCPF:-default yes}" "${AGF:-default yes}" "${X11F:-default no}"
printf '  GatewayPorts=%s PermitTunnel=%s AllowStreamLocalForwarding=%s PermitOpen=%s X11UseLocalhost=%s\n' \
  "${GWP:-default no}" "${TUN:-default no}" "${SLF:-default yes}" "${POPEN:-any}" "${X11LH:-default yes}"

if [ "$DISFWD" = "yes" ]; then
  chk ssh.forwarding PASS "DisableForwarding yes" "one directive disables TCP, X11, agent, tunnel and unix-socket forwarding together, and it cannot be partially undone by a directive defaulting back on"
else
  FWDON=""
  [ "${TCPF:-yes}" = "yes" ] || [ "${TCPF:-yes}" = "all" ] && FWDON="$FWDON tcp"
  [ "${AGF:-yes}" = "yes" ] && FWDON="$FWDON agent"
  [ "${X11F:-no}" = "yes" ] && FWDON="$FWDON x11"
  [ "${SLF:-yes}" = "yes" ] || [ "${SLF:-yes}" = "all" ] && FWDON="$FWDON unix-socket"
  case "${TUN:-no}" in no) ;; *) FWDON="$FWDON tunnel" ;; esac
  if [ -n "$FWDON" ]; then
    chk ssh.forwarding FAIL "enabled:$FWDON" "each of these extends an SSH login beyond a shell. Set 'DisableForwarding yes' where forwarding is not a requirement, and note the defaults are permissive, so leaving these unset enables them"
  else
    chk ssh.forwarding PASS "all forwarding channels disabled individually" "consider 'DisableForwarding yes' to state it in one directive that no future default can undo"
  fi
fi

case "${TCPF:-yes}" in
  no) chk ssh.forward_tcp PASS "AllowTcpForwarding no" "" ;;
  local|remote) chk ssh.forward_tcp WARN "AllowTcpForwarding $TCPF" "one direction still permitted" ;;
  *) chk ssh.forward_tcp FAIL "AllowTcpForwarding ${TCPF:-yes (default)}" "any SSH user can run 'ssh -L' or 'ssh -D' and reach ANYTHING this host can reach: databases on the private network, cloud metadata, other segments. Network segmentation you enforce at the firewall is bypassed by a user who simply has a shell here. This is the single most consequential forwarding setting on a bastion" ;;
esac
case "${AGF:-yes}" in
  no) chk ssh.forward_agent PASS "AllowAgentForwarding no" "" ;;
  *) chk ssh.forward_agent FAIL "AllowAgentForwarding ${AGF:-yes (default)}" "a forwarded agent socket lets ROOT ON THIS HOST, or anyone who compromises it, authenticate onward as the connecting user, to every system that user's key opens. The user gets no prompt and no record. Prefer ProxyJump, which never exposes the agent to the intermediate host" ;;
esac
case "${X11F:-no}" in
  no) chk ssh.forward_x11 PASS "X11Forwarding no" "" ;;
  *) chk ssh.forward_x11 FAIL "X11Forwarding $X11F" "the X11 protocol assumes a trusted client: a malicious or compromised server can capture keystrokes and read the display of the connecting workstation. Disable it, or at minimum ensure X11UseLocalhost=yes and never use ForwardX11Trusted"
     [ "${X11LH:-yes}" = "no" ] && chk ssh.x11_localhost FAIL "X11UseLocalhost no" "the forwarded X11 port listens on all interfaces, reachable by other hosts" ;;
esac
case "${GWP:-no}" in
  no) chk ssh.gatewayports PASS "GatewayPorts no" "" ;;
  *) chk ssh.gatewayports FAIL "GatewayPorts $GWP" "remote-forwarded ports bind all interfaces instead of loopback, so a user's 'ssh -R' publishes an internal service to the whole network" ;;
esac
case "${TUN:-no}" in
  no) chk ssh.permittunnel PASS "PermitTunnel no" "" ;;
  *) chk ssh.permittunnel FAIL "PermitTunnel $TUN" "layer 2/3 tunnelling over SSH: a full VPN into the network for anyone who can log in" ;;
esac
case "${SLF:-yes}" in
  no) chk ssh.forward_unix PASS "AllowStreamLocalForwarding no" "" ;;
  *) chk ssh.forward_unix WARN "AllowStreamLocalForwarding ${SLF:-yes (default)}" "unix-domain socket forwarding reaches local sockets, including /var/run/docker.sock, which is host root" ;;
esac
[ -n "$POPEN" ] && [ "$POPEN" != "any" ] && chk ssh.permitopen PASS "PermitOpen $POPEN" "forwarding destinations restricted"
if [ "${TCPF:-yes}" = "yes" ] && { [ -z "$POPEN" ] || [ "$POPEN" = "any" ]; }; then
  chk ssh.permitopen WARN "PermitOpen unset (any destination)" "if forwarding must stay on, scope it: 'PermitOpen host:port' limits where a tunnel may terminate, which keeps a jump host useful without making it a universal pivot"
fi

raw "SSH CLIENT forwarding defaults (outbound connections from this host)"
SSHCLI="$( { cat "$(rf /etc/ssh/ssh_config)" 2>/dev/null; cat "$(rf /etc/ssh/ssh_config.d)"/*.conf 2>/dev/null; } | grep -vE '^\s*#|^\s*$')"
printf '%s\n' "$SSHCLI" | grep -iE 'Forward(Agent|X11|X11Trusted)|StrictHostKeyChecking|UserKnownHostsFile|ControlMaster' | cap 12
if [ -z "$SSHCLI" ]; then
  chk ssh.client_forwarding NA "no readable ssh_config" "client-side forwarding defaults not determinable"
else
  printf '%s' "$SSHCLI" | grep -qiE '^\s*ForwardAgent\s+yes' \
    && chk ssh.client_forwardagent FAIL "ForwardAgent yes in ssh_config" "this host forwards its agent to every server it connects to by default: any of them can then authenticate onward as this host's user. Set 'ForwardAgent no' globally and enable per-host only where genuinely needed" \
    || chk ssh.client_forwardagent PASS "ForwardAgent not enabled globally" ""
  printf '%s' "$SSHCLI" | grep -qiE '^\s*ForwardX11(Trusted)?\s+yes' \
    && chk ssh.client_forwardx11 FAIL "ForwardX11/ForwardX11Trusted yes" "outbound X11 forwarding by default; ForwardX11Trusted additionally removes the X security extension restrictions, giving the remote host full access to the local display"
fi

raw "Match blocks (these override the global settings above)"
SSHCFG="$( { [ -r "$(rf /etc/ssh/sshd_config)" ] && cat "$(rf /etc/ssh/sshd_config)"; cat "$(rf /etc/ssh/sshd_config.d)"/*.conf ; } 2>/dev/null )"
printf '%s\n' "$SSHCFG" | grep -nE '^\s*Match' | sed 's/^/  /'
MATCHN="$(printf '%s\n' "$SSHCFG" | grep -cE '^\s*Match ')"
if [ "${MATCHN:-0}" = "0" ]; then
  chk ssh.match_overrides PASS "no Match blocks" "the global configuration is the whole configuration"
else
  raw "auth-relevant directives inside Match blocks"
  printf '%s\n' "$SSHCFG" | awk '/^[[:space:]]*Match /{inm=1; blk=$0; print "  "$0; next}
    inm && /^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|PermitRootLogin|AuthenticationMethods|AllowUsers|AllowGroups|PermitEmptyPasswords|AllowTcpForwarding|AllowAgentForwarding|X11Forwarding|GatewayPorts|PermitTunnel|AllowStreamLocalForwarding|PermitOpen|ForceCommand|ChrootDirectory)/ {print "      "$0}
    inm && /^[[:space:]]*Match /{blk=$0}' | cap 30
  REENABLE="$(printf '%s\n' "$SSHCFG" | awk '/^[[:space:]]*Match /{inm=1} inm && /^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|AllowTcpForwarding|AllowAgentForwarding|X11Forwarding|GatewayPorts|PermitTunnel|AllowStreamLocalForwarding)[[:space:]]+(yes|all|point-to-point|ethernet)/{print}' | head -5)"
  if [ -n "$REENABLE" ]; then
    chk ssh.match_overrides FAIL "$(printf '%s' "$REENABLE" | tr '\n' ';' | cut -c1-160)" "a Match block RE-ENABLES password/keyboard-interactive authentication or a forwarding channel for some users, groups or source addresses. The global settings, and 'sshd -T', do not show this, so a check that reads only the global config reports public-key-only while a password path is open. Verify per-context with: sshd -T -C user=<u>,host=<h>,addr=<a>"
  else
    chk ssh.match_overrides WARN "${MATCHN} Match block(s), none re-enabling password auth" "no obvious re-enable, but Match semantics are positional and easy to get wrong. Confirm with 'sshd -T -C user=...,addr=...' for each context the blocks target"
  fi
fi
# resolve a few concrete contexts where possible: this is what actually proves it
if [ "$AM_ROOT" = "1" ] && have sshd && [ "$OFFLINE" = "0" ]; then
  raw "effective auth methods for specific contexts (sshd -T -C)"
  for u in root $(awk -F: '$3>=1000 && $3<65534 {print $1}' "$(rf /etc/passwd)" 2>/dev/null | head -3); do
    printf '  user=%s: %s\n' "$u" "$(sshd -T -C user=$u,host=localhost,addr=127.0.0.1 2>/dev/null | grep -iE '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|permitrootlogin)' | tr '\n' ' ')"
  done
fi

fi   # end SSH_READ guard

P="$(sshd_get port)"; chk ssh.port INFO "${P:-22}" ""
chk ssh.allowusers INFO "$(sshd_get allowusers)$(sshd_get allowgroups)" "empty = every local account may attempt SSH"
raw "sshd Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms"
for k in ciphers macs kexalgorithms hostkeyalgorithms pubkeyacceptedalgorithms; do printf '%s: %s\n' "$k" "$(sshd_get $k)"; done
if [ -r "$(rf /etc/ssh/moduli)" ]; then
  WEAK="$(awk '$5 < 3071' "$(rf /etc/ssh/moduli)" 2>/dev/null | wc -l)"
  TOT="$(wc -l < "$(rf /etc/ssh/moduli)" 2>/dev/null)"
  [ "${WEAK:-0}" -gt 0 ] && chk ssh.moduli FAIL "$WEAK weak of $TOT" "DH moduli < 3071 bits present: filter with awk '\$5 >= 3071'" \
                         || chk ssh.moduli PASS "0 weak of $TOT" ""
else chk ssh.moduli NA "no /etc/ssh/moduli" ""; fi
raw "host key fingerprints (must be unique per host)"
for k in "$LSA_ROOT"/etc/ssh/ssh_host_*_key.pub; do [ -r "$k" ] && ssh-keygen -lf "$k" 2>/dev/null; done
raw "host key file permissions"
ls -l "$LSA_ROOT"/etc/ssh/ssh_host_*key 2>/dev/null
raw "authorized_keys files + permissions"
for d in "$LSA_ROOT"/root "$LSA_ROOT"/home/*; do
  [ -f "$d/.ssh/authorized_keys" ] || continue
  ls -l "$d/.ssh/authorized_keys"
  awk '{print $1" "$2" ... "$NF}' "$d/.ssh/authorized_keys" 2>/dev/null
  grep -qE '^\s*(command=|no-port-forwarding)' "$d/.ssh/authorized_keys" 2>/dev/null || true
  grep -cE '^ssh-rsa|^ssh-dss' "$d/.ssh/authorized_keys" 2>/dev/null | sed 's/^/rsa_or_dss_keys=/'
done
raw "ssh client config (outbound hardening)"
grep -rhvE '^\s*#|^\s*$' "$(rf /etc/ssh/ssh_config)" "$(rf /etc/ssh/ssh_config.d/)" 2>/dev/null

# ------------------------------------------------------------- 12. FIREWALL
sec FIREWALL
FW=""
if have nft && [ "$AM_ROOT" = "1" ]; then
  raw "nftables ruleset"; run nft list ruleset
  nft list ruleset 2>/dev/null | grep -qE '^[[:space:]]*(chain|table)' && FW="$FW nftables"
fi
if have iptables && [ "$AM_ROOT" = "1" ]; then
  raw "iptables -S"; run iptables -S
  raw "ip6tables -S"; run ip6tables -S
  # Count real rules, and separately treat a non-ACCEPT default policy as a firewall in its
  # own right: a host whose entire policy is "-P INPUT DROP" is filtering, not unprotected.
  # (Positive match rather than `grep -qv`: the inverted-quiet idiom is not portable.)
  IPT_OUT="$(iptables -S 2>/dev/null)"
  IPT_RULES="$(printf '%s\n' "$IPT_OUT" | grep -cE '^-(A|I|N)')"
  IPT_DENY="$(printf '%s\n' "$IPT_OUT" | grep -cE '^-P [A-Z]+ (DROP|REJECT)')"
  { [ "${IPT_RULES:-0}" -gt 0 ] || [ "${IPT_DENY:-0}" -gt 0 ]; } && FW="$FW iptables"
  IPT6_OUT="$(ip6tables -S 2>/dev/null)"
  { [ "$(printf '%s\n' "$IPT6_OUT" | grep -cE '^-(A|I|N)')" -gt 0 ] \
    || [ "$(printf '%s\n' "$IPT6_OUT" | grep -cE '^-P [A-Z]+ (DROP|REJECT)')" -gt 0 ]; } && FW="$FW ip6tables"
fi
if have ufw; then raw "ufw status"; run ufw status verbose; ufw status 2>/dev/null | grep -qi '^Status: active' && FW="$FW ufw"; fi
if have firewall-cmd; then raw "firewalld"; run firewall-cmd --state; run firewall-cmd --list-all-zones | cap 80; firewall-cmd --state 2>/dev/null | grep -q running && FW="$FW firewalld"; fi
have systemctl && { raw "firewall services"; run systemctl is-active nftables firewalld ufw iptables 2>/dev/null; }
FW="$(printf '%s' "$FW" | sed 's/^ *//')"
if [ "$AM_ROOT" != "1" ]; then
  chk firewall.active NA "cannot enumerate rules as non-root" "iptables/nft require root to list the ruleset: this is NOT evidence that no firewall exists"
elif [ -n "$FW" ]; then
  chk firewall.active PASS "$FW" ""
else
  chk firewall.active FAIL "none detected" "no active packet filter found via nft, iptables, ufw or firewalld: the host relies entirely on cloud/provider ACLs"
fi
# ---- direction-aware policy: INPUT, OUTPUT and FORWARD are three separate controls ----
raw "DEFAULT POLICIES BY DIRECTION"
if offline_na firewall.policies "live ruleset"; then :
elif [ "$AM_ROOT" != "1" ]; then
  chk firewall.policies NA "needs root to list the ruleset" ""
else
  IPT_POL="$(iptables -S 2>/dev/null | grep '^-P')"
  NFT_ALL="$(nft list ruleset 2>/dev/null)"
  printf '%s\n' "$IPT_POL"
  printf '%s\n' "$NFT_ALL" | grep -E 'chain (input|output|forward)|type filter hook' | cap 12
  UFW_DEF="$(grep -hE '^DEFAULT_(INPUT|OUTPUT|FORWARD)_POLICY' "$(rf /etc/default/ufw)" 2>/dev/null)"
  [ -n "$UFW_DEF" ] && printf '%s\n' "$UFW_DEF"

  pol_of() { # pol_of <INPUT|OUTPUT|FORWARD>
    p1="$(printf '%s\n' "$IPT_POL" | awk -v c="$1" '$2==c{print $3}')"
    [ -n "$p1" ] && { printf '%s' "$p1"; return; }
    p2="$(printf '%s\n' "$NFT_ALL" | grep -A1 "hook $(printf '%s' "$1" | tr 'A-Z' 'a-z')" | grep -oE 'policy (accept|drop)' | awk '{print toupper($2)}' | head -1)"
    [ -n "$p2" ] && { printf '%s' "$p2"; return; }
    printf '%s' "$(printf '%s\n' "$UFW_DEF" | grep "_$1_" | cut -d'"' -f2)"
  }
  PIN="$(pol_of INPUT)"; POUT="$(pol_of OUTPUT)"; PFWD="$(pol_of FORWARD)"
  case "$PIN" in
    DROP|REJECT|drop|deny) chk firewall.policy_input PASS "INPUT=$PIN" "default-deny inbound" ;;
    "") chk firewall.policy_input NA "INPUT policy not determined" "no iptables/nft/ufw default found" ;;
    *)  chk firewall.policy_input FAIL "INPUT=$PIN" "default-accept inbound: anything not explicitly denied is reachable, so every future service that binds a port is exposed the moment it starts. Invert to default-deny plus an explicit allow list" ;;
  esac
  case "$PFWD" in
    DROP|REJECT|drop|deny) chk firewall.policy_forward PASS "FORWARD=$PFWD" "" ;;
    "") ;;
    *)  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
          chk firewall.policy_forward WARN "FORWARD=$PFWD with ip_forward=1" "this host routes: confirm the forward rules are scoped, not open"
        else
          chk firewall.policy_forward WARN "FORWARD=$PFWD" "default-accept forwarding on a host that is not a router"
        fi ;;
  esac

  # ---- EGRESS ----
  case "$POUT" in
    DROP|REJECT|drop|deny)
      chk firewall.policy_output PASS "OUTPUT=$POUT" "default-deny egress: the control that turns a code-execution bug into a dead end"
      raw "explicitly permitted egress"
      printf '%s\n' "$(iptables -S OUTPUT 2>/dev/null | grep -vE '^-P')" | cap 25
      ;;
    "") chk firewall.policy_output NA "OUTPUT policy not determined" "" ;;
    *)  chk firewall.policy_output FAIL "OUTPUT=$POUT" "UNRESTRICTED EGRESS. Inbound filtering only stops the first step; with open egress a compromised process can reach any C2 endpoint, exfiltrate to any destination, pull a second stage, and open a reverse shell outbound through the firewall you do have. Egress filtering is what makes an initial foothold non-monetisable. Start with: allow DNS to your resolvers, NTP to your servers, HTTPS to your package mirrors and monitored endpoints, then default-deny with logging and read the log for a week before enforcing" ;;
  esac
  EGRESS_RULES="$(iptables -S OUTPUT 2>/dev/null | grep -cvE '^-P')"
  [ "${EGRESS_RULES:-0}" = "0" ] && [ -n "$POUT" ] && \
    chk firewall.egress_rules WARN "no OUTPUT rules at all" "egress is entirely unfiltered; not even DNS/NTP/HTTPS are scoped to known destinations"
  raw "outbound rules referencing specific destinations (scoped egress is the goal)"
  iptables -S OUTPUT 2>/dev/null | grep -E '\-d |dport' | cap 15
  printf '%s\n' "$NFT_ALL" | grep -A20 'hook output' | grep -E 'daddr|dport' | cap 15

  # ---- do the opened ports correspond to anything actually listening? ----
  raw "FIREWALL/LISTENER RECONCILIATION"
  ALLOWED="$( { iptables -S 2>/dev/null | grep -oE '\-\-dport [0-9]+' | awk '{print $2}'
                iptables -S 2>/dev/null | grep -oE 'dports [0-9,]+' | tr ',' '\n' | grep -oE '[0-9]+'
                printf '%s\n' "$NFT_ALL" | grep -oE 'dport (\{[^}]*\}|[0-9]+)' | grep -oE '[0-9]+'
                ufw status 2>/dev/null | awk '/ALLOW/{print $1}' | grep -oE '^[0-9]+'
              } 2>/dev/null | sort -un )"
  LISTENING="$(ss -tulnH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un)"
  printf '  firewall-allowed ports: %s\n' "$(printf '%s' "$ALLOWED" | tr '\n' ' ')"
  printf '  actually listening    : %s\n' "$(printf '%s' "$LISTENING" | tr '\n' ' ')"
  STALE=""
  for a in $ALLOWED; do printf '%s\n' "$LISTENING" | grep -qx "$a" || STALE="$STALE $a"; done
  UNPROT=""
  for l in $(ss -tulnH 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\])' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un); do
    printf '%s\n' "$ALLOWED" | grep -qx "$l" || UNPROT="$UNPROT $l"
  done
  [ -n "$STALE" ] && chk firewall.stale_allows WARN "allowed but nothing listening:$STALE" "a rule that opens a port with no service behind it. Harmless today, but it silently pre-authorises whatever binds that port next, including something an attacker starts. Remove rules when the service goes away" \
                  || chk firewall.stale_allows PASS "every allowed port has a listener" ""
  [ -n "$UNPROT" ] && [ -n "$ALLOWED" ] && chk firewall.unfiltered_listeners WARN "listening off-loopback but not in any allow rule:$UNPROT" "either the firewall is not the thing protecting these (a provider security group may be), or the default policy is ACCEPT and the allow list is decorative. Reconcile the two"
fi

raw "default policies"
[ "$AM_ROOT" = "1" ] && have iptables && iptables -S 2>/dev/null | grep '^-P'
raw "fail2ban"
have fail2ban-client && run fail2ban-client status || echo "fail2ban not installed"

# ------------------------------------------------------- 13. NETWORK EXPOSURE
sec NETWORK
raw "listening sockets"
if have ss; then run ss -tulpnH; elif have netstat; then run netstat -tulpn; fi
raw "listening on non-loopback (attack surface)"
if have ss; then ss -tulpnH 2>/dev/null | awk '{print $1" "$5" "$7}' | grep -vE '127\.0\.0\.1|\[::1\]|127\.0\.0\.53'; fi
NLISTEN="$(ss -tulnH 2>/dev/null | awk '{print $5}' | grep -vcE '127\.0\.0\.1|\[::1\]')"
have ss || chk net.public_listeners NA "ss not available" "listening sockets not enumerable"
have ss && chk net.public_listeners INFO "${NLISTEN:-?}" "each is directly reachable attack surface"

raw "high-risk services exposed off-loopback"
# port|service|why it must not face the internet
RISKY='21|ftp|cleartext credentials
23|telnet|cleartext credentials and session
25|smtp|open relay / user enumeration if unauthenticated
111|rpcbind|enumerates RPC services, UDP amplification reflector
135|msrpc|
139|netbios-ssn|SMB
445|microsoft-ds|SMB: worm and ransomware target
161|snmp|community strings are often default; leaks full host inventory
389|ldap|cleartext directory + amplification reflector
512|rexec|
513|rlogin|
514|rsh_or_syslog|cleartext
873|rsync|frequently unauthenticated and world-readable
1433|mssql|database
1521|oracle|database
2049|nfs|filesystem export
2375|docker-api|UNAUTHENTICATED DOCKER API = instant root on the host
2376|docker-api-tls|verify client-cert auth is actually enforced
2379|etcd|cluster secrets
3306|mysql|database
3389|rdp|
4444|metasploit-default|investigate
5432|postgres|database
5672|amqp|message broker
5900|vnc|often no/weak auth
5984|couchdb|database
6379|redis|USUALLY NO AUTH: trivial RCE via config rewrite
7001|weblogic|
8020|hadoop|
8086|influxdb|metrics database
8088|hadoop-yarn|known unauthenticated RCE
8500|consul|
9042|cassandra|database
9092|kafka|
9200|elasticsearch|USUALLY NO AUTH: full data read/write
9300|elasticsearch-transport|
11211|memcached|no auth, huge UDP amplification factor
15672|rabbitmq-mgmt|default guest:guest
27017|mongodb|database
5601|kibana|
9090|prometheus_or_cockpit|
9100|node-exporter|leaks full host telemetry
6443|kube-apiserver|verify authn/authz
10250|kubelet|unauthenticated kubelet = container exec'
if have ss; then
  LISTEN_PUB="$(ss -tulnH 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\])' )"
  printf '%s\n' "$RISKY" | while IFS='|' read -r port svc why; do
    [ -z "$port" ] && continue
    if printf '%s\n' "$LISTEN_PUB" | grep -qE "[:.]${port}\$"; then
      OWNER="$(ss -tulpnH 2>/dev/null | awk -v p=":$port" '$5 ~ p"$" {print $NF}' | head -1)"
      chk "exposed.$port" FAIL "$svc listening off-loopback ($OWNER)" "${why:-verify this must be public}"
    fi
  done
fi
raw "BIND ADDRESS DISCIPLINE"
NIFS="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ' ')"
NIFCOUNT="$(printf '%s' "$NIFS" | wc -w | tr -d ' ')"
printf '  global interfaces (%s): %s\n' "${NIFCOUNT:-?}" "${NIFS:-unknown}"
WILDCARD="$(ss -tulpnH 2>/dev/null | awk '$5 ~ /^(0\.0\.0\.0|\[::\])/ {print $1" "$5" "$NF}')"
printf '%s\n' "$WILDCARD" | grep -v '^$' | sed 's/^/  /' | cap 25
NWILD="$(printf '%s' "$WILDCARD" | grep -c .)"
if offline_na net.bind_address "listening sockets"; then :
elif ! have ss; then
  chk net.bind_address NA "ss not available" "cannot enumerate listening sockets: no bind-address verdict. Absence of evidence is not a clean result"
elif [ "${NWILD:-0}" = "0" ]; then
  chk net.bind_address PASS "no wildcard binds" "every listener is bound to a specific address"
elif [ "${NIFCOUNT:-1}" -gt 1 ]; then
  chk net.bind_address FAIL "${NWILD} service(s) bound to 0.0.0.0/:: on a host with ${NIFCOUNT} global interfaces" "a wildcard bind exposes the service on EVERY interface: management network, VPN/WireGuard, private VPC, container bridge and the public NIC alike. On a multi-homed host that routinely turns an internal-only service into an internet-facing one, and it is invisible in the service's own config because the config says nothing about interfaces. Bind each service to the specific address it should serve (nginx 'listen 10.0.0.5:443', sshd 'ListenAddress', postgres 'listen_addresses', redis 'bind'). Binding beats firewalling: a bind cannot be bypassed by a rule ordering mistake"
else
  chk net.bind_address WARN "${NWILD} service(s) bound to 0.0.0.0/::" "single global interface, so the immediate exposure equals that interface, but the bind becomes wrong the moment a second interface is added (a VPN, a private network, a container bridge), and nothing will flag it then. Prefer explicit addresses"
fi
raw "wildcard binds that also have an explicit-address alternative configured"
for c in "$(rf /etc/ssh/sshd_config)" "$(rf /etc/postgresql)" "$(rf /etc/redis/redis.conf)" "$(rf /etc/mysql)"; do
  [ -e "$c" ] && grep -rhE '^\s*(ListenAddress|listen_addresses|bind|bind-address)' "$c" 2>/dev/null | head -4
done
raw "IPv6 state"
[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && printf 'disable_ipv6=%s\n' "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)"
ip -6 addr show scope global 2>/dev/null | grep -c inet6 | sed 's/^/global_ipv6_addrs=/'
raw "interfaces + addresses"
ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null
raw "routing"
ip route 2>/dev/null
raw "ip_forward"
cat /proc/sys/net/ipv4/ip_forward 2>/dev/null
raw "hosts.allow / hosts.deny"
grep -hvE '^\s*#|^\s*$' "$(rf /etc/hosts.allow)" "$(rf /etc/hosts.deny)" 2>/dev/null
raw "resolver"
[ -r "$(rf /etc/resolv.conf)" ] && grep -vE '^\s*#' "$(rf /etc/resolv.conf)"

# -------------------------------------------------------------- 14. SERVICES
sec SERVICES
raw "running services"
if have systemctl; then run systemctl list-units --type=service --state=running --no-pager --no-legend; else run service --status-all; fi
raw "enabled services"
have systemctl && run systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend
raw "failed units"
have systemctl && run systemctl --failed --no-pager --no-legend
raw "systemd-analyze security (sandboxing exposure per unit; lower is better)"
have systemd-analyze && run systemd-analyze security --no-pager 2>/dev/null | cap 60
# ---- root-process audit: every process should run as the least-privileged user that works ----
raw "PROCESS PRIVILEGE AUDIT"
raw "process count by user"
ps -eo user= 2>/dev/null | sort | uniq -c | sort -rn | cap 20

# kernel threads (ppid 2 or bracketed comm) are root by definition and are not findings
raw "non-kernel processes running as root"
ps -eo user,pid,ppid,args 2>/dev/null | awk '$1=="root" && $3!=2 && $2!=2 && $4 !~ /^\[/' | cap 80

NROOT="$(ps -eo user,pid,ppid,args 2>/dev/null | awk '$1=="root" && $3!=2 && $2!=2 && $4 !~ /^\[/' | grep -vc '^USER')"
NTOT="$(ps -eo user= 2>/dev/null | grep -vc '^$')"
chk proc.root_count INFO "${NROOT:-?} non-kernel root processes of ${NTOT:-?} total" "each is a full-host compromise if exploited"

# Infrastructure that legitimately requires root. Everything else is a candidate for User=.
ROOT_EXPECTED='systemd|systemd-journald|systemd-udevd|systemd-logind|systemd-networkd|systemd-resolved|systemd-timesyn|systemd-oomd|init|kthreadd|dbus-daemon|dbus-broker|sshd|cron|crond|atd|agetty|login|auditd|rsyslogd|syslog-ng|containerd|dockerd|kubelet|snapd|multipathd|irqbalance|lvmetad|udisksd|polkitd|acpid|smartd|thermald|unattended-upgr|apt\.systemd|packagekitd|NetworkManager|wpa_supplicant|chronyd|ntpd|firewalld|ufw|fail2ban|amazon-ssm-agent|google_guest_agent|qemu-ga|vmtoolsd|cloud-init|zabbix_agentd|node_exporter|wazuh|osqueryd|usbguard|aide|sudo|su|bash|sh|-bash|ps|awk|grep|find|tail'
raw "root processes that are NOT standard root infrastructure (review each for a least-privilege user)"
ps -eo user,pid,args 2>/dev/null \
  | awk '$1=="root" && $3 !~ /^\[/' \
  | grep -vE "$ROOT_EXPECTED" | cap 40
UNEXP="$(ps -eo user,pid,args 2>/dev/null | awk '$1=="root" && $3 !~ /^\[/' | grep -vcE "$ROOT_EXPECTED")"
[ "${UNEXP:-0}" -gt 0 ] && chk proc.root_unexpected WARN "${UNEXP} process(es)" "application-level daemons running as root: each should run under a dedicated service account unless it needs a root-only capability (binding <1024 can use CAP_NET_BIND_SERVICE or a systemd socket instead)" \
                        || chk proc.root_unexpected PASS "only standard root infrastructure" ""

# network-facing AND root is the combination that matters most
raw "root processes with a listening socket (root + network = highest-value target)"
if have ss; then
  ss -tulpnH 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' | while read -r l; do
    pid="$(printf '%s' "$l" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
    [ -n "$pid" ] || continue
    u="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
    [ "$u" = "root" ] && printf '  %s  %s\n' "$(printf '%s' "$l" | awk '{print $1" "$5}')" "$(ps -o args= -p "$pid" 2>/dev/null | cut -c1-70)"
  done | sort -u | cap 25
  NRL="$(ss -tulpnH 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | while read -r pid; do ps -o user= -p "$pid" 2>/dev/null | tr -d ' '; done | grep -c '^root$')"
  [ "${NRL:-0}" -gt 0 ] && chk proc.root_listeners WARN "${NRL}" "root-owned process(es) listening on a non-loopback address: a remote bug in any of them is immediate root. Drop privileges after bind, or use systemd socket activation with User=" \
                        || chk proc.root_listeners PASS "no root-owned public listeners" ""
fi

# systemd units that could declare User= but do not
if have systemctl; then
  raw "running systemd services with no User= (they run as root)"
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | while read -r u; do
    [ -n "$u" ] || continue
    US="$(systemctl show "$u" -p User --value 2>/dev/null)"
    DP="$(systemctl show "$u" -p DynamicUser --value 2>/dev/null)"
    if [ -z "$US" ] && [ "$DP" != "yes" ]; then printf '  %s\n' "$u"; fi
  done | cap 40
  NOUSER="$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | while read -r u; do
    [ -n "$u" ] || continue
    [ -z "$(systemctl show "$u" -p User --value 2>/dev/null)" ] && [ "$(systemctl show "$u" -p DynamicUser --value 2>/dev/null)" != "yes" ] && echo x
  done | wc -l | tr -d ' ')"
  chk proc.units_without_user INFO "${NOUSER:-?} running unit(s) without User= or DynamicUser=" "not all can drop privileges, but each should be justified; DynamicUser=yes is the cheapest fix for stateless daemons"
fi

# processes still holding capabilities / not NoNewPrivileges
raw "capabilities held by running root processes (CapEff of the top offenders)"
for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}' | head -25); do
  [ -r "/proc/$pid/status" ] || continue
  ce="$(awk '/^CapEff/{print $2}' "/proc/$pid/status" 2>/dev/null)"
  nnp="$(awk '/^NoNewPrivs/{print $2}' "/proc/$pid/status" 2>/dev/null)"
  cm="$(tr -d '\0' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-50)"
  [ -n "$ce" ] && printf '  pid=%-7s CapEff=%-18s NoNewPrivs=%s  %s\n' "$pid" "$ce" "${nnp:-?}" "${cm:-?}"
done 2>/dev/null | cap 25
have capsh && echo "(decode with: capsh --decode=<CapEff>)"
raw "listening processes not owned by root (good) vs root (review)"
have ss && ss -tulpnH 2>/dev/null | grep -oE 'users:\(\("[^"]+"' | sort | uniq -c | sort -rn
raw "inetd / xinetd"
ls -la "$(rf /etc/xinetd.d/)" 2>/dev/null; [ -r "$(rf /etc/inetd.conf)" ] && grep -vE '^\s*#' "$(rf /etc/inetd.conf)"
raw "containers"
have docker && { run docker version --format '{{.Server.Version}}' ; run docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'; }
ls -l "$(rf /var/run/docker.sock)" /run/docker.sock 2>/dev/null
if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ]; then
  DS="$(stat -c '%a %U %G' "$(rf /var/run/docker.sock)" 2>/dev/null || stat -c '%a %U %G' /run/docker.sock 2>/dev/null)"
  chk docker.socket_perms INFO "$DS" "write access to this socket is root on the host"
fi
have docker && [ "$AM_ROOT" = "1" ] && { raw "privileged containers"; docker ps -q 2>/dev/null | while read -r c; do docker inspect -f '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' "$c" 2>/dev/null; done; }
raw "docker daemon TLS / exposure"
[ -r "$(rf /etc/docker/daemon.json)" ] && cat "$(rf /etc/docker/daemon.json)"
have systemctl && systemctl cat docker.service 2>/dev/null | grep -E 'ExecStart|-H ' | head -5

# ------------------------------------------------------------- 15. WEBSERVER
sec WEBSERVER
WS=""
for w in nginx apache2 httpd caddy lighttpd haproxy openlitespeed; do have "$w" && WS="$WS $w"; done
[ -d "$(rf /etc/nginx)" ]   && WS="$WS nginx-config"
[ -d "$(rf /etc/apache2)" ] && WS="$WS apache2-config"
[ -d "$(rf /etc/httpd)" ]   && WS="$WS httpd-config"
chk web.present INFO "${WS:-none detected}" ""

if [ -n "$WS" ]; then
  raw "web server versions (EOL/unpatched versions are the finding)"
  [ "$OFFLINE" = "0" ] && have nginx   && run nginx -v 2>&1
  have apache2 && run apache2 -v
  [ "$OFFLINE" = "0" ] && have httpd   && run httpd -v
  have caddy   && run caddy version
  have haproxy && run haproxy -v 2>&1 | head -2

  # ---- config file ownership and permissions ----
  # If the worker user can write the config, a file-write bug becomes permanent RCE: the
  # server rewrites its own config (or an .htaccess) and reloads.
  static_on
  raw "web server config ownership and permissions"
  WEBUSER="$(ps -eo user,args 2>/dev/null | grep -E 'nginx: worker|apache2 -k|httpd -D|php-fpm: pool' | grep -v grep | awk '{print $1}' | grep -v '^root$' | sort -u | head -1)"
  printf '  worker user: %s\n' "${WEBUSER:-unknown}"
  for cd in "$LSA_ROOT"/etc/nginx "$LSA_ROOT"/etc/apache2 "$LSA_ROOT"/etc/httpd "$LSA_ROOT"/etc/php; do
    [ -d "$cd" ] || continue
    stat -c '  %a %U:%G %n' "$cd" 2>/dev/null
    BADCFG="$(find "$cd" -maxdepth 3 ! -type l \( -perm -0002 -o -perm -0020 \) -print 2>/dev/null | head -15)"
    if [ -n "$BADCFG" ]; then
      printf '%s\n' "$BADCFG" | tr '\n' '\0' | xargs -0 ls -ld 2>/dev/null
      chk "web.config_writable.$(basename "$cd")" FAIL "$(printf '%s' "$BADCFG" | tr '\n' ' ' | cut -c1-140)" "group- or world-writable web server config: whoever can write it controls what the server executes on the next reload"
    else
      chk "web.config_writable.$(basename "$cd")" PASS "no group/world-writable files under $cd" ""
    fi
    if [ -n "$WEBUSER" ]; then
      OWNED="$(find "$cd" -maxdepth 3 -user "$WEBUSER" -print 2>/dev/null | head -10)"
      [ -n "$OWNED" ] && chk "web.config_owned_by_worker.$(basename "$cd")" FAIL "$(printf '%s' "$OWNED" | tr '\n' ' ' | cut -c1-140)" "config files owned by the worker user ($WEBUSER): the process serving requests can rewrite its own configuration"
    fi
  done
  raw "private keys readable by the worker user"
  [ -n "$WEBUSER" ] && for k in "$LSA_ROOT"/etc/ssl/private/* "$LSA_ROOT"/etc/pki/tls/private/* "$LSA_ROOT"/etc/letsencrypt/live/*/privkey.pem; do
    [ -f "$k" ] || continue
    stat -c '  %a %U:%G %n' "$k" 2>/dev/null
  done
  # ---- .htaccess and .user.ini CONTENT audit ----
  # These are configuration files that live inside the served tree, so anything able to write
  # into the webroot can change server behaviour. Audit what they actually contain.
  raw ".htaccess / .user.ini files and their security-relevant directives"
  HTFILES="$(find "$(rf /var/www)" "$(rf /srv/www)" "$(rf /usr/share/nginx)" "$(rf /opt)" -maxdepth 6 \( -name '.htaccess' -o -name '.user.ini' -o -name '.htpasswd' \) -print 2>/dev/null | head -40)"
  [ -n "$HTFILES" ] && printf '%s\n' "$HTFILES" | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null
  _oifs=$IFS; IFS=$'\n'
  for h in $HTFILES; do
    case "$h" in
      *.htpasswd)
        m="$(stat -c '%a %U:%G' "$h" 2>/dev/null)"
        printf '\n[%s] %s: %s entries\n' "$h" "$m" "$(grep -c : "$h" 2>/dev/null)"
        # a password file inside the served tree is downloadable unless explicitly denied
        case "$h" in
          /var/www/*|/srv/www/*|/usr/share/nginx/*)
            chk "htaccess.htpasswd_in_webroot.$(basename "$(dirname "$h")")" FAIL "$h ($m)" "password hash file inside the document root; verify it is not servable, then move it outside the webroot entirely" ;;
        esac
        # hash algorithm: crypt() and Apache-MD5 are trivially cracked
        if grep -qE ':\$apr1\$|:[A-Za-z0-9./]{13}$' "$h" 2>/dev/null; then
          chk "htaccess.htpasswd_weak.$(basename "$(dirname "$h")")" WARN "$h" "uses crypt() (13 chars, DES, 8-char password limit) or Apache-MD5 (\$apr1\$); regenerate with bcrypt: htpasswd -B"
        fi
        continue ;;
    esac
    printf '\n[%s] %s\n' "$h" "$(stat -c '%a %U:%G' "$h" 2>/dev/null)"
    grep -vE '^\s*#|^\s*$' "$h" 2>/dev/null | head -30 | sed 's/^/    /'
    HC="$(grep -vE '^\s*#' "$h" 2>/dev/null)"
    hid="$(printf '%s' "$h" | tr '/' '_' | cut -c1-40)"
    # auto_prepend_file is the classic .htaccess/.user.ini webshell: every PHP request in this
    # directory tree first executes an attacker-chosen file
    printf '%s' "$HC" | grep -qiE 'auto_(pre|ap)pend_file' \
      && chk "htaccess.auto_prepend$hid" FAIL "$(printf '%s' "$HC" | grep -iE 'auto_(pre|ap)pend_file' | head -1)" "auto_prepend_file/auto_append_file runs a chosen PHP file before or after EVERY request in this tree: a standard, quiet webshell persistence mechanism. Verify the referenced file"
    printf '%s' "$HC" | grep -qiE '(AddHandler|SetHandler|AddType)[^\n]*(php|x-httpd|cgi|fcgi)' \
      && chk "htaccess.handler$hid" FAIL "$(printf '%s' "$HC" | grep -iE '(AddHandler|SetHandler|AddType)[^\n]*(php|cgi)' | head -2 | tr '\n' ';')" "maps additional extensions to the PHP/CGI interpreter: this is how an uploaded .jpg or .txt is made executable, and how a handler-deny rule in an upload directory is undone"
    printf '%s' "$HC" | grep -qiE 'Options[^\n]*\+?(ExecCGI|Includes|FollowSymLinks|Indexes)' \
      && chk "htaccess.options$hid" WARN "$(printf '%s' "$HC" | grep -iE '^\s*Options' | head -1)" "Options set from inside the served tree: ExecCGI/Includes add code execution, FollowSymLinks escapes the docroot, Indexes lists files"
    printf '%s' "$HC" | grep -qiE 'php_(value|flag|admin_value|admin_flag)[^\n]*(disable_functions|open_basedir|allow_url|safe_mode|engine)' \
      && chk "htaccess.php_override$hid" FAIL "$(printf '%s' "$HC" | grep -iE 'php_(value|flag|admin_)' | head -2 | tr '\n' ';')" "PHP security settings overridden from inside the webroot: disable_functions and open_basedir set here can be widened, not just narrowed"
    printf '%s' "$HC" | grep -qiE 'RewriteRule[^\n]*\[[^]]*P[,\]]' \
      && chk "htaccess.rewrite_proxy$hid" FAIL "$(printf '%s' "$HC" | grep -iE 'RewriteRule[^\n]*\[[^]]*P' | head -1)" "RewriteRule with the [P] proxy flag turns this path into a proxy: a server-side request forgery primitive, and potentially an open proxy"
    printf '%s' "$HC" | grep -qiE '(Allow from all|Require all granted|Satisfy any)' \
      && chk "htaccess.access_override$hid" WARN "$(printf '%s' "$HC" | grep -iE '(Allow from all|Require all granted|Satisfy any)' | head -1)" "relaxes an access restriction inherited from the parent configuration; 'Satisfy any' in particular makes authentication optional when a host-based rule matches"
    AUF="$(printf '%s' "$HC" | grep -iE '^\s*AuthUserFile' | awk '{print $2}' | head -1)"
    if [ -n "$AUF" ]; then
      case "$AUF" in
        /var/www/*|/srv/www/*|/usr/share/nginx/*) chk "htaccess.authuserfile$hid" FAIL "AuthUserFile $AUF" "the password file is inside the document root and may be downloadable" ;;
      esac
    fi
    printf '%s' "$HC" | grep -qiE '^\s*ErrorDocument[^\n]*\.(php|cgi|pl)' \
      && chk "htaccess.errordocument$hid" INFO "$(printf '%s' "$HC" | grep -iE '^\s*ErrorDocument' | head -1)" "error handler invokes a script: reachable by forcing an error"
  done
  IFS=$_oifs
  [ -n "$HTFILES" ] && chk htaccess.count INFO "$(printf '%s' "$HTFILES" | grep -c .) file(s)" "each is server configuration living inside the writable served tree; with AllowOverride None they are inert; check that first"

  runtime_on
  raw "worker processes and their user (workers must not run as root)"
  ps -eo user,pid,args 2>/dev/null | grep -E '(nginx|apache2|httpd|caddy|php-fpm|haproxy)' | grep -v grep | cap 25
  WROOT="$(ps -eo user,args 2>/dev/null | grep -E '(nginx: worker|apache2 |httpd |php-fpm: pool)' | grep -v grep | awk '$1=="root"' | wc -l)"
  [ "${WROOT:-0}" -gt 0 ] && chk web.worker_user WARN "$WROOT worker/pool process(es) as root" "only the master should be root; workers must drop privileges" \
                          || chk web.worker_user PASS "workers not running as root" ""
fi

# ---- nginx ----
if [ -d "$(rf /etc/nginx)" ] || have_target nginx; then
  raw "nginx config test"
  [ "$OFFLINE" = "0" ] && have nginx && run nginx -t 2>&1
  raw "nginx effective config (nginx -T)"
  if [ "$OFFLINE" = "0" ] && [ "$AM_ROOT" = "1" ] && have nginx; then NGX="$(nginx -T 2>/dev/null)"; else NGX="$(grep -rhvE '^\s*#|^\s*$' "$(rf /etc/nginx/)" 2>/dev/null)"; fi
  printf '%s\n' "$NGX" | grep -vE '^\s*#' | grep -vE '^\s*$' | cap 400

  ngx_has() { printf '%s' "$NGX" | grep -qiE "$1"; }
  ngx_has '^\s*server_tokens\s+off' && chk nginx.server_tokens PASS "off" "" \
    || chk nginx.server_tokens FAIL "on (default)" "version banner in every response and error page aids targeted exploitation"
  raw "nginx ssl_protocols / ssl_ciphers in use"
  printf '%s\n' "$NGX" | grep -iE '^\s*(ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|ssl_session_tickets|ssl_stapling|ssl_dhparam|ssl_ecdh_curve)' | sort -u
  if printf '%s' "$NGX" | grep -iqE '^\s*ssl_protocols[^;]*(SSLv2|SSLv3|TLSv1(\s|;)|TLSv1\.0|TLSv1\.1)'; then
    chk nginx.tls_versions FAIL "$(printf '%s' "$NGX" | grep -iE '^\s*ssl_protocols' | head -1 | tr -s ' ')" "obsolete TLS versions enabled"
  elif printf '%s' "$NGX" | grep -iqE '^\s*ssl_protocols'; then
    chk nginx.tls_versions PASS "$(printf '%s' "$NGX" | grep -iE '^\s*ssl_protocols' | head -1 | tr -s ' ')" ""
  else
    chk nginx.tls_versions WARN "not set" "relies on the nginx default for this build"
  fi
  ngx_has '^\s*autoindex\s+on' && chk nginx.autoindex FAIL "autoindex on" "directory listing exposes files not meant to be enumerable" \
    || chk nginx.autoindex PASS "no autoindex on" ""
  for h in Strict-Transport-Security X-Content-Type-Options X-Frame-Options Content-Security-Policy Referrer-Policy Permissions-Policy; do
    ngx_has "add_header\s+$h" && chk "nginx.header.$h" PASS present "" || chk "nginx.header.$h" WARN absent "security response header not set in config"
  done
  ngx_has '^\s*(limit_req_zone|limit_conn_zone)' && chk nginx.rate_limit PASS configured "" \
    || chk nginx.rate_limit WARN absent "no limit_req/limit_conn: login and expensive endpoints are brute-forceable"
  ngx_has 'client_max_body_size' && chk nginx.body_limit PASS "$(printf '%s' "$NGX" | grep -iE 'client_max_body_size' | head -1 | tr -s ' ')" "" \
    || chk nginx.body_limit INFO "default 1m" ""
  printf '%s' "$NGX" | grep -qiE 'fastcgi_split_path_info|SCRIPT_FILENAME\s+\$document_root\$fastcgi_script_name' && \
    { printf '%s' "$NGX" | grep -qi 'try_files.*\$uri.*=404\|fastcgi_param\s*PHP_VALUE' || chk nginx.php_pathinfo WARN "fastcgi without a try_files =404 guard" "classic arbitrary-PHP-execution misconfiguration (uploads served as PHP)"; }
  raw "nginx: proxy_pass targets and any open-proxy shaped config"
  printf '%s\n' "$NGX" | grep -iE '^\s*proxy_pass' | sort -u | cap 20
  raw "nginx: server_name / listen directives"
  printf '%s\n' "$NGX" | grep -iE '^\s*(listen|server_name|root|ssl_certificate\b|ssl_certificate_key)' | sort -u | cap 60
  raw "nginx: locations exposing status/metrics"
  printf '%s\n' "$NGX" | grep -iE 'stub_status|/nginx_status|/server-status|/metrics' | head

  # ---- nginx modules: dynamically loaded and compiled-in, vs actually used ----
  raw "nginx dynamic modules (load_module) and build-time modules (nginx -V)"
  printf '%s\n' "$NGX" | grep -iE '^\s*load_module' | sort -u
  [ "$OFFLINE" = "0" ] && have nginx && run nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--(with|add)' | sort
  NGV="$(nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--(with|add)' | tr '\n' ' ')"
  NGLOAD="$(printf '%s\n' "$NGX" | grep -iE '^\s*load_module' | grep -oE '[A-Za-z0-9_]+_module' | sort -u | tr '\n' ' ')"

  # module | build flag or dynamic name | directive regex that proves it is used | why
  NGINX_MODMAP='dav~http_dav_module ngx_http_dav_module~dav_methods|dav_access~WebDAV: PUT/DELETE/MKCOL against the served tree: an upload primitive bolted onto the web server
autoindex~ngx_http_autoindex_module~autoindex[[:space:]]+on~directory listing
ssi~http_ssi_module ngx_http_ssi_module~ssi[[:space:]]+on~Server-Side Includes: command and file inclusion inside served pages
stub_status~http_stub_status_module~stub_status~exposes connection counters; harmless if restricted, reconnaissance if not
random_index~http_random_index_module~random_index[[:space:]]+on~serves a random file from a directory
perl~http_perl_module ngx_http_perl_module~perl_(set|modules|require)~embedded Perl: arbitrary code execution surface, and it blocks the event loop
image_filter~http_image_filter_module ngx_http_image_filter_module~image_filter~image transformation driven by request parameters: a decoder attack surface (libgd)
xslt~http_xslt_module ngx_http_xslt_module~xslt_stylesheet~XSLT processing: XXE and code-execution surface (libxslt)
mp4~http_mp4_module~^[[:space:]]*mp4;~media pseudo-streaming parser
flv~http_flv_module~^[[:space:]]*flv;~legacy media pseudo-streaming parser
geoip~http_geoip_module ngx_http_geoip_module~geoip_(country|city|org|proxy)~deprecated GeoIP1 lookups
sub~http_sub_module~sub_filter~response body rewriting
addition~http_addition_module~add_(before|after)_body~response body injection
mail~--with-mail ngx_mail_module~^[[:space:]]*mail[[:space:]]*\\{~mail proxy: a whole extra protocol stack listening
stream~--with-stream ngx_stream_module~^[[:space:]]*stream[[:space:]]*\\{~generic TCP/UDP proxying'

  raw "nginx modules: present vs used"
  printf '%s\n' "$NGINX_MODMAP" | while IFS='~' read -r name flags dirre why; do
    [ -z "$name" ] && continue
    present=""
    for f in $flags; do
      case "$NGV" in *"$f"*) present="compiled-in" ;; esac
      case "$NGLOAD" in *"$f"*) present="dynamically loaded" ;; esac
    done
    [ -z "$present" ] && continue
    if printf '%s\n' "$NGX" | grep -qiE "$dirre"; then
      printf '  used     %-14s (%s)\n' "$name" "$present"
    else
      printf '  UNUSED   %-14s (%s) %s\n' "$name" "$present" "$why"
      case "$present" in
        "dynamically loaded") chk "nginx.unused_mod.$name" FAIL "$present, no directive uses it" "$why; remove the load_module line" ;;
        *) chk "nginx.unused_mod.$name" WARN "$present, no directive uses it" "$why: compiled in, so removing it needs a rebuild or a different package; at minimum confirm no vhost can reach it" ;;
      esac
    fi
  done
  raw "nginx log config (missing access log = no forensics)"
  printf '%s\n' "$NGX" | grep -iE '^\s*(access_log|error_log)' | sort -u | cap 20
  printf '%s' "$NGX" | grep -qiE '^\s*access_log\s+off' && chk nginx.access_log WARN "access_log off somewhere" "no request record for incident response"
  raw "real-client-IP handling behind a CDN/proxy"
  printf '%s\n' "$NGX" | grep -iE 'real_ip_header|set_real_ip_from' | sort -u | cap 20
  if printf '%s' "$NGX" | grep -qi 'real_ip_header' && ! printf '%s' "$NGX" | grep -qi 'set_real_ip_from'; then
    chk nginx.real_ip FAIL "real_ip_header without set_real_ip_from" "any client can forge its source IP, defeating rate limits, allowlists and fail2ban"
  fi
fi

# ---- apache ----
# Offline the installed binary belongs to the AUDITING host: `apachectl -D DUMP_MODULES` would
# dump the auditor's loaded modules and attribute them to the image. Config is read from the tree.
APACHECTL=""
if [ "$OFFLINE" = "0" ]; then
  have apache2ctl && APACHECTL=apache2ctl
  have apachectl && [ -z "$APACHECTL" ] && APACHECTL=apachectl
fi
if [ -n "$APACHECTL" ] || [ -d "$(rf /etc/apache2)" ] || [ -d "$(rf /etc/httpd)" ]; then
  raw "apache config test + vhost map"
  [ -n "$APACHECTL" ] && { run $APACHECTL -t 2>&1; run $APACHECTL -S 2>&1; }
  raw "apache loaded modules"
  [ -n "$APACHECTL" ] && run $APACHECTL -M 2>/dev/null | sort
  APM="$([ -n "$APACHECTL" ] && $APACHECTL -M 2>/dev/null)"

  # "Used" means a SITE uses it. Deliberately excludes mods-enabled/mods-available, because a
  # module's own packaged .conf (Debian ships DavLockDB inside dav_fs.conf) would otherwise make
  # every module look used. Scope: vhosts, conf-enabled, the main config, and .htaccess.
  APC_USE="$(grep -rhvE '^\s*#|^\s*$' \
      /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ /etc/apache2/apache2.conf \
      /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/ /etc/apache2/httpd.conf 2>/dev/null)"
  APC_USE="$APC_USE
$(find "$(rf /var/www)" "$(rf /srv/www)" -maxdepth 4 -name '.htaccess' -exec cat {} \; 2>/dev/null)"

  # module | regex of the directives that module provides | why it matters when exposed
  APACHE_MODMAP='dav_module~Dav[[:space:]]+(On|on)|DavDepthInfinity~WebDAV: HTTP write methods (PUT/DELETE/MOVE) against the document root. Historically the fastest route from "web server" to "attacker-uploaded webshell"
dav_fs_module~Dav[[:space:]]+(On|on)|DavDepthInfinity~WebDAV filesystem backend, only meaningful with dav_module
dav_lock_module~Dav[[:space:]]+(On|on)~WebDAV locking backend
status_module~SetHandler[[:space:]]+server-status|ExtendedStatus~/server-status exposes live request URLs, client IPs, and internal state to whoever can reach it
info_module~SetHandler[[:space:]]+server-info~/server-info dumps the entire effective configuration, including module list and paths
userdir_module~^[[:space:]]*UserDir~maps /~user/ to home directories: enumerates local accounts and serves files out of them
autoindex_module~Options[^\n]*\+?Indexes|IndexOptions|IndexIgnore~generates directory listings: exposes files never meant to be enumerable
cgi_module~ScriptAlias|SetHandler[[:space:]]+cgi-script|AddHandler[[:space:]]+cgi-script|Options[^\n]*\+?ExecCGI~arbitrary script execution surface (Shellshock class)
cgid_module~ScriptAlias|SetHandler[[:space:]]+cgi-script|AddHandler[[:space:]]+cgi-script|Options[^\n]*\+?ExecCGI~arbitrary script execution surface
include_module~Options[^\n]*\+?Includes|AddOutputFilter[[:space:]]+INCLUDES|XBitHack~Server-Side Includes execute commands via <!--#exec-->; with a writable docroot this is direct RCE
proxy_module~ProxyPass|ProxyRequests|<Proxy|ProxyPreserveHost~reverse/forward proxy: the SSRF pivot, and ProxyRequests On is an open proxy
proxy_http_module~ProxyPass|ProxyRequests~proxying over HTTP
proxy_ajp_module~ProxyPass[^\n]*ajp://~AJP proxying; see Ghostcat (CVE-2020-1938)
proxy_fcgi_module~ProxyPass[^\n]*fcgi://|SetHandler[^\n]*proxy:fcgi~FastCGI proxying
proxy_balancer_module~<Proxy[[:space:]]+balancer|BalancerMember~load balancing; the balancer-manager handler is also exposed by it
lua_module~Lua(Hook|MapHandler|Inherit|Scope)~embedded Lua: arbitrary code execution surface inside the server
imagemap_module~ImapBase|ImapMenu~obsolete imagemap handling
negotiation_module~Options[^\n]*\+?MultiViews|AddLanguage|LanguagePriority~content negotiation: MultiViews leaks file variants and has enabled source-disclosure bugs
speling_module~CheckSpelling|CheckCaseOnly~guesses near-miss URLs: turns a 404 into a probe oracle for hidden files
substitute_module~Substitute~response body rewriting
actions_module~^[[:space:]]*Action[[:space:]]|^[[:space:]]*Script[[:space:]]~maps handlers to CGI scripts
asis_module~AddHandler[[:space:]]+send-as-is|SetHandler[[:space:]]+send-as-is~serves files with raw, unfiltered headers: header injection
cern_meta_module~MetaFiles|MetaDir~legacy metafile handling
vhost_alias_module~VirtualDocumentRoot|VirtualScriptAlias~mass virtual hosting driven by the Host header: a Host-header injection reaches other document roots
suexec_module~SuexecUserGroup~runs CGI under a different UID
authnz_ldap_module~AuthLDAPURL~LDAP authentication backend
auth_digest_module~AuthType[[:space:]]+Digest~digest auth (obsolete; prefer basic over TLS)
usertrack_module~CookieTracking|CookieName~sets tracking cookies
mime_magic_module~MimeMagicFile~content sniffing by magic bytes
buffer_module~BufferSize~request buffering
reqtimeout_module~RequestReadTimeout~(defensive: this one is GOOD to have)
headers_module~Header[[:space:]]|RequestHeader~(needed for security headers)
rewrite_module~RewriteEngine|RewriteRule~(commonly needed)
ssl_module~SSLEngine~(needed for TLS)'

  raw "apache modules: loaded vs actually used by a site"
  UNUSED=""; RISKY_UNUSED=""
  printf '%s\n' "$APACHE_MODMAP" | while IFS='~' read -r mod dirre why; do
    [ -z "$mod" ] && continue
    printf '%s' "$APM" | grep -q "[[:space:]]$mod\b\|^$mod\b\| $mod " || continue
    if printf '%s\n' "$APC_USE" | grep -qE "$dirre"; then
      printf '  used     %-24s\n' "$mod"
    else
      printf '  UNUSED   %-24s %s\n' "$mod" "$why"
      case "$mod" in
        reqtimeout_module|headers_module|rewrite_module|ssl_module) ;;
        *) chk "apache.unused_mod.$mod" FAIL "loaded, no directive in any site uses it" "$why" ;;
      esac
    fi
  done

  # count for a single headline finding
  APMCOUNT="$(printf '%s' "$APM" | grep -c '_module')"
  chk apache.module_count INFO "${APMCOUNT:-?} modules loaded" "every loaded module is parsing attacker-reachable input whether or not a site uses it; Debian/RHEL default sets are far larger than any single site needs"
  raw "how apache modules are enabled (Debian: symlinks in mods-enabled)"
  ls -l "$LSA_ROOT"/etc/apache2/mods-enabled/*.load 2>/dev/null | awk '{print $9}' | xargs -n1 basename 2>/dev/null | tr '\n' ' '
  echo
  ls "$(rf /etc/httpd/conf.modules.d/)" 2>/dev/null
  APC="$(grep -rhvE '^\s*#|^\s*$' "$(rf /etc/apache2/)" "$(rf /etc/httpd/)" 2>/dev/null)"
  raw "apache security-relevant directives"
  printf '%s\n' "$APC" | grep -iE '^\s*(ServerTokens|ServerSignature|TraceEnable|Options|AllowOverride|Require|Order|Allow|Deny|Header\s+(always\s+)?set|SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder|SSLUseStapling|Timeout|KeepAliveTimeout|LimitRequestBody|LimitRequestFields|FileETag|ServerName|DocumentRoot|User|Group)' | sort -u | cap 80
  if [ -z "$APC" ]; then
    chk apache.config_readable NA "apache is present but no config content was read" "the config tree could not be read (permissions, or a non-standard ServerRoot). Every apache.* directive check would otherwise report the BUILT-IN DEFAULT as though it were the configured value: suppressed instead"
  else
  case "$(printf '%s' "$APC" | grep -iE '^\s*ServerTokens' | head -1)" in
    *[Pp]rod*) chk apache.servertokens PASS "Prod" "" ;;
    "")        chk apache.servertokens FAIL "unset (default Full)" "banner leaks Apache version, OS and module versions" ;;
    *)         chk apache.servertokens FAIL "$(printf '%s' "$APC" | grep -iE '^\s*ServerTokens' | head -1)" "want ServerTokens Prod" ;;
  esac
  printf '%s' "$APC" | grep -qiE '^\s*ServerSignature\s+Off' && chk apache.serversignature PASS Off "" \
    || chk apache.serversignature FAIL "not Off" "version/hostname footer on generated error pages"
  printf '%s' "$APC" | grep -qiE '^\s*TraceEnable\s+Off' && chk apache.traceenable PASS Off "" \
    || chk apache.traceenable FAIL "not Off" "HTTP TRACE enabled (Cross-Site Tracing)"
  printf '%s' "$APC" | grep -qiE '^\s*Options[^\n]*\bIndexes\b' && chk apache.indexes FAIL "Options Indexes present" "directory listing enabled" \
    || chk apache.indexes PASS "no Options Indexes" ""
  printf '%s' "$APC" | grep -qiE '^\s*Options[^\n]*\b(ExecCGI|Includes)\b' && chk apache.execcgi WARN "ExecCGI/Includes enabled" "arbitrary script execution surface in the served tree"
  printf '%s' "$APC" | grep -qiE '^\s*AllowOverride\s+(All|Options)' && chk apache.allowoverride WARN "AllowOverride All/Options" "any writable directory in the tree can change server behaviour via .htaccess: combine with a writable webroot and it is RCE"
  if printf '%s' "$APC" | grep -iqE '^\s*SSLProtocol[^\n]*(SSLv2|SSLv3|\+TLSv1(\s|$)|TLSv1\.1)'; then
    chk apache.tls_versions FAIL "$(printf '%s' "$APC" | grep -iE '^\s*SSLProtocol' | head -1)" "obsolete TLS versions enabled"
  fi
  fi
  raw "apache <Directory /> default policy (should deny)"
  grep -rhA5 '<Directory */ *>' "$(rf /etc/apache2/apache2.conf)" "$(rf /etc/httpd/conf/httpd.conf)" 2>/dev/null | cap 20
  raw "apache status/info endpoints"
  printf '%s\n' "$APC" | grep -iB2 -A4 'server-status\|server-info' | cap 30
fi

# ---- TLS certificates ----
raw "TLS certificates found in web config (expiry + key permissions)"
CERTS="$( { printf '%s\n' "${NGX:-}" ; printf '%s\n' "${APC:-}" ; } 2>/dev/null | grep -ioE '(ssl_certificate|SSLCertificateFile|SSLCertificateKeyFile|ssl_certificate_key)\s+[^;[:space:]]+' | awk '{print $2}' | sort -u)"
_oifs=$IFS; IFS=$'\n'
for c in $CERTS; do
  [ -r "$c" ] || { printf 'UNREADABLE %s\n' "$c"; continue; }
  case "$c" in
    *key*|*.key) printf 'KEY %s %s\n' "$(stat -c '%a %U:%G' "$c" 2>/dev/null)" "$c"
      K="$(stat -c '%a' "$c" 2>/dev/null)"
      case "$K" in 600|400|640|0600|0400|0640) ;; *) chk "tls.keyperm.$c" FAIL "$K" "private key readable beyond root/group" ;; esac ;;
    *) if have openssl; then
         printf 'CERT %s\n' "$c"
         openssl x509 -in "$c" -noout -subject -issuer -enddate -text 2>/dev/null | grep -E 'subject=|issuer=|notAfter=|Signature Algorithm|Public-Key' | head -6
         if ! openssl x509 -in "$c" -noout -checkend 1209600 >/dev/null 2>&1; then
           chk "tls.expiry.$c" FAIL "expires within 14 days (or already expired)" "outage + users trained to click through warnings"
         fi
       fi ;;
  esac
done
IFS=$_oifs

# ---- webroot exposure ----
raw "document roots"
DOCROOTS="$( { printf '%s\n' "${NGX:-}"; printf '%s\n' "${APC:-}"; } 2>/dev/null | grep -ioE '^\s*(root|DocumentRoot)\s+[^;[:space:]]+' | awk '{print $2}' | sed 's/;$//' | sort -u)"
[ -z "$DOCROOTS" ] && DOCROOTS="$(ls -d "$LSA_ROOT"/var/www/* "$LSA_ROOT"/srv/www/* "$(rf /usr/share/nginx/html)" 2>/dev/null | head -10)"
printf '%s\n' "$DOCROOTS"
# Resolve the identity that actually serves requests, and every group it belongs to, so
# "writable by the web server" is evaluated by ALL THREE routes (owner / group / other)
# rather than only the group bit. A directory owned by www-data with mode 755 is fully
# writable by www-data: that is the most common real case and the old check missed it.
WWWUSER="${WEBUSER:-}"
[ -z "$WWWUSER" ] && WWWUSER="$(ps -eo user,args 2>/dev/null | grep -E 'nginx: worker|apache2 -k|httpd -D|php-fpm: pool' | grep -v grep | awk '{print $1}' | grep -v '^root$' | sort -u | head -1)"
[ -z "$WWWUSER" ] && for u in www-data nginx apache http httpd php-fpm; do id "$u" >/dev/null 2>&1 && { WWWUSER="$u"; break; }; done
case "$WWWUSER" in
  root) chk web.worker_identity FAIL "worker runs as root" "every path in the document root is writable by the request-handling process by definition; the writable-webroot analysis below is meaningless until the worker drops privileges"
        WWWUSER="" ;;
  # No web server on the target at all: there is no worker to identify, and warning about one
  # invents a subject. UBI ships neither nginx nor httpd and still got this warning.
  "")   if [ -z "${WS//[[:space:]]/}" ] && [ -z "${DOCROOTS//[[:space:]]/}" ]; then
          chk web.worker_identity NA "no web server on this target" "no nginx/apache/httpd binary, configuration directory or document root was found, so there is no request-handling identity to evaluate"
        else
        chk web.worker_identity WARN "worker user not determined" "no running worker and no standard account found; writability is evaluated for world-writable only"
        fi ;;
  *)    chk web.worker_identity INFO "user=$WWWUSER groups=$(id -nG "$WWWUSER" 2>/dev/null)" "writability below is evaluated against this identity, by all three routes: owner, group, and other" ;;
esac
WWWGROUPS="$(id -nG "$WWWUSER" 2>/dev/null)"

# does a PHP (or other interpreter) handler apply inside the document root?
PHP_ACTIVE=0
printf '%s' "${NGX:-}${APC:-}" | grep -qiE 'fastcgi_pass|SetHandler[^\n]*php|AddHandler[^\n]*php|php-fpm|proxy:fcgi' && PHP_ACTIVE=1
have php && [ "$PHP_ACTIVE" = "0" ] && PHP_ACTIVE=1

TOTAL_WDIR=0; TOTAL_WPHP=0
_oifs=$IFS; IFS=$'\n'
for d in $DOCROOTS; do
  [ -d "$d" ] || continue
  printf '\n[%s] owner/mode: %s\n' "$d" "$(stat -c '%a %U:%G' "$d" 2>/dev/null)"

  # files that must never be web-reachable (POSIX -print; -printf is GNU-only and would
  # silently return nothing on a find that lacks it)
  find "$d" -maxdepth 3 \( -name '.git' -o -name '.env' -o -name '.env.*' -o -name '*.sql' -o -name '*.sql.gz' \
       -o -name '*.bak' -o -name '*.old' -o -name '*.swp' -o -name 'wp-config.php.*' -o -name '.htpasswd' \
       -o -name 'id_rsa*' -o -name '*.pem' -o -name 'composer.lock' -o -name '.DS_Store' -o -name 'phpinfo.php' \
       -o -name 'adminer*.php' -o -name 'info.php' -o -name '*.log' -o -name 'dump.rdb' \) -print 2>/dev/null \
    | head -25 | tr '\n' '\0' | xargs -0 ls -ld 2>/dev/null | sed 's/^/  SENSITIVE-IN-WEBROOT /'

  # build a find expression covering all three write routes for the worker identity
  set -- -type d "("
  [ -n "$WWWUSER" ] && set -- "$@" "(" -user "$WWWUSER" -perm -u+w ")" -o
  for g in $WWWGROUPS; do set -- "$@" "(" -group "$g" -perm -g+w ")" -o; done
  set -- "$@" -perm -o+w ")"

  WDIRS="$(find "$d" -maxdepth 6 "$@" -print 2>/dev/null | head -60)"
  NW="$(printf '%s' "$WDIRS" | grep -c . )"
  if [ "${NW:-0}" -gt 0 ]; then
    printf '%s\n' "$WDIRS" | head -30 | tr '\n' '\0' | xargs -0 ls -ld 2>/dev/null | sed 's/^/  WRITABLE-DIR /'
    TOTAL_WDIR=$((TOTAL_WDIR + NW))

    # the combination that matters: writable AND the interpreter runs there AND no local
    # deny rule. Check for an execution-blocking .htaccess or nginx location per directory.
    for w in $(printf '%s\n' "$WDIRS" | head -20); do
      GUARD=""
      [ -f "$w/.htaccess" ] && grep -qiE 'php_flag[[:space:]]+engine[[:space:]]+off|SetHandler[[:space:]]+(None|default-handler)|RemoveHandler|Deny from all|Require all denied|<Files.*\\.php' "$w/.htaccess" 2>/dev/null && GUARD="htaccess-deny"
      rel="${w#$d}"
      printf '%s' "${NGX:-}" | grep -qiE "location[^\n]*${rel}[^\n]*\{[^}]*(deny all|return 40[0-3])" && GUARD="nginx-deny"
      if [ -z "$GUARD" ] && [ "$PHP_ACTIVE" = "1" ]; then
        printf '  EXECUTABLE-AND-WRITABLE %s (no local handler-deny rule found)\n' "$w"
      fi
    done
  fi

  # writable FILES: a writable .php is modified directly, no upload needed
  set -- -type f "("
  [ -n "$WWWUSER" ] && set -- "$@" "(" -user "$WWWUSER" -perm -u+w ")" -o
  for g in $WWWGROUPS; do set -- "$@" "(" -group "$g" -perm -g+w ")" -o; done
  set -- "$@" -perm -o+w ")"
  WPHP="$(find "$d" -maxdepth 6 "$@" \( -name '*.php' -o -name '*.phtml' -o -name '*.inc' \) -print 2>/dev/null | head -30)"
  NP="$(printf '%s' "$WPHP" | grep -c . )"
  if [ "${NP:-0}" -gt 0 ]; then
    printf '%s\n' "$WPHP" | head -20 | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null | sed 's/^/  WRITABLE-PHP-FILE /'
    TOTAL_WPHP=$((TOTAL_WPHP + NP))
  fi

  # .htaccess writable by the web server = the application rewrites its own server config
  if [ -n "$WWWUSER" ]; then
    WHT="$(find "$d" -maxdepth 6 -name '.htaccess' \( -perm -o+w -o \( -user "$WWWUSER" -perm -u+w \) \) -print 2>/dev/null | head -10)"
  else
    WHT="$(find "$d" -maxdepth 6 -name '.htaccess' -perm -o+w -print 2>/dev/null | head -10)"
  fi
  if [ -n "$WHT" ]; then
    printf '%s\n' "$WHT" | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null | sed 's/^/  WRITABLE-HTACCESS /'
    chk webroot.writable_htaccess FAIL "$(printf '%s' "$WHT" | tr '\n' ' ' | cut -c1-140)" "a writable .htaccess lets the web process change server behaviour: re-enable the PHP handler in an upload directory, set a new handler, or disable an access restriction. With AllowOverride All this is equivalent to editing the vhost"
  fi
done
IFS=$_oifs

if [ "${TOTAL_WPHP:-0}" -gt 0 ]; then
  chk webroot.writable_php FAIL "${TOTAL_WPHP} PHP file(s) writable by ${WWWUSER:-the worker}" "existing application code can be modified in place by the process serving requests: no upload bug required, and the change survives as a webshell. Application code should be owned by a deploy user and read-only to the worker"
else
  chk webroot.writable_php PASS "no worker-writable PHP files" ""
fi
if [ "${TOTAL_WDIR:-0}" -gt 0 ]; then
  if [ "$PHP_ACTIVE" = "1" ]; then
    chk webroot.writable_dirs FAIL "${TOTAL_WDIR} director(ies) writable by ${WWWUSER:-the worker}, PHP handler active in this tree" "writable + interpreted + web-reachable is the webshell triad. Genuine upload/cache directories need a rule that stops the interpreter running there: nginx: a location that denies \\.php\$ under the upload path; Apache: php_flag engine off (or SetHandler None) in that directory. Everything else should be read-only to the worker"
  else
    chk webroot.writable_dirs WARN "${TOTAL_WDIR} director(ies) writable by ${WWWUSER:-the worker}" "no interpreter handler detected in this tree, so a dropped file is served rather than executed, still an upload and defacement primitive, and a stored-XSS/malware host"
  fi
else
  chk webroot.writable_dirs PASS "no worker-writable directories in the document root" ""
fi

# ---- PHP ----
if have php || ls "$LSA_ROOT"/etc/php* >/dev/null 2>&1; then
  raw "php version (EOL versions receive no security fixes)"
  have php && run php -v 2>/dev/null | head -2
  raw "php-fpm pools: user, listen socket, permissions"
  grep -rhE '^\s*(user|group|listen|listen\.owner|listen\.group|listen\.mode|listen\.allowed_clients|security\.limit_extensions)\s*=' "$LSA_ROOT"/etc/php*/*/fpm/pool.d/ "$(rf /etc/php-fpm.d/)" 2>/dev/null | sort -u
  raw "php.ini security settings (effective files)"
  have php && run php -i 2>/dev/null | grep -E '^(Loaded Configuration File|Scan this dir)'
  PHPINI="$(grep -rhE '^\s*(expose_php|display_errors|display_startup_errors|log_errors|allow_url_fopen|allow_url_include|disable_functions|open_basedir|file_uploads|upload_max_filesize|max_execution_time|session\.cookie_httponly|session\.cookie_secure|session\.cookie_samesite|session\.use_strict_mode|enable_dl|cgi\.fix_pathinfo|register_globals)\s*=' "$LSA_ROOT"/etc/php*/ "$(rf /etc/php.ini)" "$(rf /etc/php.d/)" 2>/dev/null | sed 's/  */ /g' | sort -u)"
  printf '%s\n' "$PHPINI"
  php_want() { # php_want <setting> <wanted regex> <severity note>
    v="$(printf '%s\n' "$PHPINI" | grep -iE "^\s*$1\s*=" | tail -1)"
    if [ -z "$v" ]; then chk "php.$1" INFO "unset (build default)" "$3"
    elif printf '%s' "$v" | grep -qiE "$2"; then chk "php.$1" PASS "$v" ""
    else chk "php.$1" FAIL "$v" "$3"; fi
  }
  php_want expose_php            '=\s*(Off|0|false)'  "X-Powered-By reveals exact PHP version"
  php_want display_errors        '=\s*(Off|0|false)'  "error output leaks paths, queries and sometimes credentials to users"
  php_want allow_url_fopen       '=\s*(Off|0|false)'  "turns many bugs into SSRF/remote file inclusion"
  php_want allow_url_include     '=\s*(Off|0|false)'  "remote file inclusion => RCE"
  php_want cgi.fix_pathinfo      '=\s*0'              "with a permissive fastcgi config, uploads can be executed as PHP"
  php_want session.cookie_httponly '=\s*(On|1|true)'  "session cookie readable by JavaScript (XSS => session theft)"
  php_want session.cookie_secure   '=\s*(On|1|true)'  "session cookie sent over plaintext HTTP"
  php_want session.use_strict_mode '=\s*(On|1|true)'  "session fixation"
  php_want log_errors            '=\s*(On|1|true)'    "no error record for incident response"
  printf '%s\n' "$PHPINI" | grep -qiE '^\s*disable_functions\s*=\s*\S' \
    && chk php.disable_functions PASS "$(printf '%s\n' "$PHPINI" | grep -iE '^\s*disable_functions' | tail -1 | cut -c1-160)" "" \
    || chk php.disable_functions WARN "empty" "exec/system/passthru/proc_open available to any included PHP file: a webshell needs nothing else"
  printf '%s\n' "$PHPINI" | grep -qiE '^\s*open_basedir\s*=\s*\S' \
    && chk php.open_basedir PASS set "" \
    || chk php.open_basedir WARN unset "PHP can read anywhere the worker user can: LFI reaches /etc, keys, other vhosts"

  # ---- loaded PHP extensions: each is C code parsing attacker input ----
  raw "loaded PHP extensions"
  have php && run php -m 2>/dev/null | tr '\n' ' '
  echo
  PHPM="$(php -m 2>/dev/null | tr 'A-Z' 'a-z')"
  # extension | why it is a finding in production
  PHP_EXTMAP='xdebug|A DEBUGGER IN PRODUCTION. xdebug 2 accepts remote debug connections and xdebug 3 exposes profiling/tracing; historically trivially turned into remote code execution. Remove it from production entirely
ffi|Foreign Function Interface: calls arbitrary native library functions from PHP, which defeats disable_functions and open_basedir completely
phar|Phar archive handling: the deserialization gadget path (phar:// stream wrappers turn any file operation into unserialize())
imagick|ImageMagick bindings: a long history of RCE via crafted images (ImageTragick, and the MSL/ephemeral coder classes)
exif|EXIF parser with a steady CVE record; only needed if you actually read image metadata
pcntl|process control: fork/exec primitives normally unnecessary in a web SAPI
shmop|shared memory access
sysvshm|System V shared memory
sysvsem|System V semaphores
posix|POSIX process/user functions: useful for enumeration after a compromise
odbc|ODBC connectivity
snmp|SNMP client
ldap|LDAP client (fine if used for auth; an SSRF/injection surface otherwise)
soap|SOAP client/server: XXE surface
xmlrpc|XML-RPC, unmaintained and an XXE/deserialization surface
sqlite3|bundled SQLite
mysqli|MySQL client
pdo_mysql|MySQL client via PDO'
  for e in $(printf '%s\n' "$PHP_EXTMAP" | cut -d'|' -f1); do
    printf '%s' "$PHPM" | grep -qx "$e" || continue
    why="$(printf '%s\n' "$PHP_EXTMAP" | grep "^$e|" | cut -d'|' -f2-)"
    case "$e" in
      xdebug|ffi) chk "php.ext.$e" FAIL loaded "$why" ;;
      phar|imagick|exif|pcntl) chk "php.ext.$e" WARN loaded "$why" ;;
      *) chk "php.ext.$e" INFO loaded "$why" ;;
    esac
  done
  EXTCOUNT="$(printf '%s\n' "$PHPM" | grep -vc '^\[' )"
  chk php.extension_count INFO "${EXTCOUNT:-?} extensions loaded" "each is C code parsing attacker-controlled input in every request; disable what the application does not call"
  raw "where extensions are enabled"
  ls "$LSA_ROOT"/etc/php/*/mods-available/ "$(rf /etc/php.d/)" 2>/dev/null | cap 30
fi

# ---- live response headers (loopback only, never leaves the host) ----
HTTP_LISTENING=0
have ss && ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE '[:.](80|443|8080|8443)$' && HTTP_LISTENING=1
if [ "$PROBE" = "1" ] && have curl && { [ -n "$WS" ] || [ "$HTTP_LISTENING" = "1" ]; }; then
  active_on
  raw "live response headers from localhost (http/https)"
  for u in http://127.0.0.1/ https://127.0.0.1/; do
    printf '\n>>> %s\n' "$u"
    run curl -skI --max-time 6 "$u" | cap 25
  done
  HDRS="$(curl -skI --max-time 6 https://127.0.0.1/ 2>/dev/null; curl -skI --max-time 6 http://127.0.0.1/ 2>/dev/null)"
  for h in "Strict-Transport-Security" "X-Content-Type-Options" "X-Frame-Options" "Content-Security-Policy" "Referrer-Policy"; do
    printf '%s' "$HDRS" | grep -qi "^$h:" && chk "http.header.$h" PASS present "" || chk "http.header.$h" WARN absent "not returned on the default vhost"
  done
  printf '%s' "$HDRS" | grep -qiE '^(Server|X-Powered-By):.*[0-9]\.[0-9]' \
    && chk http.version_disclosure FAIL "$(printf '%s' "$HDRS" | grep -iE '^(Server|X-Powered-By):' | head -2 | tr '\n' ' ')" "exact software versions in response headers"
  raw "HTTP methods accepted (OPTIONS)"
  run curl -skI -X OPTIONS --max-time 6 http://127.0.0.1/ | grep -i '^allow:'
  active_off
elif have curl; then
  chk http.headers NA "not probed" "passive mode (--passive) or no HTTP listener"
fi

if [ -n "$WS" ]; then
  raw "web application firewall / rate limiting"
  WAF=""
  printf '%s' "${APM:-}" | grep -qi 'security2_module'   && WAF="$WAF mod_security2"
  printf '%s' "${NGX:-}" | grep -qiE 'modsecurity\s+on'  && WAF="$WAF nginx-modsecurity"
  printf '%s' "${NGX:-}" | grep -qi 'naxsi'              && WAF="$WAF naxsi"
  [ -d "$(rf /etc/modsecurity)" ] || [ -d "$(rf /etc/nginx/modsec)" ]    && WAF="$WAF modsecurity-config"
  have fail2ban-client && fail2ban-client status 2>/dev/null | grep -qiE 'nginx|apache|wordpress|http' && WAF="$WAF fail2ban-http-jail"
  [ -n "$WAF" ] && chk web.waf PASS "$WAF" "" \
                || chk web.waf WARN none "no WAF or HTTP-aware rate limiting in front of the application"
  have fail2ban-client && run fail2ban-client status
fi

# ------------------------------------------------------------------ 16. TLS
# Cipher/protocol validation for every TLS endpoint on this host, plus mutual-TLS
# enforcement for internal tunnels. Probes are loopback/local-address only and send
# nothing but a ClientHello; disable with --no-probe.
sec TLS

if ! have openssl; then
  chk tls.tooling NA "openssl not installed" "cannot validate ciphers or certificates on this host"
else

# ---- classify each TLS-capable listener as internal or external ----
is_internal_addr() {
  case "$1" in
    127.*|::1|\[::1\]|localhost)                                  echo loopback ;;
    10.*|192.168.*|169.254.*)                                     echo internal ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*)                        echo internal ;;
    fd*|\[fd*|fe80*|\[fe80*)                                      echo internal ;;
    0.0.0.0|\[::\]|\*)                                            echo wildcard ;;
    *)                                                            echo external ;;
  esac
}

TLS_PORTS=""
if [ "$PROBE" = "1" ] && have ss; then
  # every locally listening TCP port, deduped
  TLS_PORTS="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -un | head -24 | tr '\n' ' ')"
elif [ "$PROBE" = "1" ]; then
  TLS_PORTS="443 8443 9443 6514 2376 636 993 465 5671 8883"
fi
if [ "$PROBE" = "1" ]; then
  chk tls.ports_probed INFO "$TLS_PORTS" "loopback ClientHello probe of each listening TCP port" active
else
  chk tls.ports_probed NA "probing disabled (--passive)" "cipher suites, protocol versions and mutual-TLS ENFORCEMENT cannot be established from configuration alone; re-run without --passive against a running host to confirm them"
fi

# one bounded handshake attempt; prints s_client output, empty if the port does not speak TLS
tls_hs() { echo | tmo 6 openssl s_client -connect "127.0.0.1:$1" ${2:+$2} -servername localhost </dev/null 2>&1; }
# true if the given s_client output shows a completed handshake with a real cipher
# (POSIX character classes throughout: \s is not portable across awk/grep implementations)
# A real handshake reports a NAMED cipher. OpenSSL prints "Cipher : 0000" (and TLSv1.2 as the
# protocol) when nothing was negotiated, which is what you get probing SSH on 22 or plaintext
# HTTP on 80. Treating that as a TLS endpoint made every non-TLS port produce a full set of
# bogus weak-cipher FAILs, so require a cipher name that is not 0000/(NONE)/empty.
tls_ok() {
  _c="$(printf '%s' "$1" | awk -F': *' '/^[[:space:]]*Cipher[[:space:]]*:/{print $2; exit}' | tr -d ' \r')"
  case "$_c" in
    ""|0000|"(NONE)"|NONE) return 1 ;;
    *[A-Za-z]*) return 0 ;;    # a named suite, e.g. ECDHE-RSA-AES256-GCM-SHA384
    *) return 1 ;;
  esac
}
tls_field() { printf '%s' "$1" | awk -F': *' -v k="$2" '$0 ~ "^[[:space:]]*"k"[[:space:]]*:" {print $2; exit}'; }
# Did the server send a CertificateRequest? NOTE: "No client certificate CA names sent" is printed
# by some TLS libraries even when no CertificateRequest was made: it is NOT a valid indicator.
tls_asks_client_cert() {
  printf '%s' "$1" | grep -qE 'Acceptable client certificate CA names|Client Certificate Types|Requested Signature Algorithms'
}
# Did our no-client-certificate handshake get rejected? Covers OpenSSL and LibreSSL phrasings.
tls_handshake_failed() {
  printf '%s' "$1" | grep -qiE 'error:[0-9A-Fa-f]{6,}|alert number (40|42|45|46|48|116)|alert handshake failure|alert certificate required|alert bad certificate|peer did not return a certificate|no certificate returned|Connection reset by peer|write:errno'
}

active_on
for p in $TLS_PORTS; do
  HS="$(tls_hs "$p")"
  tls_ok "$HS" || continue                      # not a TLS listener; skip, cheaply
  BIND="$(ss -tlnH 2>/dev/null | awk -v pt=":$p" '$4 ~ pt"$" {print $4; exit}' | sed 's/:[0-9]*$//')"
  SCOPE="$(is_internal_addr "${BIND:-127.0.0.1}")"

  raw "TLS endpoint 127.0.0.1:$p (bind=${BIND:-?} scope=$SCOPE)"
  printf '%s\n' "$HS" | grep -E '^\s*(Protocol|Cipher|Server public key|Peer signature type|Negotiated TLS1.3 group|Verify return code|subject=|issuer=)' | cap 12

  NEGO_P="$(tls_field "$HS" Protocol)"
  NEGO_C="$(tls_field "$HS" Cipher)"
  chk "tls.$p.negotiated" INFO "${NEGO_P:-?} / ${NEGO_C:-?}" "scope=$SCOPE"

  # ---- obsolete protocol versions actually accepted ----
  OLD=""; UNTESTED=""
  for v in ssl3 tls1 tls1_1; do
    O="$(tls_hs "$p" "-$v")"
    case "$O" in *"unknown option"*|*"unrecognized"*) UNTESTED="$UNTESTED $v"; continue ;; esac
    tls_ok "$O" && OLD="$OLD $v"
  done
  if [ -n "$OLD" ]; then
    chk "tls.$p.obsolete_protocols" FAIL "accepted:$OLD" "SSLv3/TLS1.0/TLS1.1 are deprecated and broken (POODLE, BEAST, downgrade): require TLS 1.2 minimum, prefer 1.3"
  else
    chk "tls.$p.obsolete_protocols" PASS "none accepted" "${UNTESTED:+not testable by local openssl:$UNTESTED; confirm with testssl.sh}"
  fi
  MINOK=0
  for v in tls1_2 tls1_3; do
    R="$(tls_hs "$p" "-$v")"
    if tls_ok "$R"; then MINOK=1; printf '  %-8s %s\n' "$v" "$(tls_field "$R" Cipher)"; fi
  done
  [ "$MINOK" = "0" ] && chk "tls.$p.modern_protocols" WARN "neither TLS1.2 nor TLS1.3 negotiated by local openssl" "verify manually"

  # ---- weak cipher families: will the server negotiate any of them? ----
  for spec in \
    "anon|aNULL:@SECLEVEL=0|anonymous key exchange: encrypted but UNAUTHENTICATED, trivially MITM'd" \
    "null|eNULL:NULL:@SECLEVEL=0|NULL cipher: authenticated but NOT ENCRYPTED" \
    "export|EXPORT:@SECLEVEL=0|export-grade crypto (FREAK/Logjam)" \
    "rc4|RC4:@SECLEVEL=0|RC4 keystream biases are practically exploitable" \
    "des3|DES:3DES:@SECLEVEL=0|DES/3DES: 64-bit block cipher, Sweet32" \
    "md5|MD5:@SECLEVEL=0|MD5 MAC" \
    "sha1|SHA1:@SECLEVEL=0|SHA-1 MAC" \
    "cbc|AES128-SHA:AES256-SHA:@SECLEVEL=0|CBC-mode suites without AEAD (Lucky13 / padding-oracle class)" \
    "nopfs|kRSA:@SECLEVEL=0|static RSA key exchange: NO forward secrecy; one stolen private key decrypts all past recorded traffic" \
  ; do
    lbl="${spec%%|*}"; rest="${spec#*|}"; cs="${rest%%|*}"; note="${rest#*|}"
    # A modern openssl will not OFFER RC4/3DES/EXPORT at all, so it cannot test for them. If the
    # local build has no cipher matching the spec, the probe proves nothing; report NA rather
    # than a verdict. Without this the client's inability to ask reads as the server's answer.
    if [ -z "$(openssl ciphers "$cs" 2>/dev/null)" ]; then
      chk "tls.$p.weak.$lbl" NA "local openssl offers no cipher matching '$cs'" "this build cannot test that family, not evidence the server rejects it. Use a legacy openssl build, or testssl.sh, which carries its own"
      continue
    fi
    O="$(echo | tmo 6 openssl s_client -connect "127.0.0.1:$p" -cipher "$cs" </dev/null 2>&1)"
    case "$O" in *"no cipher match"*|*"unknown option"*|*"no ciphers available"*)
      chk "tls.$p.weak.$lbl" NA "local openssl refused the cipher spec" "cannot test this family from here"; continue ;; esac
    if tls_ok "$O"; then
      # A handshake completed, but confirm the NEGOTIATED cipher is actually in the family we
      # asked for. If -cipher failed to constrain and the server picked something modern, the
      # server did not accept the weak family and reporting it as ACCEPTED would be wrong.
      NEG="$(tls_field "$O" Cipher)"
      if openssl ciphers "$cs" 2>/dev/null | tr ':' '\n' | grep -qxF "$NEG"; then
        chk "tls.$p.weak.$lbl" FAIL "ACCEPTED ($NEG)" "$note"
      else
        chk "tls.$p.weak.$lbl" PASS "rejected (negotiated $NEG, outside the tested family)" ""
      fi
    else
      chk "tls.$p.weak.$lbl" PASS "rejected" ""
    fi
  done

  # ---- certificate quality ----
  CERTPEM="$(printf '%s' "$HS" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')"
  if [ -n "$CERTPEM" ]; then
    CINFO="$(printf '%s' "$CERTPEM" | openssl x509 -noout -subject -issuer -enddate -text 2>/dev/null)"
    printf '%s\n' "$CINFO" | grep -E 'subject=|issuer=|notAfter=|Signature Algorithm|Public-Key|DNS:' | head -8
    printf '%s' "$CINFO" | grep -qiE 'Signature Algorithm: .*(md5|sha1)WithRSA' \
      && chk "tls.$p.cert_sigalg" FAIL "SHA-1 or MD5 signature" "collision-forgeable signature algorithm"
    KB="$(printf '%s' "$CINFO" | grep -oE 'Public-Key: \(([0-9]+) bit\)' | grep -oE '[0-9]+' | head -1)"
    if printf '%s' "$CINFO" | grep -q 'id-ecPublicKey\|ECDSA'; then :;
    elif [ -n "$KB" ] && [ "$KB" -lt 2048 ]; then chk "tls.$p.cert_keysize" FAIL "${KB} bit RSA" "below 2048-bit minimum"; fi
    printf '%s' "$CERTPEM" | openssl x509 -noout -checkend 1209600 >/dev/null 2>&1 \
      || chk "tls.$p.cert_expiry" FAIL "expires within 14 days or already expired" ""
    printf '%s' "$CINFO" | grep -q 'DNS:' || chk "tls.$p.cert_san" WARN "no subjectAltName" "modern clients reject certs without SAN"
    VRC="$(printf '%s' "$HS" | grep -m1 'Verify return code')"
    printf '%s\n' "  $VRC"
  fi

  # ---- mutual TLS: does the server ask for a client certificate, and does it REQUIRE one? ----
  # Some TLS libraries (notably LibreSSL) print no CertificateRequest information for a
  # TLS 1.3 handshake: they emit "No client certificate CA names sent" whether or not the
  # server asked. Retry over TLS 1.2, where the signal is reliable, before concluding.
  MT="$HS"
  tls_asks_client_cert "$MT" || MT="$(tls_hs "$p" "-tls1_2")"
  if tls_asks_client_cert "$MT"; then
    HS="$MT"
    # The server sent a CertificateRequest. We connected WITHOUT a client certificate:
    # if the handshake still completed, the requirement is advisory and authenticates nobody.
    if tls_handshake_failed "$HS"; then
      chk "tls.$p.mtls" PASS "required (handshake refused without a client certificate)" "scope=$SCOPE"
    else
      chk "tls.$p.mtls" WARN "requested but NOT enforced" "the server asks for a client certificate yet completed the handshake without one: permissive/optional mTLS authenticates nobody unless the application separately rejects unverified peers (nginx \$ssl_client_verify, Apache SSLVerifyClient require)"
    fi
    raw "accepted client CA names for port $p"
    printf '%s\n' "$HS" | sed -n '/Acceptable client certificate CA names/,/^---/p' | cap 10
  else
    case "$SCOPE" in
      loopback)
        chk "tls.$p.mtls" INFO "no client cert requested" "loopback-only listener; mTLS not required if nothing off-host reaches it" ;;
      internal|wildcard)
        chk "tls.$p.mtls" FAIL "no client cert requested" "INTERNAL TLS endpoint (bind=$BIND) authenticates the server to the client but not the client to the server: any host that can reach it is trusted. Internal tunnels must be mutual TLS with strict verification on both ends" ;;
      *)
        chk "tls.$p.mtls" INFO "no client cert requested" "public endpoint: server-auth TLS is normal here; mTLS only if this is a machine-to-machine API" ;;
    esac
  fi
done
active_off

# ---- per-service mutual-TLS configuration audit (config is authoritative; the probe can miss) ----
raw "MUTUAL TLS CONFIGURATION BY SERVICE"

mtls_chk() { # mtls_chk <id> <config-present?> <enforcing-regex-matched?> <detail> <what-enforcement-means>
  if [ "$2" != "1" ]; then return; fi
  if [ "$3" = "1" ]; then chk "mtls.$1" PASS "$4" ""
  else chk "mtls.$1" FAIL "$4" "$5"; fi
}

# Docker daemon: --tls alone is encryption only; --tlsverify is what validates the client cert
DKARGS="$( { systemctl cat docker.service 2>/dev/null; cat "$(rf /etc/docker/daemon.json)" 2>/dev/null; ps -eo args 2>/dev/null | grep '[d]ockerd'; } 2>/dev/null )"
if [ -n "$DKARGS" ]; then
  raw "docker daemon TLS flags"
  printf '%s\n' "$DKARGS" | grep -oE '(\-\-tlsverify|\-\-tls\b|\-\-tlscacert[= ][^ "]*|\-\-tlscert[= ][^ "]*|\-\-tlskey[= ][^ "]*|"tlsverify":[^,}]*|"tlscacert":[^,}]*|-H [^ "]*)' | sort -u
  if printf '%s' "$DKARGS" | grep -qE '\-H\s*(tcp|fd)?://?[^ ]*:[0-9]+|"hosts".*tcp://'; then
    if printf '%s' "$DKARGS" | grep -qE '\-\-tlsverify|"tlsverify"\s*:\s*true'; then
      printf '%s' "$DKARGS" | grep -qE '\-\-tlscacert|"tlscacert"' \
        && chk mtls.docker PASS "tlsverify + tlscacert" "client certificates are validated against the CA" \
        || chk mtls.docker FAIL "tlsverify without tlscacert" "no CA to validate client certs against"
    elif printf '%s' "$DKARGS" | grep -qE '\-\-tls\b|"tls"\s*:\s*true'; then
      chk mtls.docker FAIL "--tls without --tlsverify" "TCP Docker API is ENCRYPTED BUT UNAUTHENTICATED: anyone who can reach the port gets root on this host. --tlsverify is what enforces client-certificate auth"
    else
      chk mtls.docker FAIL "TCP socket with no TLS" "UNAUTHENTICATED, UNENCRYPTED Docker API = remote root"
    fi
  else
    chk mtls.docker PASS "unix socket only (no TCP listener)" ""
  fi
fi

# rsyslog TLS: StreamDriverAuthMode anon means the peer certificate is not validated
if [ -d "$(rf /etc/rsyslog.d)" ] || [ -r "$(rf /etc/rsyslog.conf)" ]; then
  RSC="$(grep -rhE 'StreamDriver|PermittedPeers|CAFile|CertFile|KeyFile|gtls' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" 2>/dev/null)"
  if printf '%s' "$RSC" | grep -q 'gtls'; then
    raw "rsyslog TLS settings"; printf '%s\n' "$RSC"
    if printf '%s' "$RSC" | grep -qE 'StreamDriverAuthMode\s*=?\s*"?x509/(name|fingerprint)'; then
      printf '%s' "$RSC" | grep -qE 'PermittedPeers' \
        && chk mtls.rsyslog PASS "x509/name + PermittedPeers" "" \
        || chk mtls.rsyslog WARN "x509/name without PermittedPeers" "any certificate from the CA is accepted; pin the expected peer"
    else
      chk mtls.rsyslog FAIL "StreamDriverAuthMode not x509" "log transport is encrypted but the peer is NOT validated (anon): an attacker can impersonate the log collector or inject forged log entries"
    fi
  fi
fi

# nginx: client verification (server side) and upstream verification (client side)
if [ -n "${NGX:-}" ]; then
  raw "nginx mutual-TLS directives"
  printf '%s\n' "$NGX" | grep -iE '^\s*(ssl_verify_client|ssl_client_certificate|ssl_trusted_certificate|ssl_verify_depth|proxy_ssl_verify|proxy_ssl_trusted_certificate|proxy_ssl_certificate|proxy_ssl_certificate_key|proxy_ssl_name|proxy_ssl_server_name|grpc_ssl_verify|uwsgi_ssl_verify)' | sort -u
  if printf '%s' "$NGX" | grep -qiE '^\s*ssl_verify_client\s+on'; then
    chk mtls.nginx_client PASS "ssl_verify_client on" ""
  elif printf '%s' "$NGX" | grep -qiE '^\s*ssl_verify_client\s+optional'; then
    chk mtls.nginx_client WARN "ssl_verify_client optional" "a missing or invalid client cert still gets through unless \$ssl_client_verify is checked in the config; verify that it is"
  fi
  # nginx as a TLS client to an upstream: verification is OFF by default
  if printf '%s' "$NGX" | grep -qiE '^\s*proxy_pass\s+https://'; then
    if printf '%s' "$NGX" | grep -qiE '^\s*proxy_ssl_verify\s+on'; then
      printf '%s' "$NGX" | grep -qiE '^\s*proxy_ssl_trusted_certificate' \
        && chk mtls.nginx_upstream PASS "proxy_ssl_verify on + trusted_certificate" "" \
        || chk mtls.nginx_upstream FAIL "proxy_ssl_verify on without proxy_ssl_trusted_certificate" "no CA bundle to verify against"
    else
      chk mtls.nginx_upstream FAIL "proxy_pass https:// with proxy_ssl_verify off (the default)" "nginx does NOT validate the upstream certificate by default: the encrypted hop to the backend is MITM-able"
    fi
  fi
fi

# apache: client verification and proxy-side verification
if [ -n "${APC:-}" ]; then
  raw "apache mutual-TLS directives"
  printf '%s\n' "$APC" | grep -iE '^\s*(SSLVerifyClient|SSLCACertificateFile|SSLCACertificatePath|SSLVerifyDepth|SSLProxyVerify|SSLProxyCACertificateFile|SSLProxyCheckPeerCN|SSLProxyCheckPeerName|SSLProxyCheckPeerExpire|SSLProxyMachineCertificateFile)' | sort -u
  printf '%s' "$APC" | grep -qiE '^\s*SSLVerifyClient\s+require' && chk mtls.apache_client PASS "SSLVerifyClient require" ""
  printf '%s' "$APC" | grep -qiE '^\s*SSLVerifyClient\s+optional' && chk mtls.apache_client WARN "SSLVerifyClient optional" "unverified clients still connect"
  if printf '%s' "$APC" | grep -qiE '^\s*SSLProxyEngine\s+on'; then
    printf '%s' "$APC" | grep -qiE '^\s*SSLProxyVerify\s+require' \
      && chk mtls.apache_proxy PASS "SSLProxyVerify require" "" \
      || chk mtls.apache_proxy FAIL "SSLProxyEngine on without SSLProxyVerify require" "backend certificate not validated"
    printf '%s' "$APC" | grep -qiE '^\s*SSLProxyCheckPeerName\s+off|^\s*SSLProxyCheckPeerCN\s+off' \
      && chk mtls.apache_proxy_name FAIL "SSLProxyCheckPeerName/CN off" "hostname not checked: any valid certificate is accepted"
  fi
fi

# haproxy; 'verify required' + ca-file needed on BOTH bind (client auth) and server (upstream auth)
if [ -r "$(rf /etc/haproxy/haproxy.cfg)" ]; then
  raw "haproxy TLS lines"
  grep -hE '^\s*(bind|server|default-server).*(ssl|crt|ca-file|verify)' "$(rf /etc/haproxy/haproxy.cfg)" 2>/dev/null | sed 's/  */ /g'
  grep -qE '^\s*bind.*ssl.*verify\s+required' "$(rf /etc/haproxy/haproxy.cfg)" 2>/dev/null \
    && chk mtls.haproxy_bind PASS "bind ... verify required" "" \
    || grep -qE '^\s*bind.*ssl' "$(rf /etc/haproxy/haproxy.cfg)" 2>/dev/null \
       && chk mtls.haproxy_bind INFO "TLS bind without 'verify required'" "no client-certificate auth on this frontend"
  if grep -qE '^\s*(server|default-server).*ssl' "$(rf /etc/haproxy/haproxy.cfg)" 2>/dev/null; then
    grep -qE '^\s*(server|default-server).*ssl.*verify\s+required.*ca-file|ca-file.*verify\s+required' "$(rf /etc/haproxy/haproxy.cfg)" 2>/dev/null \
      && chk mtls.haproxy_server PASS "server ... verify required ca-file" "" \
      || chk mtls.haproxy_server FAIL "backend 'ssl' without 'verify required ca-file'" "haproxy defaults to verify none on server lines: the backend certificate is not checked at all"
  fi
fi

# stunnel
if ls "$LSA_ROOT"/etc/stunnel/*.conf >/dev/null 2>&1; then
  raw "stunnel config"
  grep -hE '^\s*(verify|verifyChain|verifyPeer|CAfile|cert|key|checkHost|checkIP|sslVersion|ciphers|client|accept|connect)' "$LSA_ROOT"/etc/stunnel/*.conf 2>/dev/null
  grep -qhE '^\s*(verifyChain|verifyPeer)\s*=\s*yes' "$LSA_ROOT"/etc/stunnel/*.conf 2>/dev/null \
    && chk mtls.stunnel PASS "verifyChain/verifyPeer yes" "" \
    || chk mtls.stunnel FAIL "no verifyChain/verifyPeer" "stunnel does NOT verify the peer certificate by default: the tunnel is encrypted but unauthenticated"
fi

# databases
if ls "$(rf /etc/mysql/)" "$(rf /etc/my.cnf.d/)" "$(rf /etc/my.cnf)" >/dev/null 2>&1; then
  MYC="$(grep -rhE '^\s*(ssl|ssl_ca|ssl_cert|ssl_key|ssl_cipher|tls_version|require_secure_transport)' "$(rf /etc/mysql/)" "$(rf /etc/my.cnf)" "$(rf /etc/my.cnf.d/)" 2>/dev/null)"
  [ -n "$MYC" ] && { raw "mysql/mariadb TLS"; printf '%s\n' "$MYC"; }
  printf '%s' "$MYC" | grep -qiE 'require_secure_transport\s*=\s*(ON|1|true)' \
    && chk mtls.mysql PASS "require_secure_transport ON" "also confirm users are created with REQUIRE X509 for client-cert auth" \
    || { [ -n "$MYC" ] && chk mtls.mysql WARN "TLS configured but not required" "clients may still connect in plaintext; set require_secure_transport=ON and REQUIRE X509 per user"; }
  printf '%s' "$MYC" | grep -qiE 'tls_version' || [ -z "$MYC" ] || chk tls.mysql_version WARN "tls_version unset" "may still negotiate TLSv1/TLSv1.1"
fi
PGC="$(ls "$LSA_ROOT"/etc/postgresql/*/main/postgresql.conf "$(rf /var/lib/pgsql/data/postgresql.conf)" 2>/dev/null | head -1)"
if [ -n "$PGC" ]; then
  raw "postgresql TLS"
  grep -hE '^\s*(ssl|ssl_ca_file|ssl_cert_file|ssl_ciphers|ssl_min_protocol_version|ssl_prefer_server_ciphers)' "$PGC" 2>/dev/null
  PGHBA="$(dirname "$PGC")/pg_hba.conf"
  [ -r "$PGHBA" ] && { raw "pg_hba.conf (hostssl + clientcert)"; grep -vE '^\s*#|^\s*$' "$PGHBA" | cap 20; }
  if [ -r "$PGHBA" ]; then
    grep -qE '^\s*hostssl.*clientcert\s*=\s*verify-full' "$PGHBA" 2>/dev/null \
      && chk mtls.postgres PASS "hostssl clientcert=verify-full" "" \
      || { grep -qE '^\s*host\s' "$PGHBA" 2>/dev/null && chk mtls.postgres WARN "plain 'host' entries present" "connections allowed without TLS or without client-certificate verification; use hostssl + clientcert=verify-full for internal links"; }
  fi
fi
if [ -r "$(rf /etc/mongod.conf)" ]; then
  raw "mongodb TLS"; grep -A12 -E '^\s*net:' "$(rf /etc/mongod.conf)" 2>/dev/null | grep -E 'tls|ssl|mode|CAFile|allowConnections'
  grep -qE 'allowConnectionsWithoutCertificates:\s*true' "$(rf /etc/mongod.conf)" 2>/dev/null \
    && chk mtls.mongodb FAIL "allowConnectionsWithoutCertificates: true" "client certificates are requested but optional: mTLS is not enforced"
  grep -qE 'mode:\s*requireTLS' "$(rf /etc/mongod.conf)" 2>/dev/null && grep -qE 'CAFile:' "$(rf /etc/mongod.conf)" 2>/dev/null \
    && chk mtls.mongodb_mode PASS "requireTLS + CAFile" ""
fi
if [ -r "$(rf /etc/redis/redis.conf)" ] || [ -r "$(rf /etc/redis.conf)" ]; then
  raw "redis TLS"; grep -hE '^\s*(port|tls-port|tls-cert-file|tls-ca-cert-file|tls-auth-clients|tls-protocols|tls-ciphers|requirepass)' "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null
  if grep -qhE '^\s*tls-port\s+[1-9]' "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null; then
    grep -qhE '^\s*tls-auth-clients\s+(no|optional)' "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null \
      && chk mtls.redis FAIL "tls-auth-clients no/optional" "Redis defaults to REQUIRING client certs; this config disables that" \
      || chk mtls.redis PASS "tls-auth-clients default (yes)" ""
  fi
  grep -qhE '^\s*port\s+0' "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null \
    || { grep -qhE '^\s*tls-port' "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null && chk tls.redis_plaintext FAIL "plaintext port still enabled alongside tls-port" "set 'port 0' to force TLS"; }
fi
# etcd / kubelet
if ps -eo args 2>/dev/null | grep -q '[e]tcd'; then
  raw "etcd TLS flags"; ps -eo args 2>/dev/null | grep '[e]tcd' | tr ' ' '\n' | grep -E '^--(cert|key|trusted-ca|client-cert-auth|peer-|auto-tls)' | sort -u
  ps -eo args 2>/dev/null | grep '[e]tcd' | grep -q -- '--client-cert-auth' \
    && chk mtls.etcd PASS "--client-cert-auth" "" \
    || chk mtls.etcd FAIL "no --client-cert-auth" "etcd holds cluster secrets and accepts any TLS client"
  ps -eo args 2>/dev/null | grep '[e]tcd' | grep -q -- '--peer-client-cert-auth' \
    || chk mtls.etcd_peer FAIL "no --peer-client-cert-auth" "peer connections not mutually authenticated"
fi
# openvpn / wireguard
if ls "$LSA_ROOT"/etc/openvpn/*.conf "$LSA_ROOT"/etc/openvpn/*/*.conf >/dev/null 2>&1; then
  raw "openvpn TLS"; grep -hE '^\s*(tls-auth|tls-crypt|remote-cert-tls|verify-x509-name|ns-cert-type|cipher|data-ciphers|auth|tls-version-min|verify-client-cert)' "$LSA_ROOT"/etc/openvpn/*.conf "$LSA_ROOT"/etc/openvpn/*/*.conf 2>/dev/null | sort -u
  grep -qhE '^\s*verify-client-cert\s+none' "$LSA_ROOT"/etc/openvpn/*.conf "$LSA_ROOT"/etc/openvpn/*/*.conf 2>/dev/null \
    && chk mtls.openvpn FAIL "verify-client-cert none" "client certificates not required"
  grep -qhE '^\s*(remote-cert-tls|verify-x509-name)' "$LSA_ROOT"/etc/openvpn/*.conf "$LSA_ROOT"/etc/openvpn/*/*.conf 2>/dev/null \
    && chk mtls.openvpn_peer PASS "remote-cert-tls/verify-x509-name set" "" \
    || chk mtls.openvpn_peer WARN "no remote-cert-tls / verify-x509-name" "client accepts any cert signed by the CA, including another client's: enables client-impersonates-server MITM"
  grep -qhE '^\s*tls-version-min\s+1\.2' "$LSA_ROOT"/etc/openvpn/*.conf "$LSA_ROOT"/etc/openvpn/*/*.conf 2>/dev/null \
    || chk tls.openvpn_version WARN "tls-version-min not 1.2+" ""
fi
# mail / ldap
if [ -r "$(rf /etc/postfix/main.cf)" ]; then
  raw "postfix TLS"; grep -hE '^\s*smtp(d)?_tls_(security_level|mandatory_protocols|protocols|mandatory_ciphers|ciphers|CAfile|cert_file|key_file|ask_ccert|req_ccert)' "$(rf /etc/postfix/main.cf)" 2>/dev/null
  grep -qE '^\s*smtp_tls_security_level\s*=\s*(verify|secure)' "$(rf /etc/postfix/main.cf)" 2>/dev/null \
    && chk mtls.postfix_out PASS "outbound security_level verify/secure" "" \
    || chk mtls.postfix_out INFO "outbound TLS opportunistic (may)" "certificate not validated on outbound relay: acceptable for public MX, not for an internal relay"
fi
if [ -r "$(rf /etc/openldap/ldap.conf)" ] || [ -r "$(rf /etc/ldap/ldap.conf)" ]; then
  raw "ldap client TLS"; grep -hE '^\s*(TLS_REQCERT|TLS_CACERT|TLS_CIPHER_SUITE|TLS_PROTOCOL_MIN)' "$(rf /etc/openldap/ldap.conf)" "$(rf /etc/ldap/ldap.conf)" 2>/dev/null
  grep -qhiE '^\s*TLS_REQCERT\s+(never|allow|try)' "$(rf /etc/openldap/ldap.conf)" "$(rf /etc/ldap/ldap.conf)" 2>/dev/null \
    && chk mtls.ldap FAIL "TLS_REQCERT not 'demand'" "LDAP server certificate is not validated: credentials can be captured by an impersonator"
fi

# ---- TLS verification switched OFF on the client side (very common, very quiet) ----
raw "TLS/certificate verification disabled in scripts, units and env"
INSECURE_RE='curl[^|]*(-k|--insecure)|wget[^|]*--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*.?0|PYTHONHTTPSVERIFY\s*=\s*.?0|GIT_SSL_NO_VERIFY|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER[^;]*(false|0)|InsecureSkipVerify\s*:\s*true|check_certificate\s*=\s*off|ssl_verify\s*=\s*(false|none)|sslverify\s*=\s*(false|0)'
# bounded file list: depth- and size-capped so this never walks a large /opt or /usr/local tree
CANDFILES="$(tmo 30 find "$(rf /etc/cron.d)" "$(rf /etc/cron.daily)" "$(rf /etc/cron.hourly)" "$(rf /etc/cron.weekly)" "$(rf /etc/cron.monthly)" \
      /etc/systemd/system /etc/profile.d /usr/local/bin /usr/local/sbin /opt \
      -maxdepth 3 -type f -size -256k 2>/dev/null | head -500)"
for f in "$LSA_ROOT"/etc/crontab "$LSA_ROOT"/etc/environment "$LSA_ROOT"/root/.curlrc "$LSA_ROOT"/etc/curlrc "$LSA_ROOT"/root/.wgetrc "$LSA_ROOT"/etc/wgetrc "$LSA_ROOT"/etc/gitconfig "$LSA_ROOT"/root/.gitconfig; do
  [ -f "$f" ] && CANDFILES="$CANDFILES
$f"
done
INSECURE="$(printf '%s\n' "$CANDFILES" | grep -v '^$' | tr '\n' '\0' \
            | tmo 40 xargs -0 grep -lIsE "$INSECURE_RE" 2>/dev/null | head -30)"
if [ -n "$INSECURE" ]; then
  printf '%s\n' "$INSECURE"
  printf '%s\n' "$INSECURE" | while read -r f; do
    [ -f "$f" ] && grep -nIsE "$INSECURE_RE" "$f" 2>/dev/null | head -3 | sed "s|^|  $f:|"
  done
  chk tls.verification_disabled FAIL "$(printf '%s' "$INSECURE" | tr '\n' ' ' | cut -c1-200)" "certificate verification switched off: the TLS in these paths provides encryption but NO authentication, so any on-path attacker can substitute themselves"
else
  chk tls.verification_disabled PASS "none found" ""
fi

raw "system CA trust store"
ls -l "$(rf /etc/ssl/certs/ca-certificates.crt)" "$(rf /etc/pki/tls/certs/ca-bundle.crt)" 2>/dev/null
have update-ca-certificates && ls -la "$(rf /usr/local/share/ca-certificates/)" 2>/dev/null
ls -la "$(rf /etc/pki/ca-trust/source/anchors/)" 2>/dev/null
CUSTOMCA="$(ls "$LSA_ROOT"/usr/local/share/ca-certificates/*.crt "$LSA_ROOT"/etc/pki/ca-trust/source/anchors/* 2>/dev/null | wc -l)"
[ "${CUSTOMCA:-0}" -gt 0 ] && chk tls.custom_ca WARN "${CUSTOMCA} locally added CA(s)" "each added root CA can mint a trusted certificate for ANY domain: enumerate and justify every one; this is also a known persistence/interception technique"

fi  # end openssl-present

# -------------------------------------------------------------- 17. PACKAGES
sec PACKAGES
if have dpkg-query; then
  raw "package count"; dpkg-query -f '${binary:Package}\n' -W 2>/dev/null | wc -l
  raw "manually installed packages"; have apt-mark && run apt-mark showmanual | tr '\n' ' '
  echo
  raw "pending updates"; run apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | cap 60
  PEND="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
  SECU="$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci 'security')"
  [ "${SECU:-0}" -gt 0 ] && chk packages.security_updates FAIL "$SECU pending" "known-vulnerable packages installed" \
                         || chk packages.security_updates PASS "0 security / ${PEND:-0} total pending" ""
  raw "unattended-upgrades"
  [ -r "$(rf /etc/apt/apt.conf.d/20auto-upgrades)" ] && cat "$(rf /etc/apt/apt.conf.d/20auto-upgrades)"
  if [ -n "$CTR" ]; then
    chk packages.auto_updates NA "container image" "in-place auto-patching is the wrong control for an image: the container is replaced on the next deploy, so patching belongs to the rebuild pipeline and a base-image refresh, not to unattended-upgrades inside the image"
  else
  grep -rqs 'Unattended-Upgrade::Allowed-Origins\|Origins-Pattern' "$(rf /etc/apt/apt.conf.d/50unattended-upgrades)" 2>/dev/null \
    && chk packages.auto_updates PASS configured "" || chk packages.auto_updates WARN "not configured" "security patches are not applied automatically"
  fi
  raw "apt sources using plain http"
  grep -rhE '^\s*(deb|URIs)' "$(rf /etc/apt/sources.list)" "$(rf /etc/apt/sources.list.d/)" 2>/dev/null | grep -c 'http://' | sed 's/^/http_sources=/'
  raw "apt sandbox"
  grep -rhs 'Sandbox' "$(rf /etc/apt/apt.conf.d/)" 2>/dev/null
  have debsecan && { raw "debsecan (known CVEs)"; run debsecan --suite "$(lsb_release -cs 2>/dev/null)" --format summary 2>/dev/null | cap 30; }
elif have rpm; then
  raw "package count"; rpm -qa 2>/dev/null | wc -l
  raw "installed packages"; rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort | tr '\n' ' '
  echo
  raw "pending security updates"
  have dnf && run dnf -q updateinfo list security 2>/dev/null | cap 40
  have yum && ! have dnf && run yum -q updateinfo list security 2>/dev/null | cap 40
  # full verification runs once, in the INTEGRITY section, not duplicated here
  raw "automatic updates"
  have systemctl && run systemctl is-enabled dnf-automatic.timer yum-cron 2>/dev/null
elif have apk; then
  raw "package count"; apk info 2>/dev/null | wc -l
  raw "installed"; apk info 2>/dev/null | tr '\n' ' '
fi
# ---- repository trust: are packages signature-verified before install? ----
raw "REPOSITORY SIGNATURE VERIFICATION"

# --- RPM / dnf / yum ---
if [ -d "$(rf /etc/yum.repos.d)" ] || [ -r "$(rf /etc/dnf/dnf.conf)" ] || [ -r "$(rf /etc/yum.conf)" ]; then
  raw "global gpgcheck settings (/etc/dnf/dnf.conf, /etc/yum.conf)"
  grep -hE '^\s*(gpgcheck|localpkg_gpgcheck|repo_gpgcheck|sslverify|skip_if_unavailable)\s*=' \
       /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null

  conf_get() { grep -hE "^\s*$1\s*=" "$(rf /etc/dnf/dnf.conf)" "$(rf /etc/yum.conf)" 2>/dev/null | tail -1 | tr -d '[:space:]' | cut -d= -f2; }
  G="$(conf_get gpgcheck)"
  case "$G" in
    1) chk repo.global_gpgcheck PASS "gpgcheck=1" "" ;;
    "") chk repo.global_gpgcheck WARN "unset" "dnf's built-in default is 1, but relying on it is fragile and per-repo settings still override; set it explicitly in dnf.conf [main]" ;;
    *) chk repo.global_gpgcheck FAIL "gpgcheck=$G" "packages are installed WITHOUT signature verification: a compromised mirror or MITM installs arbitrary root-run code" ;;
  esac
  L="$(conf_get localpkg_gpgcheck)"
  case "$L" in
    1) chk repo.localpkg_gpgcheck PASS "localpkg_gpgcheck=1" "" ;;
    *) chk repo.localpkg_gpgcheck WARN "${L:-unset (default 0)}" "locally supplied .rpm files are installed unverified" ;;
  esac
  R="$(conf_get repo_gpgcheck)"
  case "$R" in
    1) chk repo.repo_gpgcheck PASS "repo_gpgcheck=1" "" ;;
    *) chk repo.repo_gpgcheck INFO "${R:-unset (default 0)}" "repository *metadata* signature is not verified: package signatures still are; enable where the repo signs its metadata" ;;
  esac

  raw "per-repository settings in /etc/yum.repos.d/ (per-repo values OVERRIDE the global)"
  if ls "$LSA_ROOT"/etc/yum.repos.d/*.repo >/dev/null 2>&1; then
    awk '
      function flush() {
        if (sec != "")
          printf "%-40s [%s] enabled=%s gpgcheck=%s repo_gpgcheck=%s gpgkey=%s sslverify=%s url=%s\n",
                 FILENAME, sec, (en==""?"1(default)":en), (gc==""?"unset(inherit)":gc),
                 (rgc==""?"unset":rgc), (gk==""?"NONE":"set"), (sv==""?"unset":sv), (url==""?"-":url)
      }
      /^[[:space:]]*\[/ { flush(); sec=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/,"",sec); en="";gc="";rgc="";gk="";sv="";url=""; next }
      /^[[:space:]]*enabled[[:space:]]*=/       { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); en=a[2] }
      /^[[:space:]]*gpgcheck[[:space:]]*=/      { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); gc=a[2] }
      /^[[:space:]]*repo_gpgcheck[[:space:]]*=/ { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); rgc=a[2] }
      /^[[:space:]]*gpgkey[[:space:]]*=/        { gk="set" }
      /^[[:space:]]*sslverify[[:space:]]*=/     { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); sv=a[2] }
      /^[[:space:]]*(baseurl|metalink|mirrorlist)[[:space:]]*=/ { split($0,a,"="); u=a[2]; gsub(/[[:space:]]/,"",u); if (url=="") url=substr(u,1,60) }
      END { flush() }
    ' /etc/yum.repos.d/*.repo 2>/dev/null

    # any ENABLED repo with gpgcheck=0 is the finding
    BAD="$(awk '
      /^[[:space:]]*\[/ { sec=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/,"",sec); en="1"; gc="" ; next }
      /^[[:space:]]*enabled[[:space:]]*=/  { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); en=a[2] }
      /^[[:space:]]*gpgcheck[[:space:]]*=/ { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); gc=a[2];
                                             if (gc=="0" && en!="0") print FILENAME"["sec"]" }
    ' /etc/yum.repos.d/*.repo 2>/dev/null | tr '\n' ' ')"
    if [ -n "$BAD" ]; then
      chk repo.per_repo_gpgcheck FAIL "$BAD" "these ENABLED repositories install packages without checking the GPG signature"
    else
      chk repo.per_repo_gpgcheck PASS "no enabled repo sets gpgcheck=0" ""
    fi

    # enabled repos with no gpgkey= and no inherited key are unverifiable in practice
    NOKEY="$(awk '
      /^[[:space:]]*\[/ { if (sec!="" && en!="0" && gk=="" ) print FILENAME"["sec"]"; sec=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/,"",sec); en="1"; gk=""; next }
      /^[[:space:]]*enabled[[:space:]]*=/ { split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); en=a[2] }
      /^[[:space:]]*gpgkey[[:space:]]*=/  { gk="set" }
      END { if (sec!="" && en!="0" && gk=="") print FILENAME"["sec"]" }
    ' /etc/yum.repos.d/*.repo 2>/dev/null | tr '\n' ' ')"
    [ -n "$NOKEY" ] && chk repo.gpgkey_missing WARN "$NOKEY" "no gpgkey=: verification can only work if the key is already in the RPM keyring"

    # plaintext transport to the mirror
    HTTPREPO="$(grep -hE '^\s*(baseurl|metalink|mirrorlist)\s*=\s*http://' "$LSA_ROOT"/etc/yum.repos.d/*.repo 2>/dev/null | wc -l)"
    [ "${HTTPREPO:-0}" -gt 0 ] && chk repo.http_transport WARN "$HTTPREPO plaintext URL(s)" "signatures still protect integrity, but plaintext leaks the exact package set and enables downgrade/freeze attacks" \
                               || chk repo.http_transport PASS "all https" ""
    SSLOFF="$(grep -hE '^\s*sslverify\s*=\s*(0|False|false)' "$LSA_ROOT"/etc/yum.repos.d/*.repo 2>/dev/null | wc -l)"
    [ "${SSLOFF:-0}" -gt 0 ] && chk repo.sslverify FAIL "$SSLOFF repo(s) with sslverify=0" "TLS certificate of the mirror is not validated"
  fi

  raw "imported RPM GPG keys"
  have rpm && rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\n' 2>/dev/null
  KN="$(rpm -q gpg-pubkey 2>/dev/null | grep -vc 'not installed')"
  chk repo.imported_keys INFO "${KN:-0} key(s) in the RPM keyring" "each is a party trusted to ship root-run code; remove keys for repos you no longer use"
fi

# --- APT / Debian / Ubuntu ---
if [ -d "$(rf /etc/apt)" ]; then
  raw "apt sources (one-line and deb822)"
  grep -rhE '^\s*(deb|deb-src)\s' "$(rf /etc/apt/sources.list)" "$LSA_ROOT"/etc/apt/sources.list.d/*.list 2>/dev/null
  grep -rhE '^\s*(Types|URIs|Suites|Components|Signed-By|Trusted|Enabled):' "$LSA_ROOT"/etc/apt/sources.list.d/*.sources "$(rf /etc/apt/sources.list)" 2>/dev/null

  # [trusted=yes] disables signature verification entirely for that source
  TRUSTED="$(grep -rhE '^\s*deb.*\[[^]]*trusted\s*=\s*yes' "$(rf /etc/apt/sources.list)" "$(rf /etc/apt/sources.list.d/)" 2>/dev/null)"
  TRUSTED2="$(grep -rhiE '^\s*Trusted:\s*yes' "$LSA_ROOT"/etc/apt/sources.list.d/*.sources 2>/dev/null)"
  if [ -n "$TRUSTED$TRUSTED2" ]; then
    chk repo.apt_trusted_yes FAIL "$(printf '%s %s' "$TRUSTED" "$TRUSTED2" | tr '\n' ';' | cut -c1-200)" "trusted=yes is the APT equivalent of gpgcheck=0: packages from this source are installed with NO signature verification"
  else
    chk repo.apt_trusted_yes PASS "no trusted=yes source" ""
  fi

  # allow-insecure / allow-downgrade
  AI="$(grep -rhE 'allow-insecure\s*=\s*yes|allow-downgrade-to-insecure\s*=\s*yes' "$(rf /etc/apt/sources.list)" "$(rf /etc/apt/sources.list.d/)" 2>/dev/null)"
  [ -n "$AI" ] && chk repo.apt_allow_insecure FAIL "$(printf '%s' "$AI" | tr '\n' ';' | cut -c1-160)" "unsigned/insecure repositories explicitly permitted"

  # apt.conf overrides that globally disable verification
  raw "apt.conf settings affecting verification"
  grep -rhE 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|Check-Valid-Until|Verify-Peer|Verify-Host' \
       /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null
  if grep -rqiE '(AllowUnauthenticated|AllowInsecureRepositories)\s*"?true' "$(rf /etc/apt/apt.conf)" "$(rf /etc/apt/apt.conf.d/)" 2>/dev/null; then
    chk repo.apt_unauthenticated FAIL "AllowUnauthenticated/AllowInsecureRepositories true" "signature verification globally disabled for apt"
  else
    chk repo.apt_unauthenticated PASS "not disabled" ""
  fi
  if grep -rqiE 'Verify-Peer\s*"?false|Verify-Host\s*"?false' "$(rf /etc/apt/apt.conf)" "$(rf /etc/apt/apt.conf.d/)" 2>/dev/null; then
    chk repo.apt_tls_verify FAIL "Acquire::https::Verify-Peer/Host false" "TLS certificate validation disabled for package downloads"
  fi

  # third-party sources should pin their key with Signed-By, not the global keyring
  THIRD="$(ls "$(rf /etc/apt/sources.list.d/)" 2>/dev/null | wc -l)"
  NOSIGNEDBY="$(grep -rLE 'signed-by|Signed-By' "$LSA_ROOT"/etc/apt/sources.list.d/*.list "$LSA_ROOT"/etc/apt/sources.list.d/*.sources 2>/dev/null | tr '\n' ' ')"
  if [ -n "$NOSIGNEDBY" ]; then
    chk repo.apt_signed_by WARN "$NOSIGNEDBY" "third-party source without signed-by=: its key is trusted for EVERY repository, so that vendor can sign a replacement for any distro package"
  else
    chk repo.apt_signed_by PASS "all third-party sources scoped with signed-by" "${THIRD} file(s) in sources.list.d"
  fi

  raw "apt trusted keyrings"
  ls -la "$(rf /etc/apt/trusted.gpg)" "$(rf /etc/apt/trusted.gpg.d/)" "$(rf /etc/apt/keyrings/)" "$(rf /usr/share/keyrings/)" 2>/dev/null
  if [ -s "$(rf /etc/apt/trusted.gpg)" ]; then
    chk repo.apt_legacy_keyring WARN "/etc/apt/trusted.gpg non-empty" "legacy apt-key keyring: every key in it is trusted for every repository (deprecated since apt 2.4); migrate to per-source signed-by keyrings"
  fi
  raw "keys and expiry"
  if have gpg; then
    for kr in "$LSA_ROOT"/etc/apt/trusted.gpg "$LSA_ROOT"/etc/apt/trusted.gpg.d/*.gpg "$LSA_ROOT"/etc/apt/keyrings/*.gpg "$LSA_ROOT"/etc/apt/keyrings/*.asc; do
      [ -s "$kr" ] || continue
      printf '\n[%s]\n' "$kr"
      gpg --no-default-keyring --keyring "$kr" --list-keys --with-colons 2>/dev/null \
        | awk -F: '$1=="pub"{printf "  %s exp=%s %s\n", $5, ($7==""?"never":$7), ($2=="e"?"EXPIRED":"")}'
    done
  fi
  raw "sources using plaintext http"
  APTHTTP="$(grep -rhE '^\s*(deb|deb-src)\s+(\[[^]]*\]\s+)?http://|^\s*URIs:\s*http://' "$(rf /etc/apt/sources.list)" "$(rf /etc/apt/sources.list.d/)" 2>/dev/null)"
  printf '%s\n' "$APTHTTP" | cap 20
  NHTTP="$(printf '%s' "$APTHTTP" | grep -c .)"
  if [ "${NHTTP:-0}" -gt 0 ]; then
    chk repo.apt_http FAIL "${NHTTP} source(s) over plaintext http://" "package signatures protect integrity, so this is not remote code execution on its own, but plaintext still lets an on-path observer read your EXACT package and version inventory (a ready-made list of which CVEs apply to this host), and lets them mount freeze/replay attacks by serving a stale Release file to withhold security updates until Valid-Until expires. Every major distro serves HTTPS; switch the URIs"
  else
    chk repo.apt_http PASS "all apt sources use https" ""
  fi
  raw "apt verification self-test (does update report any unsigned repo?)"
  # `apt-get update` REFRESHES /var/lib/apt/lists: the only thing in this collector that
  # writes to the system. Off by default; enable with --apt-update when a stale-signature
  # check is worth the cache refresh.
  if [ "$APTUPDATE" = "1" ] && [ "$AM_ROOT" = "1" ] && have apt-get; then
    active_on
    run apt-get -o Debug::NoLocking=1 -qq update 2>&1 | grep -iE 'NO_PUBKEY|not signed|InRelease|signature|EXPKEYSIG|Insufficient' | cap 10
    active_off
  else
    chk repo.apt_signature_selftest NA "not run" "verifying that every repo is signed requires 'apt-get update', which refreshes /var/lib/apt/lists. Pass --apt-update to include it; otherwise this is inferred from configuration only"
  fi
fi

# --- other package managers ---
if have apk; then
  raw "apk repositories + keys"
  cat "$(rf /etc/apk/repositories)" 2>/dev/null
  ls "$(rf /etc/apk/keys/)" 2>/dev/null
  grep -q -- '--allow-untrusted' "$LSA_ROOT"/etc/apk/* 2>/dev/null && chk repo.apk_untrusted FAIL "--allow-untrusted present" "signature checks bypassed"
fi
if have zypper; then
  raw "zypper repositories (gpgcheck per repo)"
  run zypper --non-interactive lr -d 2>/dev/null | cap 40
fi
raw "language package managers pulling code at build/run time"
ls "$(rf /etc/pip.conf)" ~/.pip/pip.conf "$(rf /etc/npmrc)" ~/.npmrc "$(rf /etc/gemrc)" 2>/dev/null
grep -rhsE 'trusted-host|strict-ssl\s*=\s*false|insecure' "$(rf /etc/pip.conf)" "$(rf /etc/npmrc)" ~/.npmrc 2>/dev/null

# ---- attack-surface inventory: every installed package is code that can carry a CVE ----
raw "PACKAGE ATTACK SURFACE"
PKGN=0
# Offline: query the IMAGE's package database, not the auditing host's. Without this,
# packages.count is 0 and every package-derived check silently becomes a no-op.
RPMOPT=""; DPKGOPT=""
if [ "$OFFLINE" = "1" ]; then
  [ -d "$(rf /var/lib/rpm)" ] && RPMOPT="--dbpath $(rf /var/lib/rpm)"
  [ -d "$(rf /var/lib/dpkg)" ] && DPKGOPT="--admindir=$(rf /var/lib/dpkg)"
fi
if have dpkg-query && { [ "$OFFLINE" = "0" ] || [ -n "$DPKGOPT" ]; }; then
  PKGN="$(dpkg-query $DPKGOPT -f '${binary:Package}\n' -W 2>/dev/null | wc -l | tr -d ' ')"
elif have rpm && { [ "$OFFLINE" = "0" ] || [ -n "$RPMOPT" ]; }; then
  PKGN="$(rpm $RPMOPT -qa 2>/dev/null | wc -l | tr -d ' ')"
elif have apk; then PKGN="$(apk info 2>/dev/null | wc -l | tr -d ' ')"; fi
[ "$OFFLINE" = "1" ] && chk packages.offline_db INFO "rpm='${RPMOPT:-n/a}' dpkg='${DPKGOPT:-n/a}'" "package queries are directed at the mounted image's database"
# rough reference points: debootstrap minbase ~120, minimal server ~350, default server ~600,
# anything with a desktop >1200. The number is only a prompt to ask "why".
if [ "${PKGN:-0}" = "0" ]; then
  chk packages.count NA "no packages enumerated" "the package database was not read: rpm/dpkg absent, or an offline tree needing 'rpm --dbpath <root>/var/lib/rpm' / 'dpkg --root'. Zero packages is a COLLECTION FAILURE, not a minimal system, and every package-derived check (prohibited tooling, imported keys, orphans) is therefore NA rather than clean"
elif [ "${PKGN:-0}" -gt 1200 ]; then
  chk packages.count WARN "$PKGN packages" "far more than a server needs (a minimal Debian is ~350, a default server install ~600). Each package is code that can carry a CVE and generate patch work. Consider a minimal base image"
else
  chk packages.count INFO "$PKGN packages" "reference: minbase ~120, minimal server ~350, default server ~600, desktop >1200"
fi

# --- packages NOT provided by any configured repository: these never get security updates ---
raw "packages with no candidate in any configured repository (orphaned / locally installed)"
# apt-cache has no offline mode: it answers from the auditing host's lists no matter what
# --admindir the query used, so the whole comparison is meaningless against a mounted image.
if [ "$OFFLINE" = "1" ]; then
  chk packages.orphaned NA "repository candidates are not determinable offline" "apt-cache/dnf answer from the auditing host's repository metadata, not the image's; check this on the booted instance"
elif have apt-cache && have dpkg-query; then
  # One apt-cache call per package meant up to 800 forks here, unbounded and not covered by
  # --quick, which is enough to make the whole run look like it has hung. apt-cache policy takes
  # a package list, so xargs turns that into one or two invocations.
  ORPH="$(dpkg-query ${DPKGOPT:-} -f '${binary:Package}\n' -W 2>/dev/null | head -800 \
          | tmo 120 xargs -r apt-cache policy 2>/dev/null \
          | awk '/^[^[:space:]][^:]*:$/ { pk=substr($0,1,length($0)-1) }
                 /Candidate:/ { if ($2=="(none)") printf "%s ", pk }')"
  if [ -n "$ORPH" ]; then
    chk packages.orphaned FAIL "$(printf '%s' "$ORPH" | cut -c1-200)" "installed but no repository offers them any more: a locally installed .deb, or a PPA/vendor repo that was removed. These receive NO security updates and no CVE feed covers them. Either restore the repo or remove the package"
  else
    chk packages.orphaned PASS "every installed package has a repository candidate" ""
  fi
  raw "packages held back from upgrades"
  apt-mark showhold 2>/dev/null | cap 10
  HELD="$(apt-mark showhold 2>/dev/null | wc -l | tr -d ' ')"
  [ "${HELD:-0}" -gt 0 ] && chk packages.held WARN "${HELD} package(s) on hold" "held packages are excluded from security updates; confirm each hold is still justified"
elif have dnf && [ "$OFFLINE" = "0" ]; then
  raw "packages not in any repository (dnf repoquery --extras)"
  # Run once and reuse: the second, unbounded call doubled the cost of the slowest query in
  # this section on a host with a large repo set.
  DNFX="$(run dnf -q repoquery --extras 2>/dev/null)"; DNFRC=$?
  printf '%s\n' "$DNFX" | cap 20
  EXTRA="$(printf '%s\n' "$DNFX" | grep -c .)"
  if [ "$DNFRC" != "0" ]; then
    # No network, no subscription, or a broken repo config. Whatever the reason, the question
    # "is any installed package absent from every repository" was not answered.
    chk packages.orphaned NA "dnf repoquery failed (rc=$DNFRC)" "the repositories could not be queried, so orphaned packages are not determinable. Common inside a container run without network, or on an unsubscribed RHEL host"
    EXTRA=-1
  fi
  [ "${EXTRA:-0}" -gt 0 ] && chk packages.orphaned FAIL "${EXTRA} package(s) not provided by any repo" "no security updates reach these"
  [ "${EXTRA:-0}" = "0" ] && chk packages.orphaned PASS "every installed package is provided by a repository" ""
fi

# --- removed-but-not-purged (Debian): config, and sometimes data, left behind ---
if have dpkg-query; then
  RC="$(dpkg-query -f '${db:Status-Abbrev} ${binary:Package}\n' -W 2>/dev/null | awk '/^rc/{print $2}' | tr '\n' ' ')"
  [ -n "$RC" ] && chk packages.not_purged INFO "$(printf '%s' "$RC" | cut -c1-160)" "removed but not purged: configuration files remain, sometimes including credentials. 'apt purge' to clear"
fi

# --- what an administrator deliberately added: the real review list ---
raw "manually installed packages (the deliberate additions; review these, not the base system)"
have apt-mark && apt-mark showmanual 2>/dev/null | tr '\n' ' ' | fold -w 160 | cap 10
have dnf && run dnf -q repoquery --userinstalled 2>/dev/null | cap 30

# --- toolchains and dual-use tooling that do not belong on a production server ---
raw "build toolchains, network tooling and interpreters present"
SURFACE=""
for p in gcc g++ clang make cmake automake autoconf binutils gdb strace ltrace \
         nmap netcat netcat-openbsd netcat-traditional ncat socat tcpdump wireshark tshark \
         nikto sqlmap john hashcat hydra masscan \
         python3-dev libc6-dev linux-headers-generic dkms \
         wget curl git subversion mercurial rsync \
         perl python3 ruby php-cli nodejs golang rustc; do
  if have dpkg-query; then dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && SURFACE="$SURFACE $p"
  elif have rpm; then rpm -q "$p" >/dev/null 2>&1 && SURFACE="$SURFACE $p"; fi
done
[ -n "$SURFACE" ] && printf '  %s\n' "$SURFACE"
OFFENSIVE=""
for p in nmap masscan nikto sqlmap john hashcat hydra wireshark tshark; do
  case " $SURFACE " in *" $p "*) OFFENSIVE="$OFFENSIVE $p" ;; esac
done
[ -n "$OFFENSIVE" ] && chk packages.offensive_tooling WARN "$OFFENSIVE" "security testing tools installed on this host: legitimate on a pentest workstation, a finding on a production server, where they save an attacker the trouble of bringing their own"

# For dual-use tools the presence of the binary is the weak signal. What decides whether a
# NON-ROOT attacker can use it is its capabilities or SUID bit: a root-only tcpdump adds
# little (an attacker who is already root does not need it); a tcpdump with cap_net_raw
# hands packet capture to any user who can execute it.
raw "dual-use tools: who can actually run them"
DUALCAP=""
for b in /usr/sbin/tcpdump /usr/bin/tcpdump /usr/bin/dumpcap /usr/bin/wireshark /usr/bin/nmap \
         /usr/bin/ping /usr/bin/gdb /usr/bin/strace /usr/bin/ltrace /usr/sbin/tshark; do
  [ -f "$b" ] || continue
  m="$(stat -c '%a %U:%G' "$b" 2>/dev/null)"
  c="$(getcap "$b" 2>/dev/null | sed 's/^[^ ]* //')"
  printf '  %-24s %s%s\n' "$b" "$m" "${c:+  caps=$c}"
  mode="${m%% *}"; grp="$(printf '%s' "$m" | awk '{print $2}' | cut -d: -f2)"
  if [ -n "$c" ]; then
    DUALCAP="$DUALCAP $b(caps=$c)"
  elif [ "${#mode}" = "4" ] && printf '%s' "$mode" | cut -c1 | grep -qE '[2467]'; then
    DUALCAP="$DUALCAP $b(setuid/setgid $mode)"
  else
    # group-executable by a NON-root group that actually has members = a deliberate delegation
    case "$grp" in
      root|wheel|"") ;;
      *) if printf '%s' "$mode" | cut -c2 | grep -qE '[1357]'; then
           getent group "$grp" 2>/dev/null | cut -d: -f4 | grep -q '[a-z]' && DUALCAP="$DUALCAP $b(group $grp can execute, $mode)"
         fi ;;
    esac
  fi
done
if [ -n "$DUALCAP" ]; then
  chk packages.dualuse_reachable FAIL "$DUALCAP" "these carry file capabilities, are setuid/setgid, or are delegated to a non-root group, so a NON-ROOT user can use them with privilege. tcpdump/dumpcap with cap_net_raw gives any such user full packet capture: credentials from every cleartext protocol on the segment, plus internal reconnaissance. Fix with 'setcap -r', or 0750 root:adm, or uninstall"
else
  chk packages.dualuse_reachable PASS "no dual-use tool is privileged for non-root users" "aggravating detail only: the baseline finding is packages.prohibited, which requires these not to be installed at all. A root-only copy is less bad than a cap_net_raw one, but neither belongs on a hardened production host"
fi

# --- packages that must not be present on a hardened production host ---
# Baseline: absence, not restriction. Capabilities and modes can be re-added by root or by a
# package upgrade; a package that is not installed cannot be re-enabled, cannot carry a CVE,
# and does not need patching. CIS and DISA STIG both require removal of compilers on hardened
# profiles, and libpcap/tcpdump parse hostile network data as a privileged process.
MUSTNOT=""
for p in gcc g++ cpp clang tcc make binutils dkms libc6-dev linux-headers-generic build-essential \
         tcpdump dumpcap wireshark tshark wireshark-common nmap masscan netcat netcat-openbsd \
         netcat-traditional ncat socat gdb strace ltrace sqlmap nikto john hashcat hydra; do
  if have dpkg-query; then dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && MUSTNOT="$MUSTNOT $p"
  elif have rpm; then rpm -q "$p" >/dev/null 2>&1 && MUSTNOT="$MUSTNOT $p"
  elif have apk; then apk info -e "$p" >/dev/null 2>&1 && MUSTNOT="$MUSTNOT $p"; fi
done
# also catch a binary present without a package record (manually copied in).
# `have` resolves against the AUDITING host's PATH, so offline this would report the auditor's
# own toolchain as the image's. Look for the binary inside the tree instead.
BINPRESENT=""
for b in gcc cc clang tcpdump nmap socat gdb strace; do
  have_target "$b" || continue
  case " $MUSTNOT " in *" $b "*) ;; *) BINPRESENT="$BINPRESENT $b" ;; esac
done
if [ -n "$MUSTNOT$BINPRESENT" ]; then
  chk packages.prohibited FAIL "$MUSTNOT$BINPRESENT" "these must not be installed on a hardened production host. A compiler and headers let an attacker build a local privilege-escalation exploit in place instead of smuggling in a version-matched binary; tcpdump/wireshark parse attacker-supplied network data in a privileged process and carry their own CVE history (libpcap and the dissectors especially); the network and debugging tools save an attacker the work of bringing their own. Removal is the control: file modes and capabilities can be restored by root or reset by a package upgrade, but a package that is not installed cannot be re-enabled, cannot carry a CVE, and does not need patching"
else
  chk packages.prohibited PASS "no compilers, packet-capture or network/debug tooling installed" ""
fi
[ -n "$BINPRESENT" ] && chk packages.prohibited_unpackaged FAIL "$BINPRESENT" "present as a binary with no owning package: copied in by hand, so it is invisible to the package manager, receives no updates, and will not be removed by 'apt purge'. Locate with 'command -v' and delete, then find out how it arrived"
raw "how to operate without them (state this in the report next to the finding)"
cat <<'HOWTO'
  packet capture   : capture from a sidecar/ephemeral container sharing the netns
                     (docker run --rm --net=container:<id> ...; kubectl debug),
                     from a SPAN/mirror port on the switch, or from the hypervisor.
                     For connection state without capture: ss -tulpn, /proc/net/*, conntrack.
  compiling        : build on a dedicated build host or in CI and ship an artifact.
                     For DKMS/out-of-tree modules, build once elsewhere and install the
                     signed .ko: this also composes with module.sig_enforce=1.
  live debugging   : ephemeral debug container with the tools, sharing pid/net namespaces;
                     remove it afterwards. Keeps the tooling off the production image.
  if truly needed  : install-on-demand, then purge in the same maintenance window; never
                     leave it resident.
HOWTO
# --- snap / flatpak: a second, independently-updated software channel ---
if have snap; then raw "snap packages"; run snap list 2>/dev/null | cap 15
  SN="$(snap list 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
  [ "${SN:-0}" -gt 0 ] && chk packages.snap INFO "${SN} snap(s)" "snaps update on their own schedule outside apt/dnf, so distro patch reporting does not cover them"
fi
have flatpak && { raw "flatpak"; run flatpak list 2>/dev/null | cap 10; }
raw "language package managers with globally installed packages"
have pip3 && run pip3 list --user 2>/dev/null | cap 10
have npm && run npm ls -g --depth=0 2>/dev/null | cap 10
have gem && run gem list --local 2>/dev/null | cap 10

raw "risky / unnecessary packages present"
for p in telnet telnetd rsh-server rsh-client talk talkd ypbind ypserv tftp tftpd xinetd inetutils-inetd \
         nis rpcbind samba nfs-kernel-server avahi-daemon cups isc-dhcp-server slapd snmpd \
         squid apache2 nginx httpd sendmail postfix exim4 vsftpd proftpd bind9 named \
         xserver-xorg gdm3 lightdm; do
  if have dpkg-query; then dpkg-query -W -f='${Status} ${binary:Package}\n' "$p" 2>/dev/null | grep -q '^install ok installed' && echo "PRESENT: $p"
  elif have rpm; then rpm -q "$p" >/dev/null 2>&1 && echo "PRESENT: $p"; fi
done

# ------------------------------------------------------------------ 18. TIME
sec TIME
raw "timedatectl"
have timedatectl && run timedatectl
raw "time sync daemon"
have systemctl && run systemctl is-active systemd-timesyncd chronyd chrony ntp ntpd openntpd 2>/dev/null
[ "$PROBE" = "1" ] && have chronyc && { active_on; raw "chrony sources"; run chronyc -n sources; run chronyc tracking; active_off; }
[ "$PROBE" = "1" ] && have ntpq && { active_on; raw "ntpq"; run ntpq -pn; active_off; }
raw "timesyncd/chrony config (NTS = authenticated time)"
grep -rhvE '^\s*#|^\s*$' "$(rf /etc/systemd/timesyncd.conf)" "$(rf /etc/systemd/timesyncd.conf.d/)" "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" "$(rf /etc/ntp.conf)" 2>/dev/null
NTPCONF="$(grep -rhvE '^\s*#|^\s*$' "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" "$(rf /etc/ntp.conf)" "$(rf /etc/ntpsec/ntp.conf)" "$(rf /etc/systemd/timesyncd.conf)" "$(rf /etc/systemd/timesyncd.conf.d/)" 2>/dev/null)"

# --- authenticated time (NTS / symmetric keys) ---
if printf '%s' "$NTPCONF" | grep -qiE '(^|\s)nts\b|ntsdumpdir|NTS=yes'; then
  chk time.authenticated PASS "NTS configured" ""
elif printf '%s' "$NTPCONF" | grep -qiE '^\s*(keys|trustedkey|requestkey|controlkey)'; then
  chk time.authenticated WARN "symmetric NTP keys" "authenticated but pre-shared-key based; NTS is the modern option"
else
  chk time.authenticated WARN "unauthenticated NTP" "an on-path attacker can shift the clock: breaks cert expiry checks, TOTP, Kerberos, log ordering, and can expire or resurrect revoked credentials"
fi

# --- is this host an NTP *server* to the world? (amplification / reflection) ---
NTP_LISTEN_PUB=0
have ss && ss -ulnH 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\])' | grep -qE '[:.]123$' && NTP_LISTEN_PUB=1
if [ "$NTP_LISTEN_PUB" = "1" ]; then
  chk time.server_exposed WARN "udp/123 listening off-loopback" "this host answers NTP from the network: must be deliberate, and must not answer control/status queries (DDoS reflector)"
else
  chk time.server_exposed PASS "client-only (no public udp/123)" ""
fi

# --- ntpd: restrict lines, monlist/mode6-mode7 amplification ---
if [ -r "$(rf /etc/ntp.conf)" ] || [ -r "$(rf /etc/ntpsec/ntp.conf)" ]; then
  raw "ntpd restrict directives"
  grep -hE '^\s*restrict' "$(rf /etc/ntp.conf)" "$(rf /etc/ntpsec/ntp.conf)" 2>/dev/null
  RD="$(grep -hE '^\s*restrict\s+default' "$(rf /etc/ntp.conf)" "$(rf /etc/ntpsec/ntp.conf)" 2>/dev/null)"
  MISS=""
  for w in noquery nomodify notrap nopeer; do
    printf '%s' "$RD" | grep -q "$w" || MISS="$MISS $w"
  done
  if [ -z "$RD" ]; then
    chk time.ntpd_restrict FAIL "no 'restrict default' line" "ntpd answers queries from anyone: mode 6/7 and monlist are classic DDoS amplifiers (CVE-2013-5211)"
  elif [ -n "$MISS" ]; then
    chk time.ntpd_restrict FAIL "$RD" "missing:$MISS"
  else
    chk time.ntpd_restrict PASS "$RD" ""
  fi
  grep -qE '^\s*disable\s+monitor' "$(rf /etc/ntp.conf)" "$(rf /etc/ntpsec/ntp.conf)" 2>/dev/null \
    && chk time.ntpd_monlist PASS "disable monitor" "" \
    || chk time.ntpd_monlist WARN "monitor not disabled" "add 'disable monitor' to kill monlist amplification"
fi

# --- chrony: command port and who may query/sync ---
if [ -r "$(rf /etc/chrony/chrony.conf)" ] || [ -r "$(rf /etc/chrony.conf)" ]; then
  raw "chrony access-control directives"
  grep -hE '^\s*(allow|deny|cmdallow|cmddeny|cmdport|port|bindcmdaddress|local\b|nts|server|pool|makestep|rtcsync|leapsec)' \
    /etc/chrony/chrony.conf /etc/chrony.conf 2>/dev/null
  if grep -qhE '^\s*allow\b' "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" 2>/dev/null; then
    chk time.chrony_serving WARN "$(grep -hE '^\s*allow' "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" 2>/dev/null | tr '\n' ';')" "chrony is serving time to these networks; confirm intended and scoped"
  else
    chk time.chrony_serving PASS "no allow directive (client only)" ""
  fi
  if grep -qhE '^\s*cmdport\s+0' "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" 2>/dev/null; then
    chk time.chrony_cmdport PASS "cmdport 0" ""
  else
    BCA="$(grep -hE '^\s*bindcmdaddress' "$(rf /etc/chrony/chrony.conf)" "$(rf /etc/chrony.conf)" 2>/dev/null | tr '\n' ';')"
    chk time.chrony_cmdport INFO "${BCA:-default (localhost only)}" "chronyd's command port defaults to loopback; confirm it is not bound publicly"
  fi
fi

# --- how many independent sources? a single source is a single point of manipulation ---
NSRC="$(printf '%s' "$NTPCONF" | grep -cE '^\s*(server|pool|NTP=)')"
[ "${NSRC:-0}" -lt 2 ] && chk time.sources WARN "${NSRC:-0} configured source line(s)" "use >=3 independent sources so one lying server cannot move the clock" \
                       || chk time.sources PASS "${NSRC} source line(s)" ""
printf '%s' "$NTPCONF" | grep -qiE '^\s*makestep\s+[0-9.]+\s+-1' \
  && chk time.makestep WARN "makestep with unlimited steps" "clock can be stepped arbitrarily at any time; prefer a bounded step count"

SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
[ "$SYNC" = "yes" ] && chk time.synced PASS yes "" || chk time.synced WARN "${SYNC:-unknown}" "clock not confirmed in sync"

# --- peer health: configured sources are not the same as working, trustworthy sources ---
if [ "$PROBE" = "1" ]; then
  active_on
  if have chronyc; then
    CS="$(chronyc -n sources 2>/dev/null)"
    ST="$(chronyc tracking 2>/dev/null | awk -F': *' '/Stratum/{print $2}')"
    SEL="$(printf '%s' "$CS" | grep -c '^\^\*')"
    FALSE="$(printf '%s' "$CS" | grep -c '^\^x')"
    [ "${SEL:-0}" -ge 1 ] && chk time.peer_selected PASS "a source is selected (^*)" "" \
                          || chk time.peer_selected FAIL "no selected source" "chrony has no source it trusts: the clock is free-running"
    [ "${FALSE:-0}" -gt 0 ] && chk time.falsetickers FAIL "${FALSE} falseticker(s) (^x)" "a configured server disagrees with the majority, either broken or actively lying about the time"
    [ -n "$ST" ] && { [ "$ST" -ge 16 ] 2>/dev/null && chk time.stratum FAIL "stratum $ST" "stratum 16 means unsynchronised" || chk time.stratum PASS "stratum $ST" ""; }
  elif have ntpq; then
    NQ="$(ntpq -pn 2>/dev/null)"
    printf '%s' "$NQ" | grep -q '^\*' && chk time.peer_selected PASS "a peer is selected (*)" "" \
                                      || chk time.peer_selected FAIL "no selected peer" "ntpd is not synchronised to any source"
    FALSE="$(printf '%s' "$NQ" | grep -c '^x')"
    [ "${FALSE:-0}" -gt 0 ] && chk time.falsetickers FAIL "${FALSE} falseticker(s)" "a configured server disagrees with the majority"
    printf '%s' "$NQ" | awk 'NR>2 && $1 !~ /^[*+#o]/ && $7=="0" {c++} END{if(c>0) print c}' | while read -r u; do
      [ -n "$u" ] && chk time.unreachable_peers WARN "${u} peer(s) with reach=0" "configured but never answering: the real number of independent sources is lower than the config suggests"
    done
  fi
  active_off
fi
raw "clock offset / drift"
have chronyc && run chronyc tracking | grep -iE 'stratum|offset|leap|ref'
[ -r "$(rf /var/lib/ntp/ntp.drift)" ] && cat "$(rf /var/lib/ntp/ntp.drift)"

# --------------------------------------------------------------- 19. LOGGING
sec LOGGING
raw "logging daemons"
have systemctl && run systemctl is-active rsyslog syslog-ng journald systemd-journald auditd 2>/dev/null
raw "journald config"
grep -rhvE '^\s*#|^\s*$' "$(rf /etc/systemd/journald.conf)" "$(rf /etc/systemd/journald.conf.d/)" 2>/dev/null
raw "rsyslog remote forwarding rules"
grep -rhE '^\s*[^#]*@' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" 2>/dev/null | cap 30
grep -rhE 'omfwd|target=|StreamDriver|DefaultNetstreamDriver|action\(' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" 2>/dev/null | cap 30
REMOTE=0
grep -rqsE '^\s*[^#]*\*\.\*\s*@|omfwd|@@' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" "$(rf /etc/syslog-ng/)" 2>/dev/null && REMOTE=1
grep -rqs 'ForwardToSyslog=yes\|Storage=' "$(rf /etc/systemd/journald.conf)" 2>/dev/null
LOGCFG_SEEN=0
{ readable "$(rf /etc/rsyslog.conf)" || dir_readable "$(rf /etc/rsyslog.d)" \
  || dir_readable "$(rf /etc/syslog-ng)" || readable "$(rf /etc/systemd/journald.conf)" \
  || dir_readable "$(rf /etc/systemd/journald.conf.d)"; } && LOGCFG_SEEN=1
# a shipping agent is also "remote logging" even with no syslog forwarding configured
AGENT=""
for a in vector filebeat fluent-bit fluentd promtail otelcol otelcol-contrib awslogs \
         amazon-cloudwatch-agent google-fluentd datadog-agent splunkforwarder rsyslog-relp; do
  have "$a" && AGENT="$AGENT $a"
  [ -d "$(rf /etc/$a)" ] && AGENT="$AGENT $a(config)"
done
[ -n "$AGENT" ] && chk logging.shipping_agent PASS "$AGENT" "a log-shipping agent is present; confirm it is running, its destination is reachable, and its transport is authenticated"
if [ "$LOGCFG_SEEN" = "0" ] && [ -z "$AGENT" ]; then
  chk logging.remote NA "no logging configuration could be read" "neither rsyslog/syslog-ng/journald config nor a shipping agent was found or readable: off-host forwarding is undetermined, not absent"
elif [ "$REMOTE" = "1" ]; then
  if grep -rqsE 'StreamDriver(Mode)?\s*=\s*"?1|gtls|@@\(o\)|tls' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" "$(rf /etc/syslog-ng/)" 2>/dev/null; then
    chk logging.remote PASS "remote + TLS" ""
  else
    chk logging.remote WARN "remote, no TLS detected" "logs traverse the network in cleartext and unauthenticated"
  fi
elif [ -n "$AGENT" ]; then
  chk logging.remote WARN "no syslog forwarding, but a shipping agent is present:$AGENT" "logs may leave the host via the agent rather than syslog; verify its destination and that it covers auth.log/journal, not just application logs"
else
  chk logging.remote FAIL "local only" "no syslog forwarding and no shipping agent: an attacker with root deletes the only copy of the evidence"
fi
raw "auditd"
have auditctl && [ "$AM_ROOT" = "1" ] && { run auditctl -s; run auditctl -l | cap 60; }
if [ "$OFFLINE" = "1" ] || ! have systemctl; then
  # offline / no systemd: the configured state is still checkable from files
  if [ -r "$(rf /etc/audit/auditd.conf)" ] || dir_readable "$(rf /etc/audit/rules.d)"; then
    ARN="$(cat "$(rf /etc/audit/rules.d)"/*.rules 2>/dev/null | grep -cvE '^\s*#|^\s*$')"
    chk logging.auditd INFO "auditd configured, ${ARN:-0} rule line(s) on disk" "runtime state not determinable here; verify 'auditctl -s' and 'auditctl -l' on a booted instance"
  else
    chk logging.auditd NA "no auditd configuration found or readable" "undetermined, not absent"
  fi
elif systemctl is-active auditd >/dev/null 2>&1; then
  NR="$(auditctl -l 2>/dev/null | grep -vc 'No rules')"
  chk logging.auditd PASS "active, ${NR:-?} rules" ""
elif systemctl list-unit-files 2>/dev/null | grep -q '^auditd'; then
  chk logging.auditd FAIL "auditd installed but not active" "no syscall-level audit trail: the unit exists and is not running"
else
  chk logging.auditd FAIL "auditd not installed" "no syscall-level audit trail: no record of who executed what, who read which file, or who changed a privilege"
fi
# ============================ LOG RETENTION ============================
raw "LOG RETENTION: how far back can an incident actually be reconstructed?"

# --- journald ---
JC="$(grep -rhE '^\s*[A-Za-z]' "$(rf /etc/systemd/journald.conf)" "$(rf /etc/systemd/journald.conf.d/)" 2>/dev/null | grep -vE '^\s*#')"
if [ -n "$JC" ] || have journalctl; then
  raw "journald settings"
  printf '%s\n' "$JC"
  jget() { printf '%s\n' "$JC" | awk -F= -v k="$1" 'tolower($1) ~ "^[[:space:]]*"tolower(k)"[[:space:]]*$" {gsub(/[[:space:]]/,"",$2); v=$2} END{print v}'; }
  JSTOR="$(jget Storage)"
  if [ -d "$(rf /var/log/journal)" ]; then
    chk logret.journal_persistent PASS "Storage=${JSTOR:-auto} and /var/log/journal exists" ""
  else
    chk logret.journal_persistent FAIL "Storage=${JSTOR:-auto}, no /var/log/journal" "the journal lives in /run and is ERASED ON EVERY REBOOT: an attacker reboots the host and the local record is gone. Set Storage=persistent"
  fi
  JRET="$(jget MaxRetentionSec)"
  if [ -n "$JRET" ]; then
    chk logret.journal_maxretention PASS "MaxRetentionSec=$JRET" "explicit time-based retention"
  else
    chk logret.journal_maxretention WARN "MaxRetentionSec unset" "retention is bounded by SIZE, not time: how many days you keep depends on how chatty the system is, so it silently shrinks under load or during an attack that generates log volume. Set MaxRetentionSec to state a real retention period"
  fi
  raw "journal size caps and current usage"
  JMU="$(jget SystemMaxUse)"; JKF="$(jget SystemKeepFree)"
  JMF="$(jget SystemMaxFileSize)"; JFS="$(jget MaxFileSec)"
  printf '  SystemMaxUse=%s SystemKeepFree=%s SystemMaxFileSize=%s MaxFileSec=%s\n' \
    "${JMU:-unset (default 10% of filesystem)}" "${JKF:-unset}" "${JMF:-unset}" "${JFS:-unset (default 1month)}"
  have journalctl && run journalctl --disk-usage 2>/dev/null
  raw "oldest journal data actually on disk (the empirical retention)"
  ls -lt --time-style=long-iso "$LSA_ROOT"/var/log/journal/*/*.journal 2>/dev/null | tail -3
  OLDEST="$(ls -lt --time-style=long-iso "$LSA_ROOT"/var/log/journal/*/system*.journal 2>/dev/null | tail -1 | awk '{print $6}')"
  [ -n "$OLDEST" ] && chk logret.journal_oldest INFO "oldest journal file dated $OLDEST" "compare against the retention the policy claims"
  have journalctl && { raw "boots recorded in the journal"; run journalctl --list-boots 2>/dev/null | head -3; run journalctl --list-boots 2>/dev/null | tail -1; }
fi

# --- logrotate: compute the effective retention window ---
if [ -r "$(rf /etc/logrotate.conf)" ]; then
  raw "logrotate global policy"
  grep -hE '^\s*(daily|weekly|monthly|yearly|rotate|maxage|compress|create|su|dateext|notifempty)' "$(rf /etc/logrotate.conf)" 2>/dev/null
  GFREQ="$(grep -hoE '^\s*(daily|weekly|monthly|yearly)' "$(rf /etc/logrotate.conf)" 2>/dev/null | tr -d ' ' | head -1)"
  GROT="$(grep -hE '^\s*rotate\s+[0-9]+' "$(rf /etc/logrotate.conf)" 2>/dev/null | head -1 | awk '{print $2}')"
  GMAX="$(grep -hE '^\s*maxage\s+[0-9]+' "$(rf /etc/logrotate.conf)" 2>/dev/null | head -1 | awk '{print $2}')"
  DAYS=""
  case "$GFREQ" in
    daily)   DAYS=$(( ${GROT:-0} * 1 )) ;;
    weekly)  DAYS=$(( ${GROT:-0} * 7 )) ;;
    monthly) DAYS=$(( ${GROT:-0} * 30 )) ;;
    yearly)  DAYS=$(( ${GROT:-0} * 365 )) ;;
  esac
  [ -n "$GMAX" ] && [ -n "$DAYS" ] && [ "$GMAX" -lt "$DAYS" ] && DAYS="$GMAX"
  if [ -n "$DAYS" ] && [ "$DAYS" -gt 0 ]; then
    if [ "$DAYS" -lt 30 ]; then
      chk logret.logrotate_global FAIL "${DAYS} days (${GFREQ}, rotate ${GROT}${GMAX:+, maxage $GMAX})" "intrusions are commonly discovered weeks or months after the fact; under 30 days of logs means the evidence is already deleted when you go looking"
    elif [ "$DAYS" -lt 90 ]; then
      chk logret.logrotate_global WARN "${DAYS} days (${GFREQ}, rotate ${GROT})" "below the 90-day floor most incident-response and compliance regimes assume (PCI DSS wants 1 year, 3 months immediately available)"
    else
      chk logret.logrotate_global PASS "${DAYS} days (${GFREQ}, rotate ${GROT})" ""
    fi
  else
    chk logret.logrotate_global WARN "cannot compute (freq=${GFREQ:-unset} rotate=${GROT:-unset})" "no global rotation policy: per-file configs govern, check them individually"
  fi

  raw "per-logfile retention overrides in /etc/logrotate.d/"
  for f in "$LSA_ROOT"/etc/logrotate.d/*; do
    [ -r "$f" ] || continue
    # a logrotate block may cover several paths; accumulate them all so the
    # security-relevant one (auth.log) is not hidden behind a later sibling
    awk -v F="$(basename "$f")" '
      /\{/ {inblk=1; freq="";rot="";age=""; hdr=paths; paths=""; next}
      !inblk && NF && !/^[[:space:]]*#/ {paths = (paths=="" ? $0 : paths " " $0)}
      inblk && /^[[:space:]]*(daily|weekly|monthly|yearly)/ {t=$0; gsub(/[[:space:]]/,"",t); freq=t}
      inblk && /^[[:space:]]*rotate[[:space:]]+[0-9]+/ {rot=$2}
      inblk && /^[[:space:]]*maxage[[:space:]]+[0-9]+/ {age=$2}
      /\}/ && inblk {
        if (freq!="" || rot!="" || age!="")
          printf "  %-18s freq=%-8s rotate=%-4s maxage=%-5s %s\n", F, (freq==""?"-":freq), (rot==""?"-":rot), (age==""?"-":age), substr(hdr,1,70)
        inblk=0
      }
    ' "$f" 2>/dev/null
  done | cap 40

  # the security-relevant logs specifically
  raw "retention for the security-relevant logs"
  for L in auth.log secure sudo.log audit/audit.log wtmp btmp syslog messages; do
    C="$(grep -rls "$L" "$(rf /etc/logrotate.d/)" "$(rf /etc/logrotate.conf)" 2>/dev/null | head -1)"
    [ -n "$C" ] && printf '  %-18s governed by %s\n' "$L" "$C"
  done
fi

# --- auditd has its own retention, independent of logrotate ---
if [ -r "$(rf /etc/audit/auditd.conf)" ]; then
  raw "auditd retention"
  grep -hE '^\s*(max_log_file|num_logs|max_log_file_action|space_left|space_left_action|admin_space_left|admin_space_left_action|disk_full_action|flush)' "$(rf /etc/audit/auditd.conf)" 2>/dev/null
  ANUM="$(awk -F= '/^\s*num_logs/{gsub(/[[:space:]]/,"",$2); print $2}' "$(rf /etc/audit/auditd.conf)" 2>/dev/null)"
  ASZ="$(awk -F= '/^\s*max_log_file\s*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$(rf /etc/audit/auditd.conf)" 2>/dev/null)"
  AACT="$(awk -F= '/^\s*max_log_file_action/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$(rf /etc/audit/auditd.conf)" 2>/dev/null)"
  chk logret.auditd INFO "num_logs=${ANUM:-?} x max_log_file=${ASZ:-?}MB = ~$(( ${ANUM:-0} * ${ASZ:-0} ))MB total, action=${AACT:-?}" "auditd retention is a byte budget, not a time period"
  case "$AACT" in
    rotate) chk logret.auditd_action WARN "ROTATE" "the oldest audit log is DELETED when the budget fills: under a high-volume attack the evidence of the attack overwrites itself. Consider keep_logs plus off-host shipping" ;;
    keep_logs) chk logret.auditd_action PASS "keep_logs" "nothing is deleted; ensure the partition cannot fill" ;;
    ignore|suspend) chk logret.auditd_action FAIL "$AACT" "auditing stops or entries are silently dropped when the budget fills: an attacker can blind auditd by generating volume" ;;
  esac
  ASLA="$(awk -F= '/^\s*space_left_action/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$(rf /etc/audit/auditd.conf)" 2>/dev/null)"
  [ "$ASLA" = "ignore" ] && chk logret.auditd_space FAIL "space_left_action=ignore" "no warning before the audit partition fills"
fi

# --- wtmp/btmp: login history retention ---
raw "login history (wtmp/btmp) size and age"
ls -l --time-style=long-iso "$LSA_ROOT"/var/log/wtmp* "$LSA_ROOT"/var/log/btmp* "$(rf /var/log/lastlog)" 2>/dev/null
have last && { OLDLOGIN="$(last -F 2>/dev/null | tail -3 | head -1)"; [ -n "$OLDLOGIN" ] && printf '  oldest wtmp record: %s\n' "$OLDLOGIN"; }

# --- off-host retention is the one that actually survives ---
chk logret.offhost_note INFO "local retention above is only half the answer" "an attacker with root deletes local logs regardless of retention settings: the retention that matters for incident response is the collector's, which cannot be verified from this host. Confirm it separately"

# ==================== LOG READABILITY BY UNPRIVILEGED USERS ====================
raw "LOG READABILITY: can a regular user read the logs?"

raw "/var/log directory and key file permissions"
ls -ld "$(rf /var/log)" "$(rf /var/log/journal)" "$(rf /var/log/audit)" 2>/dev/null
ls -l "$(rf /var/log/auth.log)" "$(rf /var/log/secure)" "$(rf /var/log/syslog)" "$(rf /var/log/messages)" "$(rf /var/log/sudo.log)" \
      /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null

VLD="$(stat -c '%a %U:%G' "$(rf /var/log)" 2>/dev/null)"
chk logperm.var_log INFO "$VLD" ""

# world-readable log files: anything with o+r is readable by every local account.
# POSIX -print (not GNU -printf): a find that does not support -printf would return an empty
# list and produce a false PASS here.
WRLIST="$(find "$(rf /var/log)" -maxdepth 3 -type f -perm -004 -print 2>/dev/null | head -40)"
NWR="$(find "$(rf /var/log)" -maxdepth 3 -type f -perm -004 -print 2>/dev/null | wc -l | tr -d ' ')"
if [ "${NWR:-0}" -gt 0 ]; then
  printf '%s\n' "$WRLIST" | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null | cap 40
  chk logperm.world_readable FAIL "${NWR} world-readable file(s) under /var/log" "every local user, including a compromised low-privilege service account, can read these. Logs disclose usernames, source IPs, internal hostnames, file paths, software versions, cron command lines, and often tokens or query strings; they are reconnaissance material and sometimes contain credentials outright"
else
  chk logperm.world_readable PASS "no world-readable files under /var/log" ""
fi

# the sensitive ones specifically: these must never be world-readable
for L in "$LSA_ROOT"/var/log/auth.log "$LSA_ROOT"/var/log/secure "$LSA_ROOT"/var/log/sudo.log \
        "$LSA_ROOT"/var/log/audit/audit.log "$LSA_ROOT"/var/log/btmp; do
  [ -e "$L" ] || continue
  M="$(stat -c '%a' "$L" 2>/dev/null)"; O="$(stat -c '%U:%G' "$L" 2>/dev/null)"
  case "$M" in
    *[4567]) chk "logperm.$(basename "$L")" FAIL "$M $O" "world-readable. Authentication logs record usernames, failed-login sources and sudo command lines, and a password typed at a username prompt is logged verbatim. btmp/auth.log are the classic source of leaked credentials" ;;
    600|640|660|0600|0640) chk "logperm.$(basename "$L")" PASS "$M $O" "" ;;
    *) chk "logperm.$(basename "$L")" WARN "$M $O" "review: not world-readable but broader than 640" ;;
  esac
done

# audit logs must be root-only
if [ -d "$(rf /var/log/audit)" ]; then
  AM="$(stat -c '%a %U:%G' "$(rf /var/log/audit/audit.log)" 2>/dev/null)"
  case "${AM%% *}" in 600|0600) chk logperm.audit PASS "$AM" "" ;;
    *) chk logperm.audit FAIL "$AM" "audit.log should be 0600 root:root: it records every privileged action and file access on the host" ;; esac
  grep -hE '^\s*log_group' "$(rf /etc/audit/auditd.conf)" 2>/dev/null
fi

# journald access is group-based: systemd-journal (all), adm/wheel (via ACL)
if [ -d "$(rf /var/log/journal)" ]; then
  raw "journal ACLs (who can read the journal without root)"
  have getfacl && run getfacl -p /var/log/journal 2>/dev/null | cap 12
  ls -ld "$LSA_ROOT"/var/log/journal/* 2>/dev/null | head -3
fi

raw "group membership granting log access (these accounts read logs without sudo)"
for g in adm systemd-journal wheel syslog systemd-journal-remote; do
  M="$(getent group "$g" 2>/dev/null | cut -d: -f4)"
  [ -n "$M" ] && printf '  %-22s %s\n' "$g" "$M"
done
LOGREADERS="$( { getent group adm 2>/dev/null | cut -d: -f4; getent group systemd-journal 2>/dev/null | cut -d: -f4; } | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
[ -n "$LOGREADERS" ] && chk logperm.log_reader_accounts INFO "$LOGREADERS" "members of adm/systemd-journal can read all system logs without sudo and without leaving a sudo audit trail; confirm each is intended"

# logrotate's create mode decides the permissions of every FUTURE rotated file
raw "logrotate 'create' modes (these set the permissions of rotated logs)"
grep -rhE '^\s*(create|su)\s' "$(rf /etc/logrotate.conf)" "$(rf /etc/logrotate.d/)" 2>/dev/null | sed 's/  */ /g' | sort | uniq -c | sort -rn | cap 15
# a mode whose final (other) digit is 4-7 grants world read on every rotated file
if grep -rhqE '^[[:space:]]*create[[:space:]]+[0-9]*[4567][[:space:]]' "$(rf /etc/logrotate.conf)" "$(rf /etc/logrotate.d/)" 2>/dev/null; then
  chk logperm.logrotate_create FAIL "$(grep -rhE '^[[:space:]]*create[[:space:]]+[0-9]*[4567][[:space:]]' "$(rf /etc/logrotate.conf)" "$(rf /etc/logrotate.d/)" 2>/dev/null | sed 's/^[[:space:]]*//' | sort -u | head -3 | tr '\n' ';')" "logrotate recreates these logs world-readable after every rotation, fixing the permissions by hand will silently revert at the next rotate"
else
  chk logperm.logrotate_create PASS "no world-readable create modes" ""
fi

# rsyslog decides the permissions of files it creates
raw "rsyslog file/dir creation modes"
grep -rhE '\$(FileCreateMode|DirCreateMode|FileOwner|FileGroup)|umask' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" 2>/dev/null
FCM="$(grep -rhE '^\s*\$FileCreateMode' "$(rf /etc/rsyslog.conf)" "$(rf /etc/rsyslog.d/)" 2>/dev/null | tail -1 | awk '{print $2}')"
case "$FCM" in
  *[4567]) chk logperm.rsyslog_create FAIL "\$FileCreateMode $FCM" "rsyslog creates new log files world-readable" ;;
  "") chk logperm.rsyslog_create WARN "\$FileCreateMode unset (default 0644)" "rsyslog's default creates world-readable logs; set \$FileCreateMode 0640" ;;
  *) chk logperm.rsyslog_create PASS "\$FileCreateMode $FCM" "" ;;
esac

# application logs outside /var/log are a common leak (web app logs in the webroot!)
raw "world-readable log files outside /var/log (app logs in a webroot are servable AND readable)"
[ "$QUICK" = "1" ] || find "$(rf /home)" "$(rf /opt)" "$(rf /srv)" "$(rf /var/www)" -maxdepth 4 -type f \
  \( -name '*.log' -o -name '*.log.[0-9]' \) -perm -004 -print 2>/dev/null \
  | head -20 | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null

# ------------------------------------------------------ 20. INTEGRITY / FIM
sec INTEGRITY
FIM=none
for t in aide tripwire samhain ossec-control wazuh-agent osqueryi auditd; do have "$t" && FIM="$FIM,$t"; done
ls -la "$(rf /var/lib/aide/)" 2>/dev/null
[ -r "$(rf /etc/aide/aide.conf)" ] && echo "aide.conf present"
have aide && { raw "aide db age"; ls -l "$LSA_ROOT"/var/lib/aide/aide.db* 2>/dev/null; }
case "$FIM" in none) chk integrity.fim FAIL none "no file-integrity monitoring: a modified binary or a new SUID file is invisible" ;;
  *) chk integrity.fim PASS "$FIM" "verify the database is current and stored off-host" ;; esac

# ---- kernel-enforced integrity (stronger than a scanning FIM: enforced at exec/read time) ----
raw "IMA / EVM / dm-verity / dm-integrity"
[ -d /sys/kernel/security/ima ] && { echo "IMA present"; cat /sys/kernel/security/ima/policy 2>/dev/null | head -5; ls /sys/kernel/security/ima/ 2>/dev/null; }
[ -e /sys/kernel/security/evm ] && printf 'EVM=%s\n' "$(cat /sys/kernel/security/evm 2>/dev/null)"
case " $(cat /proc/cmdline 2>/dev/null) " in *" ima_appraise="*|*" ima_policy="*) echo "IMA configured on the kernel cmdline" ;; esac
have dmsetup && dmsetup targets 2>/dev/null | grep -E 'verity|integrity'
runtime_on   # /sys/kernel/security and dmsetup describe the RUNNING kernel, never a mounted image
if [ -d /sys/kernel/security/ima ] || dmsetup targets 2>/dev/null | grep -q verity; then
  chk integrity.kernel_enforced PASS "IMA/dm-verity present" "measurement or verification happens in the kernel, not on a schedule"
else
  chk integrity.kernel_enforced INFO "no IMA/EVM/dm-verity" "optional: a scanning FIM detects changes after the fact; IMA appraisal and dm-verity refuse to execute modified files at all. Worth it for appliances and immutable images"
fi

# ---- package-manager file verification: does what is on disk still match the package? ----
# This is the cheapest tamper check on a packaged system: every distro records a checksum for
# each shipped file. A modified CONFIG file is ordinary administration; a modified BINARY or
# LIBRARY is a backdoored binary until proven otherwise, so the two are counted separately.
#
# Trust boundary, state it in the report: verification reads the same package database an
# attacker with root can rewrite (/var/lib/dpkg/info/*.md5sums, the rpm DB). It reliably
# catches opportunistic tampering and accidental drift; it does not catch an attacker who
# cleaned up after themselves. That is what an off-host AIDE database or dm-verity is for.
raw "PACKAGE FILE VERIFICATION"
PKGV_BIN=""; PKGV_CFG=0; PKGV_MISS=0; PKGV_RUN=no
SYSBIN_RE='^/(usr/)?(local/)?(s?bin|lib|lib64|libexec)/|^/usr/lib(exec)?/|^/boot/'

if [ "$QUICK" = "1" ]; then
  chk integrity.package_verify NA "skipped (--quick)" "full package verification checksums every packaged file and is I/O-bound; re-run without --quick"
elif [ "$OFFLINE" = "1" ] && [ -z "$DPKGOPT" ] && [ -z "$RPMOPT" ]; then
  chk integrity.package_verify NA "no package database in the mounted tree" "without the image's own dpkg/rpm database there is nothing to verify against; verifying with the auditing host's database would describe the wrong machine"
elif have dpkg && { [ "$OFFLINE" = "0" ] || [ -n "$DPKGOPT" ]; }; then
  # dpkg --verify is built into dpkg >=1.17: no extra package required, unlike debsums
  raw "dpkg --verify (built in; flags are ??5?????? = md5 mismatch, 'c' marks a conffile)"
  DPKGV="$(tmo 600 dpkg ${DPKGOPT:-} --verify 2>/dev/null)"
  PKGV_RUN=yes
  printf '%s\n' "$DPKGV" | cap 60
  PKGV_CFG="$(printf '%s\n' "$DPKGV" | grep -c ' c /' )"
  PKGV_MISS="$(printf '%s\n' "$DPKGV" | grep -c '^missing' )"
  PKGV_BIN="$(printf '%s\n' "$DPKGV" | grep -v ' c /' | grep -oE '/[^ ]+$' | grep -E "$SYSBIN_RE" | head -25 | tr '\n' ' ')"
  if have debsums && [ "$OFFLINE" = "0" ]; then
    raw "debsums -c (cross-check; covers only packages that shipped md5sums)"
    tmo 600 debsums -c 2>/dev/null | cap 30
    NOSUMS="$(tmo 120 debsums -l 2>/dev/null | wc -l | tr -d ' ')"
    [ "${NOSUMS:-0}" -gt 0 ] && chk integrity.pkgverify_coverage WARN "${NOSUMS} package(s) ship no checksums" "these cannot be verified at all: a real coverage gap, not a pass. 'debsums -l' lists them"
  else
    chk integrity.pkgverify_tooling INFO "debsums not installed" "dpkg --verify covers the same ground for md5 mismatches; debsums additionally reports which packages have no checksums to verify against"
  fi
elif have rpm && { [ "$OFFLINE" = "0" ] || [ -n "$RPMOPT" ]; }; then
  raw "rpm -Va (S=size M=mode 5=digest D=device L=symlink U=user G=group T=mtime P=capabilities)"
  RPMV="$(tmo 900 rpm ${RPMOPT:-} -Va --nodeps --noscripts 2>/dev/null)"
  PKGV_RUN=yes
  printf '%s\n' "$RPMV" | cap 60
  PKGV_CFG="$(printf '%s\n' "$RPMV" | grep -c ' c /' )"
  PKGV_MISS="$(printf '%s\n' "$RPMV" | grep -c 'missing' )"
  PKGV_BIN="$(printf '%s\n' "$RPMV" | grep -v ' c /' | grep -E '^[SM5DLUGTP.?]{9}' | grep '5' | grep -oE '/[^ ]+$' | grep -E "$SYSBIN_RE" | head -25 | tr '\n' ' ')"
  raw "mode / owner / capability changes on packaged files (not content, but still tampering)"
  printf '%s\n' "$RPMV" | grep -E '^([SM5DLUGTP.?]*[MUGP])' | grep -v ' c /' | cap 20
  MODEC="$(printf '%s\n' "$RPMV" | grep -cE '^[SM5DLUGTP.?]*[MUGP]' )"
  [ "${MODEC:-0}" -gt 0 ] && chk integrity.pkgverify_modes WARN "${MODEC} packaged file(s) with changed mode/owner/capabilities" "content unchanged but permissions were altered; check for a removed or added setuid bit, or an added file capability, on a packaged binary"
elif have apk; then
  raw "apk audit --system"
  tmo 300 apk audit --system 2>/dev/null | cap 40
  PKGV_RUN=yes
  PKGV_BIN="$(tmo 300 apk audit --system 2>/dev/null | awk '$1=="U"{print $2}' | grep -E "$SYSBIN_RE" | head -25 | tr '\n' ' ')"
else
  chk integrity.package_verify NA "no supported package manager" "nothing to verify against on this system"
fi

if [ "$PKGV_RUN" = "yes" ]; then
  if [ -n "$PKGV_BIN" ]; then
    chk integrity.pkgverify_binaries FAIL "$PKGV_BIN" "PACKAGED BINARIES OR LIBRARIES NO LONGER MATCH THEIR PACKAGE. Config drift is ordinary; this is not. Treat each as a possibly backdoored binary until explained: compare against a freshly downloaded package ('apt-get download <pkg>' / 'dnf download'), check the file's mtime against the package install time, and check whether the owning package was reinstalled or patched locally. Do not simply reinstall the package: that destroys the evidence"
  else
    chk integrity.pkgverify_binaries PASS "no packaged binary or library diverges from its package" ""
  fi
  [ "${PKGV_CFG:-0}" -gt 0 ] && chk integrity.pkgverify_configs INFO "${PKGV_CFG} modified config file(s)" "expected on any administered host: these are conffiles the admin edited. Worth skimming for anything nobody remembers changing"
  [ "${PKGV_MISS:-0}" -gt 0 ] && chk integrity.pkgverify_missing "$([ -n "${CTR:-}" ] && echo INFO || echo WARN)" "${PKGV_MISS} packaged file(s) missing from disk" "a file the package installed is gone: a broken upgrade, a manual deletion, or an attacker removing something that got in the way (a log, an auditd rule, a binary they replaced with a different path)"
  chk integrity.pkgverify_trust INFO "verification uses the local package database" "an attacker with root can rewrite the recorded checksums, so a clean result proves the absence of opportunistic tampering, not the absence of a competent intruder. An off-host AIDE database, dm-verity, or comparing against freshly downloaded packages is what closes that gap"
fi

# ---- IDS / IPS ----
IDS=""
for t in snort suricata zeek bro ossec-control wazuh-agentd aide falco tripwire; do have "$t" && IDS="$IDS $t"; done
have systemctl && for s in suricata snort wazuh-agent falco; do systemctl is-active "$s" >/dev/null 2>&1 && IDS="$IDS ${s}(active)"; done
[ -n "$IDS" ] && chk integrity.ids PASS "$IDS" "" || chk integrity.ids INFO "none detected" "no host IDS/IPS: detection depends entirely on log review"

# ---- process accounting: a record of every command executed ----
if [ -s "$(rf /var/log/account/pacct)" ] || [ -s "$(rf /var/account/pacct)" ] || [ -s "$(rf /var/log/pacct)" ]; then
  chk integrity.process_accounting PASS "accounting file present and non-empty" ""
else
  chk integrity.process_accounting INFO "not enabled" "psacct/acct records every command executed with its user and time: cheap forensic coverage that survives when an attacker clears shell history. auditd execve rules are the modern alternative"
fi
raw "rkhunter/chkrootkit"
have rkhunter && echo "rkhunter installed"; have chkrootkit && echo "chkrootkit installed"
raw "recently modified files in system bin dirs (last 7 days)"
find "$(rf /usr/bin)" "$(rf /usr/sbin)" "$(rf /bin)" "$(rf /sbin)" "$(rf /usr/local/bin)" "$(rf /usr/local/sbin)" -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | cap 30

# ------------------------------------------------------------- 21. SCHEDULED
sec SCHEDULED_TASKS
raw "/etc/crontab"
[ -r "$(rf /etc/crontab)" ] && grep -vE '^\s*#|^\s*$' "$(rf /etc/crontab)"
raw "/etc/cron.d and cron.{hourly,daily,weekly,monthly}"
ls -la "$(rf /etc/cron.d/)" "$(rf /etc/cron.hourly/)" "$(rf /etc/cron.daily/)" "$(rf /etc/cron.weekly/)" "$(rf /etc/cron.monthly/)" 2>/dev/null
grep -rhvE '^\s*#|^\s*$' "$(rf /etc/cron.d/)" 2>/dev/null
raw "per-user crontabs"
if [ "$AM_ROOT" = "1" ]; then
  for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    c="$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')"
    [ -n "$c" ] && printf '[%s]\n%s\n' "$u" "$c"
  done
else echo "(need root)"; fi
raw "cron.allow / cron.deny"
ls -l "$(rf /etc/cron.allow)" "$(rf /etc/cron.deny)" "$(rf /etc/at.allow)" "$(rf /etc/at.deny)" 2>/dev/null
raw "systemd timers"
have systemctl && run systemctl list-timers --all --no-pager --no-legend
# ============ ROOT CRON: does it touch anything an unprivileged user controls? ============
# A root cron job is a scheduled root shell. It only needs to READ, SOURCE or ARCHIVE
# something a normal user can write for that user to become root. Three distinct routes:
#   1. the script itself, or any DIRECTORY on its path, is writable  -> replace the file
#   2. the job reads/sources data in a user-writable location        -> control its contents
#   3. the job globs (*) in a user-writable directory                -> argument injection
raw "ROOT CRON PRIVILEGE ANALYSIS"


# collect every command that runs as root on a schedule
CRONCMDS="$( {
  # /etc/crontab and /etc/cron.d: field 6 is the user, fields 7+ the command
  awk '!/^[[:space:]]*#/ && NF>6 && $1 !~ /^[A-Z_]+=/ {u=$6; $1=$2=$3=$4=$5=$6=""; if (u=="root") print}' \
      /etc/crontab /etc/cron.d/* 2>/dev/null
  # root's own crontab
  [ "$AM_ROOT" = "1" ] && crontab -l -u root 2>/dev/null | awk '!/^[[:space:]]*#/ && NF>5 && $1 !~ /^[A-Z_]+=/ {$1=$2=$3=$4=$5=""; print}'
  # run-parts directories execute everything in them as root
  ls -1 "$LSA_ROOT"/etc/cron.hourly/* "$LSA_ROOT"/etc/cron.daily/* "$LSA_ROOT"/etc/cron.weekly/* "$LSA_ROOT"/etc/cron.monthly/* 2>/dev/null
  # systemd timers -> their unit's ExecStart, when the unit has no User=
  if have systemctl; then
    systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $NF}' | sort -u | while read -r t; do
      [ -n "$t" ] || continue
      [ -z "$(systemctl show "$t" -p User --value 2>/dev/null)" ] && systemctl show "$t" -p ExecStart --value 2>/dev/null | grep -oE '/[^ ;"]+' | head -1
    done
  fi
} 2>/dev/null | sed 's/^[[:space:]]*//' | grep -v '^$' | sort -u )"

printf '%s\n' "$CRONCMDS" | cap 40

CRONFIND=0
printf '%s\n' "$CRONCMDS" | while IFS= read -r cmd; do
  [ -n "$cmd" ] || continue

  # --- route 1 & 2: every absolute path the command names, script or data alike ---
  printf '%s\n' "$cmd" | grep -oE '/[A-Za-z0-9._/@+-]{2,}' | sort -u | while read -r p; do
    case "$p" in
      /proc/*|/sys/*|/dev/null|/dev/zero) continue ;;
    esac
    [ -e "$p" ] || continue
    r="$(path_risk "$p")"
    [ -n "$r" ] && printf '  RISK %s\n       referenced by root job: %s\n' "$r" "$(printf '%s' "$cmd" | cut -c1-90)"
  done

  # --- route 2b: config/data files the script itself reads or sources ---
  s="$(printf '%s\n' "$cmd" | grep -oE '/[A-Za-z0-9._/-]+\.(sh|bash|py|pl|rb)' | head -1)"
  if [ -n "$s" ] && [ -r "$s" ]; then
    grep -ohE '(^|[^A-Za-z])(\.|source|cat|awk -f|python3?|bash|sh)[[:space:]]+"?/[A-Za-z0-9._/-]+' "$s" 2>/dev/null \
      | grep -oE '/[A-Za-z0-9._/-]+' | sort -u | head -10 | while read -r d; do
        [ -e "$d" ] || continue
        r2="$(path_risk "$d")"
        [ -n "$r2" ] && printf '  RISK %s\n       sourced/read by %s (root cron)\n' "$r2" "$s"
      done
  fi

  # --- route 3: glob expansion in a user-writable directory (argument injection) ---
  case "$cmd" in
    *\**)
      if printf '%s' "$cmd" | grep -qE '(^|[[:space:]/])(tar|rsync|chown|chmod|chgrp|zip|7z|scp|cp|mv|rm|find)[[:space:]]'; then
        wd="$(printf '%s' "$cmd" | grep -oE '/[A-Za-z0-9._/-]+/\*' | head -1 | sed 's|/\*$||')"
        [ -n "$wd" ] && [ -d "$wd" ] && { rw="$(path_risk "$wd")"; [ -n "$rw" ] && \
          printf '  RISK GLOB-IN-WRITABLE-DIR %s\n       %s\n' "$rw" "$(printf '%s' "$cmd" | cut -c1-90)"; }
        printf '  NOTE glob passed to an archiving/permission tool: %s\n' "$(printf '%s' "$cmd" | cut -c1-90)"
      fi ;;
  esac
done | sort -u | cap 40

# emit a verdict based on a second, non-subshell pass so the count survives
CRONRISK=0
for cmd in $(printf '%s\n' "$CRONCMDS" | tr ' ' '\n' | grep -oE '^/[A-Za-z0-9._/@+-]{2,}$' | sort -u); do
  [ -e "$cmd" ] || continue
  path_risk "$cmd" >/dev/null 2>&1 && CRONRISK=$((CRONRISK+1))
done
if [ "$CRONRISK" -gt 0 ]; then
  chk cron.writable_inputs FAIL "${CRONRISK} path(s) referenced by root scheduled jobs are writable by a non-root principal" "a root cron job that executes, sources or reads a file which an unprivileged user can modify (or whose PARENT DIRECTORY they can modify, allowing the file to be replaced) is a scheduled root shell for that user"
else
  chk cron.writable_inputs PASS "no writable paths referenced by root scheduled jobs" ""
fi

# --- PATH dependency: a relative command in a root crontab resolves via cron's PATH ---
raw "PATH declared in crontabs (a relative command name resolves through it)"
grep -hE '^\s*PATH\s*=' "$(rf /etc/crontab)" "$LSA_ROOT"/etc/cron.d/* 2>/dev/null
[ "$AM_ROOT" = "1" ] && crontab -l -u root 2>/dev/null | grep -E '^\s*PATH\s*='
CRONPATH="$(grep -hE '^\s*PATH\s*=' "$(rf /etc/crontab)" 2>/dev/null | head -1 | cut -d= -f2)"
if [ -n "$CRONPATH" ]; then
  BADCP=""
  OLDIFS2="$IFS"; IFS=:
  for d in $CRONPATH; do
    case "$d" in ""|.|./*) BADCP="$BADCP [relative:'${d:-empty}']"; continue ;; esac
    [ -d "$d" ] || continue
    r="$(path_risk "$d")"; [ -n "$r" ] && BADCP="$BADCP [$r]"
  done
  IFS="$OLDIFS2"
  [ -n "$BADCP" ] && chk cron.path FAIL "$BADCP" "cron's PATH contains a writable or relative element: any command a root job calls by bare name can be hijacked" \
                  || chk cron.path PASS "cron PATH elements are root-owned and not writable" ""
fi
raw "root jobs calling commands by bare name (resolved via cron PATH)"
printf '%s\n' "$CRONCMDS" | grep -vE '^\s*/' | cap 10

# --- run-parts directory permissions: write access here = arbitrary root execution ---
raw "cron directory permissions (write access to any of these is root execution)"
for d in "$LSA_ROOT"/etc/cron.d "$LSA_ROOT"/etc/cron.hourly "$LSA_ROOT"/etc/cron.daily "$LSA_ROOT"/etc/cron.weekly "$LSA_ROOT"/etc/cron.monthly "$LSA_ROOT"/var/spool/cron "$LSA_ROOT"/var/spool/cron/crontabs "$LSA_ROOT"/etc/crontab; do
  [ -e "$d" ] || continue
  s="$(stat -c '%a %U:%G' "$d" 2>/dev/null)"
  printf '  %-30s %s\n' "$d" "$s"
  m="${s%% *}"
  case "$m" in
    *[2367]) chk "cron.perm.$(basename "$d")" FAIL "$s $d" "world-writable cron location: any user schedules a root command" ;;
    ?[2367]?) chk "cron.perm.$(basename "$d")" WARN "$s $d" "group-writable cron location" ;;
    700|0700|755|0755|600|0600|644|0644) ;;
    *) chk "cron.perm.$(basename "$d")" INFO "$s $d" "review" ;;
  esac
done
raw "cron.allow / cron.deny (restrict who may schedule at all)"
ls -l "$(rf /etc/cron.allow)" "$(rf /etc/cron.deny)" "$(rf /etc/at.allow)" "$(rf /etc/at.deny)" 2>/dev/null
[ -e "$(rf /etc/cron.allow)" ] && chk cron.allow PASS "/etc/cron.allow present (allow-list)" "" \
                       || chk cron.allow WARN "no /etc/cron.allow" "cron access is controlled by cron.deny (deny-list), so any account not explicitly denied may schedule jobs"

# ------------------------------------------------------------------ 22. USB
sec USB_PERIPHERALS
if [ -n "$CTR" ] || [ "$OFFLINE" = "1" ]; then
  if [ -n "$CTR" ]; then
    chk usb_peripherals.container_context NA "running inside a $CTRTYPE container" "USB is a host concern; a container has no device enumeration of its own, so audit the host for this section"
  else
    chk usb_peripherals.container_context NA "offline (--root): no device enumeration in a mounted image" "whether the machine is physical, and what is plugged into it, are properties of a running system. Audit the booted instance for this section"
  fi
else
HAS_USB_HW=0
[ -d /sys/bus/usb/devices ] && ls /sys/bus/usb/devices/ 2>/dev/null | grep -q . && HAS_USB_HW=1
chk usb.context INFO "platform=$PLATFORM virt=$VIRT usb_bus_present=$HAS_USB_HW${CHASSIS:+ chassis=$CHASSIS}" \
  "decides how the rest of this section is scored: a machine with real ports is held to them, a virtual instance with no USB bus is not"

# How to score a missing USB control on THIS platform. A control that cannot be exercised is
# not a defect, and a control that can be is not excused by being inconvenient.
#   physical              -> FAIL. Somebody can walk up and plug something in.
#   virtual, USB bus      -> WARN. A bus exists. Whether it reaches a physical port depends on
#                            passthrough configured in the hypervisor, which is not visible
#                            from inside the guest, so do not assert either way.
#   virtual, no USB bus   -> NA.   Nothing to lock down. NA is not a pass: it says the question
#                            was not applicable here, and the summary check still WARNs that a
#                            controller attached later would be unrestricted.
if [ "$PLATFORM" = "physical" ]; then
  USB_MISS=FAIL
  USB_WHY="this is bare metal${CHASSIS:+ ($CHASSIS)}, so a port exists that somebody can plug into"
elif [ "$PLATFORM" = "unknown" ]; then
  # No systemd-detect-virt, no DMI, no device tree, no hypervisor bit. Reported at WARN rather
  # than FAIL because the premise is unproven, and never suppressed, because the machine may
  # well be physical. Deciding it is a guest on no evidence is how a real exposure gets buried.
  USB_MISS=WARN
  USB_WHY="the platform could not be determined, so this is reported at reduced severity rather than suppressed. If this machine is physical, treat it as a finding; install systemd or dmidecode to let the next run decide"
elif [ "$HAS_USB_HW" = "1" ]; then
  USB_MISS=WARN
  USB_WHY="a USB bus is present on a $VIRT guest; whether it reaches a physical port depends on passthrough configured in the hypervisor, which cannot be seen from inside the guest"
else
  USB_MISS=NA
  USB_WHY="no USB bus on a $VIRT guest, so there is no port to restrict. Not a pass: see usb.restriction_present for what changes if a controller is attached later"
fi

# --- 1. USBGuard: the policy-based control (allow-list of specific devices) ---
if have usbguard || [ -d "$(rf /etc/usbguard)" ]; then
  raw "usbguard configuration"
  grep -hE '^\s*(RuleFile|ImplicitPolicyTarget|PresentDevicePolicy|PresentControllerPolicy|InsertedDevicePolicy|RestoreControllerDeviceState|AuthorizedDefault|IPCAllowedUsers|IPCAllowedGroups)' \
       /etc/usbguard/usbguard-daemon.conf 2>/dev/null
  UGACTIVE=0
  have systemctl && systemctl is-active usbguard >/dev/null 2>&1 && UGACTIVE=1
  # rules.conf ships 0600 root:root. Counting its lines with wc also counted comments and blanks,
  # and an unreadable file counted as zero, so a non-root run reported "0 rule(s)" and failed the
  # host for an empty policy it had never actually read. Only real rule lines count, and a failed
  # read is recorded as a failed read.
  UGRF="$(rf /etc/usbguard/rules.conf)"
  RULES=""; RULES_READ=0
  if [ -r "$UGRF" ]; then
    RULES_READ=1
    RULES="$(grep -cE '^[[:space:]]*(allow|block|reject)' "$UGRF" 2>/dev/null | tr -d ' ')"
  fi
  IPT="$(grep -hE '^\s*ImplicitPolicyTarget' "$(rf /etc/usbguard/usbguard-daemon.conf)" 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}')"
  if [ "$UGACTIVE" = "1" ]; then
    # Precedence matters here. Written as `A && B || C` the shell reads it as `(A && B) || C`,
    # so ImplicitPolicyTarget=reject used to satisfy the whole condition on its own and a policy
    # with ZERO rules reported PASS. The default target is decided first because it needs no
    # rule count, which keeps an unreadable rule file from masquerading as an empty one.
    if [ "$IPT" != "block" ] && [ "$IPT" != "reject" ]; then
      chk usb.usbguard FAIL "active but ImplicitPolicyTarget=${IPT:-allow}" "USBGuard is running in allow-by-default mode: it logs devices but blocks nothing. This is a deny-list posture, and the point of USBGuard is the opposite one. Set ImplicitPolicyTarget=block and generate an allow-list with 'usbguard generate-policy'"
    elif [ "$RULES_READ" = "0" ]; then
      chk usb.usbguard NA "active, ImplicitPolicyTarget=$IPT, rules.conf not readable" "the default is to deny, which is the right posture, but the allow-list could not be read (0600 root:root) so it is not known whether it is populated. Re-run as root to score it"
    elif [ "${RULES:-0}" -gt 0 ]; then
      chk usb.usbguard PASS "active, ${RULES:-0} rule(s), ImplicitPolicyTarget=$IPT" "a device that is not on the allow-list is refused, so an unknown one fails closed. See usb.usbguard_rule_scope for whether those rules name devices or admit whole classes"
    else
      chk usb.usbguard FAIL "active, ImplicitPolicyTarget=$IPT, but 0 rule(s)" "the default is to deny and nothing is explicitly allowed, so every device including the console keyboard is blocked. That is either a lockout waiting to happen or a policy that was never generated: run 'usbguard generate-policy' against the devices this host is meant to accept"
    fi
  else
    chk usb.usbguard FAIL "installed but not active" "the daemon must be enabled and running for the policy to apply"
  fi

  # An allow-list that admits an entire interface class is barely an allow-list: "allow
  # with-interface { 08:*:* }" accepts every mass-storage device ever made, which is the deny-list
  # failure mode wearing an allow-list's clothes. Rules that carry no device id, or wildcard the
  # vendor or product, are the ones to look at.
  if [ "$RULES_READ" = "1" ]; then
    UG_BROAD="$(awk '
      /^[[:space:]]*allow/ {
        broad = 0
        if ($0 !~ /[[:space:]]id[[:space:]]/)                 broad = 1   # no device identity at all
        if ($0 ~ /[[:space:]]id[[:space:]]+\*:\*/)            broad = 1   # any vendor, any product
        if ($0 ~ /[[:space:]]id[[:space:]]+[0-9a-fA-F]+:\*/)  broad = 1   # an entire vendor
        if (broad) printf "line %d: %s\n", NR, substr($0, 1, 90)
      }' "$UGRF" 2>/dev/null)"
    if [ -n "$UG_BROAD" ]; then
      UG_BROAD_N="$(printf '%s\n' "$UG_BROAD" | grep -c .)"
      chk usb.usbguard_rule_scope WARN "${UG_BROAD_N} allow rule(s) admit a class or wildcard rather than a device" \
        "$(printf '%s' "$UG_BROAD" | tr '\n' ';') | any device presenting a matching interface class or vendor is accepted, so the policy stops being an inventory of permitted hardware. A BadUSB device picks the class it presents. Pin the rules to vendor:product with serial and hash where the device supports it, which is what 'usbguard generate-policy' emits by default"
      raw "usbguard allow rules that are not device-specific"
      printf '%s\n' "$UG_BROAD" | cap 10
    else
      chk usb.usbguard_rule_scope PASS "every allow rule names a specific device" "the allow-list is an inventory of permitted hardware rather than of permitted categories"
    fi
  else
    chk usb.usbguard_rule_scope NA "rules.conf not readable" "cannot tell whether the allow-list names devices or admits whole classes; re-run as root"
  fi
  [ "$AM_ROOT" = "1" ] && have usbguard && { raw "usbguard device list"; run usbguard list-devices 2>/dev/null | cap 20; raw "usbguard rules"; run usbguard list-rules 2>/dev/null | cap 20; }
  raw "usbguard IPC access (who can change the policy)"
  grep -hE '^\s*IPCAllowed(Users|Groups)' "$(rf /etc/usbguard/usbguard-daemon.conf)" 2>/dev/null
else
  chk usb.usbguard "$USB_MISS" "not installed" "no device-level USB policy. USBGuard restricts devices by identity (vendor/product/serial/interface class), which blocks BadUSB-style HID injection, rogue network adapters and mass storage that a simple usb-storage blacklist does not. $USB_WHY"
fi

# Defence in depth rather than the primary control, so it never exceeds WARN on a machine that
# does have ports; but it is still NA where there is no bus to blacklist drivers for.
USB_ADV=WARN; [ "$USB_MISS" = "NA" ] && USB_ADV=NA

# --- 2. kernel-level blanket controls (coarser alternatives / defence in depth) ---
if [ -e /proc/sys/kernel/deny_new_usb ]; then
  DNU="$(cat /proc/sys/kernel/deny_new_usb 2>/dev/null)"
  [ "$DNU" = "1" ] && chk usb.deny_new_usb PASS "1" "no new USB device is accepted after boot" \
                   || chk usb.deny_new_usb "$USB_MISS" "$DNU" "set to 1 (late in boot) to refuse all new USB devices. $USB_WHY"
else
  chk usb.deny_new_usb NA "sysctl absent" "requires a linux-hardened kernel; use USBGuard or authorized_default instead"
fi
case " $(cat /proc/cmdline 2>/dev/null) " in *" nousb "*) chk usb.nousb PASS "nousb on cmdline" "USB support disabled entirely" ;; esac

# --- 3. authorized_default: deny new devices at the bus level via udev ---
AD_DENY=0; AD_STATE=""
for a in /sys/bus/usb/devices/usb*/authorized_default; do
  [ -r "$a" ] || continue
  v="$(cat "$a" 2>/dev/null)"; AD_STATE="$AD_STATE $(basename "$(dirname "$a")")=$v"
  [ "$v" = "0" ] && AD_DENY=1
done
if [ -n "$AD_STATE" ]; then
  [ "$AD_DENY" = "1" ] && chk usb.authorized_default PASS "$AD_STATE" "at least one controller denies new devices by default" \
                       || chk usb.authorized_default WARN "$AD_STATE" "every USB controller authorizes new devices automatically; a udev rule setting authorized_default=0 is the no-extra-software way to change this"
fi
raw "udev rules mentioning USB authorization / mass storage"
grep -rlsE 'authorized|usb_storage|ID_USB|SUBSYSTEM=="usb"' "$(rf /etc/udev/rules.d/)" 2>/dev/null | cap 10
grep -rhsE 'authorized' "$(rf /etc/udev/rules.d/)" 2>/dev/null | cap 10

# --- 4. module-level: block the drivers that make a rogue device useful ---
USBMODS=""
for m in usb_storage uas usbnet cdc_ether rndis_host cdc_ncm usbhid hid_generic; do
  if printf '%s' "$MPD" | grep -qE "^\s*install\s+$(printf '%s' "$m" | sed 's/_/[_-]/g')\s+/bin/(false|true)" \
     || printf '%s' "$MPD" | grep -qE "^\s*blacklist\s+$m\s*$"; then :; else USBMODS="$USBMODS $m"; fi
done
[ -n "$USBMODS" ] && chk usb.module_blacklist "$USB_ADV" "not blocked:$USBMODS" "usb_storage/uas enable mass-storage exfiltration; usbnet/cdc_ether/rndis let a USB device become a network interface and hijack routing/DNS; usbhid is the BadUSB keystroke-injection path (blocking it disables real keyboards, so headless hosts only). $USB_WHY" \
                || chk usb.module_blacklist PASS "storage/network/HID USB modules blocked" "worth having, but it is a deny-list: only these drivers are refused and any other USB class still binds. usb.restriction_present is the check that says whether a default-deny policy exists"
raw "USB-related modules currently loaded"
lsmod 2>/dev/null | grep -E '^(usb_storage|uas|usbnet|cdc_ether|rndis_host|usbhid|firewire|thunderbolt)'

# --- 5. DMA-capable ports (Thunderbolt/FireWire): direct memory read, no driver needed ---
if [ -d /sys/bus/thunderbolt/devices ]; then
  raw "thunderbolt devices and authorization"
  for d in /sys/bus/thunderbolt/devices/*/authorized; do [ -r "$d" ] && printf '%s = %s\n' "$d" "$(cat "$d")"; done
  IOMMU=0; ls /sys/class/iommu/ 2>/dev/null | grep -q . && IOMMU=1
  [ "$IOMMU" = "1" ] && chk usb.iommu PASS "IOMMU active" "DMA from Thunderbolt/PCIe is constrained" \
                     || chk usb.iommu FAIL "no IOMMU groups present" "a Thunderbolt/FireWire device can read and write system memory directly, bypassing every software control. Enable intel_iommu=on/amd_iommu=on"
fi

# --- overall verdict: is ANY effective USB restriction in place? ---
# Allow-listing and deny-listing are not two ways of doing the same thing, and this check used to
# score them as if they were: blocking eight module names was enough to report PASS. A deny-list
# enumerates badness, so it is only ever as complete as the list, and the attacker picks what is
# not on it. An allow-list refuses anything that was not named in advance, so an unknown device
# fails closed. Only default-deny controls count toward a pass here.
USB_ALLOW=""
# usbguard qualifies only when it is actually deny-by-default AND has rules, matching the verdict
# in usb.usbguard. reject counts as well as block: both refuse an unlisted device.
[ "$UGACTIVE" = "1" ] && [ "${RULES:-0}" -gt 0 ] && { [ "$IPT" = "block" ] || [ "$IPT" = "reject" ]; } \
  && USB_ALLOW="$USB_ALLOW usbguard"
[ "$(cat /proc/sys/kernel/deny_new_usb 2>/dev/null)" = "1" ] && USB_ALLOW="$USB_ALLOW deny_new_usb"
[ "$AD_DENY" = "1" ] && USB_ALLOW="$USB_ALLOW authorized_default=0"
case " $(cat /proc/cmdline 2>/dev/null) " in *" nousb "*) USB_ALLOW="$USB_ALLOW nousb" ;; esac
# Deny-list controls: named drivers are refused, everything else still binds automatically.
USB_DENY=""
[ -z "$USBMODS" ] && USB_DENY=" module-blacklist"
if [ -n "$USB_ALLOW" ]; then
  chk usb.restriction_present PASS "default-deny:$USB_ALLOW${USB_DENY:+ (plus$USB_DENY)}" \
    "an unlisted device is refused rather than driven"
elif [ -n "$USB_DENY" ]; then
  chk usb.restriction_present "$USB_ADV" "deny-list only:$USB_DENY, no default-deny policy" \
    "the named modules are refused and every other USB driver still binds automatically: usbserial/ftdi_sio/cdc_acm for a serial console, audio or video class, or any HID that is not usbhid, and a BadUSB device chooses which class to present. A deny-list is worth keeping as depth, but it is not the control. Add USBGuard with ImplicitPolicyTarget=block and an allow-list from 'usbguard generate-policy', or set authorized_default=0 via udev, so that a device nobody listed is refused instead of enumerated"
elif [ "$PLATFORM" = "physical" ]; then
  chk usb.restriction_present FAIL "none${CHASSIS:+ ($CHASSIS)}" "any USB device plugged into this machine is accepted and driven automatically: mass storage for exfiltration, a keyboard for BadUSB keystroke injection, or a network adapter that becomes the default route. Install USBGuard with ImplicitPolicyTarget=block, or set authorized_default=0 via udev"
elif [ "$HAS_USB_HW" = "1" ]; then
  chk usb.restriction_present WARN "none (platform=$PLATFORM, virt=$VIRT, USB bus present)" "no USB restriction is configured, and a USB bus exists. On a guest that bus is usually an emulated root hub or tablet that nobody can reach by hand; confirm the hypervisor is not passing a physical controller through, and that this is not in fact a bare-metal machine, before treating it as low risk"
else
  chk usb.restriction_present WARN "none (platform=$PLATFORM, virt=$VIRT, no USB bus detected)" "low practical risk on this platform, but a USB controller added later would be unrestricted"
fi

# --------------------------------------------------- 23. PRIVILEGE-ESCALATION PATHS
# Local escalation routes: the chain from "any code execution as a normal user or a
# service account" to root. These are what an attacker enumerates after a web shell.
fi

sec PRIVESC_PATHS

# ---- sudo: the configuration details that hand out root ----
SUDOALL="$( { [ -r "$(rf /etc/sudoers)" ] && cat "$(rf /etc/sudoers)"; cat "$(rf /etc/sudoers.d)"/* ; } 2>/dev/null | grep -vE '^\s*#|^\s*$')"
# /etc/sudoers is 0440 root:root. A non-root run, or an offline tree with different uid
# mapping: reads NOTHING, and "read nothing" must never surface as "no sudo hardening".
# Every sudo.* verdict below is gated on having actually read the file (field feedback §1).
SUDO_READ=1
readable "$(rf /etc/sudoers)" || SUDO_READ=0
[ "$SUDO_READ" = "1" ] && [ -z "$SUDOALL" ] && SUDO_READ=0
if [ "$SUDO_READ" = "0" ]; then
  chk sudo.policy_readable NA "/etc/sudoers could not be read" "0440 root:root; re-run as root on the target. No sudo policy verdict is issued, because an empty read is not an absent rule"
  dir_readable "$(rf /etc/sudoers.d)" && chk sudo.partial_read INFO "/etc/sudoers.d listable, /etc/sudoers not" "partial view: drop-ins visible, the main file and its Defaults not"
else
  chk sudo.policy_readable PASS "sudo policy read ($(printf '%s' "$SUDOALL" | grep -c .) directive lines)" ""
fi
raw "sudo version (check against known CVEs)"
have sudo && run sudo -V 2>/dev/null | head -2
SUDOV="$(sudo -V 2>/dev/null | awk '/version/{print $NF; exit}')"
runtime_on   # queries the installed binary, not the image
chk sudo.version INFO "${SUDOV:-unknown}" "compare against CVE-2021-3156 (Baron Samedit, <1.9.5p2), CVE-2019-14287 (Runas -1 bypass, <1.8.28), CVE-2023-22809 (sudoedit EDITOR, 1.8.0-1.9.12p1), CVE-2025-32463 (chroot, <1.9.17p1)"
method_reset   # sudo.version was runtime; everything below reads the sudoers file itself
raw "sudo Defaults lines"
printf '%s\n' "$SUDOALL" | grep -iE '^\s*Defaults'
# env_keep with the dynamic-linker variables is an unconditional root shell
if [ "$SUDO_READ" = "0" ]; then :
elif [ "$SUDO_READ" = "0" ]; then :
elif printf '%s' "$SUDOALL" | grep -iqE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB|NODE_OPTIONS)'; then
  chk sudo.env_keep FAIL "$(printf '%s' "$SUDOALL" | grep -iE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB)' | head -2 | tr '\n' ';')" "preserving the dynamic-linker environment across sudo lets any sudo-capable user load their own library into a root process: this is a direct, unconditional root shell"
else
  chk sudo.env_keep PASS "no linker variables in env_keep" ""
fi
if [ "$SUDO_READ" = "1" ]; then
  printf '%s' "$SUDOALL" | grep -iqE 'env_reset' && chk sudo.env_reset PASS "env_reset present" "" \
    || chk sudo.env_reset FAIL "env_reset absent" "the caller's whole environment is passed to the root command"
  printf '%s' "$SUDOALL" | grep -qE '!\s*authenticate' && chk sudo.noauthenticate FAIL "!authenticate present" "sudo runs without any password prompt for these rules"
  # ---- GTFOBins: commands that, granted via sudo, are equivalent to granting ALL ----
  # Grouped by escalation primitive so the report can say WHY each one is a root shell.
  GTFO_SHELL='sh|bash|dash|ash|ksh|zsh|csh|tcsh|busybox|env|nice|nohup|timeout|stdbuf|setarch|unshare|nsenter|flock|xargs|watch|time|ionice|taskset|script|screen|tmux|expect|socat|nc|ncat|rlwrap|run-parts|start-stop-daemon|make|cpulimit'
  GTFO_EDITOR='vi|vim|rvim|view|nano|pico|emacs|ed|red|less|more|man|pg|sed|ul|nroff|pic|soelim|jq'
  GTFO_INTERP='python[0-9.]*|perl|ruby|irb|lua|luajit|node|nodejs|php|gdb|awk|gawk|mawk|nawk|tclsh|jjs|jrunscript|ghc|octave|pdb|byebug|cpan|gem|pip[0-9.]*|easy_install|rake'
  GTFO_FILEWRITE='dd|tee|cp|mv|install|rsync|tar|zip|unzip|7z|cpio|gzip|bzip2|xz|openssl|curl|wget|scp|sftp|shuf|logsave|xxd|base64|date|sqlite3'
  GTFO_ADMIN='systemctl|service|mount|umount|apt|apt-get|dpkg|rpm|yum|dnf|zypper|apk|docker|podman|lxc|kubectl|crontab|at|git|ansible|puppet|chef|nmap|tcpdump|strace|ltrace|ip|iptables|nft|modprobe|insmod|sysctl|ldconfig|chmod|chown|chroot|pkexec|su|find|journalctl|dmesg'
  gtfo_hits() { # gtfo_hits <regex> <label>
    H="$(printf '%s\n' "$SUDOALL" | grep -vE '^\s*(Defaults|#|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)' \
         | grep -oE "(^|[[:space:],])/?([A-Za-z0-9_/.-]*/)?($1)([[:space:]]|,|$)" | tr -d ' ,' | sort -u | tr '\n' ' ')"
    [ -n "$H" ] && chk "sudo.gtfobins.$2" FAIL "$H" "$3"
  }
  raw "sudo command grants matched against GTFOBins escalation primitives"
  printf '%s\n' "$SUDOALL" | grep -vE '^\s*(Defaults|#)' | grep -E '=' | cap 30
  gtfo_hits "$GTFO_SHELL"     shell     "these spawn or wrap a shell directly, granting them via sudo is granting root, full stop"
  gtfo_hits "$GTFO_EDITOR"    editor    "pagers and editors escape to a shell (:!sh in vi/less/man). Granting them via sudo is granting root"
  gtfo_hits "$GTFO_INTERP"    interp    "an interpreter executes arbitrary code by definition: python -c 'import os;os.system(\"/bin/sh\")'"
  gtfo_hits "$GTFO_FILEWRITE" filewrite "arbitrary file write as root: overwrite /etc/shadow, /etc/sudoers, a cron file or a systemd unit. tar/rsync additionally execute via --checkpoint-action / -e"
  gtfo_hits "$GTFO_ADMIN"     admin     "these run other programs as root (systemctl/service/docker/git hooks/find -exec/apt hooks) or directly modify privilege state"
  # an argument-restricted grant is only as strong as the argument parsing
  printf '%s' "$SUDOALL" | grep -qE '=\s*(\(.*\)\s*)?(NOPASSWD:\s*)?[^,]*\s+[^,]*\*' \
    && chk sudo.arg_wildcard FAIL "$(printf '%s' "$SUDOALL" | grep -E '\*' | grep -v '^\s*Defaults' | head -2 | tr '\n' ';')" "a wildcard in the argument list is almost always escapable: 'systemctl restart *' takes a path, 'tar -c *' takes --checkpoint-action, and ../ traversal reaches other binaries"
  printf '%s' "$SUDOALL" | grep -qE 'sudoedit|SETENV:' \
    && chk sudo.setenv WARN "$(printf '%s' "$SUDOALL" | grep -E 'SETENV:|sudoedit' | head -2 | tr '\n' ';')" "SETENV lets the caller set any environment variable for the root command (including the linker ones); sudoedit has its own CVE history (CVE-2023-22809)"
  # a grant on a directory rather than a binary matches everything in it
  printf '%s' "$SUDOALL" | grep -qE '=\s*(\(.*\)\s*)?(NOPASSWD:\s*)?/[A-Za-z0-9_/.-]*/\s*(,|$)' \
    && chk sudo.directory_grant FAIL "$(printf '%s' "$SUDOALL" | grep -E '/\s*(,|$)' | head -2 | tr '\n' ';')" "a sudoers entry ending in / grants every executable in that directory"
  printf '%s' "$SUDOALL" | grep -qE 'ALL\s*,\s*!\s*/' && chk sudo.negation_bypass FAIL "$(printf '%s' "$SUDOALL" | grep -E 'ALL\s*,\s*!' | head -2 | tr '\n' ';')" "command-negation rules (ALL, !/bin/su) are trivially bypassed by copying or symlinking the binary: they do not restrict anything"
  printf '%s' "$SUDOALL" | grep -qE '^\s*[^#]*=\s*\(\s*ALL\s*\)\s*[^,]*\*' && chk sudo.wildcards WARN "$(printf '%s' "$SUDOALL" | grep -E '\*' | head -2 | tr '\n' ';')" "wildcards in a sudo command spec usually expand further than intended (path traversal into an arbitrary binary)"
  printf '%s' "$SUDOALL" | grep -qiE 'secure_path' && chk sudo.secure_path PASS "secure_path set" "" \
    || chk sudo.secure_path FAIL "secure_path not set" "sudo uses the caller's PATH, so a writable directory in it becomes root code execution"
fi

# ---- sudoers hygiene: the file itself, its includes, and the Defaults that weaken auth ----
raw "sudoers file permissions and syntax"
ls -l "$(rf /etc/sudoers)" 2>/dev/null; ls -l "$(rf /etc/sudoers.d/)" 2>/dev/null
SM="$(stat -c '%a %U:%G' "$(rf /etc/sudoers)" 2>/dev/null)"
case "${SM%% *}" in 440|400|0440|0400) chk sudo.file_perms PASS "$SM" "" ;;
  "") ;; *) chk sudo.file_perms FAIL "$SM" "/etc/sudoers must be 0440 root:root: anything writable here is a direct root grant" ;; esac
for f in "$LSA_ROOT"/etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  m="$(stat -c '%a %U:%G' "$f" 2>/dev/null)"
  case "${m%% *}" in 440|400|0440|0400) ;; *) chk "sudo.dperms.$(basename "$f")" FAIL "$m $f" "sudoers.d file with permissions looser than 0440" ;; esac
  case "$m" in *" root:"*) ;; *) chk "sudo.downer.$(basename "$f")" FAIL "$m $f" "sudoers.d file not owned by root" ;; esac
done
have visudo && { raw "visudo -c (syntax validity)"; run visudo -c 2>&1 | cap 10; }
raw "sudoers include directives"
grep -hE '^\s*[#@]include' "$(rf /etc/sudoers)" 2>/dev/null

raw "Defaults that weaken authentication"
printf '%s' "$SUDOALL" | grep -qE 'timestamp_timeout\s*=\s*-1' \
  && chk sudo.timestamp_timeout FAIL "timestamp_timeout=-1" "the sudo credential cache never expires for the session: one authentication grants root indefinitely"
TSV="$(printf '%s' "$SUDOALL" | grep -oE 'timestamp_timeout\s*=\s*[0-9]+' | head -1 | grep -oE '[0-9]+$')"
[ -n "$TSV" ] && [ "$TSV" -gt 15 ] 2>/dev/null && chk sudo.timestamp_long WARN "timestamp_timeout=$TSV" "long credential cache window"
printf '%s' "$SUDOALL" | grep -qE '!\s*tty_tickets' \
  && chk sudo.tty_tickets FAIL "!tty_tickets" "the sudo timestamp is shared across all of the user's terminals: another process in another TTY can sudo without a password"
printf '%s' "$SUDOALL" | grep -qE '(^|\s)pwfeedback' \
  && chk sudo.pwfeedback FAIL "pwfeedback enabled" "CVE-2019-18634: a stack buffer overflow reachable by any local user when pwfeedback is on (sudo < 1.8.31)"
printf '%s' "$SUDOALL" | grep -qE 'Defaults.*\btargetpw\b|Defaults.*\brootpw\b|Defaults.*\brunaspw\b' \
  && chk sudo.targetpw WARN "$(printf '%s' "$SUDOALL" | grep -E 'targetpw|rootpw|runaspw' | head -1)" "changes which password sudo asks for: rootpw means users must know the root password, which usually means it is shared"
printf '%s' "$SUDOALL" | grep -qE 'Defaults.*!\s*requiretty' && chk sudo.requiretty INFO "!requiretty" "sudo usable without a TTY (needed for some automation; also removes a small barrier to non-interactive abuse)"
printf '%s' "$SUDOALL" | grep -qE 'NOEXEC' && chk sudo.noexec PASS "NOEXEC tag used" "prevents the sudo'd command from spawning further programs"

raw "who has sudo, resolved through group membership"
for g in sudo wheel admin sudoers; do
  M="$(getent group "$g" 2>/dev/null | cut -d: -f4)"
  [ -n "$M" ] && printf '  %-10s %s\n' "$g" "$M"
done
printf '%s\n' "$SUDOALL" | grep -E '^\s*%' | cap 10
raw "sudo grants for the invoking user (non-authoritative: only this account)"
[ "$PROBE" = "1" ] && { active_on; run sudo -n -l 2>/dev/null | cap 20; active_off; }
raw "recent sudo usage from the logs"
grep -rhs 'sudo:' "$(rf /var/log/auth.log)" "$(rf /var/log/secure)" 2>/dev/null | tail -10
have journalctl && run journalctl -q --no-pager -n 10 -t sudo 2>/dev/null

# ---- PATH: a writable or relative element is code execution as whoever uses it ----
raw "PATH analysis"
printf '  PATH=%s\n' "$PATH"
BADPATH=""
OLDIFS="$IFS"; IFS=:
for d in $PATH; do
  case "$d" in
    ""|.|./*) BADPATH="$BADPATH [relative:'${d:-empty}']" ; continue ;;
  esac
  [ -d "$d" ] || continue
  if [ -w "$d" ] && [ "$AM_ROOT" != "1" ]; then BADPATH="$BADPATH [writable:$d]"; fi
  # -L: a symlink is always mode 0777, so without dereferencing, merged-/usr systems report
  # /bin and /sbin as world-writable when the real directories are 0755 root:root.
  P="$(stat -L -c '%a %U' "$d" 2>/dev/null)"
  case "${P%% *}" in *[2367]) BADPATH="$BADPATH [world-writable:$d]" ;; esac
done
IFS="$OLDIFS"
runtime_on   # $PATH belongs to the shell running the audit, never to a mounted image
[ -n "$BADPATH" ] && chk privesc.path FAIL "$BADPATH" "a writable, world-writable, empty or relative PATH element lets an attacker place a binary that a higher-privileged user then executes by name" \
                  || chk privesc.path PASS "no writable or relative PATH elements" ""
method_reset

# ---- writable systemd units and the binaries they run ----
raw "writable systemd unit files (a writable unit is root at next start/reboot)"
WUNITS="$(find "$(rf /etc/systemd/system)" "$(rf /lib/systemd/system)" "$(rf /usr/lib/systemd/system)" /run/systemd/system \
  -maxdepth 2 -type f ! -type l \( -perm -0002 -o -perm -0020 \) -print 2>/dev/null | head -20)"
if [ -n "$WUNITS" ]; then
  printf '%s\n' "$WUNITS" | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null
  chk privesc.writable_units FAIL "$(printf '%s' "$WUNITS" | tr '\n' ' ' | cut -c1-160)" "group- or world-writable unit file: whoever can write it controls a command that systemd runs as root"
else
  chk privesc.writable_units PASS "no group/world-writable unit files" ""
fi
raw "unit files not owned by root"
find "$(rf /etc/systemd/system)" "$(rf /lib/systemd/system)" "$(rf /usr/lib/systemd/system)" -maxdepth 2 -type f ! -user root -print 2>/dev/null | cap 10
raw "writable ExecStart binaries of running units"
if have systemctl; then
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -40 | while read -r u; do
    b="$(systemctl show "$u" -p ExecStart --value 2>/dev/null | grep -oE '/[^ ;"]+' | head -1)"
    [ -n "$b" ] && [ -f "$b" ] || continue
    m="$(stat -c '%a %U' "$b" 2>/dev/null)"
    case "${m%% *}" in
      *[2367]) printf '  WORLD-WRITABLE %s %s (%s)\n' "$m" "$b" "$u" ;;
      ?[2367]?) printf '  GROUP-WRITABLE %s %s (%s)\n' "$m" "$b" "$u" ;;
    esac
    case "$m" in *" root") ;; *) printf '  NOT-ROOT-OWNED %s %s (%s)\n' "$m" "$b" "$u" ;; esac
  done | cap 20
fi

# ---- NFS exports: no_root_squash is a one-line root escalation for any client ----
if [ -r "$(rf /etc/exports)" ] || [ -d "$(rf /etc/exports.d)" ]; then
  raw "NFS exports"
  grep -hvE '^\s*#|^\s*$' "$(rf /etc/exports)" "$LSA_ROOT"/etc/exports.d/* 2>/dev/null
  EXP="$(grep -hvE '^\s*#|^\s*$' "$(rf /etc/exports)" "$LSA_ROOT"/etc/exports.d/* 2>/dev/null)"
  printf '%s' "$EXP" | grep -q 'no_root_squash' \
    && chk nfs.no_root_squash FAIL "$(printf '%s' "$EXP" | grep 'no_root_squash' | head -2 | tr '\n' ';')" "any client that can mount this export writes files as real root; mount it, drop a SUID root shell, run it. This is a complete compromise of the exporting host" \
    || chk nfs.no_root_squash PASS "no no_root_squash" ""
  printf '%s' "$EXP" | grep -q 'no_all_squash' && chk nfs.no_all_squash WARN "present" "client UIDs are trusted verbatim"
  printf '%s' "$EXP" | grep -qE '^\s*\S+\s+\*' && chk nfs.world_exported FAIL "$(printf '%s' "$EXP" | grep -E '\s\*' | head -2 | tr '\n' ';')" "exported to * (every host that can reach the NFS port)"
  printf '%s' "$EXP" | grep -q 'insecure' && chk nfs.insecure_ports WARN "insecure option" "allows requests from unprivileged source ports"
  have showmount && [ "$PROBE" = "1" ] && { raw "showmount -e localhost"; active_on; run showmount -e localhost 2>/dev/null; active_off; }
fi
raw "NFS mounts on this host (client side)"
grep -E '\snfs[45]?\s' /proc/mounts 2>/dev/null | cap 10

# ---- credentials and keys lying around ----
raw "private keys and credential files with weak permissions"
for d in "$LSA_ROOT"/root "$LSA_ROOT"/home/*; do
  [ -d "$d" ] || continue
  for f in "$d"/.ssh/id_* "$d"/.ssh/*.pem "$d"/.netrc "$d"/.pgpass "$d"/.git-credentials \
           "$d"/.aws/credentials "$d"/.docker/config.json "$d"/.kube/config "$d"/.gnupg/*.key; do
    [ -f "$f" ] || continue
    case "$f" in *.pub) continue ;; esac
    mo="$(statmode "$f")"; ow="$(statown "$f")"
    if [ -z "$mo" ]; then
      chk "cred.perm.$(basename "$d")-$(basename "$f")" NA "stat failed for $f" "mode not determinable, not a failure"
      continue
    fi
    # Only the GROUP and OTHER bits define "readable beyond owner". Owner identity is
    # irrelevant, and resolving owner NAMES across an offline mount is unreliable because
    # uid->name mapping differs from the target system (field feedback §3).
    g="$(printf '%s' "$mo" | sed 's/.*\(.\)./\1/')"; o="$(printf '%s' "$mo" | sed 's/.*\(.\)/\1/')"
    if [ "$o" = "0" ] && { [ "$g" = "0" ] || [ "$g" = "4" ]; }; then
      printf '  ok   %s (uid:gid %s) %s\n' "$mo" "$ow" "$f"
    else
      printf '  WEAK %s (uid:gid %s) %s\n' "$mo" "$ow" "$f"
      chk "cred.perm.$(basename "$d")-$(basename "$f")" FAIL "mode $mo (uid:gid $ow) $f" "group or other bits are set on a credential/private-key file: must be 0600, or 0640 with a deliberate group"
    fi
  done
done
raw "unencrypted SSH private keys (no passphrase = usable immediately if stolen)"
for k in "$LSA_ROOT"/root/.ssh/id_* "$LSA_ROOT"/home/*/.ssh/id_*; do
  [ -f "$k" ] || continue; case "$k" in *.pub) continue ;; esac
  if head -3 "$k" 2>/dev/null | grep -q 'ENCRYPTED'; then printf '  encrypted   %s\n' "$k"
  else printf '  UNENCRYPTED %s\n' "$k"; fi
done
raw ".rhosts / .forward / hosts.equiv (legacy trust, remote login without auth)"
ls -l "$(rf /root/.rhosts)" "$LSA_ROOT"/home/*/.rhosts "$(rf /root/.forward)" "$LSA_ROOT"/home/*/.forward "$(rf /etc/hosts.equiv)" 2>/dev/null
[ -e "$(rf /etc/hosts.equiv)" ] && chk privesc.hosts_equiv FAIL "present" "host-based trust without authentication"

# ---- shell history: anti-forensics and leaked secrets ----
raw "shell history configuration and anti-forensics indicators"
for h in "$LSA_ROOT"/root/.bash_history "$LSA_ROOT"/home/*/.bash_history "$LSA_ROOT"/root/.zsh_history "$LSA_ROOT"/home/*/.zsh_history; do
  [ -e "$h" ] || continue
  if [ -L "$h" ]; then
    printf '  SYMLINK %s -> %s\n' "$h" "$(readlink "$h")"
    chk privesc.history_nulled FAIL "$h -> $(readlink "$h")" "history redirected to /dev/null: deliberate anti-forensics, treat as a compromise indicator until explained"
  else
    printf '  %s %s (%s bytes)\n' "$(stat -c '%a %U' "$h" 2>/dev/null)" "$h" "$(stat -c '%s' "$h" 2>/dev/null)"
  fi
done
grep -rhsE '^\s*(export\s+)?(HISTFILE|HISTSIZE|HISTFILESIZE|HISTCONTROL)\s*=' "$(rf /etc/profile)" "$(rf /etc/bash.bashrc)" "$(rf /etc/profile.d/)" "$(rf /root/.bashrc)" "$LSA_ROOT"/home/*/.bashrc 2>/dev/null | sort -u | cap 10
grep -rqsE '(HISTFILE=/dev/null|HISTSIZE=0|unset\s+HISTFILE)' "$(rf /etc/profile)" "$(rf /etc/profile.d/)" "$(rf /root/.bashrc)" "$LSA_ROOT"/home/*/.bashrc 2>/dev/null \
  && chk privesc.history_disabled FAIL "HISTFILE=/dev/null or HISTSIZE=0 configured" "command history disabled system-wide or for a user: removes the record of what was run"
raw "possible secrets in shell history (pattern match only, no values shown)"
for h in "$LSA_ROOT"/root/.bash_history "$LSA_ROOT"/home/*/.bash_history; do
  [ -r "$h" ] || continue
  n="$(grep -ciE '(password|passwd|secret|token|api[_-]?key|-p[[:alnum:]]|curl.*-u )' "$h" 2>/dev/null)"
  [ "${n:-0}" -gt 0 ] && printf '  %s: %s line(s) matching credential patterns\n' "$h" "$n"
done

# ---- user dotfile permissions (CIS) ----
raw "group/world-writable dotfiles in home directories"
find "$(rf /root)" "$(rf /home)" -maxdepth 2 -name '.*' -type f \( -perm -0002 -o -perm -0020 \) -print 2>/dev/null | cap 15

# ---- binfmt_misc: registered interpreters run on execve of a matching file ----
if [ -d /proc/sys/fs/binfmt_misc ]; then
  raw "binfmt_misc registered handlers"
  ls /proc/sys/fs/binfmt_misc/ 2>/dev/null
  BF="$(ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -vE '^(register|status)$' | tr '\n' ' ')"
  [ -n "$BF" ] && chk privesc.binfmt_misc WARN "$BF" "registered non-native binary formats: each maps a file signature to an interpreter that runs on execve. Useful for qemu/wine, but also a quiet execution and persistence vector; disable the mount if unused"
fi

# ---- compilers and interpreters present on a server ----
raw "compilers and their permissions"
for c in gcc cc g++ clang tcc make ld as cargo go javac rustc; do
  if [ "$OFFLINE" = "1" ]; then
    for _cd in /usr/bin /usr/sbin /bin /sbin /usr/local/bin; do
      p="${LSA_ROOT}${_cd}/$c"; [ -x "$p" ] && break || p=""
    done
  else
    p="$(command -v "$c" 2>/dev/null)"
  fi
  [ -n "$p" ] && printf '  %s %s\n' "$(stat -c '%a %U:%G' "$p" 2>/dev/null)" "$p"
done
COMPS="$(for c in gcc cc g++ clang tcc; do have_target "$c" && printf '%s ' "$c"; done)"
[ -n "$COMPS" ] && chk hardening.compilers WARN "$COMPS" "compilers on a production server let an attacker build local privilege-escalation exploits in place. Remove them, or restrict to a group (chmod 750, chgrp compiler)"

# ---- writable SUID/SGID binaries: instant root ----
if [ "$QUICK" != "1" ]; then
  raw "writable SUID/SGID binaries"
  _oifs=$IFS; IFS=$'\n'
  for d in $SCANDIRS; do
    find "$d" -xdev \( -perm -4000 -o -perm -2000 \) -type f -perm -0022 -print 2>/dev/null
  done | head -10 | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null
  IFS=$_oifs
fi

# ------------------------------------------------- 24. DATA SERVICE AUTHENTICATION
# TLS (section TLS) covers transport. This covers whether anything checks WHO is connecting.
sec DATA_SERVICES_AUTH

# Redis: historically no auth at all; an unauthenticated Redis is a reliable RCE
RCONF="$(ls "$(rf /etc/redis/redis.conf)" "$(rf /etc/redis.conf)" 2>/dev/null | head -1)"
if [ -n "$RCONF" ] || pgrep -x redis-server >/dev/null 2>&1; then
  raw "redis auth settings"
  grep -hE '^\s*(bind|protected-mode|requirepass|user\s|aclfile|rename-command|port|tls-port)' "$RCONF" 2>/dev/null
  grep -qE '^\s*requirepass\s+\S' "$RCONF" 2>/dev/null \
    && chk dbauth.redis_password PASS "requirepass set" "" \
    || { grep -qE '^\s*aclfile' "$RCONF" 2>/dev/null \
         && chk dbauth.redis_password PASS "ACL file configured" "" \
         || chk dbauth.redis_password FAIL "no requirepass and no aclfile" "unauthenticated Redis: an attacker sets dir/dbfilename and writes an SSH key or a cron entry as the redis user: a well-known path to RCE"; }
  grep -qE '^\s*protected-mode\s+no' "$RCONF" 2>/dev/null \
    && chk dbauth.redis_protected FAIL "protected-mode no" "the last-resort guard against unauthenticated remote access is disabled"
  grep -qE '^\s*bind\s+127\.0\.0\.1|^\s*bind\s+.*::1' "$RCONF" 2>/dev/null \
    && chk dbauth.redis_bind PASS "bound to loopback" "" \
    || chk dbauth.redis_bind WARN "$(grep -hE '^\s*bind' "$RCONF" 2>/dev/null | head -1)" "not loopback-only"
  grep -qE '^\s*rename-command\s+(CONFIG|FLUSHALL|FLUSHDB)' "$RCONF" 2>/dev/null \
    && chk dbauth.redis_rename PASS "dangerous commands renamed" "" \
    || chk dbauth.redis_rename INFO "CONFIG not renamed" "renaming CONFIG blocks the write-a-file escalation even if auth is bypassed"
fi

# MongoDB
if [ -r "$(rf /etc/mongod.conf)" ]; then
  raw "mongodb auth settings"
  grep -E '^\s*(security:|  authorization:|  keyFile:|net:|  bindIp:|  port:)' "$(rf /etc/mongod.conf)" 2>/dev/null
  grep -qE '^\s*authorization:\s*enabled' "$(rf /etc/mongod.conf)" 2>/dev/null \
    && chk dbauth.mongodb PASS "authorization enabled" "" \
    || chk dbauth.mongodb FAIL "authorization not enabled" "MongoDB with authorization disabled grants full read/write of every database to anyone who can connect: the single most-ransomed database misconfiguration"
  grep -qE '^\s*bindIp:\s*(0\.0\.0\.0|::)' "$(rf /etc/mongod.conf)" 2>/dev/null \
    && chk dbauth.mongodb_bind FAIL "bindIp 0.0.0.0" "listening on all interfaces"
fi

# MySQL / MariaDB
if have mysql || [ -d "$(rf /etc/mysql)" ]; then
  raw "mysql/mariadb auth-relevant settings"
  grep -rhE '^\s*(bind-address|skip-networking|skip-grant-tables|local-infile|secure-file-priv|require_secure_transport)' "$(rf /etc/mysql/)" "$(rf /etc/my.cnf)" "$(rf /etc/my.cnf.d/)" 2>/dev/null
  grep -rqE '^\s*skip-grant-tables' "$(rf /etc/mysql/)" "$(rf /etc/my.cnf)" "$(rf /etc/my.cnf.d/)" 2>/dev/null \
    && chk dbauth.mysql_skipgrant FAIL "skip-grant-tables enabled" "ALL authentication is disabled: anyone who can connect is root on the database"
  grep -rqE '^\s*local-infile\s*=\s*1' "$(rf /etc/mysql/)" "$(rf /etc/my.cnf)" "$(rf /etc/my.cnf.d/)" 2>/dev/null \
    && chk dbauth.mysql_local_infile WARN "local-infile=1" "enables client-side file read via LOAD DATA LOCAL: an SQLi becomes arbitrary file disclosure"
  grep -rhqE '^\s*bind-address\s*=\s*(0\.0\.0\.0|\*|::)' "$(rf /etc/mysql/)" "$(rf /etc/my.cnf)" "$(rf /etc/my.cnf.d/)" 2>/dev/null \
    && chk dbauth.mysql_bind WARN "bind-address 0.0.0.0" "listening on all interfaces"
  raw "credentials in world-readable my.cnf / .my.cnf files"
  for f in /etc/mysql/debian.cnf /root/.my.cnf /home/*/.my.cnf; do
    [ -f "$f" ] || continue
    m="$(stat -c '%a %U' "$f" 2>/dev/null)"
    printf '  %s %s\n' "$m" "$f"
    case "${m%% *}" in *[4567]) chk "dbauth.mycnf.$(basename "$f")" FAIL "$m $f" "file contains a database password and is world-readable" ;; esac
  done
fi

# PostgreSQL: 'trust' in pg_hba means no password at all
PGHBA2="$(ls "$LSA_ROOT"/etc/postgresql/*/main/pg_hba.conf "$(rf /var/lib/pgsql/data/pg_hba.conf)" 2>/dev/null | head -1)"
if [ -n "$PGHBA2" ]; then
  raw "postgresql pg_hba.conf auth methods"
  grep -vE '^\s*#|^\s*$' "$PGHBA2" 2>/dev/null | cap 20
  grep -qE '^\s*(local|host|hostssl|hostnossl)\s+.*\s+trust\s*$' "$PGHBA2" 2>/dev/null \
    && chk dbauth.postgres_trust FAIL "$(grep -E '\strust\s*$' "$PGHBA2" | head -2 | tr '\n' ';')" "'trust' authentication accepts any connection as any database user with NO password" \
    || chk dbauth.postgres_trust PASS "no trust auth methods" ""
  grep -qE '^\s*host\s+.*\s+(password|md5)\s*$' "$PGHBA2" 2>/dev/null \
    && chk dbauth.postgres_weakauth WARN "md5 or cleartext password auth in use" "prefer scram-sha-256"
fi

# Elasticsearch / OpenSearch
if [ -r "$(rf /etc/elasticsearch/elasticsearch.yml)" ] || [ -r "$(rf /etc/opensearch/opensearch.yml)" ]; then
  EY="$(ls "$(rf /etc/elasticsearch/elasticsearch.yml)" "$(rf /etc/opensearch/opensearch.yml)" 2>/dev/null | head -1)"
  raw "elasticsearch/opensearch security settings"
  grep -hE '^\s*(xpack\.security|network\.host|http\.port|plugins\.security)' "$EY" 2>/dev/null
  grep -qE '^\s*xpack\.security\.enabled:\s*true' "$EY" 2>/dev/null \
    && chk dbauth.elasticsearch PASS "xpack.security.enabled true" "" \
    || chk dbauth.elasticsearch FAIL "security not enabled" "unauthenticated Elasticsearch exposes every index for read and write: a standard mass-ransom target"
fi

# SNMP: community strings are passwords, and the defaults are universally known
SNMPC="$(ls "$(rf /etc/snmp/snmpd.conf)" 2>/dev/null | head -1)"
if [ -n "$SNMPC" ]; then
  raw "snmpd configuration"
  grep -hvE '^\s*#|^\s*$' "$SNMPC" 2>/dev/null | cap 20
  if grep -qE '^\s*(rocommunity|rwcommunity)6?\s+(public|private)\b' "$SNMPC" 2>/dev/null; then
    chk snmp.default_community FAIL "$(grep -E '^\s*r[ow]community' "$SNMPC" | head -2 | tr '\n' ';')" "default community string: 'public'/'private' are the first thing any scanner tries, and they expose a full inventory of the host (and with rwcommunity, write access)"
  else
    chk snmp.default_community PASS "no default community strings" ""
  fi
  grep -qE '^\s*rwcommunity' "$SNMPC" 2>/dev/null && chk snmp.write_community FAIL "rwcommunity configured" "SNMP write access can reconfigure the device"
  grep -qE '^\s*(createUser|authpriv|usmUser)' "$SNMPC" 2>/dev/null \
    && chk snmp.v3 PASS "SNMPv3 user configured" "" \
    || chk snmp.v3 WARN "no SNMPv3" "SNMP v1/v2c sends the community string in cleartext"
fi

# ------------------------------------------------- 25. INSECURE / DEFAULT-OPEN SERVICES
# Services that are either cleartext by design, or ship with an insecure default that
# most installs never change. Each is reported as installed / enabled / listening:
# an installed-but-inert package is a different finding from a live listener.
sec INSECURE_SERVICES

pkg_installed() {
  if have dpkg-query; then dpkg-query ${DPKGOPT:-} -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
  elif have rpm; then rpm ${RPMOPT:-} -q "$1" >/dev/null 2>&1
  elif have apk; then apk info -e "$1" >/dev/null 2>&1
  else return 1; fi
}
svc_active()  { have systemctl && systemctl is-active  "$1" >/dev/null 2>&1; }
svc_enabled() { have systemctl && systemctl is-enabled "$1" >/dev/null 2>&1; }
port_listening() { have ss && ss -tulnH 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${1}\$"; }
port_public()    { have ss && ss -tulnH 2>/dev/null | awk '{print $5}' | grep -vE '^(127\.|\[::1\])' | grep -qE "[:.]${1}\$"; }

# id | packages | systemd units | port | why it is a finding
CLEARTEXT='telnet|telnetd telnet-server inetutils-telnetd krb5-telnet|telnet.socket telnet.service inetd|23|credentials and the entire session in cleartext; the protocol has no integrity protection at all
rsh|rsh-server rsh-redone-server rsh|rsh.socket rlogin.socket rexec.socket|514|.rhosts host-based trust with no cryptography; credentials in cleartext
rlogin|rsh-server|rlogin.socket|513|cleartext, host-based trust
rexec|rsh-server|rexec.socket|512|cleartext remote execution
ftp|vsftpd proftpd-basic pure-ftpd ftpd inetutils-ftpd|vsftpd proftpd pure-ftpd|21|credentials and data in cleartext unless TLS is explicitly forced; anonymous access is a frequent default
tftp|tftpd tftpd-hpa atftpd|tftpd-hpa.service tftp.socket atftpd|69|NO authentication whatsoever, UDP; historically used to pull and push firmware/configs
finger|fingerd efingerd|finger.socket|79|enumerates local users and their login habits to anyone
talk|talkd ntalk|talk.socket ntalk.socket|518|legacy, unauthenticated
nis|nis ypserv ypbind|ypserv ypbind nis|0|NIS distributes the password map over the network with weak/no protection
rpcbind|rpcbind portmap|rpcbind.service rpcbind.socket|111|enumerates every RPC service; a UDP amplification reflector
avahi|avahi-daemon|avahi-daemon.service avahi-daemon.socket|5353|mDNS advertises the host and its services to the whole L2 segment; large parsing attack surface
cups|cups cups-daemon|cups.service cups.socket|631|print service; only ever needed on a workstation, and its network share mode exposes it
xinetd|xinetd|xinetd.service|0|legacy super-server; audit what it actually starts
inetd|openbsd-inetd inetutils-inetd|inetd.service|0|legacy super-server
squid|squid squid3|squid.service|3128|an open forward proxy is used to pivot into your network and to launder traffic
snmpd|snmpd net-snmp|snmpd.service|161|v1/v2c community strings in cleartext
memcached|memcached|memcached.service|11211|no authentication by design; the UDP port is a very high-factor amplification reflector
vnc|tigervnc-standalone-server x11vnc vnc4server tightvncserver|vncserver@.service x11vnc|5900|weak/absent auth and a cleartext framebuffer unless tunnelled
dhcpd|isc-dhcp-server dhcp-server|isc-dhcp-server.service|67|a rogue or misconfigured DHCP server can redirect an entire segment'

runtime_on
raw "cleartext and legacy service inventory"
printf '%s\n' "$CLEARTEXT" | while IFS='|' read -r id pkgs units port why; do
  [ -z "$id" ] && continue
  st=""; det=""
  for p in $pkgs; do pkg_installed "$p" && { st="installed"; det="$det pkg:$p"; }; done
  for u in $units; do
    svc_enabled "$u" && { st="enabled"; det="$det enabled:$u"; }
    svc_active  "$u" && { st="ACTIVE";  det="$det active:$u"; }
  done
  if [ "$port" != "0" ] && port_listening "$port"; then
    st="LISTENING"; det="$det port:$port"
    port_public "$port" && { st="LISTENING-PUBLIC"; det="$det (non-loopback)"; }
  fi
  [ -z "$st" ] && continue
  case "$st" in
    LISTENING-PUBLIC) chk "insecure.$id" FAIL "$st: $det" "$why" ;;
    LISTENING|ACTIVE) chk "insecure.$id" FAIL "$st: $det" "$why" ;;
    enabled)          chk "insecure.$id" FAIL "enabled at boot: $det" "$why" ;;
    installed)        chk "insecure.$id" WARN "installed, not running: $det" "not currently exposed, but present for an attacker to start or to use as a client. $why" ;;
  esac
done

static_on
# ---- rsync daemon: the classic 'anyone can read/write the whole share' service ----
if [ -r "$(rf /etc/rsyncd.conf)" ] || [ -d "$(rf /etc/rsyncd.d)" ] || port_listening 873 || svc_active rsync || svc_active rsyncd; then
  raw "rsync daemon configuration"
  grep -hvE '^\s*#|^\s*$' "$(rf /etc/rsyncd.conf)" "$LSA_ROOT"/etc/rsyncd.d/* 2>/dev/null
  RS="$(grep -hvE '^\s*#|^\s*$' "$(rf /etc/rsyncd.conf)" "$LSA_ROOT"/etc/rsyncd.d/* 2>/dev/null)"
  if [ -n "$RS" ]; then
    # per-module view: name, read only, auth users, hosts allow, uid, chroot
    raw "rsync modules"
    awk '
      function flush() {
        if (m!="") printf "  [%s] path=%-24s read_only=%-5s auth_users=%-10s hosts_allow=%-16s uid=%-6s chroot=%s\n",
          m, (pth==""?"-":pth), (ro==""?"yes(default)":ro), (au==""?"NONE":au), (ha==""?"NONE":ha), (uid==""?"root(default)":uid), (ch==""?"yes(default)":ch)
      }
      /^[[:space:]]*\[/ {flush(); m=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/,"",m); pth="";ro="";au="";ha="";uid="";ch=""; next}
      /^[[:space:]]*path[[:space:]]*=/            {split($0,a,"="); gsub(/^[[:space:]]+|[[:space:]]+$/,"",a[2]); pth=a[2]}
      /^[[:space:]]*read[[:space:]]*only[[:space:]]*=/ {split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); ro=tolower(a[2])}
      /^[[:space:]]*write[[:space:]]*only[[:space:]]*=/ {next}
      /^[[:space:]]*auth[[:space:]]*users[[:space:]]*=/ {split($0,a,"="); gsub(/^[[:space:]]+/,"",a[2]); au=a[2]}
      /^[[:space:]]*hosts[[:space:]]*allow[[:space:]]*=/ {split($0,a,"="); gsub(/^[[:space:]]+/,"",a[2]); ha=a[2]}
      /^[[:space:]]*uid[[:space:]]*=/             {split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); uid=a[2]}
      /^[[:space:]]*use[[:space:]]*chroot[[:space:]]*=/ {split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); ch=tolower(a[2])}
      END {flush()}
    ' /etc/rsyncd.conf /etc/rsyncd.d/* 2>/dev/null

    # writable modules: "read only = no" with no auth users is anonymous write to the filesystem
    WRMOD="$(awk '
      /^[[:space:]]*\[/ {if(m!="" && ro=="no" && au=="") print m; m=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/,"",m); ro="";au=""; next}
      /^[[:space:]]*read[[:space:]]*only[[:space:]]*=/ {split($0,a,"="); gsub(/[[:space:]]/,"",a[2]); ro=tolower(a[2])}
      /^[[:space:]]*auth[[:space:]]*users[[:space:]]*=/ {au="set"}
      END {if(m!="" && ro=="no" && au=="") print m}
    ' /etc/rsyncd.conf /etc/rsyncd.d/* 2>/dev/null | tr '\n' ' ')"
    [ -n "$WRMOD" ] && chk rsync.anonymous_write FAIL "modules: $WRMOD" "'read only = no' with no 'auth users': ANY host that can reach tcp/873 can WRITE into this path anonymously. If the path is served by a web server or read by a cron job, that is remote code execution; if uid=root, it is arbitrary file write as root" \
                    || chk rsync.anonymous_write PASS "no anonymous-writable modules" ""

    printf '%s' "$RS" | grep -qE '^\s*auth\s*users\s*=' \
      && chk rsync.auth PASS "auth users configured" "also confirm the secrets file is 0600 and the passwords are not reused" \
      || chk rsync.auth FAIL "no 'auth users' in any module" "the rsync daemon protocol is unauthenticated by default: every module is world-readable to anyone who can reach the port"
    printf '%s' "$RS" | grep -qE '^\s*hosts\s*allow\s*=' \
      && chk rsync.hosts_allow PASS "hosts allow set" "" \
      || chk rsync.hosts_allow FAIL "no 'hosts allow'" "no source-address restriction; combine with a public tcp/873 and the share is world-accessible"
    UIDR="$(printf '%s' "$RS" | grep -E '^\s*uid\s*=' | head -1)"
    case "$UIDR" in *root*) chk rsync.uid FAIL "$UIDR" "the daemon reads and writes as root; any path traversal or writable module is a root-level file operation" ;;
      "") chk rsync.uid WARN "uid not set (defaults to nobody on most builds, root on some)" "set 'uid = nobody' explicitly" ;; esac
    printf '%s' "$RS" | grep -qE '^\s*use\s*chroot\s*=\s*(no|false|0)' \
      && chk rsync.chroot FAIL "use chroot = no" "without chroot, symlinks inside the module escape it and expose the wider filesystem"
    SECF="$(printf '%s' "$RS" | grep -E '^\s*secrets\s*file\s*=' | head -1 | cut -d= -f2 | tr -d ' ')"
    if [ -n "$SECF" ] && [ -e "$SECF" ]; then
      M="$(stat -c '%a %U' "$SECF" 2>/dev/null)"
      case "${M%% *}" in 600|400|0600|0400) chk rsync.secrets PASS "$M $SECF" "" ;;
        *) chk rsync.secrets FAIL "$M $SECF" "rsync secrets file holds cleartext passwords and must be 0600" ;; esac
    fi
    printf '%s' "$RS" | grep -qE '^\s*(port|address)\s*=' && printf '%s\n' "$RS" | grep -E '^\s*(port|address)\s*='
  fi
  port_public 873 && chk rsync.exposed FAIL "tcp/873 on a non-loopback address" "the rsync daemon protocol is cleartext and unauthenticated by default"
fi
raw "rsync in cron/scripts using the unauthenticated daemon protocol (rsync://)"
grep -rhsE 'rsync://[^ ]*' "$(rf /etc/cron.d/)" "$(rf /etc/crontab)" "$(rf /etc/systemd/system)" 2>/dev/null | head -5

# ---- FTP servers ----
if [ -r "$(rf /etc/vsftpd.conf)" ] || [ -r "$(rf /etc/vsftpd/vsftpd.conf)" ]; then
  VC="$(ls "$(rf /etc/vsftpd.conf)" "$(rf /etc/vsftpd/vsftpd.conf)" 2>/dev/null | head -1)"
  raw "vsftpd configuration"
  grep -hvE '^\s*#|^\s*$' "$VC" 2>/dev/null
  vs() { grep -hiE "^\s*$1\s*=" "$VC" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '; }
  [ "$(vs anonymous_enable)" = "YES" ] && chk ftp.anonymous FAIL "anonymous_enable=YES" "anyone may log in without credentials" \
                                       || chk ftp.anonymous PASS "anonymous_enable not YES" ""
  [ "$(vs anon_upload_enable)" = "YES" ] && chk ftp.anon_upload FAIL "anon_upload_enable=YES" "ANONYMOUS WRITE: unauthenticated file upload to the server"
  [ "$(vs anon_mkdir_write_enable)" = "YES" ] && chk ftp.anon_mkdir FAIL "anon_mkdir_write_enable=YES" "anonymous directory creation"
  [ "$(vs ssl_enable)" = "YES" ] && {
    [ "$(vs force_local_logins_ssl)" = "NO" ] || [ "$(vs force_local_data_ssl)" = "NO" ] \
      && chk ftp.tls WARN "ssl_enable=YES but force_*_ssl=NO" "TLS available but not required: clients still send credentials in cleartext" \
      || chk ftp.tls PASS "ssl_enable=YES and forced" ""; } \
    || chk ftp.tls FAIL "ssl_enable not YES" "FTP credentials and data traverse the network in cleartext"
  [ "$(vs chroot_local_user)" = "YES" ] && chk ftp.chroot PASS "chroot_local_user=YES" "" \
                                        || chk ftp.chroot WARN "chroot_local_user not YES" "authenticated users can browse the whole filesystem"
  [ "$(vs write_enable)" = "YES" ] && chk ftp.write INFO "write_enable=YES" "uploads permitted; confirm the target directory is not served or executed by a web server"
fi
if [ -r "$(rf /etc/proftpd/proftpd.conf)" ] || [ -r "$(rf /etc/proftpd.conf)" ]; then
  PC="$(ls "$(rf /etc/proftpd/proftpd.conf)" "$(rf /etc/proftpd.conf)" 2>/dev/null | head -1)"
  raw "proftpd configuration"
  grep -hiE '^\s*(<Anonymous|User|Group|RequireValidShell|DefaultRoot|TLSEngine|TLSRequired|AllowOverwrite|<Limit|AllowAll|DenyAll|UseFtpUsers)' "$PC" 2>/dev/null | cap 25
  grep -qiE '^\s*<Anonymous' "$PC" 2>/dev/null && chk ftp.proftpd_anonymous FAIL "<Anonymous> block present" "anonymous FTP access configured"
  grep -qiE '^\s*TLSEngine\s+on' "$PC" 2>/dev/null || chk ftp.proftpd_tls FAIL "TLSEngine not on" "cleartext credentials"
  grep -qiE '^\s*DefaultRoot\s+~' "$PC" 2>/dev/null || chk ftp.proftpd_chroot WARN "no DefaultRoot ~" "users are not confined to their home directory"
fi
if [ -d "$(rf /etc/pure-ftpd)" ]; then
  raw "pure-ftpd configuration"
  ls "$(rf /etc/pure-ftpd/conf/)" 2>/dev/null
  [ -e "$(rf /etc/pure-ftpd/conf/NoAnonymous)" ] && printf 'NoAnonymous=%s\n' "$(cat "$(rf /etc/pure-ftpd/conf/NoAnonymous)" 2>/dev/null)"
  [ -e "$(rf /etc/pure-ftpd/conf/TLS)" ] && printf 'TLS=%s\n' "$(cat "$(rf /etc/pure-ftpd/conf/TLS)" 2>/dev/null)"
fi

# ---- TFTP: no authentication at all; the only control is the served directory ----
if [ -r "$(rf /etc/default/tftpd-hpa)" ] || [ -d "$(rf /etc/xinetd.d)" ] && grep -rqs tftp "$(rf /etc/xinetd.d/)" 2>/dev/null; then
  raw "tftp configuration"
  grep -hvE '^\s*#|^\s*$' "$(rf /etc/default/tftpd-hpa)" 2>/dev/null
  grep -rhs -A8 'service tftp' "$(rf /etc/xinetd.d/)" 2>/dev/null | cap 15
  grep -qs -- '-c\|--create' /etc/default/tftpd-hpa 2>/dev/null \
    && chk tftp.upload FAIL "TFTP_OPTIONS includes -c (create)" "unauthenticated WRITE to the TFTP root: anyone on the network can upload files"
  chk tftp.present WARN "tftpd configured" "TFTP has no authentication and no encryption; restrict by firewall to the provisioning VLAN and keep the root read-only"
fi

# ---- Samba / SMB ----
if [ -r "$(rf /etc/samba/smb.conf)" ]; then
  raw "samba configuration (global + shares)"
  grep -hvE '^\s*#|^\s*;|^\s*$' "$(rf /etc/samba/smb.conf)" 2>/dev/null | cap 60
  SMB="$(grep -hvE '^\s*#|^\s*;|^\s*$' "$(rf /etc/samba/smb.conf)" 2>/dev/null)"
  have testparm && [ "$AM_ROOT" = "1" ] && { raw "testparm -s (effective config)"; run testparm -s 2>/dev/null | cap 40; }
  printf '%s' "$SMB" | grep -qiE '^\s*(guest ok|public)\s*=\s*yes' \
    && chk smb.guest FAIL "$(printf '%s' "$SMB" | grep -iE '^\s*(guest ok|public)\s*=' | head -2 | tr '\n' ';')" "guest access: the share is readable (and if writable, writable) with no credentials" \
    || chk smb.guest PASS "no guest-enabled shares" ""
  printf '%s' "$SMB" | grep -qiE '^\s*map to guest\s*=\s*bad user' \
    && chk smb.map_guest WARN "map to guest = bad user" "any unknown username silently becomes the guest account instead of being rejected"
  MINP="$(printf '%s' "$SMB" | grep -iE '^\s*(server )?min protocol\s*=' | head -1)"
  case "$MINP" in
    *SMB2*|*SMB3*) chk smb.protocol PASS "$MINP" "" ;;
    *NT1*|*LANMAN*|*CORE*) chk smb.protocol FAIL "$MINP" "SMB1/NT1 is the WannaCry/EternalBlue protocol and has no meaningful integrity protection" ;;
    "") chk smb.protocol WARN "min protocol unset" "modern Samba defaults to SMB2, but set 'server min protocol = SMB3' explicitly" ;;
  esac
  printf '%s' "$SMB" | grep -qiE '^\s*null passwords\s*=\s*yes' && chk smb.null_passwords FAIL "null passwords = yes" "accounts with empty passwords may authenticate"
  printf '%s' "$SMB" | grep -qiE '^\s*(server signing|client signing)\s*=\s*(mandatory|required)' \
    && chk smb.signing PASS "signing mandatory" "" \
    || chk smb.signing WARN "signing not mandatory" "without required signing, SMB sessions can be relayed and tampered with"
  printf '%s' "$SMB" | grep -qiE '^\s*(hosts allow|hosts deny)\s*=' \
    && chk smb.hosts_allow PASS "hosts allow/deny set" "" \
    || chk smb.hosts_allow WARN "no hosts allow/deny" "no source restriction at the Samba layer"
  raw "writable samba shares"
  printf '%s\n' "$SMB" | awk '/^\[/{s=$0} /^[[:space:]]*(writable|writeable|read only)[[:space:]]*=/{print "  "s" "$0}' | cap 15
fi

# ---- mail: open relay and cleartext auth ----
if [ -r "$(rf /etc/postfix/main.cf)" ]; then
  raw "postfix relay controls"
  grep -hE '^\s*(mynetworks|relay_domains|smtpd_recipient_restrictions|smtpd_relay_restrictions|inet_interfaces|smtpd_tls_auth_only|smtpd_sasl_auth_enable|smtpd_banner)' "$(rf /etc/postfix/main.cf)" 2>/dev/null
  MYN="$(grep -hE '^\s*mynetworks\s*=' "$(rf /etc/postfix/main.cf)" 2>/dev/null)"
  printf '%s' "$MYN" | grep -qE '0\.0\.0\.0/0|\s/0' && chk mail.open_relay FAIL "$MYN" "mynetworks includes the whole internet: this is an open relay and will be found and abused within hours"
  grep -qE '^\s*smtpd_relay_restrictions.*reject_unauth_destination|^\s*smtpd_recipient_restrictions.*reject_unauth_destination' "$(rf /etc/postfix/main.cf)" 2>/dev/null \
    && chk mail.relay_restrictions PASS "reject_unauth_destination present" "" \
    || chk mail.relay_restrictions WARN "reject_unauth_destination not found" "verify the relay policy explicitly: an open relay is the default failure mode"
  grep -qE '^\s*smtpd_sasl_auth_enable\s*=\s*yes' "$(rf /etc/postfix/main.cf)" 2>/dev/null && \
    { grep -qE '^\s*smtpd_tls_auth_only\s*=\s*yes' "$(rf /etc/postfix/main.cf)" 2>/dev/null \
      && chk mail.auth_tls_only PASS "smtpd_tls_auth_only=yes" "" \
      || chk mail.auth_tls_only FAIL "SASL auth enabled without smtpd_tls_auth_only" "SMTP AUTH offered over an unencrypted connection: credentials in cleartext"; }
fi
if [ -d "$(rf /etc/dovecot)" ]; then
  raw "dovecot auth settings"
  grep -rhE '^\s*(disable_plaintext_auth|ssl|ssl_min_protocol|auth_mechanisms)' "$(rf /etc/dovecot/)" 2>/dev/null | cap 10
  grep -rqE '^\s*disable_plaintext_auth\s*=\s*yes' "$(rf /etc/dovecot/)" 2>/dev/null \
    && chk mail.dovecot_plaintext PASS "disable_plaintext_auth=yes" "" \
    || chk mail.dovecot_plaintext FAIL "plaintext auth not disabled" "IMAP/POP3 passwords accepted over an unencrypted connection"
  grep -rqE '^\s*ssl\s*=\s*required' "$(rf /etc/dovecot/)" 2>/dev/null || chk mail.dovecot_ssl WARN "ssl not 'required'" ""
fi

# ---- LDAP server: anonymous bind ----
if [ -r "$(rf /etc/ldap/slapd.conf)" ] || [ -d "$(rf /etc/ldap/slapd.d)" ] || [ -d "$(rf /etc/openldap/slapd.d)" ]; then
  raw "slapd access controls"
  grep -rhE '^\s*(access to|olcAccess|disallow|require|TLSCipherSuite|olcTLS)' "$(rf /etc/ldap/)" "$(rf /etc/openldap/)" 2>/dev/null | cap 20
  grep -rqE 'disallow.*bind_anon|olcDisallows.*bind_anon' "$(rf /etc/ldap/)" "$(rf /etc/openldap/)" 2>/dev/null \
    && chk ldap.anon_bind PASS "anonymous bind disallowed" "" \
    || chk ldap.anon_bind WARN "anonymous bind not disallowed" "an anonymous LDAP bind usually enumerates the entire directory: users, groups, and often more"
fi

# ---- BIND: open recursion is an amplification weapon and a cache-poisoning target ----
if [ -r "$(rf /etc/bind/named.conf.options)" ] || [ -r "$(rf /etc/named.conf)" ]; then
  NC="$(ls "$(rf /etc/bind/named.conf.options)" "$(rf /etc/named.conf)" 2>/dev/null | head -1)"
  raw "bind recursion and query controls"
  grep -hE '^\s*(recursion|allow-recursion|allow-query|allow-transfer|version|rate-limit)' "$NC" 2>/dev/null
  if grep -qE '^\s*recursion\s+yes' "$NC" 2>/dev/null; then
    grep -qE '^\s*allow-recursion' "$NC" 2>/dev/null \
      && chk dns.recursion PASS "recursion yes with allow-recursion ACL" "" \
      || chk dns.recursion FAIL "recursion yes with no allow-recursion" "open resolver: used for DNS amplification DDoS and vulnerable to cache poisoning"
  fi
  grep -qE '^\s*allow-transfer\s*\{\s*any' "$NC" 2>/dev/null && chk dns.zone_transfer FAIL "allow-transfer { any; }" "anyone can AXFR the full zone: a complete map of your infrastructure"
fi

# ---- Squid: open forward proxy ----
if [ -r "$(rf /etc/squid/squid.conf)" ]; then
  raw "squid access controls"
  grep -hE '^\s*(http_access|http_port|acl localnet|cache_effective_user)' "$(rf /etc/squid/squid.conf)" 2>/dev/null | cap 20
  grep -qE '^\s*http_access\s+allow\s+all' "$(rf /etc/squid/squid.conf)" 2>/dev/null \
    && chk proxy.squid_open FAIL "http_access allow all" "open forward proxy: used to pivot into internal networks and to launder attack traffic through your IP"
fi

# ---- memcached: no auth by design; the UDP port is an amplifier ----
if pkg_installed memcached || svc_active memcached; then
  raw "memcached options"
  grep -hE '^\s*(OPTIONS|-l|-U|-m)' "$(rf /etc/memcached.conf)" "$(rf /etc/sysconfig/memcached)" 2>/dev/null
  ps -eo args 2>/dev/null | grep '[m]emcached' | head -2
  grep -qsE '^-U\s*0|-U 0' "$(rf /etc/memcached.conf)" 2>/dev/null \
    && chk memcached.udp PASS "UDP disabled (-U 0)" "" \
    || chk memcached.udp FAIL "UDP not disabled" "memcached UDP is one of the highest-factor DDoS amplifiers in existence (>50000x); set -U 0"
  grep -qsE '^-l\s*(127\.0\.0\.1|localhost)' "$(rf /etc/memcached.conf)" 2>/dev/null \
    && chk memcached.bind PASS "bound to loopback" "" \
    || chk memcached.bind FAIL "not confirmed loopback-bound" "memcached has no authentication: anything that can reach it reads and writes all cached data, including sessions"
fi

# ---- MQTT ----
if [ -r "$(rf /etc/mosquitto/mosquitto.conf)" ]; then
  raw "mosquitto configuration"
  grep -rhE '^\s*(allow_anonymous|password_file|listener|require_certificate|cafile)' "$(rf /etc/mosquitto/)" 2>/dev/null
  grep -rqE '^\s*allow_anonymous\s+true' "$(rf /etc/mosquitto/)" 2>/dev/null \
    && chk mqtt.anonymous FAIL "allow_anonymous true" "any client may publish and subscribe to every topic without credentials"
fi

# ---- X11 listening on the network ----
if port_listening 6000 || port_listening 6001; then
  chk x11.tcp_listener FAIL "X server listening on tcp/6000" "network X11 allows keystroke capture and screen reading; start with -nolisten tcp"
fi
grep -rhs 'xhost +' "$(rf /etc/X11)" "$(rf /etc/profile.d)" "$LSA_ROOT"/home/*/.xsession "$LSA_ROOT"/home/*/.xinitrc 2>/dev/null | head -3

# ---- xinetd / inetd: what do they actually start? ----
if [ -d "$(rf /etc/xinetd.d)" ]; then
  raw "xinetd services and their disable state"
  for f in /etc/xinetd.d/*; do
    [ -r "$f" ] || continue
    d="$(grep -hE '^\s*disable\s*=' "$f" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
    printf '  %-22s disable=%s\n' "$(basename "$f")" "${d:-no(default enabled)}"
    case "${d:-no}" in
      no) case "$(basename "$f")" in
            telnet|rsh|rlogin|rexec|tftp|finger|talk|ntalk|echo|discard|daytime|chargen|time)
              chk "insecure.xinetd_$(basename "$f")" FAIL "enabled via xinetd" "legacy/cleartext service started on demand" ;;
          esac ;;
    esac
  done
fi
if [ -r "$(rf /etc/inetd.conf)" ]; then
  raw "inetd enabled services"
  grep -vE '^\s*#|^\s*$' "$(rf /etc/inetd.conf)" 2>/dev/null
  grep -qE '^\s*(telnet|shell|login|exec|tftp|finger|talk|ntalk|echo|chargen|daytime|discard|time)\s' "$(rf /etc/inetd.conf)" 2>/dev/null \
    && chk insecure.inetd_services FAIL "$(grep -E '^\s*(telnet|shell|login|exec|tftp|finger|talk|ntalk)\s' "$(rf /etc/inetd.conf)" | awk '{print $1}' | tr '\n' ' ')" "legacy cleartext services enabled in inetd.conf"
fi

# ---- systemd socket units that expose a legacy service on demand ----
if have systemctl; then
  raw "enabled socket units"
  run systemctl list-units --type=socket --state=active --no-pager --no-legend 2>/dev/null | cap 25
fi

# ------------------------------------------------- 26. BOOT AND SERVICE-START TRUST CHAIN
# Everything root reads on the way up. A root process that reads, sources, execs or maps a
# file an unprivileged user can write is a privilege-escalation path that fires automatically
# at boot or on the next service start: no attacker interaction required.
sec BOOT_CHAIN

BC_HITS=0
bc_check() { # bc_check <path> <what referenced it>
  [ -n "$1" ] || return 0
  case "$1" in /proc/*|/sys/*|/dev/*|/run/systemd/*|-*|"") return 0 ;; esac
  [ -e "$1" ] || return 0
  _r="$(path_risk "$1")"
  [ -n "$_r" ] || return 0
  printf '  RISK %s\n       referenced by: %s\n' "$_r" "$2"
  BC_HITS=$((BC_HITS+1))
}

# ---- systemd units: every directive that names a file root will touch ----
raw "systemd unit file references (EnvironmentFile, Exec*, Condition*, PIDFile, credentials...)"
UNITDIRS="${LSA_ROOT}/etc/systemd/system
${LSA_ROOT}/run/systemd/system
${LSA_ROOT}/lib/systemd/system
${LSA_ROOT}/usr/lib/systemd/system"
UNITFILES="$(find $UNITDIRS -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.socket' -o -name '*.mount' \) -print 2>/dev/null | head -400)"
chk bootchain.units_scanned INFO "$(printf '%s' "$UNITFILES" | grep -c .) unit file(s)" ""
_oifs=$IFS; IFS=$'\n'
for u in $UNITFILES; do
  # only units that actually run as root matter here
  US="$(grep -hE '^\s*User\s*=' "$u" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
  [ -n "$US" ] && [ "$US" != "root" ] && continue
  # file-valued directives
  grep -hE '^\s*(EnvironmentFile|ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop|ExecStopPost|ExecCondition|ConditionPathExists|ConditionFileNotEmpty|ConditionDirectoryNotEmpty|AssertPathExists|AssertFileNotEmpty|WorkingDirectory|PIDFile|RootDirectory|RootImage|LoadCredential|BindPaths|BindReadOnlyPaths|PathExists|PathChanged|PathModified|What)\s*=' "$u" 2>/dev/null \
  | sed 's/^[^=]*=//' | tr ' ' '\n' | grep -oE '^-?/[A-Za-z0-9._/@+-]+' | sed 's/^-//' | sort -u | while read -r pth; do
      bc_check "$pth" "$u"
    done
done
IFS=$_oifs
# recount outside the subshell
BCU="$(for u in $UNITFILES; do
  US="$(grep -hE '^\s*User\s*=' "$u" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')"
  [ -n "$US" ] && [ "$US" != "root" ] && continue
  grep -hE '^\s*(EnvironmentFile|ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop|ExecStopPost|ExecCondition|ConditionPathExists|ConditionFileNotEmpty|AssertPathExists|WorkingDirectory|PIDFile|RootImage|LoadCredential|BindPaths|PathExists|PathChanged|PathModified|What)\s*=' "$u" 2>/dev/null \
  | sed 's/^[^=]*=//' | tr ' ' '\n' | grep -oE '^-?/[A-Za-z0-9._/@+-]+' | sed 's/^-//'
done | sort -u | while read -r pth; do
  case "$pth" in /proc/*|/sys/*|/dev/*|"") continue ;; esac
  [ -e "$pth" ] || continue
  path_risk "$pth" >/dev/null 2>&1 && printf '%s\n' "$pth"
done | grep -c .)"
if [ "${BCU:-0}" -gt 0 ]; then
  chk bootchain.unit_inputs FAIL "${BCU} path(s) referenced by root units are writable by a non-root principal" "these are read, sourced or executed by systemd as root at boot or on service start. EnvironmentFile= is the classic one: a writable /etc/default/<service> injects environment (including LD_PRELOAD-style variables where the unit does not clear them) into a root process"
else
  chk bootchain.unit_inputs PASS "no writable paths referenced by root units" ""
fi
raw "drop-in directories (a writable .d dir lets anyone add directives to a root unit)"
for d in $(find "$(rf /etc/systemd/system)" -maxdepth 1 -type d -name '*.d' 2>/dev/null | head -20); do
  s="$(stat -c '%a %U:%G' "$d" 2>/dev/null)"; printf '  %s %s\n' "$s" "$d"
  case "${s%% *}" in *[2367]|?[2367]?) chk "bootchain.dropin.$(basename "$d")" FAIL "$s $d" "writable drop-in directory: an added .conf overrides ExecStart for a root unit" ;; esac
done

# ---- SysV init, rc.local and the legacy boot path ----
raw "init scripts and rc.local"
for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/* /etc/rc*.d/*; do
  [ -f "$f" ] || continue
  bc_check "$f" "boot script"
done 2>/dev/null | cap 20

# ---- the dynamic linker: a writable library path is code execution in EVERY root binary ----
raw "ld.so configuration and library search paths"
cat "$(rf /etc/ld.so.conf)" 2>/dev/null; grep -rhvE '^\s*#|^\s*$' "$(rf /etc/ld.so.conf.d/)" 2>/dev/null
LDBAD=""
for l in $(grep -rhvE '^\s*#|^\s*$|^include' "$(rf /etc/ld.so.conf)" "$(rf /etc/ld.so.conf.d/)" 2>/dev/null | sort -u); do
  [ -d "$l" ] || continue
  r="$(path_risk "$l")"
  [ -n "$r" ] && { LDBAD="$LDBAD [$r]"; }
done
if ! readable "$(rf /etc/ld.so.conf)" && ! dir_readable "$(rf /etc/ld.so.conf.d)"; then
  chk bootchain.ld_so_path NA "no ld.so configuration found" "the linker search path could not be enumerated, so nothing about it is established"
else
[ -n "$LDBAD" ] && chk bootchain.ld_so_path FAIL "$LDBAD" "a writable directory in the dynamic linker search path means every root binary that starts can be made to load an attacker's shared object: this is the broadest possible local escalation" \
                || chk bootchain.ld_so_path PASS "library search paths are root-owned and not writable" ""
fi
[ -s "$(rf /etc/ld.so.preload)" ] && { raw "/etc/ld.so.preload contents"; cat "$(rf /etc/ld.so.preload)"; }

# ---- udev: RUN+= executes as root on device events, including at boot ----
raw "udev rules that execute programs"
grep -rhE 'RUN[+]?=' "$(rf /etc/udev/rules.d/)" /run/udev/rules.d/ 2>/dev/null | cap 15
for f in $(grep -rlE 'RUN[+]?=' "$(rf /etc/udev/rules.d/)" 2>/dev/null | head -10); do bc_check "$f" "udev rule file"; done
grep -rhoE 'RUN[+]?="[^"]*"' "$(rf /etc/udev/rules.d/)" 2>/dev/null | grep -oE '/[A-Za-z0-9._/-]+' | sort -u | head -10 | while read -r p; do bc_check "$p" "udev RUN+= target"; done

# ---- profile scripts: sourced by every root login shell ----
raw "shell profile scripts executed for root logins"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/* /root/.bashrc /root/.bash_profile /root/.profile; do
  [ -f "$f" ] || continue
  bc_check "$f" "root shell profile"
done 2>/dev/null | cap 20

# ---- PAM, initramfs, generators ----
raw "other root-executed chains"
for f in /etc/pam.d/* /etc/initramfs-tools/hooks/* /etc/initramfs-tools/scripts/* \
         /etc/systemd/system-generators/* /usr/lib/systemd/system-generators/* \
         /etc/dracut.conf.d/* /etc/kernel/postinst.d/* /etc/apt/apt.conf.d/* \
         /etc/cron.d/* /etc/logrotate.d/*; do
  [ -f "$f" ] || continue
  bc_check "$f" "root-executed configuration"
done 2>/dev/null | cap 25
raw "logrotate postrotate scripts run as root"
grep -rhA3 'postrotate' "$(rf /etc/logrotate.conf)" "$(rf /etc/logrotate.d/)" 2>/dev/null | grep -oE '/[A-Za-z0-9._/-]+' | sort -u | cap 10

runtime_on
# ---- LIVE SNAPSHOT: what are root processes holding open right now? ----
# Catches the long-running case that static analysis cannot: a daemon that already opened a
# user-writable file, or mapped a shared library from a writable path.
raw "files currently OPEN by root processes that a non-root principal can write"
OPENBAD=0
if [ -d /proc/1/fd ]; then
  for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}' | head -120); do
    [ -d "/proc/$pid/fd" ] || continue
    for fd in /proc/$pid/fd/*; do
      tgt="$(readlink "$fd" 2>/dev/null)" || continue
      case "$tgt" in /*) ;; *) continue ;; esac
      case "$tgt" in /proc/*|/sys/*|/dev/*|/run/*|/memfd:*|*"(deleted)") continue ;; esac
      r="$(path_risk "$tgt" 2>/dev/null)"
      [ -n "$r" ] && { printf '  %s\n       open by pid %s (%s)\n' "$r" "$pid" "$(ps -o comm= -p "$pid" 2>/dev/null)"; OPENBAD=$((OPENBAD+1)); }
    done
  done | sort -u | cap 25
fi
raw "shared libraries MAPPED into root processes from non-root-owned paths"
if [ -r /proc/1/maps ]; then
  for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}' | head -60); do
    awk '/\.so/ {print $NF}' "/proc/$pid/maps" 2>/dev/null
  done | sort -u | head -200 | while read -r lib; do
    case "$lib" in /*) ;; *) continue ;; esac
    r="$(path_risk "$lib" 2>/dev/null)"
    [ -n "$r" ] && printf '  %s (mapped into a root process)\n' "$r"
  done | sort -u | cap 15
fi
MAPBAD="$(if [ -r /proc/1/maps ]; then
  for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}' | head -60); do
    awk '/\.so/ {print $NF}' "/proc/$pid/maps" 2>/dev/null
  done | sort -u | head -200 | while read -r lib; do
    case "$lib" in /*) ;; *) continue ;; esac
    path_risk "$lib" >/dev/null 2>&1 && printf '%s\n' "$lib"
  done | grep -c .
fi)"
[ "${MAPBAD:-0}" -gt 0 ] && chk bootchain.mapped_libs FAIL "${MAPBAD} library file(s) mapped into root processes are non-root-owned or writable" "replacing one of these gives code execution inside a running root process at its next start" \
                         || chk bootchain.mapped_libs PASS "all libraries mapped into root processes are root-owned and not writable" ""

chk bootchain.runtime_tracing INFO "static analysis only" "this section reasons about what root WILL read from configuration. To observe what root ACTUALLY reads during boot and service start, run scripts/lsa-trace.sh: it needs a service restart or a reboot and is therefore a separate, explicitly-invoked step"

# --------------------------------------------------------------- 27. SECRETS
# Cleartext credentials on disk. VALUES ARE NEVER PRINTED: this output is written to a
# file and pasted into reports, so it reports location, key name and value length only.
# Severity is driven by two multipliers: is the file readable by unprivileged users, and
# is it inside a document root (i.e. potentially downloadable over HTTP).
sec SECRETS

# key-name patterns: an assignment whose NAME says credential
SECRET_KEYS='(PASSW(OR)?D|PASSWD|PASS|SECRET|API_?KEY|APIKEY|ACCESS_?KEY|SECRET_?KEY|PRIVATE_?KEY|AUTH_?TOKEN|TOKEN|CREDENTIAL|CLIENT_?SECRET|DB_PASS|MYSQL_PWD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|SMTP_PASS|MAIL_PASSWORD|JWT_SECRET|APP_KEY|ENCRYPTION_KEY|SESSION_SECRET|WEBHOOK_SECRET)'
# High-confidence provider token formats. These are self-identifying prefixes, so a match is
# a real credential rather than a guess: no entropy heuristic needed and no false positives.
SECRET_TOKENS='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|xox[baprse]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|pk_live_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{35}|ya29\.[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|SK[a-f0-9]{32}|AC[a-f0-9]{32}|glpat-[A-Za-z0-9_-]{20,}|gldt-[A-Za-z0-9_-]{20,}|dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64}|npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}|sk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-svcacct-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{48}|hf_[A-Za-z0-9]{30,}|r8_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|pplx-[A-Za-z0-9]{30,}|xai-[A-Za-z0-9]{40,}|AGE-SECRET-KEY-1[A-Z0-9]{50,}|shpat_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}|lin_api_[A-Za-z0-9]{30,}|figd_[A-Za-z0-9_-]{30,}|atlassian_[A-Za-z0-9]{20,}|EAACEdEose0cBA[A-Za-z0-9]{20,}|sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}'
# PEM / OpenSSH / PGP private key material, wherever it is embedded
SECRET_PEM='-----BEGIN ((RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|ENCRYPTED PRIVATE|SSH2 ENCRYPTED)[[:space:]]+)?PRIVATE KEY( BLOCK)?-----'
# an assignment line whose KEY matches SECRET_KEYS. Optional surrounding quotes are matched
# with [^A-Za-z0-9]{0,2} rather than a class containing " and ', which does not survive the
# nested command substitutions this pattern is used inside.
# The leading class admits quoting and bracketing ("KEY"=, [KEY]=, - key:) but NOT comment
# markers. Without excluding them, stock config full of commented examples matched: three
# "# LU_USERPASSWORD = !!" lines in /etc/libuser.conf on a stock RHEL image produced a
# world-readable-credential finding, which is the expensive kind of wrong.
SECRET_ASSIGN_RE="^[[:space:]]*(export[[:space:]]+)?[^A-Za-z0-9#;/*]{0,2}[A-Za-z0-9_.-]*${SECRET_KEYS}[A-Za-z0-9_]{0,8}[^A-Za-z0-9]{0,2}[[:space:]]*[=:][[:space:]]*[^[:space:]]"
# credentials embedded in connection URIs
SECRET_URIS='(mysql|postgres(ql)?|mongodb(\+srv)?|redis|rediss|amqps?|ftp|sftp|https?|ldaps?|smb|s3|clickhouse|elasticsearch)://[A-Za-z0-9._%+-]*:[^@/[:space:]"'"'"']{3,}@'

# report a hit without disclosing the value
emit_secret() { # emit_secret <file> <grepline "n:content"> <kind>
  _f="$1"; _l="${2%%:*}"; _c="${2#*:}"; _k="$3"
  _key="$(printf '%s' "$_c" | grep -oE "^[[:space:]]*(export[[:space:]]+)?[\"']?[A-Za-z0-9_.\-]+" | tail -1 | tr -d ' "'"'"'')"
  _val="$(printf '%s' "$_c" | sed 's/^[^=:]*[=:][[:space:]]*//' | tr -d '"'"'"' ' | tr -d "'")"
  case "$_val" in
    ''|null|NULL|changeme|CHANGEME|\$*|%*|\{\{*|'<'*|password|example|xxx*|XXX*|"***"*) _note=" (placeholder or reference: likely not live)" ;;
    *) _note="" ;;
  esac
  printf '  %s:%s  %s = <redacted, %s chars> [%s]%s\n' "$_f" "$_l" "${_key:-?}" "${#_val}" "$_k" "$_note"
}

# bounded candidate list: config-shaped files in the places credentials actually live
SECRET_FILES="$( {
  _oifs=$IFS; IFS=$'\n'
  for r in $DOCROOTS "$LSA_ROOT"/var/www "$LSA_ROOT"/srv "$LSA_ROOT"/opt "$LSA_ROOT"/etc "$LSA_ROOT"/root "$LSA_ROOT"/home; do
    [ -d "$r" ] || continue
    find "$r" -maxdepth 4 -type f -size -512k \( \
        -name '.env' -o -name '.env.*' -o -name '*.env' -o -name 'wp-config.php' -o -name 'config.php' \
        -o -name 'configuration.php' -o -name 'settings.php' -o -name 'database.php' -o -name 'local.php' \
        -o -name 'secrets.*' -o -name 'credentials*' -o -name '*.cnf' -o -name '*.conf' -o -name '*.ini' \
        -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.properties' -o -name '*.toml' \
        -o -name 'docker-compose*.y*ml' -o -name 'Dockerfile*' -o -name '.netrc' -o -name '.pgpass' \
        -o -name '.my.cnf' -o -name '.npmrc' -o -name '.git-credentials' -o -name '*.tfvars' \) -print 2>/dev/null
  done
  IFS=$_oifs
  ls -1 "$LSA_ROOT"/etc/systemd/system/*.service "$LSA_ROOT"/etc/systemd/system/*/*.service 2>/dev/null
  ls -1 "$LSA_ROOT"/etc/cron.d/* 2>/dev/null
} | sort -u | head -600 )"
chk secrets.files_scanned INFO "$(printf '%s' "$SECRET_FILES" | grep -c .) candidate file(s)" "config-shaped files under document roots, /etc, /opt, /srv, /root and /home (depth 4, <512k)"

raw "credential assignments found (values redacted)"
NSEC=0; NSEC_WORLD=0; NSEC_WEB=0
printf '%s\n' "$SECRET_FILES" | while IFS= read -r f; do
  [ -r "$f" ] || continue
  case "$f" in *.min.js|*.map|*/node_modules/*|*/vendor/*|*.lock) continue ;; esac
  HITS="$(grep -nIE "$SECRET_ASSIGN_RE" "$f" 2>/dev/null | head -6)"
  TOKHITS="$(grep -nIEo "$SECRET_TOKENS" "$f" 2>/dev/null | head -4)"
  URIHITS="$(grep -nIEo "$SECRET_URIS" "$f" 2>/dev/null | head -4)"
  [ -z "$HITS$TOKHITS$URIHITS" ] && continue
  m="$(stat -c '%a %U:%G' "$f" 2>/dev/null)"
  scope=""
  case "${m%% *}" in *[4567]) scope=" WORLD-READABLE" ;; esac
  _oifs=$IFS; IFS=$'\n'
  for dr in $DOCROOTS; do case "$f" in "$dr"/*) scope="$scope IN-DOCUMENT-ROOT" ;; esac; done
  IFS=$_oifs
  printf '\n[%s] %s%s\n' "$f" "$m" "$scope"
  printf '%s\n' "$HITS" | grep -v '^$' \
    | grep -vE '^[0-9]+:[[:space:]]*(#|;|//|--|/\*|\*)' \
    | while IFS= read -r line; do emit_secret "$f" "$line" "key-name"; done
  printf '%s\n' "$TOKHITS" | grep -v '^$' | while IFS= read -r line; do
    printf '  %s:%s  <redacted provider token> [%s]\n' "$f" "${line%%:*}" "$(printf '%s' "${line#*:}" | cut -c1-6)…"
  done
  printf '%s\n' "$URIHITS" | grep -v '^$' | while IFS= read -r line; do
    printf '  %s:%s  <credentials embedded in a %s URI> [connection-string]\n' "$f" "${line%%:*}" "$(printf '%s' "${line#*:}" | cut -d: -f1)"
  done
  # private key material pasted INTO a config file (env var, YAML block, JSON string)
  grep -nIE -e "$SECRET_PEM" "$f" 2>/dev/null | head -3 | while IFS= read -r line; do
    printf '  %s:%s  <PRIVATE KEY material embedded in a config file> [pem-inline]\n' "$f" "${line%%:*}"
  done
done

# counts for the verdicts (separate pass so values survive the subshells above)
SECFILES_HIT="$(printf '%s\n' "$SECRET_FILES" | while IFS= read -r f; do
  [ -r "$f" ] || continue
  case "$f" in *.min.js|*.map|*/node_modules/*|*/vendor/*|*.lock) continue ;; esac
  if grep -qIE "$SECRET_ASSIGN_RE" "$f" 2>/dev/null \
     || grep -qIE "$SECRET_TOKENS" "$f" 2>/dev/null \
     || grep -qIE -e "$SECRET_PEM" "$f" 2>/dev/null \
     || grep -qIE "$SECRET_URIS" "$f" 2>/dev/null; then printf '%s\n' "$f"; fi
done)"
NSEC="$(printf '%s' "$SECFILES_HIT" | grep -c .)"
NWORLD="$(printf '%s\n' "$SECFILES_HIT" | while IFS= read -r f; do [ -n "$f" ] || continue
  m="$(stat -c '%a' "$f" 2>/dev/null)"; case "$m" in *[4567]) echo x ;; esac; done | grep -c x)"
NWEB=0
_oifs=$IFS; IFS=$'\n'
for dr in $DOCROOTS; do
  [ -n "$dr" ] || continue
  n="$(printf '%s\n' "$SECFILES_HIT" | grep -c "^$dr/")"
  NWEB=$((NWEB + n))
done
IFS=$_oifs

if [ "${NSEC:-0}" -gt 0 ]; then
  chk secrets.cleartext WARN "${NSEC} file(s) contain credential-shaped assignments" "cleartext credentials on disk are normal for application config, so the finding is not their existence: it is their READABILITY and REUSE. Confirm each file is 0600/0640 and owned correctly, that the credential is unique to this host, and that it is not also in git history or a backup"
else
  chk secrets.cleartext PASS "no credential patterns matched" "pattern- and key-name-based only; a secret in an unusual key name or format will not be caught"
fi
[ "${NWORLD:-0}" -gt 0 ] && chk secrets.world_readable FAIL "${NWORLD} credential-bearing file(s) are world-readable" "every local account, including a compromised service account, can read these credentials directly. chmod 0640 and set the group to the consuming service"
[ "${NWEB:-0}" -gt 0 ] && chk secrets.in_webroot FAIL "${NWEB} credential-bearing file(s) inside a document root" "a .env or config file under the document root is downloadable the moment the interpreter does not run it (misconfiguration, handler change, or a .php.bak/.env.save copy). Automated scanners request /.env on every host they touch; move these outside the served tree"

# ---- credentials in places people forget ----
raw "credentials in systemd units, cron, and shell environment"
grep -rhE '^\s*Environment=.*(PASS|SECRET|TOKEN|KEY)' "$(rf /etc/systemd/system/)" "$(rf /lib/systemd/system/)" 2>/dev/null \
  | redact_env | cap 10
grep -rhE '(PASS|SECRET|TOKEN|API_?KEY)[[:space:]]*=' "$(rf /etc/environment)" "$(rf /etc/profile)" "$(rf /etc/profile.d/)" 2>/dev/null \
  | sed 's/=.*/=<redacted>/' | cap 10
grep -rhE 'curl[^|]*-u[[:space:]]|--password|MYSQL_PWD|PGPASSWORD' "$(rf /etc/cron.d/)" "$(rf /etc/crontab)" 2>/dev/null \
  | sed 's/\(-u\|--password\|=\)[[:space:]]*[^[:space:]]*/\1 <redacted>/g' | cap 10
if grep -rqE '^\s*Environment=.*(PASS|SECRET|TOKEN|KEY)' "$(rf /etc/systemd/system/)" 2>/dev/null; then
  chk secrets.systemd_env FAIL "credentials in unit Environment= lines" "unit files are world-readable by default, and 'systemctl show' exposes these values to any local user. Use EnvironmentFile= pointing at a 0600 file, or a credential store (LoadCredential=)"
fi
raw "credentials in mount and network configuration"
grep -hE 'password=|credentials=' "$(rf /etc/fstab)" 2>/dev/null | sed 's/password=[^,[:space:]]*/password=<redacted>/'
grep -rhlE '^\s*(psk|wpa-psk|password)=' "$(rf /etc/NetworkManager/system-connections/)" "$(rf /etc/netplan/)" "$(rf /etc/wpa_supplicant/)" 2>/dev/null | head -5
for f in /etc/NetworkManager/system-connections/*; do
  [ -f "$f" ] || continue
  m="$(stat -c '%a' "$f" 2>/dev/null)"
  case "$m" in *[4567]) chk "secrets.nm_perms.$(basename "$f")" FAIL "$m $f" "NetworkManager connection files hold PSKs and 802.1X passwords in cleartext and must be 0600" ;; esac
done
raw "private key files and their permissions"
# Bounded candidate list by NAME first, then confirm by reading the first line. A recursive
# content grep over /opt and /home is unbounded and can take minutes on a real host.
KEYCAND="$(find "$(rf /var/www)" "$(rf /srv)" "$(rf /opt)" "$(rf /etc/ssl)" "$(rf /etc/pki)" "$(rf /etc/ssh)" "$(rf /home)" "$(rf /root)" -maxdepth 4 -type f -size -64k \
   \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_dsa*' -o -name 'id_ecdsa*' \
      -o -name 'id_ed25519*' -o -name '*.p12' -o -name '*.pfx' -o -name 'privkey*' -o -name 'server.key' \) \
   -print 2>/dev/null | head -80)"
KEYLIST=""; BADKEY=""; PLAINKEY=""
_oifs=$IFS; IFS=$'\n'
for k in $KEYCAND; do
  case "$k" in *.pub) continue ;; esac
  HDR="$(head -3 "$k" 2>/dev/null)"
  printf '%s' "$HDR" | grep -q 'PRIVATE KEY' || continue
  KEYLIST="$KEYLIST $k"
  m="$(stat -c '%a %U:%G' "$k" 2>/dev/null)"
  # passphrase-protected? OpenSSH marks it in the body, classic PEM in the header
  enc="UNENCRYPTED"
  printf '%s' "$HDR" | grep -qE 'ENCRYPTED|Proc-Type: 4,ENCRYPTED' && enc="encrypted"
  grep -qE 'Proc-Type: 4,ENCRYPTED|DEK-Info' "$k" 2>/dev/null && enc="encrypted"
  if printf '%s' "$HDR" | grep -q 'OPENSSH PRIVATE KEY'; then
    head -c 200 "$k" 2>/dev/null | base64 -d 2>/dev/null | grep -qa 'aes\|bcrypt' && enc="encrypted"
  fi
  printf '  %-6s %s  %s\n' "$enc" "$m" "$k"
  [ "$enc" = "UNENCRYPTED" ] && PLAINKEY="$PLAINKEY $k"
  case "${m%% *}" in
    600|400|0600|0400|640|0640) ;;
    *) BADKEY="$BADKEY $k(${m%% *})" ;;
  esac
done
IFS=$_oifs
[ -n "$PLAINKEY" ] && chk secrets.unencrypted_keys INFO "$PLAINKEY" "private keys with no passphrase: usable the instant they are copied. Normal for service/automation keys, but it means file permissions and backup handling are the only protection"
if [ -n "$BADKEY" ]; then
  chk secrets.private_keys FAIL "$BADKEY" "PEM private key readable beyond its owner: a key readable by the web worker or by any local account should be treated as already disclosed"
elif [ -n "$KEYLIST" ]; then
  chk secrets.private_keys PASS "$(printf '%s' "$KEYLIST" | wc -w | tr -d ' ') private key file(s), permissions correct" ""
fi
# a private key inside a document root is downloadable
_oifs=$IFS; IFS=$'\n'
for k in $KEYLIST; do
  for dr in $DOCROOTS; do
    [ -n "$dr" ] || continue
    case "$k" in "$dr"/*) chk "secrets.key_in_webroot.$(basename "$k")" FAIL "$k" "private key inside the document root: request it over HTTP to confirm, then rotate it" ;; esac
  done
done
IFS=$_oifs

# ---- git history and backups: where deleted secrets keep living ----
raw "git repositories in served or system paths (history retains removed secrets)"
find "$(rf /var/www)" "$(rf /srv)" "$(rf /opt)" -maxdepth 4 -type d -name '.git' -print 2>/dev/null | cap 10
for g in $(find "$(rf /var/www)" "$(rf /srv)" "$(rf /opt)" -maxdepth 4 -type d -name '.git' -print 2>/dev/null | head -5); do
  d="$(dirname "$g")"
  printf '  [%s]\n' "$d"
  [ -r "$d/.gitignore" ] && grep -qE '^\s*\.env' "$d/.gitignore" 2>/dev/null && printf '    .env is gitignored\n' || printf '    .env NOT in .gitignore\n'
  have git && git -C "$d" log --oneline -1 2>/dev/null | sed 's/^/    last commit: /'
done
# With no web server, DOCROOTS is empty and GNU find falls back to the CURRENT DIRECTORY, so the
# check reported the auditor's own working copy as a .git exposed in a document root. Guarded.
if [ -n "${DOCROOTS//[[:space:]]/}" ]; then
  GITWEB="$(find $DOCROOTS -maxdepth 3 -type d -name '.git' -print 2>/dev/null | head -5)"
  GITWEB_SCANNED=1
else
  GITWEB=""; GITWEB_SCANNED=0
fi
# Emit in every case: a check that stays silent when there is no document root is
# indistinguishable from one that looked and found nothing.
[ "$GITWEB_SCANNED" = "0" ] && chk secrets.git_in_webroot NA "no document root identified" "nothing to scan: no web server configuration was found, so this says nothing about whether a repository is exposed"
[ "$GITWEB_SCANNED" = "1" ] && [ -z "$GITWEB" ] && chk secrets.git_in_webroot PASS "no .git under any document root" ""
[ -n "$GITWEB" ] && chk secrets.git_in_webroot FAIL "$GITWEB" "a .git directory inside the document root is downloadable object by object: scanners do this automatically and recover the full source history, including any credential ever committed and later removed"
raw "backup and editor-leftover copies of config files"
find $DOCROOTS "$(rf /etc)" -maxdepth 4 -type f \( -name '*.bak' -o -name '*.save' -o -name '*.old' -o -name '*~' \
     -o -name '*.orig' -o -name '*.swp' -o -name '.env.*' -o -name '*.php.txt' \) -print 2>/dev/null | head -20 \
  | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null

# ------------------------------------------------- 27. IMAGE / TEMPLATE HYGIENE
# Identity and secret material that must be generated per-instance, never baked into a golden
# image, ISO, AMI, VM template or container image. Anything shipped in the image is IDENTICAL
# on every machine cloned from it, which turns a per-host secret into a fleet-wide one.
#
# Detectable on a running host as well as in an image: if the SSH host key is OLDER than the
# machine's own identity (machine-id), it did not come from first boot: it came from the image.
sec IMAGE_HYGIENE
static_on

MID="$(rf /etc/machine-id)"
MID_SIZE=0; [ -f "$MID" ] && MID_SIZE="$(wc -c < "$MID" 2>/dev/null | tr -d ' ')"
raw "instance identity"
ls -l "$MID" "$(rf /var/lib/dbus/machine-id)" 2>/dev/null
printf '  machine-id bytes=%s (0 = uninitialised, correct for a template)\n' "${MID_SIZE:-absent}"

# ---- SSH host keys: the canonical baked-in secret ----
raw "SSH host keys"
HK="$(ls "$LSA_ROOT"/etc/ssh/ssh_host_*_key 2>/dev/null)"
for k in $HK; do
  printf '  %s  %s\n' "$(stat -c '%a %U:%G %y' "$k" 2>/dev/null | cut -c1-40)" "$k"
  ssh-keygen -lf "${k}.pub" 2>/dev/null | sed 's/^/      /'
done

# is first-boot regeneration configured anywhere?
REGEN=""
have systemctl && for u in regenerate_ssh_host_keys.service ssh-keygen.service sshd-keygen.service \
                          sshd-keygen.target ssh-host-keys-regeneration.service firstboot.service; do
  systemctl list-unit-files 2>/dev/null | grep -q "^$u" && REGEN="$REGEN $u"
done
[ -f "$(rf /etc/systemd/system/regenerate_ssh_host_keys.service)" ] && REGEN="$REGEN regenerate_ssh_host_keys(drop-in)"
grep -rqs 'ssh_deletekeys' "$(rf /etc/cloud/cloud.cfg)" "$(rf /etc/cloud/cloud.cfg.d/)" 2>/dev/null && {
  grep -rhs 'ssh_deletekeys' "$(rf /etc/cloud/cloud.cfg)" "$(rf /etc/cloud/cloud.cfg.d/)" 2>/dev/null | head -2
  grep -rqsE 'ssh_deletekeys:\s*(true|1)' "$(rf /etc/cloud/cloud.cfg)" "$(rf /etc/cloud/cloud.cfg.d/)" 2>/dev/null \
    && REGEN="$REGEN cloud-init:ssh_deletekeys=true" \
    || chk image.cloudinit_deletekeys FAIL "ssh_deletekeys is set to false" "cloud-init is explicitly told NOT to regenerate host keys, so every instance from this image keeps the image's keys"
}
grep -rqs 'ssh_genkeytypes' "$(rf /etc/cloud/cloud.cfg)" "$(rf /etc/cloud/cloud.cfg.d/)" 2>/dev/null && REGEN="$REGEN cloud-init:ssh_genkeytypes"
[ -x "$(rf /usr/lib/systemd/system-generators/ssh-keygen-generator)" ] && REGEN="$REGEN ssh-keygen-generator"
# Debian/Ubuntu regenerate via the openssh-server postinst when the keys are absent;
# RHEL uses sshd-keygen@.service with ConditionPathExists=!/etc/ssh/ssh_host_*_key
ls "$(rf /usr/lib/systemd/system/sshd-keygen@.service)" >/dev/null 2>&1 && REGEN="$REGEN sshd-keygen@.service"

if [ -n "$HK" ]; then
  # Did these keys come from the image? Compare against the instance's own identity.
  BAKED=unknown
  if [ "$MID_SIZE" -gt 1 ] 2>/dev/null; then
    for k in $HK; do
      if [ "$k" -ot "$MID" ]; then BAKED=yes; break; else BAKED=no; fi
    done
  fi
  case "$BAKED" in
    yes) chk image.ssh_host_keys_baked FAIL "host key files predate /etc/machine-id" "the SSH host keys are OLDER than this instance's own identity, so they were not generated at first boot: they came from the image. Every machine cloned from that image shares these private keys: one compromised host lets an attacker impersonate the entire fleet, decrypt recorded sessions for non-forward-secret KEX, and defeat host-key pinning so a MITM no longer produces a warning. Regenerate now: rm -f /etc/ssh/ssh_host_*; dpkg-reconfigure openssh-server (or ssh-keygen -A); systemctl restart sshd, then fix the image" ;;
    no)  chk image.ssh_host_keys_baked PASS "host keys are newer than machine-id (generated on this instance)" "" ;;
    *)   chk image.ssh_host_keys_baked INFO "cannot compare (machine-id uninitialised)" "consistent with an unbooted template; the question is then whether the image ships keys at all; see below" ;;
  esac
  # In an image/template context, shipping keys at all is the finding.
  if [ "${MID_SIZE:-0}" -le 1 ]; then
    chk image.ssh_host_keys_in_template FAIL "$(printf '%s' "$HK" | tr '\n' ' ')" "this looks like an uninitialised template (machine-id is empty) yet it SHIPS SSH host private keys. Remove them from the image and let first boot generate them"
  fi
  if [ -z "$REGEN" ]; then
    chk image.ssh_regen_configured FAIL "no first-boot regeneration mechanism found" "nothing will replace the host keys on a clone. Provide one: cloud-init 'ssh_deletekeys: true', RHEL's sshd-keygen@.service, or a firstboot unit running 'ssh-keygen -A' with ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key"
  else
    chk image.ssh_regen_configured PASS "$REGEN" "confirm it actually fires: the usual failure is a mechanism that only runs when the keys are ABSENT, combined with an image that ships them"
  fi
else
  chk image.ssh_host_keys_baked PASS "no SSH host keys present" "correct for a template: they should be created at first boot"
fi

# ---- entropy seed: a cloned seed means identical early-boot randomness ----
for sd in /var/lib/systemd/random-seed /var/lib/urandom/random-seed /var/lib/random-seed; do
  [ -f "$sd" ] || continue
  chk image.random_seed FAIL "$sd present ($(stat -c '%s' "$sd" 2>/dev/null) bytes)" "the saved entropy seed must never ship in an image: every clone would start with IDENTICAL early-boot randomness, which can repeat across machines in key generation, session IDs and ASLR before the pool is reseeded. Delete it as part of image preparation: systemd recreates it at shutdown"
done

# ---- machine-id: the cloned-identity marker ----
if [ "${MID_SIZE:-0}" -gt 1 ]; then
  chk image.machine_id INFO "initialised ($MID_SIZE bytes)" "correct for a running instance. In a TEMPLATE this file must be empty (truncate, do not delete: an empty /etc/machine-id is systemd's documented first-boot trigger, a missing one can leave /etc read-only setups without an identity)"
else
  chk image.machine_id PASS "uninitialised: correct for a template" ""
fi
[ -f "$(rf /var/lib/dbus/machine-id)" ] && [ ! -L /var/lib/dbus/machine-id ] && \
  chk image.dbus_machine_id WARN "/var/lib/dbus/machine-id is a real file" "should be a symlink to /etc/machine-id, otherwise it keeps the image's identity even after machine-id is regenerated"

# ---- other per-instance material that must not be baked in ----
raw "other identity and credential material that must be per-instance"
BAKEDLIST=""
for f in /etc/iscsi/initiatorname.iscsi /var/lib/dhcp/dhclient.leases /var/lib/dhcp/dhclient6.leases \
         /var/lib/NetworkManager/secret_key /var/lib/NetworkManager/*.lease \
         /etc/salt/pki/minion/minion.pem /etc/puppetlabs/puppet/ssl/private_keys/*.pem \
         /etc/chef/client.pem /var/lib/kubelet/pki/kubelet-client-current.pem \
         /etc/consul.d/*.json /etc/vault.d/*.hcl /var/lib/snapd/state.json \
         /etc/zabbix/zabbix_agentd.psk /etc/wazuh-agent/client.keys /var/ossec/etc/client.keys; do
  [ -e "$f" ] 2>/dev/null || continue
  printf '  %s %s\n' "$(stat -c '%a %U:%G' "$f" 2>/dev/null)" "$f"
  BAKEDLIST="$BAKEDLIST $f"
done
[ -n "$BAKEDLIST" ] && chk image.per_instance_material WARN "$(printf '%s' "$BAKEDLIST" | cut -c1-200)" "per-instance identity or enrolment material. Harmless on a running host; in an image each of these is cloned across the fleet: duplicate agent identities, duplicate cluster certificates, colliding DHCP/iSCSI identifiers. Remove during image preparation"

# ---- authorized_keys and cloud credentials baked into an image ----
for a in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$a" ] || continue
  n="$(grep -cE '^(ssh|ecdsa|sk-)' "$a" 2>/dev/null)"
  printf '  %s: %s key(s)\n' "$a" "$n"
  [ "${MID_SIZE:-0}" -le 1 ] && [ "${n:-0}" -gt 0 ] && \
    chk "image.authorized_keys.$(basename "$(dirname "$(dirname "$a")")")" FAIL "$a ships ${n} key(s) in a template" "an authorized_keys baked into an image grants its holder access to every machine built from it, including ones built years later by people who never saw the image contents"
done

# ---- build-time leftovers ----
raw "build-time leftovers that should be cleaned from an image"
for f in /root/.bash_history /home/*/.bash_history /root/.ssh/known_hosts /var/log/cloud-init.log \
         /var/lib/cloud/instance /var/lib/cloud/instances /etc/hostname; do
  [ -e "$f" ] 2>/dev/null && printf '  %s %s\n' "$(stat -c '%s bytes' "$f" 2>/dev/null)" "$f"
done
if [ "${MID_SIZE:-0}" -le 1 ]; then
  [ -s "$(rf /root/.bash_history)" ] && chk image.build_history WARN "/root/.bash_history is non-empty in a template" "the image build session's commands ship with it, frequently including credentials typed on the command line"
  [ -d "$(rf /var/lib/cloud/instance)" ] && chk image.cloudinit_state FAIL "/var/lib/cloud state present in a template" "cloud-init thinks it has already run, so it will SKIP first-boot tasks including host-key regeneration. Clean with 'cloud-init clean --logs --seed' before capturing the image"
  LOGSZ="$(du -sk "$(rf /var/log)" 2>/dev/null | awk '{print $1}')"
  [ "${LOGSZ:-0}" -gt 10240 ] && chk image.logs_in_image WARN "/var/log is ${LOGSZ}KB in a template" "build logs ship with the image and often contain hostnames, IPs and credentials from the build environment"
fi
method_reset

# ----------------------------------------------------------------- 28. eBPF
# eBPF runs attacker-reachable code IN THE KERNEL without loading a module, so
# kernel.modules_disabled=1, the strongest anti-LKM-rootkit control this audit recommends,
# does not constrain it at all. Published eBPF rootkits (TripleCross, ebpfkit, boopkit) hook
# syscalls, hide processes and files, sniff credentials and implement backdoor triggers this way.
#
# Loaded programs are NOT inherently suspicious: Cilium, Calico, Falco, Datadog, Pixie, systemd
# and modern container runtimes all load them legitimately. The audit's job is to ENUMERATE and
# ATTRIBUTE, and to flag what cannot be attributed.
sec EBPF
if [ "$OFFLINE" = "1" ]; then
  chk ebpf.context NA "offline (--root)" "loaded eBPF programs are runtime state; audit the booted host"
elif [ -n "$CTR" ]; then
  chk ebpf.context NA "inside a $CTRTYPE container" "the BPF subsystem belongs to the host kernel"
else
  raw "eBPF configuration"
  UBD="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
  JITH="$(cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null)"
  JITE="$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)"
  STATS="$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null)"
  printf '  unprivileged_bpf_disabled=%s bpf_jit_harden=%s bpf_jit_enable=%s bpf_stats_enabled=%s\n' \
    "${UBD:-n/a}" "${JITH:-n/a}" "${JITE:-n/a}" "${STATS:-n/a}"
  case "$UBD" in
    1) chk ebpf.unprivileged PASS "unprivileged_bpf_disabled=1" "only CAP_BPF/CAP_SYS_ADMIN can load programs" ;;
    2) chk ebpf.unprivileged PASS "unprivileged_bpf_disabled=2" "unprivileged BPF disabled until the first privileged use, then locked" ;;
    0) chk ebpf.unprivileged FAIL "unprivileged_bpf_disabled=0" "ANY local user can load eBPF programs into the kernel. The verifier is the only thing between an unprivileged user and kernel code execution, and it has a long CVE history of being bypassed. Set to 1" ;;
    *) chk ebpf.unprivileged NA "${UBD:-not present}" "tunable absent on this kernel" ;;
  esac
  [ -n "$STATS" ] && [ "$STATS" = "1" ] && chk ebpf.stats INFO "bpf_stats_enabled=1" "run-time accounting is on; small overhead, useful for spotting a busy hidden program"

  # ---- what is actually loaded ----
  if have bpftool && [ "$AM_ROOT" = "1" ]; then
    raw "loaded eBPF programs (bpftool prog list)"
    run bpftool prog list 2>/dev/null | cap 60
    PROGS="$(bpftool prog list 2>/dev/null)"
    NPROG="$(printf '%s\n' "$PROGS" | grep -cE '^[0-9]+:')"
    chk ebpf.programs_loaded INFO "${NPROG:-0} program(s) loaded" "attribute each to a known agent; anything unaccounted for is the finding"
    raw "programs by type"
    printf '%s\n' "$PROGS" | grep -oE '^[0-9]+: [a-z_]+' | awk '{print $2}' | sort | uniq -c | sort -rn | sed 's/^/  /'
    # types that hook syscalls, packets or LSM decisions are the rootkit-capable ones
    HOOKY="$(printf '%s\n' "$PROGS" | grep -cE '^[0-9]+: (kprobe|kretprobe|tracepoint|raw_tracepoint|fentry|fexit|lsm|xdp|sched_cls|sched_act|cgroup_skb|sock_ops|sk_msg|sk_skb)')"
    [ "${HOOKY:-0}" -gt 0 ] && chk ebpf.hooking_programs WARN "${HOOKY} program(s) of syscall/packet/LSM-hooking types" "kprobe, fentry, tracepoint, lsm, xdp and tc types can observe or ALTER syscall arguments, return values and packets. Legitimate for observability and CNI agents; confirm each belongs to one, because this is exactly how an eBPF rootkit hides processes, files and network connections"
    raw "programs with no owning process (orphaned or pinned: survives the loader exiting)"
    printf '%s\n' "$PROGS" | grep -vE 'pids ' | grep -E '^[0-9]+:' | head -20 | sed 's/^/  /'
    ORPH="$(printf '%s\n' "$PROGS" | grep -E '^[0-9]+:' | grep -vc 'pids ')"
    [ "${ORPH:-0}" -gt 0 ] && chk ebpf.orphan_programs WARN "${ORPH} program(s) with no listed owning process" "a program stays loaded after its loader exits if it is pinned or still attached. Normal for CNI and systemd; for anything else it is persistence without a process to notice"
    raw "eBPF maps"
    run bpftool map list 2>/dev/null | cap 30
    raw "cgroup-attached programs"
    run bpftool cgroup tree 2>/dev/null | cap 20
    raw "BPF LSM programs (can enforce policy, or subvert it)"
    printf '%s\n' "$PROGS" | grep -E '^[0-9]+: lsm' | sed 's/^/  /'
    printf '%s' "$PROGS" | grep -qE '^[0-9]+: lsm' && chk ebpf.lsm_programs WARN "BPF LSM programs attached" "these participate in security decisions. Defensive tools (Falco, Tetragon, Tracee) use them legitimately; an attacker uses them to approve their own actions. Attribute every one"
  elif have bpftool; then
    chk ebpf.programs_loaded NA "bpftool requires root to list programs" "loaded eBPF is not enumerable as a normal user, not evidence that none is loaded"
  else
    chk ebpf.programs_loaded NA "bpftool not installed" "loaded eBPF programs cannot be enumerated. On a host that runs any eBPF-based agent this is a real blind spot: install bpftool (linux-tools / bpftool package)"
  fi

  # ---- pinned objects: persistence across reboot-free process death ----
  if [ -d /sys/fs/bpf ]; then
    raw "pinned BPF objects in bpffs (/sys/fs/bpf)"
    find /sys/fs/bpf -maxdepth 3 -print 2>/dev/null | head -25 | sed 's/^/  /'
    NPIN="$(find /sys/fs/bpf -mindepth 1 -maxdepth 3 -print 2>/dev/null | grep -c .)"
    [ "${NPIN:-0}" -gt 0 ] && chk ebpf.pinned_objects INFO "${NPIN} pinned object(s)" "pinning keeps a program or map alive with no owning process, and it is how an eBPF implant persists without a file on disk or a kernel module. Expected for Cilium/Calico; attribute anything else"
  fi

  # ---- packet-path attachments: XDP and tc ----
  raw "XDP programs attached to interfaces"
  ip link show 2>/dev/null | grep -iE 'xdp|prog/' | sed 's/^/  /'
  XDPN="$(ip link show 2>/dev/null | grep -ciE 'xdp')"
  [ "${XDPN:-0}" -gt 0 ] && chk ebpf.xdp_attached WARN "${XDPN} interface(s) with an XDP program" "XDP runs before the kernel network stack, so it can drop, rewrite or copy packets BEFORE anything else observes them, including tcpdump in some modes. Legitimate for high-performance CNI and DDoS filtering; otherwise it is invisible traffic interception"
  if have tc; then
    raw "tc BPF filters (clsact/ingress/egress)"
    for i in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | head -10); do
      f="$(tc filter show dev "$i" ingress 2>/dev/null | grep -i bpf | head -2)"
      [ -n "$f" ] && printf '  %s ingress: %s\n' "$i" "$(printf '%s' "$f" | tr '\n' ' ' | cut -c1-90)"
    done
  fi

  # ---- who is allowed to load ----
  raw "processes and files holding CAP_BPF / CAP_PERFMON / CAP_SYS_ADMIN"
  if [ "$QUICK" != "1" ] && have getcap; then
    for d in $SCANDIRS; do getcap -r "$d" 2>/dev/null; done | grep -iE 'cap_bpf|cap_perfmon' | head -10 | sed 's/^/  /'
    CAPB="$(for d in $SCANDIRS; do getcap -r "$d" 2>/dev/null; done | grep -ciE 'cap_bpf|cap_perfmon')"
    [ "${CAPB:-0}" -gt 0 ] && chk ebpf.cap_bpf_files WARN "${CAPB} binary/binaries with CAP_BPF or CAP_PERFMON" "these can load eBPF without full root. Intended for observability agents; on anything else it is a quiet route to kernel code"
  fi
  # lockdown interaction: worth stating because it is the control that actually stops this
  LD="$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oE '\[[a-z]+\]' | tr -d '[]')"
  case "$LD" in
    confidentiality) chk ebpf.lockdown PASS "lockdown=confidentiality" "bpf() access to kernel memory is blocked, which is the strongest available constraint on eBPF abuse, and the reason lsa-trace.sh cannot run here either" ;;
    integrity) chk ebpf.lockdown INFO "lockdown=integrity" "some BPF restrictions apply; kernel-memory reads are still possible in places" ;;
    *) chk ebpf.lockdown INFO "lockdown=${LD:-none}" "with kernel.modules_disabled=1 set but no lockdown, eBPF remains an unconstrained in-kernel execution path: the LKM door is shut while this one is open" ;;
  esac
fi

# ------------------------------------------------------------ 28. DOCKER HOST
# The daemon and the containers it runs, audited FROM THE HOST. Deliberately scoped to what a
# host audit can establish: daemon configuration and running-container posture. Build-time
# supply chain (image scanning, SBOM, signing, admission control) is a different lifecycle
# stage and a different tool's job (Trivy, Syft, Cosign, Kyverno); this reports whether that
# tooling exists rather than reimplementing it.
sec DOCKER_HOST
# Presence must be established from the TARGET. `have docker` resolves against the auditor's PATH
# and /var/run/docker.sock is the auditor's own socket, so offline both are evidence about the
# wrong machine: auditing an image from a workstation running Docker Desktop would otherwise emit
# a full set of daemon findings describing the workstation.
DOCKER_SOCK=0
[ "$OFFLINE" = "0" ] && [ -S /var/run/docker.sock ] && DOCKER_SOCK=1
if ! have_target docker && [ "$DOCKER_SOCK" = "0" ] && [ ! -f "$(rf /etc/docker/daemon.json)" ]; then
  chk docker.present INFO "no docker on this host" ""
else
  DJSON="$(cat "$(rf /etc/docker/daemon.json)" 2>/dev/null)"
  raw "/etc/docker/daemon.json"
  printf '%s\n' "${DJSON:-  (absent: every setting below is at its default)}"
  DINFO=""
  if [ "$OFFLINE" = "0" ] && have docker && docker info >/dev/null 2>&1; then
    DINFO="$(docker info 2>/dev/null)"
    raw "docker info (security-relevant)"
    printf '%s\n' "$DINFO" | grep -iE 'Security Options|seccomp|apparmor|selinux|userns|rootless|Cgroup|Storage Driver|Live Restore|Logging Driver|Server Version' | sed 's/^/  /'
  fi
  dj() { printf '%s' "$DJSON" | tr -d ' "' | grep -oE "$1:[^,}]*" | cut -d: -f2- | head -1; }

  # --- the daemon controls, in rough order of value ---
  if printf '%s' "$DJSON" | grep -q 'userns-remap' || printf '%s' "$DINFO" | grep -qi 'userns'; then
    chk docker.userns_remap PASS "userns-remap configured" "container root maps to an unprivileged host uid, so a container escape lands as nobody rather than root"
  else
    chk docker.userns_remap FAIL "userns-remap not set" "container UID 0 IS host UID 0. Every other container control (capabilities, seccomp, read-only rootfs) is a layer in front of that fact, and user-namespace remapping is the one that removes it. Set \"userns-remap\": \"default\" in daemon.json. Costs: shared volumes need ownership rework, and --privileged/host-namespace containers stop working"
  fi
  case "$(dj icc)" in
    false) chk docker.icc PASS "icc=false" "containers on the default bridge cannot reach each other" ;;
    *) chk docker.icc WARN "icc not disabled (default true)" "any container on the default bridge can reach any other, so a compromised container scans and attacks its neighbours. Set \"icc\": false and give each stack its own user-defined network" ;;
  esac
  printf '%s' "$DJSON" | grep -q 'no-new-privileges.*true' \
    && chk docker.no_new_privs_default PASS "no-new-privileges default true" "" \
    || chk docker.no_new_privs_default WARN "no-new-privileges not defaulted" "set it in daemon.json so every container gets it without relying on each run command"
  case "$(dj live-restore)" in
    true) chk docker.live_restore PASS "live-restore=true" "containers survive a daemon restart, so security patching the daemon is not an outage" ;;
    *) chk docker.live_restore INFO "live-restore not enabled" "a daemon restart stops every container, which in practice delays daemon patching" ;;
  esac
  case "$(dj userland-proxy)" in
    false) chk docker.userland_proxy PASS "userland-proxy=false" "" ;;
    *) chk docker.userland_proxy INFO "userland-proxy enabled (default)" "the proxy binds published ports in userspace and bypasses some iptables rules; false is preferred where the kernel supports hairpin NAT" ;;
  esac
  INSEC="$(printf '%s' "$DJSON" | tr -d ' \n"' | grep -oE 'insecure-registries:\[[^]]*\]')"
  [ -n "$INSEC" ] && chk docker.insecure_registries FAIL "$INSEC" "images are pulled over plaintext HTTP or with TLS verification disabled: an on-path attacker substitutes the image, and the container runs their code with whatever privileges it was granted"
  printf '%s' "$DJSON" | grep -q 'default-ulimits' \
    && chk docker.default_ulimits PASS "default-ulimits set" "" \
    || chk docker.default_ulimits WARN "no default-ulimits" "no per-container file-descriptor or process ceiling by default; one container can exhaust host resources"
  printf '%s' "$DJSON" | grep -qE '"log-driver"|log-driver' \
    && chk docker.log_driver PASS "log-driver configured: $(dj log-driver)" "" \
    || chk docker.log_driver WARN "default json-file log driver, no rotation configured" "container logs grow until the disk fills; set log-driver with max-size/max-file, or ship them off-host"
  printf '%s' "$DINFO" | grep -qi 'rootless' && chk docker.rootless PASS "rootless mode" "the daemon itself does not run as root"
  printf '%s' "$DINFO" | grep -qi 'seccomp' && printf '%s' "$DINFO" | grep -qi 'seccomp.*unconfined' \
    && chk docker.seccomp_default FAIL "default seccomp profile disabled" "every container gets the full syscall surface"

  # --- running containers, from the host ---
  if [ "$OFFLINE" = "0" ] && have docker && docker ps -q >/dev/null 2>&1; then
    raw "RUNNING CONTAINER POSTURE"
    CIDS="$(docker ps -q 2>/dev/null | head -40)"
    NC="$(printf '%s' "$CIDS" | grep -c .)"
    chk docker.running_count INFO "${NC} running container(s)" ""
    PRIV=""; NOLIM=""; RWROOT=""; ROOTU=""; NONNP=""; SOCKMNT=""; HOSTNET=""; LATEST=""; NOCAPDROP=""
    for c in $CIDS; do
      insp="$(docker inspect "$c" 2>/dev/null)"
      nm="$(printf '%s' "$insp" | grep -oE '"Name": "/[^"]+' | head -1 | cut -d/ -f2)"
      printf '%s' "$insp" | grep -q '"Privileged": true' && PRIV="$PRIV $nm"
      printf '%s' "$insp" | grep -qE '"Memory": 0' && printf '%s' "$insp" | grep -qE '"PidsLimit": (0|null)' && NOLIM="$NOLIM $nm"
      printf '%s' "$insp" | grep -q '"ReadonlyRootfs": false' && RWROOT="$RWROOT $nm"
      printf '%s' "$insp" | grep -qE '"User": ""' && ROOTU="$ROOTU $nm"
      printf '%s' "$insp" | grep -q 'no-new-privileges' || NONNP="$NONNP $nm"
      printf '%s' "$insp" | grep -qE '"NetworkMode": "host"' && HOSTNET="$HOSTNET $nm"
      printf '%s' "$insp" | grep -qE 'docker\.sock' && SOCKMNT="$SOCKMNT $nm"
      printf '%s' "$insp" | grep -qE '"Image": "[^"]*:latest"|"Image": "[^"@]*"' && LATEST="$LATEST $nm"
      printf '%s' "$insp" | grep -qE '"CapDrop": \[[^]]*(ALL|all)' || NOCAPDROP="$NOCAPDROP $nm"
      printf '  %-22s priv=%s ro-rootfs=%s user=%s net=%s\n' "$nm" \
        "$(printf '%s' "$insp" | grep -oE '"Privileged": (true|false)' | awk '{print $2}')" \
        "$(printf '%s' "$insp" | grep -oE '"ReadonlyRootfs": (true|false)' | awk '{print $2}')" \
        "$(printf '%s' "$insp" | grep -oE '"User": "[^"]*"' | head -1 | cut -d'"' -f4)" \
        "$(printf '%s' "$insp" | grep -oE '"NetworkMode": "[^"]*"' | cut -d'"' -f4)"
    done
    [ -n "$PRIV" ]    && chk docker.privileged_containers FAIL "$PRIV" "--privileged grants all capabilities, all devices and disables seccomp/AppArmor. It is not a container in any security sense; it is a process with a different filesystem view"
    [ -n "$SOCKMNT" ] && chk docker.socket_in_container FAIL "$SOCKMNT" "the docker socket is mounted into these containers: an immediate and complete host takeover from inside any of them"
    [ -n "$HOSTNET" ] && chk docker.host_network WARN "$HOSTNET" "--net=host removes network namespace isolation: the container binds host interfaces directly and sees all host traffic"
    [ -n "$ROOTU" ]   && chk docker.container_root FAIL "$ROOTU" "no USER set: these run as root inside the container, which without userns-remap is root on the host"
    [ -n "$NOLIM" ]   && chk docker.resource_limits FAIL "$NOLIM" "neither memory nor PID limits set. A fork bomb or memory leak in one container takes down every other workload on the host, and the OOM killer picks its victim by heuristic, not by importance. Set --memory and --pids-limit"
    [ -n "$RWROOT" ]  && chk docker.readonly_rootfs WARN "$RWROOT" "writable root filesystem: an attacker modifies the running image and persists for the container's lifetime. Use --read-only with explicit tmpfs mounts"
    [ -n "$NOCAPDROP" ] && chk docker.cap_drop WARN "$NOCAPDROP" "no 'cap_drop: ALL'. Docker's default set still includes CAP_CHOWN, CAP_SETUID, CAP_NET_RAW and others; drop all and add back only what is needed"
    [ -n "$NONNP" ]   && chk docker.no_new_privs WARN "$NONNP" "no-new-privileges not set: a SUID binary inside the image can still raise privileges"
    raw "published ports (0.0.0.0 exposes the container on every host interface)"
    docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null | head -20 | sed 's/^/  /'
    docker ps --format '{{.Ports}}' 2>/dev/null | grep -q '0\.0\.0\.0' && \
      chk docker.published_wildcard WARN "container ports published on 0.0.0.0" "same argument as host services: on a multi-homed host this exposes the container on the management network and VPN too. Publish as 127.0.0.1:port or a specific address"
    raw "secrets baked into image layers (docker history)"
    for img in $(docker ps --format '{{.Image}}' 2>/dev/null | sort -u | head -5); do
      H="$(docker history --no-trunc "$img" 2>/dev/null | grep -iE '(PASSWORD|SECRET|TOKEN|API_?KEY|AWS_|PRIVATE KEY)' | head -3)"
      [ -n "$H" ] && { printf '  %s:\n' "$img"; printf '%s\n' "$H" | sed 's/=[^ ]*/=<redacted>/g' | cut -c1-120 | sed 's/^/    /'
        chk "docker.image_secret.$(printf '%s' "$img" | tr '/:' '__')" FAIL "$img" "a credential appears in an image layer. Layers are immutable and distributed with the image, so deleting the file in a later layer does NOT remove it: anyone who can pull the image can read it. Rebuild with BuildKit secret mounts and rotate the credential"; }
    done
    raw "images in use: pinned by digest, or floating?"
    docker ps --format '{{.Image}}' 2>/dev/null | sort -u | sed 's/^/  /' | cap 15
    docker ps --format '{{.Image}}' 2>/dev/null | grep -qv '@sha256:' && \
      chk docker.image_pinning WARN "images referenced by tag, not digest" "a tag is mutable: the image you audited is not necessarily the image that runs after the next pull. Pin by @sha256: digest for anything security-relevant"
  elif [ "$OFFLINE" = "1" ]; then
    chk docker.runtime NA "offline (--root)" "running-container posture needs a live daemon"
  else
    chk docker.runtime NA "docker daemon not reachable (or insufficient privilege)" "daemon configuration above was still checked from daemon.json"
  fi

  # --- supply-chain tooling: report presence, do not reimplement ---
  DSCAN=""
  for t in trivy grype syft cosign docker-bench-security dockle; do have "$t" && DSCAN="$DSCAN $t"; done
  [ -n "$DSCAN" ] && chk docker.supplychain_tooling PASS "$DSCAN" "" \
    || chk docker.supplychain_tooling INFO "no image scanning or signing tooling found" "image CVE scanning (Trivy/Grype), SBOM generation (Syft) and signature verification (Cosign) are build- and registry-stage controls that this host audit deliberately does not attempt. If images are built or pulled here, that pipeline needs its own gate: CIS Docker Benchmark coverage via docker-bench-security is the closest equivalent to this section"
fi

# --------------------------------------------------------------- 28. CONTAINER
# Only meaningful when the audited thing IS a container (or an image run as one). The host's
# container posture (socket permissions, privileged containers, daemon TLS) is covered in
# SERVICES and TLS instead.
sec CONTAINER
if [ -z "$CTR" ]; then
  chk container.context INFO "not running inside a container" "host-level audit; container-image checks skipped"
else
  chk container.context INFO "$CTRTYPE (${CTR_MODE:-unknown} mode)" "container-level checks below; host-owned controls report NA with the reason. In inspection mode (PID 1 is a shell, so this container exists only to read the image) the runtime posture and namespaced sysctls describe THIS run, not the deployment, and report NA too: audit the compose/swarm/k8s manifest for those"

  # --- identity: the single highest-value container control ---
  CUID="$(id -u)"
  [ "$CUID" = "0" ] && chk container.runs_as_root FAIL "uid 0" "the image has no USER directive, or it was overridden. Root in a container is root on the host the moment any isolation boundary fails (a kernel bug, a writable host mount, a leaked socket). Add USER to the Dockerfile and set runAsNonRoot in Kubernetes" \
                    || chk container.runs_as_root PASS "uid $CUID" ""

  # --- capabilities of PID 1: privileged shows as a full set ---
  CAPEFF="$(awk '/^CapEff/{print $2}' /proc/1/status 2>/dev/null)"
  CAPBND="$(awk '/^CapBnd/{print $2}' /proc/1/status 2>/dev/null)"
  raw "capabilities of PID 1"
  printf '  CapEff=%s CapBnd=%s\n' "${CAPEFF:-?}" "${CAPBND:-?}"
  have capsh && run capsh --decode="${CAPEFF:-0}" 2>/dev/null | head -3
  case "$CAPEFF" in
    0000003fffffffff|000001ffffffffff|0000003fffffffff|ffffffffffffffff)
      chk container.privileged FAIL "CapEff=$CAPEFF (full capability set)" "this container is PRIVILEGED or was given every capability. It can load kernel modules, access all devices and mount filesystems: it is not a security boundary at all" ;;
    0000000000000000) chk container.privileged PASS "no effective capabilities" "" ;;
    *) chk container.privileged INFO "CapEff=$CAPEFF" "decode with 'capsh --decode='; CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH are each close to a host escape" ;;
  esac
  for c in cap_sys_admin cap_sys_module cap_sys_ptrace cap_dac_read_search cap_net_admin cap_sys_rawio; do
    have capsh && capsh --decode="${CAPEFF:-0}" 2>/dev/null | grep -q "$c" && chk "container.cap.$c" WARN "held" "this capability is a documented container-escape primitive"
  done

  # --- seccomp and MAC confinement ---
  SECC="$(awk '/^Seccomp:/{print $2}' /proc/1/status 2>/dev/null)"
  case "$SECC" in
    2) chk container.seccomp PASS "filter mode (2)" "" ;;
    1) chk container.seccomp WARN "strict mode (1)" "" ;;
    0|"") chk container.seccomp FAIL "${SECC:-absent}: no seccomp filter" "the container can issue every syscall the kernel offers, including the ones used for escapes. Docker applies a default profile unless --security-opt seccomp=unconfined or --privileged was used" ;;
  esac
  AAP="$(cat /proc/1/attr/current 2>/dev/null)"
  case "$AAP" in
    ""|unconfined*) chk container.mac WARN "${AAP:-none}" "no AppArmor/SELinux profile on PID 1: the container relies on namespaces and capabilities alone" ;;
    *) chk container.mac PASS "$AAP" "" ;;
  esac
  grep -q 'NoNewPrivs:.*1' /proc/1/status 2>/dev/null && chk container.no_new_privs PASS "set" "" \
    || chk container.no_new_privs FAIL "not set" "a SUID binary inside the image can still raise privileges; set no-new-privileges"

  # --- namespace sharing: each shared namespace removes a wall ---
  raw "namespaces of PID 1 vs this process"
  ls -l /proc/1/ns/ 2>/dev/null | awk '{print "  "$9" "$10" "$11}'
  if [ -r /proc/1/ns/pid ] && [ -r /proc/self/ns/pid ]; then
    grep -q . /proc/1/cgroup 2>/dev/null && raw "cgroup membership" && head -3 /proc/1/cgroup 2>/dev/null
  fi
  PIDCOUNT="$(ps -eo pid= 2>/dev/null | wc -l | tr -d ' ')"
  [ "${PIDCOUNT:-0}" -gt 100 ] && chk container.pid_namespace FAIL "${PIDCOUNT} processes visible" "a container should see only its own processes. Seeing the host's process table means --pid=host, which allows ptrace and /proc access to host processes"

  # --- the docker socket inside a container is a direct host takeover ---
  for sock in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do
    [ -S "$sock" ] && chk "container.socket.$(basename "$sock")" FAIL "$sock mounted inside the container" "write access to the container runtime socket from inside a container is an immediate, complete host takeover: start a new container with the host filesystem mounted. There is no configuration that makes this safe"
  done

  # --- host filesystem mounted in ---
  raw "mounts from the host"
  grep -vE ' (overlay|tmpfs|proc|sysfs|cgroup|cgroup2|devpts|mqueue|shm|securityfs|pstore|bpf|debugfs|tracefs|configfs|fusectl|nsfs) ' /proc/mounts 2>/dev/null | cap 20
  for hm in /host /hostfs /rootfs; do
    [ -d "$hm" ] && chk "container.host_mount$hm" FAIL "$hm present" "the host filesystem is mounted into the container"
  done
  grep -qE '^\S+ /etc/(passwd|shadow|ssh) ' /proc/mounts 2>/dev/null && chk container.host_sensitive_mount FAIL "host /etc file bind-mounted" "host credential files are exposed to the container"
  # writable host paths are the escape route that survives everything else
  awk '$2 !~ /^\/(proc|sys|dev|run|etc\/host|etc\/resolv)/ && $4 ~ /(^|,)rw(,|$)/ {print "  rw: "$2" ("$3")"}' /proc/mounts 2>/dev/null | cap 15
  ROFS=0
  awk '$2=="/" && $4 ~ /(^|,)ro(,|$)/ {found=1} END{exit !found}' /proc/mounts 2>/dev/null && ROFS=1
  [ "$ROFS" = "1" ] && chk container.readonly_rootfs PASS "root filesystem is read-only" "" \
                    || chk container.readonly_rootfs WARN "root filesystem is writable" "an attacker can modify the image contents at runtime and persist within the container's lifetime; --read-only plus explicit tmpfs mounts is the hardened form"

  # --- image hygiene ---
  raw "SUID/SGID binaries inside the image (each is unnecessary attack surface in a container)"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | head -20 | tr '\n' '\0' | xargs -0 ls -l 2>/dev/null
  NSUID="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | wc -l | tr -d ' ')"
  [ "${NSUID:-0}" -gt 0 ] && chk container.suid_binaries WARN "${NSUID} SUID/SGID binaries in the image" "containers almost never need any. Build with 'RUN find / -perm /6000 -type f -exec chmod a-s {} +' or use a distroless base"
  raw "package manager present in the image"
  for pm in apt-get apk dnf yum microdnf; do have "$pm" && printf '  %s present\n' "$pm"; done
  have apt-get || have apk || have dnf || true
  raw "shells and interpreters in the image"
  for sh in bash sh dash ash python3 perl ruby node; do have "$sh" && printf '  %s ' "$sh"; done; echo
  raw "credentials in the container environment (values redacted)"
  # Name-shaped matching alone is not enough: base images ship GPG_KEY (a public OpenPGP
  # fingerprint used to verify a source tarball) and *_SHA256 (a published digest). Both are
  # public by design, so a bare hex fingerprint or digest is excluded on value shape.
  env_cred() {
    tr '\0' '\n' < /proc/1/environ 2>/dev/null \
      | grep -iE '(PASS|SECRET|TOKEN|KEY|CRED)' \
      | awk -F= '{
          n=$1; v=$2
          if (n ~ /(SHA[0-9]+|_DIGEST|_FINGERPRINT|_KEY_?ID|GPG_KEY|PUBKEY)$/ && v ~ /^[0-9A-Fa-f]{32,128}$/) next
          print
        }'
  }
  env_cred | sed 's/=.*/=<redacted>/' | cap 10
  env_cred | grep -c . | while read -r n; do
    [ "${n:-0}" -gt 0 ] && chk container.env_secrets FAIL "${n} credential-shaped environment variable(s)" "environment variables are readable via /proc/<pid>/environ by anything in the container, are captured in 'docker inspect', and are baked into image metadata if set with ENV. Use a mounted secret or a secrets manager"
  done
fi

# ---------------------------------------------------- 28. STATIC vs RUNTIME DRIFT
# Many controls exist twice: as intent on disk and as reality in the kernel. Auditing only
# one side is how both of these get missed, and they mean opposite things:
#
#   RUNTIME-ONLY  applied now, not persisted  -> silently reverts at the next reboot.
#                 A config-file-only audit reports this as FAIL; a live-only audit reports
#                 it as PASS. Both are wrong.
#   CONFIG-ONLY   persisted, not applied      -> the file says compliant and the kernel
#                 disagrees. Usually a typo, an unsupported key, a value outside the
#                 architecture's range, or a later file overriding it. This is the
#                 dangerous direction: every checklist-by-grep audit scores it as a pass.
#   MISMATCH      both present, different     -> override ordering, or something changed it
#                 at runtime (tuned, a container runtime, a config-management run, or an
#                 attacker covering a change that a reboot would undo).
sec DRIFT
if [ -n "$CTR" ] || [ "$OFFLINE" = "1" ]; then
  chk drift.container_context NA "running inside a $CTRTYPE container" "static-vs-runtime drift compares this system's config against its own kernel; in a container the kernel is the host's; audit the host for this section"
else
runtime_on
DRIFTN=0

# ---- sysctl: running value vs the effective persisted value ----
# Reproduce systemd-sysctl's precedence: files are merged by BASENAME across the three
# directories (/etc wins over /run wins over /usr/lib), applied in lexicographic basename
# order, and /etc/sysctl.conf is applied last.
SYSCTL_EFFECTIVE="$(
  { for b in $( { ls "$LSA_ROOT"/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf "$LSA_ROOT"/etc/sysctl.d/*.conf 2>/dev/null; } \
                 | xargs -n1 basename 2>/dev/null | sort -u ); do
      for d in /etc/sysctl.d /run/sysctl.d /usr/lib/sysctl.d; do
        [ -r "$d/$b" ] && { printf '%s\n' "$d/$b"; break; }
      done
    done
    [ -r "$(rf /etc/sysctl.conf)" ] && printf '/etc/sysctl.conf\n'
  } | while IFS= read -r f; do grep -hE '^[[:space:]]*[a-z]' "$f" 2>/dev/null; done \
    | sed 's/#.*//' | tr -d ' \t' | grep '=' )"
raw "effective persisted sysctl assignments (later lines win)"
printf '%s\n' "$SYSCTL_EFFECTIVE" | tail -40

printf '%s\n' "$SYSCTLS" | while IFS='|' read -r key want sev; do
  [ -z "$key" ] || [ "$want" = "*" ] && continue
  path="/proc/sys/$(printf '%s' "$key" | tr '.' '/')"
  [ -e "$path" ] || continue
  live="$(trim "$(cat "$path" 2>/dev/null)")"
  # last persisted assignment for this key
  conf="$(printf '%s\n' "$SYSCTL_EFFECTIVE" | grep -E "^${key}=" | tail -1 | cut -d= -f2-)"
  if [ -z "$conf" ]; then
    if [ "$live" = "$(trim "$want")" ]; then
      chk "drift.sysctl.$key" WARN "RUNTIME-ONLY (live=$live, not in any sysctl.d file)" "the value is correct now but nothing persists it: it reverts at the next reboot. If a config-management run set it, make sure the file is written too"
      DRIFTN=$((DRIFTN+1))
    fi
  elif [ "$(trim "$conf")" != "$live" ]; then
    chk "drift.sysctl.$key" FAIL "CONFIG-ONLY (config=$conf, live=$live)" "the persisted value was NOT applied. Check 'systemd-sysctl' errors in the journal: an unsupported key, a value outside the architecture range (vm.mmap_rnd_bits is the usual one), or a later-sorting file overriding it. An audit that reads only the config file scores this as compliant"
    DRIFTN=$((DRIFTN+1))
  fi
done
DRIFT_SYSCTL="$(printf '%s\n' "$SYSCTLS" | while IFS='|' read -r key want sev; do
  [ -z "$key" ] || [ "$want" = "*" ] && continue
  path="/proc/sys/$(printf '%s' "$key" | tr '.' '/')"; [ -e "$path" ] || continue
  live="$(trim "$(cat "$path" 2>/dev/null)")"
  conf="$(printf '%s\n' "$SYSCTL_EFFECTIVE" | grep -E "^${key}=" | tail -1 | cut -d= -f2-)"
  if [ -z "$conf" ]; then [ "$live" = "$(trim "$want")" ] && echo x
  elif [ "$(trim "$conf")" != "$live" ]; then echo x; fi
done | grep -c x)"
raw "systemd-sysctl application errors (the direct evidence for CONFIG-ONLY drift)"
have journalctl && run journalctl -q --no-pager -b -u systemd-sysctl 2>/dev/null | tail -15

# ---- kernel command line: running vs what the bootloader config would produce ----
raw "kernel cmdline: running vs /etc/default/grub"
GRUBCFG="$(grep -hE '^\s*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$(rf /etc/default/grub)" 2>/dev/null | cut -d= -f2- | tr -d '"'"'"'')"
printf '  running : %s\n' "$(cat /proc/cmdline 2>/dev/null)"
printf '  intended: %s\n' "$GRUBCFG"
if [ -n "$GRUBCFG" ]; then
  MISSINGP=""
  for tok in $GRUBCFG; do
    case "$tok" in ""|\$*) continue ;; esac
    case " $(cat /proc/cmdline 2>/dev/null) " in *" $tok "*) ;; *) MISSINGP="$MISSINGP $tok" ;; esac
  done
  if [ -n "$MISSINGP" ]; then
    chk drift.cmdline FAIL "CONFIG-ONLY:$MISSINGP" "these parameters are in /etc/default/grub but NOT on the running kernel command line, either update-grub/grub2-mkconfig was never run after the edit, or the running kernel predates it. The hardening is not in effect and a reboot is required to find out whether it even works"
    DRIFTN=$((DRIFTN+1))
  else
    chk drift.cmdline PASS "running cmdline contains every parameter from /etc/default/grub" ""
  fi
fi

# ---- mount options: live vs fstab ----
raw "mount options: live vs /etc/fstab"
DRIFT_MNT=0
for mp in /home /tmp /var /var/tmp /var/log /boot /dev/shm /srv; do
  is_mp "$mp" || continue
  livo="$(mopts "$mp")"
  fso="$(awk -v m="$mp" '!/^[[:space:]]*#/ && $2==m {print $4; exit}' /etc/fstab 2>/dev/null)"
  [ -z "$fso" ] && continue
  miss=""; extra=""
  for o in nosuid noexec nodev ro; do
    case ",$fso," in *",$o,"*) case ",$livo," in *",$o,"*) ;; *) miss="$miss $o" ;; esac ;; esac
    case ",$livo," in *",$o,"*) case ",$fso,"  in *",$o,"*) ;; *) extra="$extra $o" ;; esac ;; esac
  done
  printf '  %-10s live=%s\n             fstab=%s\n' "$mp" "$livo" "$fso"
  if [ -n "$miss" ]; then
    chk "drift.mount$mp" FAIL "CONFIG-ONLY: fstab has$miss but the live mount does not" "the mount was never remounted with the new options. It will apply at the next boot, which is also when you find out if it breaks the service. Test now with: mount -o remount,$(printf '%s' "$miss" | tr -d ' ') $mp"
    DRIFT_MNT=$((DRIFT_MNT+1))
  fi
  if [ -n "$extra" ]; then
    chk "drift.mount$mp" WARN "RUNTIME-ONLY: live mount has$extra, fstab does not" "someone remounted this by hand: it reverts at the next boot"
    DRIFT_MNT=$((DRIFT_MNT+1))
  fi
done

# ---- kernel modules: blacklisted on disk but loaded in the kernel ----
raw "modules blacklisted in /etc/modprobe.d but currently loaded"
LOADED="$(lsmod 2>/dev/null | awk 'NR>1{print $1}')"
DRIFT_MOD=""
for m in $(printf '%s' "$MPD" | grep -oE '^\s*(install|blacklist)\s+[a-z0-9_-]+' | awk '{print $2}' | sort -u); do
  mn="$(printf '%s' "$m" | tr '-' '_')"
  printf '%s\n' "$LOADED" | grep -qx "$mn" && DRIFT_MOD="$DRIFT_MOD $m"
done
if [ -n "$DRIFT_MOD" ]; then
  chk drift.modules FAIL "blacklisted but LOADED:$DRIFT_MOD" "the blacklist is not in effect for these. Either it was added after boot, or the module is pulled in from the initramfs (rebuild it: update-initramfs -u / dracut -f), or something loaded it explicitly. Until a reboot proves otherwise, treat the blacklist as not applied"
  DRIFTN=$((DRIFTN+1))
else
  chk drift.modules PASS "no blacklisted module is loaded" ""
fi

# ---- firewall: live ruleset vs what is saved for the next boot ----
raw "firewall: live ruleset vs persisted rules"
LIVERULES=0
have nft && [ "$AM_ROOT" = "1" ] && LIVERULES="$(nft list ruleset 2>/dev/null | grep -c '^\s*\(ip\|tcp\|udp\|ct\|meta\|accept\|drop\|reject\)')"
[ "${LIVERULES:-0}" = "0" ] && have iptables && [ "$AM_ROOT" = "1" ] && LIVERULES="$(iptables -S 2>/dev/null | grep -vc '^-P')"
SAVED=""
for f in /etc/iptables/rules.v4 /etc/sysconfig/iptables /etc/nftables.conf /etc/ufw/user.rules /etc/firewalld/zones/*.xml; do
  [ -s "$f" ] && SAVED="$SAVED $f"
done
printf '  live rule count: %s\n  persisted rule files:%s\n' "${LIVERULES:-?}" "${SAVED:- none}"
if [ "${LIVERULES:-0}" -gt 0 ] && [ -z "$SAVED" ]; then
  chk drift.firewall FAIL "RUNTIME-ONLY: ${LIVERULES} live rules, no persisted ruleset found" "the firewall is protecting this host right now and will be EMPTY after a reboot. This is the single most common way a host silently loses its firewall"
  DRIFTN=$((DRIFTN+1))
elif [ "${LIVERULES:-0}" = "0" ] && [ -n "$SAVED" ]; then
  chk drift.firewall FAIL "CONFIG-ONLY: rules are saved in$SAVED but the live ruleset is empty" "the saved rules were never loaded: the host is unprotected now despite a config that looks correct"
  DRIFTN=$((DRIFTN+1))
else
  chk drift.firewall PASS "live and persisted firewall state are consistent" ""
fi

# ---- services: running vs enabled ----
if have systemctl; then
  raw "services: running but not enabled, or enabled but not running"
  RNE=""; ENR=""
  for u in $(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -60); do
    systemctl is-enabled "$u" >/dev/null 2>&1 || RNE="$RNE $u"
  done
  for u in $(systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -60); do
    systemctl is-active "$u" >/dev/null 2>&1 || ENR="$ENR $u"
  done
  [ -n "$RNE" ] && chk drift.services_not_enabled WARN "running but not enabled:$RNE" "these disappear at the next reboot. For a security control (fail2ban, auditd, usbguard, firewall) that is a silent loss of protection"
  [ -n "$ENR" ] && chk drift.services_not_running WARN "enabled but not running:$ENR" "these were meant to start and did not; check for a failed unit. An enabled-but-dead auditd or firewall reads as configured while providing nothing"
fi

# ---- SELinux / AppArmor: runtime mode vs configured mode ----
if have getenforce; then
  RTM="$(getenforce 2>/dev/null | tr 'A-Z' 'a-z')"
  CFM="$(awk -F= '/^\s*SELINUX\s*=/{gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$(rf /etc/selinux/config)" 2>/dev/null)"
  if [ -n "$CFM" ] && [ "$RTM" != "$CFM" ]; then
    chk drift.selinux FAIL "runtime=$RTM config=$CFM" "the running mode and the configured mode disagree, whichever is stricter, it is not the state you get after a reboot"
    DRIFTN=$((DRIFTN+1))
  fi
fi

# ---- IPv6: three places can disable it, and they can disagree ----
V6CMD=0; case " $(cat /proc/cmdline 2>/dev/null) " in *" ipv6.disable=1 "*) V6CMD=1 ;; esac
V6RUN="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
V6CFG="$(printf '%s\n' "$SYSCTL_EFFECTIVE" | grep -E '^net\.ipv6\.conf\.all\.disable_ipv6=' | tail -1 | cut -d= -f2)"
printf '  ipv6: cmdline_disabled=%s runtime_disable=%s persisted=%s\n' "$V6CMD" "${V6RUN:-n/a}" "${V6CFG:-unset}"
if [ "$V6CMD" = "1" ] && [ -n "$V6CFG" ]; then
  chk drift.ipv6 WARN "disabled at the cmdline AND set via sysctl" "with ipv6.disable=1 the net.ipv6.* tunables do not exist, so the sysctl entries fail to apply and systemd-sysctl logs errors every boot. Pick one mechanism"
fi

TOTALDRIFT=$(( ${DRIFT_SYSCTL:-0} + ${DRIFT_MNT:-0} ))
if [ "$TOTALDRIFT" -gt 0 ]; then
  chk drift.total FAIL "${TOTALDRIFT} sysctl/mount divergence(s) between disk and kernel" "each is either a control that vanishes at reboot or one that was never applied. Resolve before trusting any other PASS in this report, because a config-only audit and a runtime-only audit disagree exactly here"
else
  chk drift.total PASS "no sysctl or mount drift detected" "persisted intent matches running state"
fi
method_reset

# ------------------------------------------------------------- 28. MISC/EXTRA
fi

sec MISC
raw "ctrl-alt-del target"
have systemctl && run systemctl is-enabled ctrl-alt-del.target 2>/dev/null
raw "/etc/issue /etc/issue.net banner"
head -3 "$(rf /etc/issue)" "$(rf /etc/issue.net)" 2>/dev/null
raw "prelink"
have prelink && echo "prelink installed (weakens ASLR)"
raw "wireless"
have rfkill && run rfkill list
raw "environment: LD_PRELOAD in system config"
grep -rhs 'LD_PRELOAD\|LD_LIBRARY_PATH' "$(rf /etc/environment)" "$(rf /etc/ld.so.preload)" "$(rf /etc/profile)" "$(rf /etc/profile.d/)" 2>/dev/null
[ -s "$(rf /etc/ld.so.preload)" ] && chk misc.ld_so_preload WARN "non-empty" "classic userland-rootkit persistence; verify every entry" || chk misc.ld_so_preload PASS "empty/absent" ""
raw "kernel taint"
cat /proc/sys/kernel/tainted 2>/dev/null

# ---- interfaces in promiscuous mode (a sniffer, or a bridge you forgot about) ----
raw "promiscuous interfaces"
ip link show 2>/dev/null | grep -i promisc
PROMISC="$(ip link show 2>/dev/null | grep -ci promisc)"
[ "${PROMISC:-0}" -gt 0 ] && chk misc.promiscuous WARN "${PROMISC} interface(s) in promiscuous mode" "expected on a bridge/hypervisor/IDS sensor; anywhere else it means something is capturing traffic: identify the process" \
                          || chk misc.promiscuous PASS "none" ""

# ---- entropy: key generation quality depends on it ----
if [ -r /proc/sys/kernel/random/entropy_avail ]; then
  ENT="$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)"
  # kernels >=5.6 keep this near 256 by design and are always ready; older ones can starve
  [ "${ENT:-0}" -lt 200 ] && chk misc.entropy WARN "$ENT" "low entropy pool: on older kernels this stalls or weakens key generation; check for rngd/haveged on VMs without RDRAND" \
                          || chk misc.entropy PASS "$ENT" ""
  have rngd && echo "rngd present"; have haveged && echo "haveged present"
fi

# ---- system-wide crypto policy (RHEL family) ----
if have update-crypto-policies; then
  CP="$(update-crypto-policies --show 2>/dev/null)"
  case "$CP" in
    LEGACY*) chk misc.crypto_policy FAIL "$CP" "LEGACY re-enables SHA-1, 3DES, TLS 1.0/1.1 and 1024-bit DH across every TLS/SSH/crypto consumer on the host at once" ;;
    DEFAULT*) chk misc.crypto_policy PASS "$CP" "consider FUTURE or DEFAULT:NO-SHA1 for stricter" ;;
    FUTURE*|*NO-SHA1*) chk misc.crypto_policy PASS "$CP" "" ;;
    *) chk misc.crypto_policy INFO "${CP:-unknown}" "" ;;
  esac
fi

# ---- old kernels left installed, and running vs newest installed ----
raw "installed kernel packages"
if have dpkg-query; then
  dpkg-query -W -f='${binary:Package}\n' 'linux-image-*' 2>/dev/null | grep -E 'linux-image-[0-9]' | sort
  NK="$(dpkg-query -W -f='${binary:Package}\n' 'linux-image-*' 2>/dev/null | grep -cE 'linux-image-[0-9]')"
  NEWEST="$(dpkg-query -W -f='${binary:Package}\n' 'linux-image-*' 2>/dev/null | grep -E 'linux-image-[0-9]' | sed 's/linux-image-//' | sort -V | tail -1)"
elif have rpm; then
  rpm -q kernel 2>/dev/null | sort
  NK="$(rpm -q kernel 2>/dev/null | grep -c '^kernel-')"
  NEWEST="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -1)"
fi
[ "${NK:-0}" -gt 3 ] && chk misc.old_kernels WARN "${NK} kernel packages installed" "old kernels remain bootable from the GRUB menu: anyone with console access can select a vulnerable one and bypass the hardening of the current kernel. Purge the ones you no longer need"
if [ -n "$NEWEST" ]; then
  case "$KREL" in
    *"$NEWEST"*|"$NEWEST"*) chk misc.running_newest PASS "running $KREL (newest installed)" "" ;;
    *) chk misc.running_newest FAIL "running $KREL, newest installed is $NEWEST" "a patched kernel is on disk but not in use: reboot, or the update did nothing" ;;
  esac
fi

# ---- auditd rule coverage by event class (rules present is not rules useful) ----
if [ "$AM_ROOT" = "1" ] && have auditctl && auditctl -l >/dev/null 2>&1; then
  AR="$(auditctl -l 2>/dev/null)"
  raw "auditd rule coverage by event class"
  for cls in "time-change:adjtimex|settimeofday|clock_settime|/etc/localtime" \
             "identity:/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow" \
             "MAC-policy:/etc/selinux|/etc/apparmor" \
             "logins:/var/log/lastlog|/var/log/faillog|faillock" \
             "session:/var/run/utmp|/var/log/wtmp|/var/log/btmp" \
             "perm-mod:chmod|chown|setxattr" \
             "privileged-cmds:-F perm=x -F auid" \
             "mounts:mount" \
             "deletion:unlink|rename" \
             "sudoers:/etc/sudoers" \
             "modules:init_module|delete_module|/sbin/insmod" \
             "execve:execve"; do
    n="${cls%%:*}"; pat="${cls#*:}"
    printf '%s' "$AR" | grep -qE "$pat" && printf '  covered   %s\n' "$n" || printf '  MISSING   %s\n' "$n"
  done
  MISSCLS="$(for cls in "adjtimex|settimeofday" "/etc/passwd" "/var/log/wtmp" "chmod|chown" "unlink|rename" "/etc/sudoers" "init_module" "execve"; do
    printf '%s' "$AR" | grep -qE "$cls" || printf 'x'; done | wc -c | tr -d ' ')"
  [ "${MISSCLS:-0}" -gt 2 ] && chk logging.auditd_coverage WARN "${MISSCLS} of 8 core event classes unmonitored" "auditd is running but its ruleset does not cover the events an investigation needs. Start from the Neo23x0/auditd ruleset and tune"
fi
raw "installed audit tooling"
for t in lynis oscap openscap-scanner debsecan ssh-audit; do have "$t" && echo "$t: present"; done

# ---------------------------------------------------------------- RUN SUMMARY
# Emitted by the collector rather than documented in prose, so the figures cannot drift away
# from the check set. The report should quote these, not any number written down elsewhere.
sec RUN_SUMMARY
LSA_T1="$(date +%s 2>/dev/null || echo 0)"
printf 'collector_version=%s\n' "$LSA_VERSION"
# Piped in (`ssh host 'bash -s' < script`) $0 is the interpreter, not the script, so there is
# nothing to hash. Say so rather than printing a digest of /bin/bash and calling it provenance.
if [ -r "$0" ] && case "$0" in */lsa-collect.sh|lsa-collect.sh) true ;; *) false ;; esac; then
  printf 'collector_sha256=%s\n' \
    "$( { sha256sum "$0" 2>/dev/null || shasum -a 256 "$0" 2>/dev/null; } | awk '{print substr($1,1,16); exit}')"
else
  printf 'collector_sha256=unavailable (script piped to the interpreter; pin by version instead)\n'
fi
printf 'elapsed_seconds=%s\n' "$((LSA_T1 - LSA_T0))"

if [ -n "$LSA_TALLY" ] && [ -s "$LSA_TALLY" ]; then
  awk '
    $1=="V" { st[$2]++; me[$3]++; tot++ }
    $1=="S" { sect[$2]=$3 }
    $1=="T" { trunc++ }
    END {
      printf "checks_total=%d\n", tot
      printf "verdicts=PASS %d, FAIL %d, WARN %d, INFO %d, NA %d\n",
             st["PASS"], st["FAIL"], st["WARN"], st["INFO"], st["NA"]
      printf "method_counts=static %d, runtime %d, active %d\n",
             me["static"], me["runtime"], me["active"]
      if (tot > 0)
        printf "method_pct=static %.0f%%, runtime %.0f%%, active %.0f%%\n",
               100*me["static"]/tot, 100*me["runtime"]/tot, 100*me["active"]/tot
      # NA share is the headline number for collection quality: it is what the run could not
      # determine, and it must never be read as compliance.
      if (tot > 0) printf "undetermined_pct=%.0f%%\n", 100*st["NA"]/tot
      printf "truncated_lists=%d\n", trunc+0
      n=0
      for (s in sect) { n++; order[n]=s }
      for (i=1;i<=n;i++) for (j=i+1;j<=n;j++)
        if (sect[order[j]]+0 > sect[order[i]]+0) { t=order[i]; order[i]=order[j]; order[j]=t }
      printf "slowest_sections="
      for (i=1;i<=n && i<=5;i++) printf "%s%s %ss", (i>1 ? ", " : ""), order[i], sect[order[i]]
      printf "\n"
    }' "$LSA_TALLY"
else
  printf 'checks_total=unavailable (no mktemp; tally skipped)\n'
fi

printf '\n===== END OF COLLECTION =====\n'
