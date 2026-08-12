#!/usr/bin/env bash
# lsa-trace.sh - observe what root processes ACTUALLY open, and flag any path an
# unprivileged user can write. Complements the static BOOT_CHAIN analysis in lsa-collect.sh.
#
# THIS SCRIPT IS NOT READ-ONLY IN THE SAME SENSE AS THE COLLECTOR.
#   --unit <name>   restarts a service (brief outage for that service)
#   --boot arm      installs temporary audit rules and asks you to reboot
#   --boot report   reads back what the armed rules recorded, then disarms
#   --live <secs>   passive system-wide observation, changes nothing. Uses bpftrace/opensnoop/
#                   fatrace if present, else falls back to a dependency-free /proc snapshot poller
#                   (open fds + mmaps of root procs) that works on hardened images with no tracer.
#   --preflight     report which modes are possible on this host, change nothing
# Every mode prints exactly what it will do and requires --yes to proceed.
#
# Usage:
#   ./lsa-trace.sh --preflight           # always start here on a hardened host
#   ./lsa-trace.sh --live 60
#   ./lsa-trace.sh --unit nginx.service --yes
#   ./lsa-trace.sh --boot arm --yes      # then: reboot
#   ./lsa-trace.sh --boot report
#
# Findings are printed as: RISK <severity> <path> (<why>) <- opened by <pid/comm>

LC_ALL=C; export LC_ALL
MODE=""; UNIT=""; SECS=60; YES=0; BOOTOP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --live) MODE=live; SECS="${2:-60}"; shift ;;
    --unit) MODE=unit; UNIT="$2"; shift ;;
    --boot) MODE=boot; BOOTOP="${2:-arm}"; shift ;;
    --preflight) MODE=preflight ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
  shift
done
[ -z "$MODE" ] && { sed -n '2,20p' "$0"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
[ "$MODE" = "preflight" ] || [ "$(id -u)" = "0" ] || { echo "ERROR: must run as root - tracing syscalls requires it."; exit 1; }

# Most severe writability issue anywhere on a path (file or any ancestor directory).
# Write access to a parent directory is enough to replace the file.
path_risk() {
  _p="$1"; _w=""; _g=""; _o=""; _depth=0
  while [ -n "$_p" ] && [ "$_p" != "/" ] && [ "$_p" != "." ]; do
    if [ -e "$_p" ]; then
      _s="$(stat -c '%a %U %G' "$_p" 2>/dev/null)"
      if [ -n "$_s" ]; then
        _m="${_s%% *}"; _own="$(printf '%s' "$_s" | awk '{print $2}')"; _grp="$(printf '%s' "$_s" | awk '{print $3}')"
        # Sticky world-writable ANCESTOR directories (/tmp, /var/tmp, /dev/shm = 1777) are not a
        # replace risk: the sticky bit stops non-owners deleting or renaming entries. Without this
        # every path under /tmp reports as writable, which is noise on every host.
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

# filter noise that is never interesting
skip_path() {
  case "$1" in
    /proc/*|/sys/*|/dev/*|/run/*|/tmp/#*|*/.cache/*|/var/cache/*|/usr/share/locale/*|"") return 0 ;;
  esac
  return 1
}

analyse_paths() { # reads paths on stdin, prints findings
  _n=0
  sort -u | while IFS= read -r p; do
    skip_path "$p" && continue
    [ -e "$p" ] || continue
    r="$(path_risk "$p")"
    [ -n "$r" ] && printf 'RISK %s\n' "$r"
  done | sort -u
}

confirm() {
  printf '\n%s\n' "$1"
  if [ "$YES" = "1" ]; then echo "(--yes given, proceeding)"; return 0; fi
  printf 'Proceed? [y/N] '; read -r a
  case "$a" in y|Y|yes) return 0 ;; *) echo "aborted."; exit 1 ;; esac
}

# ------------------------------------------------------------------ PREFLIGHT
# A properly hardened host BLOCKS most tracing - that is the hardening working as
# designed. Establish what is possible WITHOUT changing anything, and never weaken
# the system silently. Runs before every mode.
PF_BPF=""; PF_PTRACE=""; PF_FAN=""; PF_AUDIT=""; PF_PROC=""
preflight() {
  echo "=== preflight: what can be traced on THIS host without changing it ==="

  LOCKDOWN="$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oE '\[[a-z]+\]' | tr -d '[]')"
  YAMA="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
  PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
  BPFDIS="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
  SEL="$(getenforce 2>/dev/null)"
  printf '  lockdown=%s  yama.ptrace_scope=%s  perf_event_paranoid=%s  unprivileged_bpf_disabled=%s  selinux=%s\n' \
    "${LOCKDOWN:-none}" "${YAMA:-0}" "${PARANOID:-?}" "${BPFDIS:-?}" "${SEL:-n/a}"

  # --- eBPF (bpftrace / bcc) ---
  if ! have bpftrace && ! have opensnoop-bpfcc && ! have opensnoop; then
    PF_BPF="unavailable: no bpftrace/bcc installed"
  elif [ "$LOCKDOWN" = "confidentiality" ]; then
    PF_BPF="BLOCKED: kernel lockdown=confidentiality forbids bpf() access to kernel memory. Only a reboot with lockdown=integrity (or none) changes this - do NOT weaken a production host for an audit"
  elif [ ! -e /sys/kernel/btf/vmlinux ] && [ ! -d /sys/kernel/debug/tracing ] && [ ! -d /sys/kernel/tracing ]; then
    PF_BPF="BLOCKED: no BTF and no tracefs. debugfs=off on the kernel cmdline removes /sys/kernel/debug; tracefs may still be mountable separately (see below)"
  else
    PF_BPF="OK"
    [ "$LOCKDOWN" = "integrity" ] && PF_BPF="OK (lockdown=integrity - tracepoints work, some kernel-memory reads may not)"
  fi

  # --- ptrace (strace) ---
  case "${YAMA:-0}" in
    3) PF_PTRACE="BLOCKED: kernel.yama.ptrace_scope=3 disables ptrace entirely and is ONE-WAY - it cannot be lowered without a reboot. strace mode is impossible here" ;;
    2) PF_PTRACE="OK for root (ptrace_scope=2 restricts to CAP_SYS_PTRACE)" ;;
    *) PF_PTRACE="OK" ;;
  esac
  have strace || PF_PTRACE="unavailable: strace not installed${PF_PTRACE:+ (and $PF_PTRACE)}"
  [ "$LOCKDOWN" = "confidentiality" ] && PF_PTRACE="BLOCKED: lockdown=confidentiality also restricts ptrace of privileged processes"

  # --- fanotify (fatrace) - the most hardening-compatible option ---
  if have fatrace; then
    PF_FAN="OK (fanotify needs CAP_SYS_ADMIN only - unaffected by lockdown, yama or BPF restrictions)"
  else
    PF_FAN="unavailable: fatrace not installed (apt install fatrace)"
  fi

  # --- /proc snapshot poller (dependency-free fallback - needs nothing but a readable /proc as root) ---
  if [ "$(id -u)" = 0 ] && [ -r /proc/1/status ]; then
    PF_PROC="OK (dependency-free - samples open fds + mmaps of root processes; catches files held open or mapped during the window, misses opens that begin and end between samples)"
  else
    PF_PROC="unavailable: must be root with a readable /proc"
  fi

  # --- auditd (boot mode) ---
  if ! have auditctl; then
    PF_AUDIT="unavailable: auditd not installed"
  else
    AENF="$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2}')"
    if [ "$AENF" = "2" ]; then
      PF_AUDIT="BLOCKED: the audit ruleset is IMMUTABLE (-e 2). Rules cannot be added until the next reboot. Making boot tracing possible would mean removing '-e 2' and rebooting - i.e. deliberately weakening the audit configuration of the host you are auditing"
    elif [ ! -w /etc/audit/rules.d ] 2>/dev/null; then
      PF_AUDIT="BLOCKED: /etc/audit/rules.d is not writable (read-only root or immutable image)"
    else
      PF_AUDIT="OK (rules are mutable; enabled=${AENF:-?})"
    fi
  fi

  printf '\n  %-14s %s\n' "--live"  "$( if [ "${PF_BPF%%:*}" = "OK" ]; then echo "$PF_BPF"; elif [ "${PF_FAN%%:*}" = "OK" ]; then echo "$PF_FAN"; else echo "$PF_PROC"; fi )"
  printf '  %-14s bpf: %s\n' ""     "$PF_BPF"
  printf '  %-14s fanotify: %s\n' "" "$PF_FAN"
  printf '  %-14s /proc-poll: %s\n' "" "$PF_PROC"
  printf '  %-14s %s\n' "--unit"   "bpf: ${PF_BPF} | ptrace: ${PF_PTRACE}"
  printf '  %-14s %s\n' "--boot"   "$PF_AUDIT"
  echo

  # Only refuse when the SELECTED mode has no viable mechanism.
  case "$MODE" in
    live)
      case "$PF_BPF$PF_FAN$PF_PROC" in *OK*) ;; *)
        echo "REFUSING: no tracing mechanism is available for --live without changing the host."
        echo
        echo "  Least-invasive way forward, in order of preference:"
        echo "   1. Install fatrace (fanotify). It needs no eBPF, no ptrace, and is unaffected by"
        echo "      kernel lockdown - it is the option that works on the most hardened hosts."
        echo "   2. Trace on a STAGING CLONE of this host instead. Same image and config, no"
        echo "      production risk, and the boot/service-start behaviour is what you want to observe."
        echo "   3. Rely on the static BOOT_CHAIN analysis and the /proc/<pid>/fd + maps snapshot in"
        echo "      lsa-collect.sh, which need none of this and already cover the persistent cases."
        echo
        echo "  Do NOT relax lockdown, ptrace_scope or audit immutability on a production host to"
        echo "  run an audit. The window during which the host is weakened is a real risk, and a"
        echo "  reboot to restore it is a bigger outage than the finding is usually worth."
        exit 2 ;;
      esac ;;
    unit)
      case "$PF_BPF$PF_PTRACE" in *OK*) ;; *)
        echo "REFUSING: neither eBPF nor ptrace is usable on this host, so a service start cannot be traced."
        echo "  ptrace_scope=3 in particular is one-way and deliberate - treat it as a control working,"
        echo "  not an obstacle. Use a staging clone, or rely on the static unit analysis."
        exit 2 ;;
      esac ;;
    boot)
      case "$PF_AUDIT" in OK*) ;; *)
        echo "REFUSING: boot tracing needs mutable audit rules. $PF_AUDIT"
        echo
        echo "  This is the mode with the worst risk/benefit on a hardened host: it requires a"
        echo "  configuration change AND a reboot, and if the ruleset is immutable (-e 2) it needs"
        echo "  TWO reboots - one to make rules mutable, one to capture the boot."
        echo "  Prefer: trace the boot of a staging clone, or accept the static BOOT_CHAIN analysis."
        exit 2 ;;
      esac ;;
  esac
}
[ "$MODE" = "preflight" ] && { MODE=""; preflight; exit 0; }
preflight

# ---------------------------------------------------------------- LIVE MODE
# Passive: watches every file open on the system for N seconds. Changes nothing.
if [ "$MODE" = "live" ]; then
  echo "=== live trace: file opens by root processes, ${SECS}s ==="
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  if have bpftrace; then
    echo "(using bpftrace)"
    timeout "$SECS" bpftrace -e '
      tracepoint:syscalls:sys_enter_openat /uid == 0/ { printf("%d %s %s\n", pid, comm, str(args->filename)); }
    ' 2>/dev/null | awk '{pid=$1; comm=$2; $1=""; $2=""; sub(/^  /,""); print pid"\t"comm"\t"$0}' > "$TMP"
  elif have opensnoop-bpfcc || have opensnoop; then
    echo "(using opensnoop)"
    OS="$(command -v opensnoop-bpfcc || command -v opensnoop)"
    timeout "$SECS" "$OS" -u 0 2>/dev/null | awk 'NR>1{pid=$1; comm=$2; path=$NF; print pid"\t"comm"\t"path}' > "$TMP"
  elif have fatrace; then
    echo "(using fatrace - fanotify, no eBPF needed)"
    timeout "$SECS" fatrace -f R 2>/dev/null | awk '{split($1,a,"("); comm=a[1]; path=$3; print "0\t"comm"\t"path}' > "$TMP"
  else
    # dependency-free fallback: no bpftrace/opensnoop/fatrace/strace on this host.
    # Snapshot-poll /proc for root processes' open fds and mmapped files. Needs nothing but a
    # readable /proc - works on the most hardened images, where the tracers above are stripped.
    echo "(no bpftrace/opensnoop/fatrace - dependency-free /proc snapshot poller)"
    echo "  sampling every ${LSA_POLL_INT:-1}s for ${SECS}s: root procs' open fds (/proc/PID/fd) +"
    echo "  mapped files (/proc/PID/maps). Catches files held open or mmapped during the window; a"
    echo "  file opened and closed entirely between two samples is missed. Confidence: partial."
    # Sampling interval. Fractional sleep is a GNU/BSD extension - busybox and POSIX sleep take
    # integers only, and a minimal hardened image (this backend's whole reason to exist) is
    # exactly where busybox lives. Probe once and fall back rather than spinning with no delay.
    _int="${LSA_POLL_INT:-1}"
    if ! sleep 0.1 2>/dev/null; then
      case "$_int" in *.*) _int=1; echo "  (this sleep(1) has no fractional support - interval forced to 1s)" ;; esac
    fi
    _nproc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
    if [ "${_nproc:-0}" -gt 250 ] && [ "${_int%%.*}" = "0" ]; then
      echo "  NOTE: ${_nproc} processes and a sub-second interval means millions of readlink()"
      echo "        calls over ${SECS}s. On a busy host raise LSA_POLL_INT (e.g. LSA_POLL_INT=2)."
    fi
    _endu=$(( $(cut -d. -f1 /proc/uptime) + SECS ))
    while [ "$(cut -d. -f1 /proc/uptime)" -lt "$_endu" ]; do
      for pd in /proc/[0-9]*; do
        [ -r "$pd/status" ] || continue
        [ "$(awk '/^Uid:/{print $2; exit}' "$pd/status" 2>/dev/null)" = 0 ] || continue
        _pid=${pd#/proc/}
        _comm=$(tr -d '\n' < "$pd/comm" 2>/dev/null); [ -n "$_comm" ] || _comm='?'
        for _fd in "$pd"/fd/*; do
          _t=$(readlink "$_fd" 2>/dev/null) || continue
          case "$_t" in /*) printf '%s\t%s\t%s\n' "$_pid" "$_comm" "${_t% (deleted)}" ;; esac
        done
        awk '$6 ~ /^\//{print $6}' "$pd/maps" 2>/dev/null | while IFS= read -r _m; do
          printf '%s\t%s\t%s\n' "$_pid" "$_comm" "$_m"
        done
      done
      sleep "$_int"
    done | sort -u > "$TMP"
  fi
  echo "--- captured $(wc -l < "$TMP") open events ---"
  echo "--- root-opened paths that a non-root principal can write ---"
  cut -f3 "$TMP" | analyse_paths
  echo
  echo "--- attribution for the paths above ---"
  cut -f3 "$TMP" | sort -u | while IFS= read -r p; do
    skip_path "$p" && continue
    [ -e "$p" ] || continue
    path_risk "$p" >/dev/null 2>&1 || continue
    printf '  %s\n' "$p"
    grep -F "	$p" "$TMP" | awk '{print "      opened by pid "$1" ("$2")"}' | sort -u | head -3
  done
  exit 0
fi

# ---------------------------------------------------------------- UNIT MODE
# Restarts one service under a syscall tracer to capture exactly what it reads on startup.
if [ "$MODE" = "unit" ]; then
  [ -n "$UNIT" ] || { echo "ERROR: --unit needs a unit name"; exit 1; }
  US="$(systemctl show "$UNIT" -p User --value 2>/dev/null)"
  echo "=== startup trace: $UNIT (runs as ${US:-root}) ==="
  confirm "This will RESTART $UNIT. That is a brief outage for this service. It does not change any configuration."
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  if have bpftrace; then
    bpftrace -e '
      tracepoint:syscalls:sys_enter_openat /uid == 0/ { printf("%d %s %s\n", pid, comm, str(args->filename)); }
      tracepoint:syscalls:sys_enter_execve { printf("%d %s EXEC %s\n", pid, comm, str(args->filename)); }
    ' > "$TMP" 2>/dev/null &
    BP=$!
    sleep 2
    systemctl restart "$UNIT"
    sleep 4
    kill "$BP" 2>/dev/null; wait "$BP" 2>/dev/null
    echo "--- paths opened during restart that are writable by a non-root principal ---"
    awk '{$1="";$2=""; sub(/^  /,""); sub(/^EXEC /,""); print}' "$TMP" | analyse_paths
  elif have strace; then
    echo "(bpftrace not present - using strace on the restart, which follows forks)"
    systemctl stop "$UNIT" 2>/dev/null
    EXECSTART="$(systemctl show "$UNIT" -p ExecStart --value 2>/dev/null | sed 's/^{ *path=//; s/ *; *argv\[\]=/ /; s/ *; *ignore_errors.*//')"
    echo "  tracing: $EXECSTART"
    timeout 20 strace -f -qq -e trace=open,openat,execve -o "$TMP" sh -c "$EXECSTART" >/dev/null 2>&1
    grep -oE '"(/[^"]+)"' "$TMP" 2>/dev/null | tr -d '"' | analyse_paths
    systemctl start "$UNIT" 2>/dev/null
    echo "  (service restarted)"
  else
    echo "ERROR: need bpftrace or strace."; exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------- BOOT MODE
# Boot cannot be traced live from userspace after the fact, so this arms auditd before a
# reboot and reads the record back afterwards.
AUDITRULES=/etc/audit/rules.d/99-lsa-boottrace.rules
if [ "$MODE" = "boot" ]; then
  have auditctl || { echo "ERROR: auditd is required for boot tracing (apt/dnf install auditd)."; exit 1; }
  case "$BOOTOP" in
    arm)
      confirm "This will INSTALL a temporary audit rule file at $AUDITRULES and load it.
It records file opens by uid=0 during the next boot. It changes audit configuration only,
and increases audit log volume until you run '--boot report'. You must then REBOOT yourself."
      cat > "$AUDITRULES" <<'EOF'
## temporary - installed by lsa-trace.sh, remove with: lsa-trace.sh --boot report
-a always,exit -F arch=b64 -S openat,open -F auid=-1 -F uid=0 -F success=1 -F key=lsa_boot
-a always,exit -F arch=b64 -S execve -F uid=0 -F key=lsa_boot
EOF
      augenrules --load >/dev/null 2>&1 || auditctl -R "$AUDITRULES" >/dev/null 2>&1
      auditctl -l | grep -c lsa_boot >/dev/null 2>&1
      echo "Rules armed. Now: reboot, then run '$0 --boot report'."
      ;;
    report)
      echo "=== paths opened by root during the recorded boot ==="
      have ausearch || { echo "ERROR: ausearch not found."; exit 1; }
      ausearch -k lsa_boot -ts boot 2>/dev/null \
        | grep -oE 'name="[^"]+"' | cut -d'"' -f2 | analyse_paths
      echo
      echo "=== programs executed as root during boot (review anything unexpected) ==="
      ausearch -k lsa_boot -ts boot -m EXECVE 2>/dev/null | grep -oE 'a0="[^"]+"' | cut -d'"' -f2 | sort | uniq -c | sort -rn | head -20
      confirm "Remove the temporary audit rules now?"
      rm -f "$AUDITRULES"
      augenrules --load >/dev/null 2>&1 || true
      echo "Removed $AUDITRULES and reloaded audit rules."
      ;;
    *) echo "ERROR: --boot takes 'arm' or 'report'"; exit 1 ;;
  esac
  exit 0
fi
