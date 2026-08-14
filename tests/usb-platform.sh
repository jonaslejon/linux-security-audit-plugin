#!/usr/bin/env bash
# Regression test for USB lockdown scoring against the platform.
#
# This exists because the collector already knew the answer and threw it away. On a Hyper-V VM
# with no USB bus at all it printed "usb_bus_present=0" and then, three lines later, FAILed
# usb.usbguard for "not installed" and WARNed that BadUSB keystroke injection was possible. A
# machine with no USB port cannot be attacked through its USB port. Every cloud instance in the
# estate carried those two findings, which is how a reader learns to skim the section.
#
# The contract under test:
#   1. On bare metal, a missing USB device policy is a FAIL. This is the whole point.
#   2. On a guest with no USB bus it is NA, and NA is never rendered as PASS.
#   3. On a guest that does have a bus, and where the platform could not be determined, it is
#      WARN: unproven either way, so neither asserted nor suppressed.
#   4. usbguard with a deny-by-default target but zero rules is a FAIL, not a PASS.
#   5. The section still finds a real misconfiguration (positive control), so a collector that
#      suppressed everything could not pass this test by being silent.
set -u

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECT="${SELF_DIR}/../plugins/linux-security-audit/skills/linux-security-audit/scripts/lsa-collect.sh"
FAILURES=0

ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# The scoring rule, lifted verbatim from the collector. Driving it directly is deliberate: the
# platform cannot be faked on the machine running the test, and a chroot would hide the very
# sysfs absence that the rule keys on.
score() { # score <platform> <has_usb_bus> -> verdict for a missing control
  local PLATFORM="$1" HAS_USB_HW="$2" USB_MISS
  if [ "$PLATFORM" = "physical" ]; then USB_MISS=FAIL
  elif [ "$PLATFORM" = "unknown" ]; then USB_MISS=WARN
  elif [ "$HAS_USB_HW" = "1" ]; then USB_MISS=WARN
  else USB_MISS=NA
  fi
  printf '%s' "$USB_MISS"
}

printf '\n== USB control scoring by platform ==\n'
for c in "physical 1 FAIL" "physical 0 FAIL" "virtual 1 WARN" "virtual 0 NA" \
         "unknown 1 WARN" "unknown 0 WARN"; do
  set -- $c
  got="$(score "$1" "$2")"
  if [ "$got" = "$3" ]; then ok "platform=$1 bus=$2 -> $got"
  else bad "platform=$1 bus=$2 -> got $got, want $3"; fi
done

# A missing control must never be scored PASS on any platform. NA and PASS are different claims:
# NA says the question did not apply, PASS says the control is in place.
printf '\n== a missing control is never a pass ==\n'
for c in "physical 1" "physical 0" "virtual 1" "virtual 0" "unknown 1" "unknown 0"; do
  set -- $c
  got="$(score "$1" "$2")"
  if [ "$got" = "PASS" ]; then bad "platform=$1 bus=$2 scored PASS for an absent control"
  else ok "platform=$1 bus=$2 -> $got (not PASS)"; fi
done

# `A && B || C` parses as `(A && B) || C`, so ImplicitPolicyTarget=reject used to satisfy the
# condition on its own and a policy with zero rules reported PASS: a deny-everything daemon that
# would lock out the console keyboard, advertised as correctly configured.
printf '\n== usbguard policy verdict ==\n'
ug() { # ug <rules> <target> -> verdict
  local RULES="$1" IPT="$2"
  if [ "${RULES:-0}" -gt 0 ] && { [ "$IPT" = "block" ] || [ "$IPT" = "reject" ]; }; then printf PASS
  elif [ "$IPT" = "block" ] || [ "$IPT" = "reject" ]; then printf FAIL
  else printf FAIL; fi
}
for c in "12 block PASS" "12 reject PASS" "0 block FAIL" "0 reject FAIL" \
         "12 allow FAIL" "0 allow FAIL"; do
  set -- $c
  got="$(ug "$1" "$2")"
  if [ "$got" = "$3" ]; then ok "rules=$1 target=$2 -> $got"
  else bad "rules=$1 target=$2 -> got $got, want $3"; fi
done

# On ARM there is usually no DMI and no CPUID hypervisor bit, so the device tree is the only
# thing left to judge by. A device tree is not proof of real hardware: QEMU's virt machine calls
# itself "linux,dummy-virt" and Xen's guests announce "xen,xenvm". Getting this backwards would
# classify an ARM guest as bare metal and hand back a FAIL for a port it does not have. The
# pattern is lifted out of the collector at run time rather than copied, so this cannot pass
# while the collector says something else.
printf '\n== ARM device-tree classification ==\n'
DT_PATTERN="$(grep -o '\*dummy-virt\*[^)]*' "$COLLECT" | head -1)"
if [ -z "$DT_PATTERN" ]; then
  bad "could not extract the device-tree pattern from the collector"
else
  ok "pattern read from the collector: $DT_PATTERN"
  dt() { eval "case \"\$1\" in ${DT_PATTERN}) printf virtual ;; *) printf physical ;; esac"; }
  while IFS='|' read -r model want; do
    [ -z "$model" ] && continue
    got="$(dt "$model")"
    if [ "$got" = "$want" ]; then ok "$model -> $got"
    else bad "$model -> got $got, want $want"; fi
  done <<'DTCASES'
linux,dummy-virt|virtual
QEMU KVM Virtual Machine|virtual
XENVM-4.11 xen,xenvm|virtual
Raspberry Pi 5 Model B Rev 1.0|physical
Raspberry Pi 4 Model B Rev 1.4|physical
Radxa ROCK 5B|physical
NVIDIA Jetson Orin Nano Developer Kit|physical
Xenon Development Board|physical
Marvell Armada 8040 community board|physical
DTCASES
fi

# An allow-list that admits a whole interface class is the deny-list failure mode wearing an
# allow-list's clothes: "allow with-interface { 08:*:* }" accepts every mass-storage device ever
# made. The awk program is lifted out of the collector rather than copied, so this cannot pass
# while the collector matches something else.
printf '\n== usbguard rule scope ==\n'
SCOPE_AWK="$(sed -n '/UG_BROAD="\$(awk/,/}'"'"' "\$UGRF"/p' "$COLLECT" | sed '1d;$s/}.*/}/')"
if [ -z "$SCOPE_AWK" ]; then
  bad "could not extract the rule-scope matcher from the collector"
else
  RULES_TMP="$(mktemp)"
  cat > "$RULES_TMP" <<'RULESEOF'
# a policy as 'usbguard generate-policy' emits it
allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" hash "jEP=" with-interface 09:00:00
allow id 046d:c52b serial "" name "USB Receiver" hash "kjh=" with-interface { 03:01:01 03:00:00 }
allow with-interface equals { 08:*:* }
allow id 046d:*
allow id *:*
allow
block with-interface equals { 03:00:* }
RULESEOF
  broad="$(awk "$SCOPE_AWK" "$RULES_TMP" 2>/dev/null | grep -c . || true)"
  if [ "$broad" = "4" ]; then
    ok "4 broad allow rules flagged, the 2 device-specific ones and the block rule left alone"
  else
    bad "expected 4 broad allow rules to be flagged, got $broad"
  fi
  # Rule counting must ignore comments and blank lines, or a file of nothing but comments reads
  # as a populated allow-list.
  n="$(grep -cE '^[[:space:]]*(allow|block|reject)' "$RULES_TMP")"
  if [ "$n" = "7" ]; then ok "rule count ignores comments and blanks: $n"
  else bad "rule count was $n, want 7"; fi
  rm -f "$RULES_TMP"
fi

# ---------------------------------------------------------------- allow-list beats deny-list
# The summary check used to treat a driver deny-list as equivalent to a device allow-list, so
# blocking eight module names reported PASS. A deny-list is only ever as complete as the list.
# Needs docker: the collector short-circuits the whole section inside a container, so the case is
# reached by making the container look like a host (PID 1 named init, no /.dockerenv).
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  printf '\n== a deny-list is not a default-deny policy ==\n'
  W="$(mktemp -d)"
  cat > "$W/drive.sh" <<'DRIVEEOF'
set -u
mkdir -p /stub /etc/modprobe.d /etc/usbguard
printf '#!/bin/sh\necho none\nexit 1\n' > /stub/systemd-detect-virt; chmod +x /stub/systemd-detect-virt
export PATH=/stub:$PATH
case "$1" in
  denylist)
    for m in usb_storage uas usbnet cdc_ether rndis_host cdc_ncm usbhid hid_generic; do
      printf 'blacklist %s\n' "$m" >> /etc/modprobe.d/usb.conf
    done ;;
  allowlist)
    printf '#!/bin/sh\n[ "$1" = "is-active" ] && exit 0\nexit 1\n' > /stub/systemctl; chmod +x /stub/systemctl
    printf 'ImplicitPolicyTarget=block\n' > /etc/usbguard/usbguard-daemon.conf
    printf 'allow id 046d:c52b serial "" name "r" hash "h=" with-interface 03:01:01\nblock\n' \
      > /etc/usbguard/rules.conf ;;
esac
bash /tmp/lsa.sh --quick --passive 2>/dev/null | grep '^CHECK|usb.restriction_present|' | cut -d'|' -f3,4
DRIVEEOF
  run_case() {
    docker run --rm -v "$W/drive.sh:/tmp/drive.sh:ro" \
      -v "$COLLECT:/tmp/lsa.sh:ro" -v /dev/null:/.dockerenv \
      --entrypoint bash --network none debian:stable-slim \
      -c "cp /bin/bash /usr/local/bin/init && exec init /tmp/drive.sh $1" 2>/dev/null
  }
  r="$(run_case denylist)"
  case "$r" in
    PASS*) bad "a module deny-list alone reported PASS: $r" ;;
    WARN*|FAIL*) ok "deny-list only -> ${r%%|*} (not a pass)" ;;
    *) bad "deny-list only produced no verdict: '$r'" ;;
  esac
  r="$(run_case allowlist)"
  case "$r" in
    PASS*) ok "usbguard allow-list with a deny-by-default target -> PASS" ;;
    *) bad "a real default-deny allow-list did not pass: '$r'" ;;
  esac
  rm -rf "$W"
else
  printf '\n(skipping deny-list vs allow-list: docker not available)\n'
fi

# ---------------------------------------------------------------- live behaviour
# The blocks above check the rule in isolation, which is only a statement of intent: they would
# still pass if the collector stopped using that rule. These run the real collector and read its
# real output. The physical branch is reached by putting a stub systemd-detect-virt ahead on
# PATH, since a CI runner is a guest and would otherwise never exercise the case that matters.
# Needs Linux and a non-container, because the collector short-circuits the whole section in a
# container and there would be nothing to assert.
if [ "$(uname -s)" != "Linux" ]; then
  printf '\n(skipping live collection: not a Linux host)\n'
elif [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
  printf '\n(skipping live collection: inside a container, the section is NA by design)\n'
else
  printf '\n== live collection: as this machine really is ==\n'
  OUT="$(mktemp)"; STUB="$(mktemp -d)"
  trap 'rm -rf "$OUT" "$STUB"' EXIT
  bash "$COLLECT" --quick --passive > "$OUT" 2>/dev/null || true

  plat="$(grep '^CHECK|system.platform|' "$OUT" | cut -d'|' -f4)"
  [ -n "$plat" ] && ok "system.platform emitted: $plat" || bad "system.platform was not emitted"

  # The platform must be one of the three values the scoring branches understand. A fourth would
  # fall through every test and be silently treated as a guest.
  case "$plat" in
    physical*|virtual*|unknown*) ok "platform value is one the scorer handles" ;;
    *) bad "platform '$plat' matches no scoring branch" ;;
  esac

  ctx="$(grep '^CHECK|usb.context|' "$OUT" | cut -d'|' -f4)"
  ugv="$(grep '^CHECK|usb.usbguard|' "$OUT" | cut -d'|' -f3)"
  printf '  (context: %s)\n' "$ctx"
  if printf '%s' "$ctx" | grep -q 'platform=virtual' && printf '%s' "$ctx" | grep -q 'usb_bus_present=0'; then
    # The exact case that was wrong: a guest with no USB bus at all, told it was vulnerable to
    # BadUSB keystroke injection through the port it does not have.
    [ "$ugv" = "NA" ] && ok "guest with no USB bus: usbguard is NA, not a finding" \
                      || bad "guest with no USB bus reported usbguard=$ugv, want NA"
    mbv="$(grep '^CHECK|usb.module_blacklist|' "$OUT" | cut -d'|' -f3)"
    if [ -z "$mbv" ] || [ "$mbv" = "NA" ] || [ "$mbv" = "PASS" ]; then
      ok "guest with no USB bus: module blacklist is ${mbv:-absent}"
    else
      bad "guest with no USB bus reported module_blacklist=$mbv, want NA"
    fi
  else
    ok "platform=${plat:-?} usbguard=$ugv (this machine does not exercise the no-bus guest case)"
  fi

  # Now force the physical branch through the collector's own detection, end to end.
  printf '\n== live collection: forced to bare metal ==\n'
  printf '#!/bin/sh\n[ "$1" = "-c" ] && { echo none; exit 1; }\necho none\nexit 1\n' > "$STUB/systemd-detect-virt"
  chmod +x "$STUB/systemd-detect-virt"
  PATH="$STUB:$PATH" bash "$COLLECT" --quick --passive > "$OUT" 2>/dev/null || true

  plat2="$(grep '^CHECK|system.platform|' "$OUT" | cut -d'|' -f4)"
  case "$plat2" in
    physical*) ok "stubbed detection yields: $plat2" ;;
    *) bad "stub did not produce a physical classification, got '$plat2'" ;;
  esac

  ug2="$(grep '^CHECK|usb.usbguard|' "$OUT" | cut -d'|' -f3)"
  rp2="$(grep '^CHECK|usb.restriction_present|' "$OUT" | cut -d'|' -f3)"
  # usbguard is not installed on a CI runner, so on bare metal this must be the headline finding.
  # If this ever reports NA or PASS, the platform gate has swallowed a real exposure.
  if [ "$ug2" = "FAIL" ]; then ok "bare metal with no usbguard: FAIL"
  else bad "bare metal with no usbguard reported '$ug2', want FAIL"; fi
  if [ "$rp2" = "FAIL" ]; then ok "bare metal with no USB restriction at all: FAIL"
  else bad "bare metal with no USB restriction reported '$rp2', want FAIL"; fi
fi

printf '\n'
if [ "$FAILURES" -eq 0 ]; then printf 'usb-platform: PASS\n'; exit 0
else printf 'usb-platform: %d FAILURE(S)\n' "$FAILURES"; exit 1; fi
