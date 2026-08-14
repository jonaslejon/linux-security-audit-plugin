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
