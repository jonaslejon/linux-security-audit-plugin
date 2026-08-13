#!/usr/bin/env bash
# A check that emits nothing is indistinguishable from a check that passed.
#
# That is the same failure the NA-is-not-PASS rule exists to prevent, in the one form nobody
# looks at: silence reads as health. It is also easy to introduce, because a check guarded by
# `[ -n "$X" ] && chk ...` simply vanishes when X is empty, and nothing in the output says so.
#
# This pins the set of check IDs a deterministic offline run emits. If a change makes a check
# stop emitting, the ID disappears from the run and this fails. New IDs are reported but do not
# fail: they are the expected result of adding a check, and the fixture is refreshed with --update.
set -u

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SELF_DIR}/.."
COLLECT="${ROOT}/plugins/linux-security-audit/skills/linux-security-audit/scripts/lsa-collect.sh"
BASELINE="${SELF_DIR}/fixtures/offline-check-ids.txt"
UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1

# The ID universe depends on the auditing ENVIRONMENT, not just the target: which checks fire at
# all varies with the tooling installed and with whether the auditor is itself a container (the
# container.* family only exists then). So the baseline is pinned to one image, and both generating
# and checking it must happen there:
#
#   docker run --rm -v "$PWD:/repo" -w /repo debian:stable-slim bash tests/check-registry.sh [--update]
#
# CI runs exactly that. Running it directly on some other Linux box will report spurious drift.
if [ "$(uname -s)" != "Linux" ]; then
  printf 'check registry: SKIP (baseline is Linux-only; this is %s)\n' "$(uname -s)"
  printf '  run it in a container:\n'
  printf '    docker run --rm -v "$PWD:/repo" -w /repo debian:stable-slim bash tests/check-registry.sh\n'
  exit 0
fi

FIXTURE="$(mktemp -d)"
OUT="$(mktemp)"
trap 'rm -rf "$FIXTURE" "$OUT"' EXIT

# The same fixture as offline-regression.sh, kept deliberately small: the point is a STABLE ID
# universe, not coverage. Anything conditional on host facts would make the baseline flap.
mkdir -p "$FIXTURE"/etc/{ssh,sudoers.d,cron.d,systemd/system} "$FIXTURE"/root "$FIXTURE"/var/log
printf 'ID=fixturelinux\nPRETTY_NAME="Fixture Linux 1.0"\nVERSION_ID="1.0"\n' > "$FIXTURE/etc/os-release"
printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$FIXTURE/etc/ssh/sshd_config"
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$FIXTURE/etc/passwd"
printf 'root:x:0:\nshadow:x:42:\n'          > "$FIXTURE/etc/group"
printf 'ALL ALL=(ALL) NOPASSWD: ALL\n'      > "$FIXTURE/etc/sudoers"

bash "$COLLECT" --root "$FIXTURE" --force > "$OUT" 2>/dev/null

IDS="$(grep '^CHECK|' "$OUT" | cut -d'|' -f2 | sort)"
UNIQ="$(printf '%s\n' "$IDS" | sort -u)"

FAILURES=0
printf 'check registry\n  emitted: %s ids (%s unique)\n\n' \
  "$(printf '%s\n' "$IDS" | grep -c .)" "$(printf '%s\n' "$UNIQ" | grep -c .)"

# An ID emitted twice means two checks share a name, so one silently overwrites the other in any
# consumer that builds a map from the output.
DUPES="$(printf '%s\n' "$IDS" | uniq -d)"
if [ -n "$DUPES" ]; then
  printf '  FAIL duplicate check IDs (one silently masks the other downstream):\n'
  printf '%s\n' "$DUPES" | sed 's/^/       /'
  FAILURES=$((FAILURES + 1))
else
  printf '  ok   no duplicate check IDs\n'
fi

if [ "$UPDATE" = "1" ]; then
  mkdir -p "$(dirname "$BASELINE")"
  printf '%s\n' "$UNIQ" > "$BASELINE"
  printf '  ok   baseline refreshed: %s ids\n' "$(grep -c . "$BASELINE")"
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  printf '  FAIL no baseline at %s (create it with: bash %s --update)\n' "$BASELINE" "$0"
  exit 1
fi

MISSING="$(comm -23 "$BASELINE" <(printf '%s\n' "$UNIQ"))"
ADDED="$(comm -13 "$BASELINE" <(printf '%s\n' "$UNIQ"))"

if [ -n "$MISSING" ]; then
  printf '  FAIL %s check(s) stopped emitting entirely.\n' "$(printf '%s\n' "$MISSING" | grep -c .)"
  printf '       A check that emits nothing reads as a pass. If the check is genuinely no longer\n'
  printf '       applicable, it must still emit NA with the reason.\n'
  printf '%s\n' "$MISSING" | sed 's/^/       - /'
  FAILURES=$((FAILURES + 1))
else
  printf '  ok   every baselined check still emits\n'
fi

if [ -n "$ADDED" ]; then
  printf '  note %s new check(s); refresh with: bash tests/check-registry.sh --update\n' \
    "$(printf '%s\n' "$ADDED" | grep -c .)"
  printf '%s\n' "$ADDED" | sed 's/^/       + /'
fi

printf '\n'
[ "$FAILURES" = "0" ] && { printf 'check registry: PASS\n'; exit 0; }
printf 'check registry: %d FAILURE(S)\n' "$FAILURES"
exit 1
