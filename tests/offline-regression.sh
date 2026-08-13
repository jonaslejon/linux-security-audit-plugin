#!/usr/bin/env bash
# Regression test for the offline (--root) contract.
#
# This exists because --root shipped broken: it was wired into two sections out of 33, so the
# collector read the machine running the audit and reported it as the image. The bug was invisible
# to every form of review that did not actually run the thing against a known tree, which is what
# this does.
#
# The contract under test:
#   1. Nothing outside the mounted tree is ever described in a CHECK line.
#   2. No runtime or active check produces a verdict offline. NA only.
#   3. The fixture's planted misconfigurations ARE found (a positive control, so that a collector
#      which reads nothing at all cannot pass by being silent).
#   4. Paths containing spaces are handled.
#   5. Argument handling fails closed.
set -u

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECT="${SELF_DIR}/../plugins/linux-security-audit/skills/linux-security-audit/scripts/lsa-collect.sh"
FIXTURE="$(mktemp -d)"
OUT="$(mktemp)"
FAILURES=0

cleanup() { rm -rf "$FIXTURE" "$OUT" "$OUT.stderr"; }
trap cleanup EXIT

ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# ---------------------------------------------------------------- fixture
mkdir -p "$FIXTURE"/etc/{ssh,sudoers.d,cron.d,systemd/system} \
         "$FIXTURE"/root "$FIXTURE"/var/lib/cloud/instance \
         "$FIXTURE/home/anna karlsson/.ssh"

cat > "$FIXTURE/etc/os-release" <<'EOF'
ID=fixturelinux
PRETTY_NAME="Fixture Linux 1.0"
VERSION_ID="1.0"
EOF
cat > "$FIXTURE/etc/ssh/sshd_config" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF
cat > "$FIXTURE/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0::/home/bd:/bin/bash
anna:x:1001:1001::/home/anna karlsson:/bin/bash
EOF
echo 'ALL ALL=(ALL) NOPASSWD: ALL' > "$FIXTURE/etc/sudoers"
chmod 777 "$FIXTURE/etc/sudoers"
# a private key under a path with a space: word-splitting used to skip this silently
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n' \
  > "$FIXTURE/home/anna karlsson/.ssh/id_ed25519"
# an SSH host key baked into the template: the headline IMAGE_HYGIENE finding
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAC3NzaC1lZDI1NTE5\n-----END OPENSSH PRIVATE KEY-----\n' \
  > "$FIXTURE/etc/ssh/ssh_host_ed25519_key"
# a secret split across two assignments on one line: redaction used to leak the first
printf 'Environment=API_KEY=leakcanary123 DB_SECRET=hunter2\n' \
  > "$FIXTURE/etc/systemd/system/leaky.service"

printf 'offline regression test\n  collector: %s\n  fixture:   %s\n\n' "$COLLECT" "$FIXTURE"

bash "$COLLECT" --root "$FIXTURE" --force > "$OUT" 2>"$OUT.stderr"
RC=$?
[ "$RC" = "0" ] && ok "collector exits 0" || bad "collector exited $RC"

# ------------------------------------------------- 1. no leakage of the auditing host
# The precise form of this test, and the one that originally exposed the bug: point --root at an
# EMPTY directory. Anything the collector then claims to have observed, it did not read from the
# tree. Scanning output for stray path strings is too noisy to gate on, because NA lines legitimately
# name canonical paths ("/etc/shadow not present") and findings legitimately name in-image paths.
EMPTY="$(mktemp -d)"
EOUT="$(mktemp)"
bash "$COLLECT" --root "$EMPTY" --force > "$EOUT" 2>/dev/null

# Against an empty tree, every determinable verdict must be NA or an "absent" finding. A PASS in
# particular is the dangerous one: it asserts a control is in place on an image that contains nothing.
# image.machine_id is exempt: an absent machine-id genuinely IS uninitialised, which is the
# correct state for a template, so it is a real verdict rather than one invented from nothing.
GHOSTS="$(grep '^CHECK|' "$EOUT" | awk -F'|' '$3=="PASS"' \
          | grep -vE '\|(no |none|absent|not present|empty|uninitialised|0 )' \
          | grep -v '^CHECK|image.machine_id|' | head -20)"
if [ -z "$GHOSTS" ]; then
  ok "an empty tree yields no PASS verdicts invented from the auditing host"
else
  bad "empty tree produced PASS verdicts, so the collector read something else:"
  printf '%s\n' "$GHOSTS" | cut -c1-115 | sed 's/^/       /'
fi

# Numbers are the clearest tell: a size, count or mode reported from an empty tree came from the host.
# A measurement is a bare number in the observed field. Parenthesised prose such as
# "(default 0644)" is documentation of a default, not something read from the tree.
NUMS="$(grep '^CHECK|' "$EOUT" | awk -F'|' '$3!="NA" && $4 ~ /(^|[[:space:]])[0-9]{3,}([[:space:]]|$)/' | head -10)"
if [ -z "$NUMS" ]; then
  ok "an empty tree reports no measured quantities"
else
  bad "empty tree reported measurements taken from the auditing host:"
  printf '%s\n' "$NUMS" | cut -c1-115 | sed 's/^/       /'
fi
rm -rf "$EMPTY" "$EOUT"

# ------------------------------------------------- 2. runtime/active never verdict offline
BADMETHOD="$(grep '^CHECK|' "$OUT" | awk -F'|' '$6 ~ /^(runtime|active)/ && $3 != "NA"')"
if [ -z "$BADMETHOD" ]; then
  ok "every runtime/active check reports NA offline"
else
  bad "runtime/active checks produced a verdict offline:"
  printf '%s\n' "$BADMETHOD" | cut -c1-110 | sed 's/^/       /' | head -10
fi

# ------------------------------------------------- 3. positive control
# Without this, a collector that reads nothing would pass tests 1 and 2 perfectly.
for expect in \
  'users.uid0|FAIL' \
  'ssh.permitrootlogin|FAIL' \
  'ssh.passwordauthentication|FAIL' \
  'image.ssh_host_keys_in_template|FAIL' \
  'sudo.file_perms|FAIL'
do
  if grep -q "^CHECK|${expect}" "$OUT"; then
    ok "found planted finding: ${expect%%|*}"
  else
    bad "MISSED planted finding: ${expect%%|*} (collector is not reading the fixture)"
  fi
done

# ------------------------------------------------- 4. paths containing spaces
if grep -q 'anna karlsson' "$OUT"; then
  ok "paths containing spaces are traversed"
else
  bad "the home directory with a space was skipped"
fi

# ------------------------------------------------- 5. no secret material in the output
for secret in leakcanary123 hunter2; do
  if grep -q "$secret" "$OUT"; then
    bad "SECRET LEAKED into the report: $secret"
  else
    ok "redacted: $secret"
  fi
done

# ------------------------------------------------- 6. arguments fail closed
bash "$COLLECT" --root            >/dev/null 2>&1; [ $? = 2 ] && ok "--root with no argument exits 2"        || bad "--root with no argument did not exit 2"
bash "$COLLECT" --root /no/such   >/dev/null 2>&1; [ $? = 2 ] && ok "--root on a missing dir exits 2"        || bad "--root on a missing dir did not exit 2"
bash "$COLLECT" --pasive          >/dev/null 2>&1; [ $? = 2 ] && ok "typo'd flag exits 2 rather than probing" || bad "unknown flag was ignored"

# ------------------------------------------------- 7. stdout stays machine-readable
# Every CHECK record must have exactly the six fields the contract promises, or `grep '^CHECK|'`
# consumers silently mis-parse. Diagnostics merged into stdout show up here as short records.
MALFORMED="$(grep '^CHECK|' "$OUT" | awk -F'|' 'NF != 6' | head -5)"
if [ -z "$MALFORMED" ]; then
  ok "every CHECK record has the six contracted fields"
else
  bad "malformed CHECK records (stderr merged into stdout, or an unescaped | in a value):"
  printf '%s\n' "$MALFORMED" | cut -c1-115 | sed 's/^/       /'
fi

# --out must not merge diagnostics into the machine-readable stream
OUT2="$(mktemp)"
bash "$COLLECT" --root "$FIXTURE" --force --out "$OUT2" 2>/dev/null
if [ -f "${OUT2}.stderr" ]; then
  ok "--out sends diagnostics to a sidecar, not into the record stream"
else
  bad "--out did not create a stderr sidecar"
fi
rm -f "$OUT2" "${OUT2}.stderr"

printf '\n'
if [ "$FAILURES" = "0" ]; then
  printf 'offline regression: PASS\n'
  exit 0
fi
printf 'offline regression: %d FAILURE(S)\n' "$FAILURES"
exit 1
