#!/usr/bin/env bash
# The check count appeared in three places and disagreed in all three: marketplace.json said
# "249 checks across 31 areas" while the README said "450+ across 33" and the collector actually
# implemented 457 across 33. Numbers written by hand drift, so they are asserted here instead.
set -u

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SELF_DIR}/.."
COLLECT="${ROOT}/plugins/linux-security-audit/skills/linux-security-audit/scripts/lsa-collect.sh"
FAILURES=0

ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

IDS="$(grep -oE '(^|[^_[:alnum:]])chk "?[A-Za-z][A-Za-z0-9_.]*' "$COLLECT" \
       | sed -E 's/.*chk "?//' | sort -u | wc -l | tr -d ' ')"
# every `sec NAME` except the trailing RUN_SUMMARY, which reports on the run rather than auditing
SECS="$(( $(grep -cE '^sec [A-Z]' "$COLLECT") - 1 ))"

printf 'metadata consistency\n  collector implements: %s checks across %s areas\n\n' "$IDS" "$SECS"

for f in "${ROOT}/README.md" \
         "${ROOT}/plugins/linux-security-audit/README.md" \
         "${ROOT}/.claude-plugin/marketplace.json"; do
  name="${f#"$ROOT"/}"
  claimed="$(grep -oE '[0-9]+\+? (distinct )?checks across [0-9]+ areas' "$f" | head -1)"
  if [ -z "$claimed" ]; then
    bad "$name states no check count"
    continue
  fi
  cn="$(printf '%s' "$claimed" | grep -oE '^[0-9]+')"
  sn="$(printf '%s' "$claimed" | grep -oE '[0-9]+ areas' | grep -oE '^[0-9]+')"
  if [ "$cn" = "$IDS" ] && [ "$sn" = "$SECS" ]; then
    ok "$name: $claimed"
  else
    bad "$name claims '$claimed' but the collector has $IDS checks across $SECS areas"
  fi
done

# the version must agree across both manifests and the collector itself
PV="$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "${ROOT}/plugins/linux-security-audit/.claude-plugin/plugin.json" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
MV="$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "${ROOT}/.claude-plugin/marketplace.json" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
CV="$(grep -oE '^LSA_VERSION="[0-9.]+"' "$COLLECT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
if [ "$PV" = "$MV" ] && [ "$PV" = "$CV" ]; then
  ok "version $PV agrees across plugin.json, marketplace.json and the collector"
else
  bad "version mismatch: plugin.json=$PV marketplace.json=$MV collector=$CV"
fi

# every released version needs a changelog entry, so a tag cannot ship undocumented again
if grep -q "^## \[${PV}\]" "${ROOT}/CHANGELOG.md"; then
  ok "CHANGELOG has an entry for $PV"
else
  bad "CHANGELOG has no entry for $PV"
fi

# the two README copies are served from different paths and must not diverge
if diff -q "${ROOT}/README.md" "${ROOT}/plugins/linux-security-audit/README.md" >/dev/null; then
  ok "both README copies are identical"
else
  bad "README.md and plugins/linux-security-audit/README.md have diverged"
fi

printf '\n'
[ "$FAILURES" = "0" ] && { printf 'metadata consistency: PASS\n'; exit 0; }
printf 'metadata consistency: %d FAILURE(S)\n' "$FAILURES"
exit 1
