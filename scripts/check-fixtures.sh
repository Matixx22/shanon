#!/usr/bin/env bash
#
# Refuse to let a real collection into the repository.
#
# CONTRIBUTING.md and CLAUDE.md both forbid committing real SharpHound output or
# mapping files, but .gitignore can only cover what it can name: it blocks
# `*.zip` and `*.map.json`, while a *directory-form* collection — loose
# `.json` files, a first-class shanon input — slips through every rule. This
# script is the mechanical enforcement, so the guarantee does not rest on a
# contributor remembering.
#
# Three checks, over tracked files only:
#
#   1. Domain SID authorities. Every `S-1-5-21-<a>-<b>-<c>` in a tracked file
#      must appear in the allowlist below. A real domain SID is high-entropy and
#      irreversibly identifies the forest it came from, so a new one showing up
#      in a diff is the single strongest signal that a live capture was staged.
#   2. Collector-shaped filenames. SharpHound and the BloodHound CE collectors
#      emit `<timestamp>_<kind>.json`; a tracked file matching that shape is a
#      dropped collection, not a fixture.
#   3. Known-real identifiers. Values that were previously committed by mistake
#      and must never reappear, whatever file they turn up in.
#
# Run locally with: ./scripts/check-fixtures.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# ---------------------------------------------------------------------------
# Allowlisted domain SID authorities.
#
# Synthetic by construction — repeating or sequential digit groups that no real
# domain would ever produce.
# ---------------------------------------------------------------------------
ALLOWED_SYNTHETIC=(
  "S-1-5-21-1111111111-2222222222-3333333333"
  "S-1-5-21-1-2-3"
  "S-1-5-21-11-22-33"
  "S-1-5-21-9-9-9"
  "S-1-5-21-111-222-333"
  "S-1-5-21-71234567-72345678-73456789"
  "S-1-5-21-71234567-22222222-33333333"
)

# ---------------------------------------------------------------------------
# Legacy allowlist — high-entropy authorities of UNVERIFIED provenance, frozen
# into cross-implementation parity vectors the Python reference produced.
#
# These are indistinguishable from real domain SIDs. They are tolerated only
# because regenerating the fixtures that carry them requires re-running the
# reference implementation, which does not live in this repository. Replace each
# with a synthetic authority the next time its fixture is regenerated, and
# delete the entry here when you do. Do not add to this list.
# ---------------------------------------------------------------------------
ALLOWED_LEGACY=(
  "S-1-5-21-3723053582-1902173673-2667344224" # tests/parity/engine_truth.json
  "S-1-5-21-1708546787-1795253718-634612481"  # tests/parity/registry_seed_truth.json, seed_extended.expected.json
  "S-1-5-21-1004336348-1177238915-682003330"  # tests/truth/catalog.json, wellknown.json
)

# ---------------------------------------------------------------------------
# Known-real identifiers, banned outright.
#
# Each was committed at some point and traced back to a real lab. Unlike the
# checks below, this list needs no heuristic: these exact strings are known bad,
# so a match is a regression rather than a judgement call. Add to this list when
# a real value is found and removed, never remove from it.
# ---------------------------------------------------------------------------
DENIED=(
  "909015691"  # lab domain SID authority, formerly in spike/sample.json
  "ESC1.LOCAL" # lab domain name (matched case-insensitively)
)

status=0

# --- Check 0: known-real identifiers ----------------------------------------
for bad in "${DENIED[@]}"; do
  hits=$(git ls-files -z | xargs -0 grep -lFi "$bad" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "ERROR: known-real identifier '$bad' present in a tracked file:"
    echo "$hits" | sed 's/^/         /'
    echo "       This value came from a real collection and was removed once already."
    status=1
  fi
done

# --- Check 1: domain SID authorities ---------------------------------------
found=$(git ls-files -z |
  xargs -0 grep -ohE 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+' 2>/dev/null |
  sed -E 's/(S-1-5-21-[0-9]+-[0-9]+-[0-9]+).*/\1/' |
  sort -u || true)

for authority in $found; do
  allowed=0
  for known in "${ALLOWED_SYNTHETIC[@]}" "${ALLOWED_LEGACY[@]}"; do
    if [ "$authority" = "$known" ]; then
      allowed=1
      break
    fi
  done
  if [ "$allowed" -eq 0 ]; then
    echo "ERROR: unrecognized domain SID authority in a tracked file: $authority"
    git ls-files -z | xargs -0 grep -lF "$authority" 2>/dev/null | sed 's/^/         /'
    echo "       If this is synthetic, add it to ALLOWED_SYNTHETIC in $0."
    echo "       If it came from a real collection, remove the file — and rewrite"
    echo "       history if it was ever pushed."
    status=1
  fi
done

# --- Check 2: collector-shaped filenames ------------------------------------
collector_named=$(git ls-files |
  grep -E '(^|/)[0-9]{8,14}_[a-z]+\.json$' || true)

if [ -n "$collector_named" ]; then
  echo "ERROR: tracked file(s) named like collector output:"
  echo "$collector_named" | sed 's/^/         /'
  echo "       Directory-form collections are a first-class shanon input and are"
  echo "       not covered by the *.zip rule in .gitignore."
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "check-fixtures: ok (${#ALLOWED_SYNTHETIC[@]} synthetic, ${#ALLOWED_LEGACY[@]} legacy authorities allowlisted)"
fi

exit "$status"
