#!/usr/bin/env bash
#
# Run the gates CI enforces, from one command.
#
# CI splits its checks across four jobs; this script runs the ones an ordinary
# code change can break, so a failure surfaces in seconds instead of after a
# push and a two-minute wait.
#
# Order is deliberate and is NOT CI's job order: check-fixtures runs first.
# Every other gate here reports a defect, and a defect costs a fixup commit.
# check-fixtures reports a real collection staged for commit, and that costs a
# history rewrite once pushed. The cheapest check is also the only irreversible
# one, so it goes first.
#
# Not covered here, deliberately:
#
#   * The `msrv` job. rust-toolchain.toml pins local development to 1.97, so
#     every build below is already an MSRV build. Re-running `cargo check` under
#     the same toolchain would prove nothing.
#   * The `supply-chain` job. Advisories and licences only move when the
#     dependency tree does, which is rare and not tied to a push. Pass --deny to
#     include it.
#   * The macOS and Windows matrix legs, and the Windows binary build. No Linux
#     machine can reproduce those; CI stays the only check on the `platform`
#     backends for those two targets.
#
# This is a fast local mirror of CI, not a replacement for it. CI sets
# RUSTFLAGS=-D warnings workflow-wide, which is marginally stricter than the
# `-D warnings` passed to clippy below, so a green run here is a strong signal
# rather than a proof.
#
# Run locally with: ./scripts/gates.sh [--deny]
# Wire it to every push with: git config core.hooksPath .githooks
set -euo pipefail

cd "$(dirname "$0")/.."

run_deny=0
for arg in "$@"; do
  case "$arg" in
  --deny) run_deny=1 ;;
  *)
    echo "usage: $0 [--deny]" >&2
    exit 2
    ;;
  esac
done

step() {
  printf '\n=== %s\n' "$1"
}

step "check-fixtures"
./scripts/check-fixtures.sh

step "cargo fmt --all --check"
cargo fmt --all --check

step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo test --workspace --locked"
cargo test --workspace --locked

if [ "$run_deny" -eq 1 ]; then
  step "cargo deny check"
  cargo deny check
fi

printf '\ngates: ok\n'
