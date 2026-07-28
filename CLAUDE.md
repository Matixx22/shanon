# CLAUDE.md

Guidance for Claude Code (claude.ai/code) and other AI assistants working in this
repository. Human contributors should start with [README.md](README.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## What shanon is

A deterministic anonymizer for SharpHound / BloodHound Active Directory
collections. It remaps every organization-bound identifier so a collection is
safe to hand to a public LLM for attack-path reasoning, while keeping the exact
SharpHound JSON format (still BloodHound-loadable) and every graph
cross-reference intact. It writes a local reversal map so the model's output can
be de-anonymized.

Non-goals, permanently: network access, LLM calls, mutating the input collection,
Windows support.

## Commands

```sh
cargo build --workspace                                # dev build
cargo build --release                                  # -> ./target/release/shanon
cargo fmt --all --check                                # gate 1
cargo clippy --workspace --all-targets -- -D warnings  # gate 2 (warnings are errors)
cargo test --workspace                                 # gate 3
cargo test --workspace --locked                        # exactly what CI runs
cargo check --workspace --all-targets --locked         # what the MSRV job runs

cargo test -p shanon-core --test verify                # one integration test file
cargo test -p shanon-core --test verify verify_name    # one test by name substring
```

Run the three gates before pushing. MSRV is **1.97** and a dedicated CI job
enforces it — do not reach for newer language or standard-library features.

## Architecture

Two-crate workspace:

- `crates/shanon-core` — the entire library: classification, policy, registry,
  transforms, verification, pipeline, platform.
- `crates/shanon-cli` — the `shanon` binary. A thin `clap` layer over
  `pipeline::anonymize_collection` and `restore::*`.

### The anonymize pipeline (fail-closed, two-pass)

`pipeline::anonymize_collection` orchestrates:

1. **Discover** every collection member and collect typed identities from both
   definitions and references (including references whose target is absent).
2. **Freeze** the registry, active policy, and catalog-backed evidence into
   immutable verification state.
3. **Transform** each member by object type and canonical field path, writing
   results to a private staging area.
4. **Verify** every accepted member independently against the frozen state.
   `verify.rs` does *not* trust the engine's transform records: it re-resolves
   policy and re-derives the expected output for every string leaf, then
   compares.
5. **Publish** by no-replace atomic rename (`platform.rs`, openat-anchored) only
   after all members pass. An existing destination is refused.

Any divergence becomes a sanitized finding (BLAKE2b-6 fingerprint of the
offender, never the real value) that aborts the run with no output written.

### Module layers in shanon-core (bottom-up)

- **Support** — `casefold` (Unicode full case folding, used for semantic identity
  everywhere), `ignorecase`, `textutil`.
- **Transforms** — `patterns`, `fields` (token matching), `components`
  (decompose composite identifiers: SIDs, GUIDs, UPNs, SPNs, DNs, emails; then
  dispatch each piece to a registry category). `wellknown` is the deprecated
  pre-catalog predicate module — do not build on it.
- **`catalog`** — the authoritative AD-defaults table. Data-driven (flat
  `CatalogEntry` rows), never a typed struct per SharpHound kind. A match
  requires exact node type + identifier kind + normalized value, and only permits
  preserving a value at an explicitly declared path. `CATALOG_VERSION` is stamped
  into the output map.
- **`policy`** — path-aware, immutable field decisions. `object_path`,
  `array_path`, and `path_tokens` form a collision-safe path grammar that must
  round-trip exactly; it drives verification-finding paths and is fuzzed in
  `tests/policy_pathgrammar.rs`.
- **`registry`** — deterministic pseudonym store. Seed is
  `blake2b(salt || category || semantic_real)`, 128-bit, big-endian. Implements
  both `components::RegistryOps` and `fields::TokenRegistry`; those traits are
  infallible by contract, so failures (collisions, unsafe mappings) are stashed
  via `take_trait_error` and drained by the engine afterward.
- **`engine`** — generic JSON walker that classifies objects and normalizes
  documents. No typed structs per SharpHound kind.
- **`pipeline`** — orchestration, size bounds, and the single `ShanonError` enum
  that backs the CLI's stderr and exit-code contract. `inspect_collection` is
  the read-only dry run behind `shanon inspect`: it shares
  `read_collection_input` with `anonymize_collection` and runs the same
  discovery, transform and verification, but never reaches the publish path, so
  it must stay incapable of writing. `ShanonError::stderr` is the frozen
  surface; `stderr_verbose` is the additive one `--verbose-failures` selects.
- **`progress`** — write-only progress channel for the CLI's bar. A
  `ProgressEvent` carries a phase tag and unit counts and *nothing else*: no
  value, path, or member name may ever be added to it (invariant 7), and the
  library never reads a sink back, so output bytes are identical with or without
  one (invariants 1 and 3). Rendering lives in `shanon-cli/src/progress.rs` and
  is suppressed unless stderr is a terminal, which is what keeps the frozen
  stdout/stderr surface intact.
- **`platform`** — openat-anchored traversal and atomic no-replace publish.
  Linux and macOS only. macOS uses `renamex_np(RENAME_EXCL)` through a scoped
  `libc` FFI call — the one `unsafe` block in the crate.

## Invariants

Breaking one of these is a regression even when the test suite is green.

1. **Fail-closed.** A change that lets a run publish while any verification check
   is uncertain is a defect. A real identifier that survives a run is a security
   bug, not an ordinary one.
2. **Byte-parity on frozen surfaces.** Serialization, the pseudonym seed layout,
   the on-disk map format, CLI stdout/stderr, and exit codes are frozen interop
   surfaces. Preserve the observable bytes; `tests/parity/` replays the truth.
3. **Determinism.** `serde_json` runs with `preserve_order` +
   `arbitrary_precision`: object key insertion order survives end to end (output
   byte-parity depends on it) and number tokens stay verbatim (no ryu
   reformatting). Any map or set whose iteration influences output **must** be an
   `IndexMap` / `IndexSet`; `HashMap` / `HashSet` are only for membership lookups
   that never drive output.
4. **Case folding, not lowercasing.** Use `casefold` for semantic identity.
   Never `to_lowercase`.
5. **Hand-rolled serializers.** `lib.rs` implements `canonical_json` (compact
   `, ` / `: `, `ensure_ascii`, lowercase `\uXXXX`, surrogate pairs for astral)
   and `canonical_json_sorted` (`indent=2, sort_keys=true` — the map save format)
   to match the reference exactly. Do not swap either for
   `serde_json::to_string`.
6. **Regex policy.** The `regex` crate only (no lookaround, no backrefs). The one
   exception is `fields`' v1 word-boundary sweep, which needs lookbehind plus
   lookahead and is the single scoped use of `fancy-regex`. Justify any new regex
   dependency or lookaround use.
7. **Sanitized diagnostics.** No error message, log line, or test output may leak
   a source secret or a source filename.
8. **MSRV 1.97.** Enforced by CI.

## Parity with the reference implementation

shanon is a Rust port of a Python reference implementation, and byte-for-byte
parity with it is a hard contract rather than a nicety. Doc comments cite that
reference by symbol (e.g. `Registry._seed_int`, `_MAX_JSON_MEMBERS`) and cite the
port plan by section (`§3.1a`, `§3.4`, `R2`).

**The plan document and the Python source are not in this repository.** Treat
those citations as provenance notes only. The executable truth that a change must
satisfy is entirely committed here: `tests/parity/` (cross-implementation replay)
and `tests/truth/` (golden vectors the reference produced). If a citation and a
committed fixture ever disagree, the fixture wins.

## Tests and fixtures

- `tests/truth/*.json` — golden vectors the reference produced. Integration tests
  load them via `../../tests/truth/<name>` and assert equality; see
  `crates/shanon-core/tests/casefold.rs` for the pattern.
- `tests/parity/*.json` — cross-implementation replay truth (engine output,
  registry seeding, map format). Wall-clock fields — the map's `created`, the ZIP
  DOS timestamp — are normalized on both sides.
- `*_property.rs` with `.proptest-regressions` — proptest fuzzing for the path
  grammar and cross-implementation invariants. Commit new regression seeds.
- `spike/` — S1 spike fixtures (canonical JSON round-trip, seed digest).

New anonymization or verification behavior needs a committed **synthetic**
fixture pinning it field by field.

**Never commit real collections or real map files.** `.gitignore` blocks `*.zip`
and `*.map.json`, with one deliberate un-ignore for the synthetic
`tests/parity/seed.map.json`. Do not weaken those rules, and do not add another
exception for a "small" sample.

## Conventions

- Conventional Commits: `fix:`, `feat:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Hardest-reviewed areas, where changes should be small and well-argued: the
  verification pass, `policy` / `catalog`, the publish path, and any new
  dependency.

## Further reading

- [README.md](README.md) — install, usage, flags, exit codes.
- [SECURITY.md](SECURITY.md) — threat model, and what shanon does **not** protect
  against.
- [CONTRIBUTING.md](CONTRIBUTING.md) — PR expectations.
