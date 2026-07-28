# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Standard SharpHound fields came back under a different name. A key no rule
  declares is treated as organization-bound and mapped through the opaque
  namespace — correct, since a custom AD attribute leaks in its name as surely
  as in its contents — but the rule table never declared `IsDeleted`,
  `IsACLProtected`, `Properties.whencreated` / `whenchanged`, the
  `FailureReason` sibling of every `Collected` flag, or `LocalGroups[]` /
  `UserRights[]`'s own `Collected`. Every collector emits them, so every output
  carried renamed keys and every `inspect` report listed drift that was not
  drift. No graph edge depends on any of them, so nothing was ever
  mis-anonymized and no collection failed to load — but the document was not a
  SharpHound document. They are now declared: the booleans and numerics as
  schema-preserved, `FailureReason` as opaque, because a populated one names the
  host that refused. Declaring a schema path cannot widen what escapes —
  `resolve_schema` type-gates them, so a string at a boolean or numeric path
  still falls through to `ReplaceOpaque` — and `tests/schema_fields.rs` pins
  exactly that alongside the key names.

- A collection where a well-known domain RID appeared both at a catalog-declared
  path and at an undeclared one aborted with `ABORTED - invalid or conflicting
  mapping data; no output written`. The catalog permits preserving a RID only at
  declared paths (`ObjectIdentifier`, `Aces[].PrincipalSID`,
  `Members[].ObjectIdentifier`, `Properties.objectsid`), and a reference also
  needs a sibling `ObjectType` / `PrincipalType` to resolve against — but the
  registry binds one structured output per SID. So `PrimaryGroupSID` (on every
  user and computer, and not a declared path) and an ACE naming the same group
  bound the same SID twice with opposite terminal intent. Whether a RID is a
  catalog default is now decided once per SID identity: any occurrence that
  qualifies publishes collection-wide evidence, `finalize_discovery` settles the
  binding before the registry freezes, and every other occurrence replays it.
  The answer no longer depends on which path the walk reached first, and
  verification re-derives it from the same frozen evidence.
- Domain-qualified SIDs (`<DOMAIN>-<SID>`, which SharpHound and both BloodHound
  CE ingestors emit) are keyed on the inner SID that `transform_sid` actually
  binds, so a prefixed spelling and a bare one no longer disagree about the
  terminal. `components::sid_identity` is the shared accessor.
- A value a field rule's operation could not parse aborted the whole
  collection. `bloodhound-ce` and `rusthound-ce` write `""` for attributes they
  could not read and names with an empty domain part (`JDOE@`); neither can
  produce a well-shaped output, so the leak gate rejected the member and the run
  ended with no output. Policy now redacts such a value opaquely instead — more
  anonymization, never less, and the gate itself is unchanged.
- A GUID in `Aces[].PrincipalSID`, which the CE collectors emit for Container,
  OU and GPO principals, was mapped through the SID transform and came back a
  SID, failing the same gate. Identifier references are now routed by the shape
  the value actually has, so the ACE and the principal's own `ObjectIdentifier`
  still resolve to one pseudonym and the edge survives.

### Added

- `shanon inspect --input <zip|dir>`: a dry run that performs the same
  discovery, transform and leak-gate verification as `anonymize` and then stops,
  writing nothing at all. It reports the `meta.type` / `meta.version` /
  node-type breakdown, unrecognized collection types, object classifications,
  audit codes, the field paths no rule covers, and the sanitized reason a run
  would abort. Exits `0` if the collection would anonymize cleanly and `1` if it
  would not. Every line is a count, a synthetic member label, a canonical path
  or a fingerprint, so the report can be shared for a collection that cannot be
  — which is what turns "it aborts on my engagement data" into a filable bug.
  `pipeline::inspect_collection` and `pipeline::InspectReport` back it.
- `--verbose-failures` now also expands the mapping-abort classes — pseudonym
  collision, unsafe mapping, publication identity, and the generic runtime
  abort. Previously the flag only affected leak-gate findings, so a run that
  died with `ABORTED - invalid or conflicting mapping data` printed exactly that
  and nothing else, with or without the flag. The engine's sanitized reason was
  computed and then discarded. The expanded block names the abort class, the
  synthetic member, the record path, the classified node type, and a BLAKE2b-6
  fingerprint of the offender — the same digest a leak-gate finding uses, so no
  source value and no source filename leaves the process (invariant 7).
- `shanon_core::engine::AbortLocator`, the sanitized leaf locator behind that
  block, plus `ShanonError::stderr_verbose`, `ShanonError::unlocated`, and
  `ShanonError::locator`. Default `stderr()` and every exit code are unchanged
  for every class, located or not; `tests/errors.rs` pins that byte for byte
  (invariant 2).
- `shanon -V` / `shanon --version`, reporting the crate version. Release
  binaries are published as standalone archives, so a user holding one
  previously had no way to identify which build it was.
- A progress bar on `anonymize`, drawn to stderr, with a per-phase count and an
  ETA. A run over a real collection takes minutes and previously gave no sign it
  was alive. Ticks once per top-level `data` object rather than once per member,
  so a collection whose object counts are lopsided across members still advances
  smoothly.
- `--progress` / `--no-progress` to force the bar on or off. By default it is
  drawn only when stderr is a terminal, so redirected stderr — every parity
  fixture and CI run — is byte-identical to before.
- `shanon_core::progress`, the write-only channel behind the bar. Events carry a
  phase tag and unit counts and nothing else, so no source value can travel
  through it and no sink can influence the transform. `tests/progress.rs` pins
  both properties: published bytes are identical with and without a sink, and
  each phase lands exactly on its declared total.

### Changed

- `pipeline::anonymize_collection` takes a trailing `Option<ProgressSink>`, and
  `verify::verify_document` gained a `verify_document_with_progress` sibling.
  The existing `verify_document` signature is unchanged.
- The README leads with what a run actually produces — a before/after excerpt
  taken from a real run over `demo/collection`, not written by hand — and with
  how to install a prebuilt binary rather than how to compile one. `demo/` is a
  new synthetic four-member collection anyone can reproduce that excerpt from;
  the reference sections are unchanged.

## [0.2.0] - 2026-07-28

First tagged release.

### Added

- Deterministic `anonymize` and `restore` commands for SharpHound / BloodHound
  collections, preserving the exact JSON format and graph cross-references.
- Fail-closed two-pass pipeline with an independent verification stage and atomic
  no-replace publication.
- Reversal map with stable pseudonyms across collections via `--reuse-map`.
- Prebuilt release binaries for `x86_64-unknown-linux-gnu` and
  `aarch64-apple-darwin`. Intel macOS is not published separately — the arm64
  build runs under Rosetta 2, and building from source is supported everywhere.
- Community health files: contributing guide, code of conduct, issue and pull
  request templates, and Dependabot config.
- `rust-toolchain.toml` pinning local development to the MSRV (1.97), so a
  feature newer than the floor fails at edit time instead of in CI. The `test`
  job overrides it with `RUSTUP_TOOLCHAIN=stable` to keep stable coverage.
- Supply-chain CI: a `cargo deny` job checking advisories, licenses, bans, and
  source registries, configured in `deny.toml`. Supersedes the former
  `cargo audit` job — same RustSec database, plus license enforcement so an
  MIT-licensed binary cannot silently redistribute a conflicting dependency.

[Unreleased]: https://github.com/Matixx22/shanon/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Matixx22/shanon/releases/tag/v0.2.0
