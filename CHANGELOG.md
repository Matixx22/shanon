# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `shanon inspect` now reports *numeric values passed through unchanged*, each
  with its canonical path and an `undeclared-numeric-value` audit code. Booleans
  and nulls are deliberately excluded: a null carries nothing, a boolean one bit,
  and a real collection has enough undeclared booleans to bury the signal.
- `crates/shanon-core/tests/zip.rs`: first test coverage of the archive path,
  input and output. Round trip with no source identifier surviving, non-JSON and
  directory entries ignored, `.JSON` matched case-insensitively, six traversal
  shapes refused, an oversized declared member refused, and five malformed
  archives rejected without a panic.
- `crates/shanon-core/tests/publish.rs`: invariant 1 asserted through
  `anonymize_collection` rather than through `platform`'s rename primitive alone.
  An aborted run leaves no collection, no map and no staging directory; an
  existing destination is refused and left byte-identical; a dangling symlink
  destination is refused before a map is written; an unsafe reuse map is refused
  at load; a clean run leaves exactly the collection and the map.
- `flate2` as a `shanon-core` dev-dependency, so `tests/zip.rs` can inflate the
  published archive to assert its contents. The archives the test builds are
  STORED, so only the read side is used.
- `scripts/check-fixtures.sh`, run by CI: refuses any tracked file that carries
  an unrecognized `S-1-5-21` domain SID authority or is named like collector
  output.
- `.gitignore` rules for the directory form of a collection:
  `<timestamp>_<kind>.json` as both collectors emit it, plus `collections/`,
  `engagements/` and `loot/`. The old `*.zip` and `*.map.json` rules covered no
  loose-JSON collection at all, and the repository's own history showed the gap.
  Pattern matching is the convenience; `check-fixtures.sh` is the guarantee.

### Changed

- `CATALOG_VERSION` is now `2`, because the catalog fix below changes what gets
  preserved.
- Docs stop overstating the guarantee: the README drops its "every
  organization-bound identifier" claim, SECURITY.md describes the numeric
  carve-out under *Numbers*, the unreachable policy arms say so in place, and
  `tests/engine.rs` pins the behavior so closing the gap has to be a deliberate
  edit to a test that explains itself.
- SECURITY.md said a `cargo audit` job guards the dependency tree. That job was
  replaced by `cargo deny` in 0.2.0, and the document now names it and the
  license, ban, and source-registry checks it adds.
- This changelog is restructured: one claim per entry, and problems that are
  known and deferred are listed under *Known gaps* rather than buried in the
  entry that found them. Documentation prose no longer uses em or en dashes.
- Every GitHub Actions `uses:` is pinned to a full commit SHA, with the tag in a
  trailing comment. Floating major tags are mutable by whoever owns (or
  compromises) the action's repository, which matters most in the release job:
  it holds `contents: write` and publishes both the binaries users download and
  the `.sha256` they verify against. Dependabot's github-actions updater bumps
  the SHA and rewrites the comment, so the pins cost no maintenance.

### Fixed

- A service principal name's `<host>:<suffix>` tail was always treated as a port
  and copied through verbatim, so a named SQL instance
  (`MSSQLSvc/sql01.corp.local:SAGE_PROD`, permitted by MS-ADTS) published the
  organization's own label. The rest of the SPN did change, so the leak gate
  never flagged it, and `tests/truth/components.json` pinned only the numeric
  case. A numeric suffix is still a port; anything else is a name and is
  remapped as one.
- A distinguished name carrying a schema-extended RDN attribute published the
  attribute *type* verbatim: `CN=Bob,ACMEPAYROLLID=99,DC=corp,DC=local` names the
  organization however thoroughly the value is redacted. Neither gate could see
  it. The policy's source gate and the verifier's output gate both only asked
  whether a component contained an `=`, and because the verifier re-derives
  output through the same `transform_dn` the engine used, re-derivation is blind
  to a type-level defect by construction. Both gates now share
  `components::dn_attribute_types_are_standard` over the RFC 4514 §3 set, and a
  DN with anything else is redacted whole. More anonymization, never less.
- The User-Change-Password control access right was one hex digit short in
  `ACCESS_RIGHT_GUIDS`: 35 characters, an 11-digit final group. Since a catalog
  match needs the exact normalized value, the row was dead rather than merely
  wrong. The real right GUID never matched and was pseudonymized, losing the
  "change password" semantics the model reasons about, and the stored value could
  never match `guid_re` either. `tests/catalog.rs` now checks that every
  GUID-kind catalog value is well formed, closing the class rather than the
  instance; a sweep found no other malformed GUID literal.
- `platform`'s test temp-directory helper derived uniqueness from
  `SystemTime::now().as_nanos()` on a shared pid. macOS quantizes the realtime
  clock to a microsecond, so two of the three parallel tests could land on the
  same directory and one would `remove_dir_all` it while another was still
  writing, failing with `EINVAL`. Linux resolves nanoseconds and never collided,
  so it only ever surfaced on `macos-latest`, at random. The helper now takes a
  per-test name, as `zip.rs`, `inspect.rs`, `progress.rs` and `publish.rs`
  already did.

### Security

- `spike/sample.json` was a real SharpHound capture of a lab domain (live domain
  SID, account names, distinguished names, logon timestamps), and
  `crates/shanon-core/tests/spike.rs` described it as one. Replaced by a
  generated collection of the same structural shape (identical key order, the
  same mix of nested objects, empty arrays, a null-valued object slot, negative
  and zero integer tokens, and a reference-only stub member), so the byte-parity
  contract it backs is unchanged in strength.
  `spike/json_roundtrip_expected.txt` was regenerated with the Python reference
  serializer, not with `canonical_json`, which would have turned a
  cross-implementation check into `Rust == Rust`.
- The lab's domain name also survived in a `tests/truth/components.json`
  domain-qualified SID vector, which the SID-authority check does not look for.
  That vector now uses the synthetic domain the other fixtures use, and both the
  domain name and the removed lab SID authority are on a permanent denylist in
  `scripts/check-fixtures.sh`: a value removed once should not be able to come
  back in any file.

### Known gaps

Recorded here so that closing any of them is a deliberate act, not a discovery.

- **Undeclared numeric leaves are published.** `engine::visit` returns every
  number, boolean and null verbatim before `FieldPolicy::resolve` runs, so a
  collector emitting an organization-bound value as a JSON number at a path no
  rule declares (a custom `employeeNumber` or `uidNumber` under
  `CollectAllProperties`) has its key anonymized and its value published.
  Redacting it would change the leaf's JSON type and the output has to stay
  BloodHound-loadable, so closing this means first deciding what a redacted
  *number* is. `shanon inspect` now makes every occurrence visible.
- **`CATALOG_VERSION` is not read back on `--reuse-map`.**
  `Registry::from_value` discards the map's whole `policy` block, so a version-1
  map reused under version 2 can silently disagree with its own sibling
  collection about the corrected User-Change-Password GUID. The bump makes the
  gap reachable rather than hypothetical.
- **A member that parses but carries no `meta` aborts the whole collection**
  instead of being skipped, taking valid siblings with it. `tests/publish.rs`
  pins the current behavior and states what a fix would look like.
- **The release job's toolchain is unpinned:** it resolves whatever
  `rustup toolchain install stable` means at tag time. The build is already
  `--locked`, so this is the last non-deterministic input to a published
  artifact.
- **Three high-entropy domain SID authorities of unverified provenance remain**
  in `tests/parity/` and `tests/truth/`, frozen into vectors the Python
  reference produced. They are allowlisted explicitly rather than silently
  tolerated, and the allowlist says to replace each one the next time its
  fixture is regenerated.
- **The removed `spike/sample.json` remains in git history.** Rewriting that
  history is a separate decision, which this release does not make.

The SPN, DN and catalog fixes diverge deliberately from the Python reference,
which carries all three defects. Their new cases live in the Rust test files, so
`tests/truth/` stays what it claims to be: a record of what the reference
produces.

## [0.3.0] - 2026-07-28

Anonymizes BloodHound CE collections, which 0.2.0 aborted on, and adds
`shanon inspect` to diagnose a collection that will not go through.

### Fixed

- Standard SharpHound fields came back under a different name. A key no rule
  declares is treated as organization-bound and mapped through the opaque
  namespace, which is correct for a custom AD attribute, but the rule table never
  declared `IsDeleted`, `IsACLProtected`, `Properties.whencreated` /
  `whenchanged`, the `FailureReason` sibling of every `Collected` flag, or
  `LocalGroups[]` / `UserRights[]`'s own `Collected`. Every collector emits them,
  so every output carried renamed keys and every `inspect` report listed drift
  that was not drift. No graph edge depends on any of them, so nothing was
  mis-anonymized, but the document was not a SharpHound document. They are now
  declared: the booleans and numerics as schema-preserved, `FailureReason` as
  opaque, because a populated one names the host that refused. Declaring a schema
  path cannot widen what escapes, since `resolve_schema` type-gates them, and
  `tests/schema_fields.rs` pins exactly that.
- A collection where a well-known domain RID appeared both at a catalog-declared
  path and at an undeclared one aborted with `ABORTED - invalid or conflicting
  mapping data; no output written`. The catalog permits preserving a RID only at
  declared paths, and a reference also needs a sibling `ObjectType` /
  `PrincipalType` to resolve against, but the registry binds one structured
  output per SID. So `PrimaryGroupSID` and an ACE naming the same group bound the
  same SID twice with opposite terminal intent. Whether a RID is a catalog
  default is now decided once per SID identity: any qualifying occurrence
  publishes collection-wide evidence, `finalize_discovery` settles the binding
  before the registry freezes, and every other occurrence replays it.
  Verification re-derives the answer from the same frozen evidence.
- Domain-qualified SIDs (`<DOMAIN>-<SID>`, which SharpHound and both BloodHound
  CE ingestors emit) are keyed on the inner SID that `transform_sid` actually
  binds, so a prefixed spelling and a bare one no longer disagree about the
  terminal. `components::sid_identity` is the shared accessor.
- A value a field rule's operation could not parse aborted the whole collection.
  `bloodhound-ce` and `rusthound-ce` write `""` for attributes they could not
  read, and names with an empty domain part (`JDOE@`); neither can produce a
  well-shaped output, so the leak gate rejected the member. Policy now redacts
  such a value opaquely instead. More anonymization, never less, and the gate
  itself is unchanged.
- A GUID in `Aces[].PrincipalSID`, which the CE collectors emit for Container, OU
  and GPO principals, was mapped through the SID transform and came back a SID,
  failing the same gate. Identifier references are now routed by the shape the
  value actually has, so the ACE and the principal's own `ObjectIdentifier` still
  resolve to one pseudonym and the edge survives.

### Added

- `shanon inspect --input <zip|dir>`: a dry run that performs the same discovery,
  transform and leak-gate verification as `anonymize` and then stops, writing
  nothing at all. It reports the `meta.type` / `meta.version` / node-type
  breakdown, unrecognized collection types, object classifications, audit codes,
  the field paths no rule covers, and the sanitized reason a run would abort.
  Exits `0` if the collection would anonymize cleanly, `1` if not. Every line is
  a count, a synthetic member label, a canonical path or a fingerprint, so the
  report can be shared for a collection that cannot be, which is what turns "it
  aborts on my engagement data" into a filable bug.
  `pipeline::inspect_collection` and `pipeline::InspectReport` back it.
- `--verbose-failures` now also expands the mapping-abort classes: pseudonym
  collision, unsafe mapping, publication identity, and the generic runtime abort.
  Previously the flag only affected leak-gate findings, so a run that died with
  `ABORTED - invalid or conflicting mapping data` printed that and nothing else
  either way, and the engine's sanitized reason was computed and discarded. The
  expanded block names the abort class, the synthetic member, the record path,
  the classified node type, and a BLAKE2b-6 fingerprint of the offender, so no
  source value and no source filename leaves the process (invariant 7).
- `shanon_core::engine::AbortLocator`, the sanitized leaf locator behind that
  block, plus `ShanonError::stderr_verbose`, `ShanonError::unlocated` and
  `ShanonError::locator`. Default `stderr()` and every exit code are unchanged
  for every class; `tests/errors.rs` pins that byte for byte (invariant 2).
- `shanon -V` / `shanon --version`, reporting the crate version. Release binaries
  are published as standalone archives, so a user holding one previously had no
  way to identify the build.
- A progress bar on `anonymize`, drawn to stderr, with a per-phase count and an
  ETA. A run over a real collection takes minutes and previously gave no sign it
  was alive. It ticks once per top-level `data` object rather than once per
  member, so a collection with lopsided member sizes still advances smoothly.
- `--progress` / `--no-progress` to force the bar on or off. By default it is
  drawn only when stderr is a terminal, so redirected stderr (every parity
  fixture and CI run) is byte-identical to before.
- `shanon_core::progress`, the write-only channel behind the bar. Events carry a
  phase tag and unit counts and nothing else, so no source value can travel
  through it and no sink can influence the transform. `tests/progress.rs` pins
  both properties.

### Changed

- `pipeline::anonymize_collection` takes a trailing `Option<ProgressSink>`, and
  `verify::verify_document` gained a `verify_document_with_progress` sibling. The
  existing `verify_document` signature is unchanged.
- The README leads with what a run actually produces, a before/after excerpt
  taken from a real run over `demo/collection` rather than written by hand, and
  with how to install a prebuilt binary rather than how to compile one. `demo/`
  is a new synthetic four-member collection anyone can reproduce that excerpt
  from; the reference sections are unchanged.

## [0.2.0] - 2026-07-28

First tagged release.

### Added

- Deterministic `anonymize` and `restore` commands for SharpHound / BloodHound
  collections, preserving the exact JSON format and graph cross-references.
- Fail-closed two-pass pipeline with an independent verification stage and atomic
  no-replace publication.
- Reversal map with stable pseudonyms across collections via `--reuse-map`.
- Prebuilt release binaries for `x86_64-unknown-linux-gnu` and
  `aarch64-apple-darwin`. Intel macOS is not published separately: the arm64
  build runs under Rosetta 2, and building from source is supported everywhere.
- Community health files: contributing guide, code of conduct, issue and pull
  request templates, and Dependabot config.
- `rust-toolchain.toml` pinning local development to the MSRV (1.97), so a
  feature newer than the floor fails at edit time instead of in CI. The `test`
  job overrides it with `RUSTUP_TOOLCHAIN=stable` to keep stable coverage.
- Supply-chain CI: a `cargo deny` job checking advisories, licenses, bans, and
  source registries, configured in `deny.toml`. Supersedes the former
  `cargo audit` job, adding license enforcement so an MIT-licensed binary cannot
  silently redistribute a conflicting dependency.

[Unreleased]: https://github.com/Matixx22/shanon/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Matixx22/shanon/releases/tag/v0.3.0
[0.2.0]: https://github.com/Matixx22/shanon/releases/tag/v0.2.0
