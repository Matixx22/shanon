# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `crates/shanon-core/tests/zip.rs` — the archive path had **no** test coverage,
  input or output, despite `--input engagement.zip` being the README's headline
  invocation and the published archive being a frozen interop surface. Every
  other pipeline test drove a directory, so reading the central directory,
  rejecting a hostile member path, honouring the size ceilings, and building a
  loadable archive were all unasserted. Now covered: round trip with no source
  identifier surviving, non-JSON and directory entries ignored, `.JSON` matched
  case-insensitively, six traversal shapes refused, an oversized declared member
  refused, and five malformed archives rejected without panicking.

- `crates/shanon-core/tests/publish.rs` — nothing asserted that a failed run
  writes nothing, the invariant-1 guarantee that matters most, previously
  covered only by `platform`'s rename primitive. Now asserted through
  `anonymize_collection`: an aborted run leaves no output collection, no mapping
  file, and no staging directory; an existing destination is refused and left
  byte-identical; a *dangling symlink* destination is refused before a mapping
  file is written; an unsafe reuse map is refused at load; and a successful run
  leaves exactly the collection and the map with no staging behind.

  One current behavior is pinned rather than fixed: a member that parses but has
  no `meta` aborts the whole collection instead of being skipped, taking valid
  siblings with it. The test says so and says what fixing it would look like.

- `shanon inspect` now reports *numeric values passed through unchanged*, with
  the canonical path of each and an `undeclared-numeric-value` audit code.

  The policy classifies string leaves. `engine::visit` returns every number,
  boolean and null verbatim before `FieldPolicy::resolve` is reached, so
  `fallback.unknown-value` and the typed arms of `resolve_schema` were
  unreachable from the pipeline and nothing in the codebase claimed otherwise
  out loud. For a declared path that pass-through is the intended answer — a
  flag or a timestamp carries no identity and BloodHound needs it intact — but a
  collector emitting an organization-bound value as a JSON number at a path no
  rule declares (a custom `employeeNumber` or `uidNumber` under
  `CollectAllProperties`) had its key anonymized and its value published, with
  no decision, no verification record and no audit trace.

  This release does not close that gap: replacing a number with a redaction
  string changes the leaf's JSON type, and the output has to stay
  BloodHound-loadable, so closing it means first deciding what a redacted
  *number* is. What it does is stop the gap being invisible. README no longer
  claims shanon remaps "every organization-bound identifier", SECURITY.md
  describes the carve-out under *Numbers*, the unreachable policy arms say so,
  and `tests/engine.rs` pins the behavior so that closing it has to be a
  deliberate edit to a test that explains itself.

  Booleans and nulls are deliberately not counted: a null carries nothing and a
  boolean carries one bit, while a real collection has enough undeclared
  booleans to bury the numeric signal. Output bytes are unchanged, and the audit
  summary gains its new key only when there is something to report, so every
  vector the Python reference produced still compares equal.

### Changed

- `CATALOG_VERSION` is now `2`, because the catalog fix below changes what gets
  preserved. Nothing reads this value back when a map is reused —
  `Registry::from_value` discards the map's whole `policy` block — so a version-1
  map reused under version 2 can silently disagree with its own sibling
  collection about the corrected identifier. The bump makes that gap reachable
  rather than hypothetical; wiring the check is tracked separately.

### Fixed

- The User-Change-Password control access right was one hex digit short in
  `ACCESS_RIGHT_GUIDS` — 35 characters, an 11-digit final group. A catalog match
  needs the exact normalized value, so the row was not a typo but a *dead* row:
  the real right GUID never matched and was pseudonymized, losing the
  "change password" semantics the model reasons about, while the stored value
  could never match `guid_re` either and was unreachable as a `Guid` kind at all.
  Nothing failed and nothing warned, which is why `tests/truth/catalog.json`
  pinned the typo rather than catching it.

  Corrected here, with `tests/catalog.rs` gaining a check that every GUID-kind
  catalog value is well formed — the class of defect, not just this instance. A
  sweep found no other malformed GUID literal in the crate. This is a deliberate
  divergence from the Python reference, which still carries the typo.

- A service principal name's `<host>:<suffix>` tail was always treated as a
  port and copied through verbatim. MS-ADTS permits
  `MSSQLSvc/<fqdn>:<instancename>` as well as `:<port>`, so a named SQL instance
  — `MSSQLSvc/sql01.corp.local:SAGE_PROD` — published the organization's own
  label. It cleared the leak gate because the rest of the SPN did change, so
  nothing flagged it, and `tests/truth/components.json` pinned only the numeric
  case. A numeric suffix is a port and still passes through; anything else is a
  name and is remapped as one.

- A distinguished name carrying a schema-extended RDN attribute published the
  attribute *type* verbatim. `transform_dn` maps RDN values but emits types as
  it found them, which is right for the standard set — `CN`, `OU` and `DC` are
  schema, not data — and wrong the moment a directory puts its own attribute in
  an RDN: `CN=Bob,ACMEPAYROLLID=99,DC=corp,DC=local` names the organization in
  the type however thoroughly the value is redacted. Neither gate could see it.
  The policy's source gate and the verifier's output gate both only asked
  whether each component contained an `=`, and because the verifier re-derives
  output through the same `transform_dn` the engine used, re-derivation is blind
  to a type-level defect by construction — the shape gate was the only possible
  backstop and it was vacuous.

  Both gates now share `components::dn_attribute_types_are_standard`, over the
  RFC 4514 §3 set. A DN with anything else is redacted whole by the policy
  rather than partially transformed. More anonymization, never less, and the
  same treatment 0.3.0 gave values its operations could not parse.

  This diverges deliberately from the Python reference, which does neither. The
  new cases live in `crates/shanon-core/tests/components.rs` rather than in
  `tests/truth/components.json`, so that file stays what it claims to be: a
  record of what the reference produces.

### Security

- `spike/sample.json` was a real SharpHound capture of a lab domain — a live
  domain SID, account names, distinguished names and logon timestamps — and
  `crates/shanon-core/tests/spike.rs` described it as one. A project whose
  entire purpose is keeping collections out of places they do not belong should
  not carry one in its own tree. It is replaced by a generated collection with
  the same structural shape (identical key order, the same mix of nested
  objects, empty arrays, a null-valued object slot, and negative and zero
  integer tokens, plus a reference-only stub member), so the byte-parity
  contract it backs is unchanged in strength.
  `spike/json_roundtrip_expected.txt` was regenerated with the Python reference
  serializer, not with `canonical_json`, keeping the test a cross-implementation
  check rather than a snapshot of our own output.

  Note that the removed file remains in git history. Rewriting that history is a
  separate decision, and this entry does not make it.

- Every GitHub Actions `uses:` is now pinned to a full commit SHA, with the tag
  in a trailing comment. They were on floating major tags, which are mutable —
  repointable at any commit by whoever owns the action's repository, or by
  whoever compromises it. That matters most in the release job, which holds
  `contents: write` and publishes both the binaries users download and the
  `.sha256` they verify against, and which installs `cargo-deny` through an
  action that fetches a binary at run time. Dependabot's github-actions updater
  understands SHA pins and rewrites the trailing comment, so the pins stay
  current without manual work.

  The release job's toolchain is the one input still unpinned: it resolves
  whatever `rustup toolchain install stable` means at tag time. The build is
  already `--locked`, so this is the last non-deterministic input to a published
  artifact, and pinning it is a maintenance trade-off left open deliberately.

- Added `scripts/check-fixtures.sh`, run by CI, refusing any tracked file that
  carries an unrecognized `S-1-5-21` domain SID authority or is named like
  collector output. `.gitignore` blocked `*.zip` and `*.map.json` only, so a
  *directory-form* collection — loose `.json` files, and a first-class shanon
  input — was covered by no rule at all; the repository's own history
  demonstrated the gap. `.gitignore` also now blocks the
  `<timestamp>_<kind>.json` shape both collectors emit, but pattern matching is
  the convenience and the script is the guarantee.

  Three high-entropy domain SID authorities of unverified provenance remain in
  `tests/parity/` and `tests/truth/`. They are frozen into vectors the Python
  reference produced, so they are allowlisted explicitly rather than silently
  tolerated, and the allowlist says to replace each one the next time its
  fixture is regenerated.

- The lab's domain name also survived in a `tests/truth/components.json`
  domain-qualified SID vector, which the SID-authority check above does not look
  for. That vector now uses the synthetic domain the rest of the fixtures
  already use, and both the domain name and the removed lab SID authority are in
  a permanent denylist in `scripts/check-fixtures.sh` — a value removed once
  should not be able to come back, whatever file it turns up in.

## [0.3.0] - 2026-07-28

Anonymizes BloodHound CE collections, which 0.2.0 aborted on, and adds
`shanon inspect` to diagnose a collection that will not go through.

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

[Unreleased]: https://github.com/Matixx22/shanon/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Matixx22/shanon/releases/tag/v0.3.0
[0.2.0]: https://github.com/Matixx22/shanon/releases/tag/v0.2.0
