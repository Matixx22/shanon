# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Known gaps

Recorded here so that closing any of them is a deliberate act, not a discovery.
Every one of these is open as of 0.5.0.

- **Windows directory input is not descriptor-anchored.** There is no `openat`,
  so the check for a reparse point and the open of the member are two
  operations. A symlink or junction escape is still refused, but an attacker who
  can write into the input directory mid-run has a race that Linux and macOS do
  not give them. Closing it means dropping to `NtCreateFile` with a relative
  root handle. ZIP input and the publish path are unaffected.
- **Windows mapping files inherit the parent directory ACL.** Windows has no
  `umask`, so the `0o600`-from-creation guarantee has no equivalent.
  `create_new` still refuses to clobber. SECURITY.md tells Windows users to keep
  the map under their user profile; closing this properly means building a DACL
  and calling `SetSecurityInfo`.
- **Undeclared numeric recognition is path-based, not value-based.** 0.5.0
  redacts numbers at paths no rule declares, which covers `ParseAllProperties`
  spill. A collector that emits an organization-bound number at a path shanon
  *does* declare would still publish it, and the fix is to keep `NUMERIC_PATHS`
  tracking the collector rather than to widen the redaction.
- **Booleans at undeclared paths are still published.** One bit cannot identify
  anyone, and a real collection has enough undeclared booleans to bury the
  numeric signal `inspect` exists to surface. Recorded so the asymmetry with
  numbers is a decision rather than an oversight.
- **Secret material is recognized by attribute name.** 0.4.1 widened the list,
  but it is still a list. A credential under an attribute it does not know is
  pseudonymized like any other string, so a collector that renames one, or a
  custom attribute holding a password, still puts the cleartext in the mapping
  file. Closing this properly means recognizing secrets by shape or entropy
  rather than by name.
- **Three high-entropy domain SID authorities of unverified provenance remain**
  in `tests/parity/` and `tests/truth/`, frozen into vectors the Python
  reference produced. They are allowlisted explicitly rather than silently
  tolerated, and the allowlist says to replace each one the next time its
  fixture is regenerated.
- **The removed `spike/sample.json` remains in git history.** Rewriting that
  history is a separate decision, which no release so far has made.

The SPN, DN and catalog fixes diverge deliberately from the Python reference,
which carries all three defects. Their new cases live in the Rust test files, so
`tests/truth/` stays what it claims to be: a record of what the reference
produces.

## [0.5.0] - 2026-07-29

Closes the numeric passthrough gap, which was the last one that leaked a real
value. A collection run before this release and one run after it differ only at
numeric leaves the policy does not declare.

### Security

- A numeric leaf at a path no rule declares is replaced with a type-stable
  sentinel instead of being published verbatim. `-1`, or `-2` where the source
  was already `-1`, and a float stays a float so the output is still
  BloodHound-loadable.
- This matters because of how the collector behaves, not just the schema.
  SharpHound's `BestGuessConvert` turns any attribute whose string value parses
  as an integer into a JSON number, so under `--collectallproperties` a custom
  `employeeNumber` or `uidNumber` arrives as one.
- The severity is re-identification, not one leaked field. Matching a numeric
  employee ID against an HR roster recovers the account behind a pseudonym, and
  its name, UPN, DN and every edge fall with it.
- The value is destroyed rather than pseudonymized. Nothing in BloodHound's
  analysis reads these attributes, so distinctness buys no reasoning and would
  preserve exactly the correlation that re-identifies. Nothing is written to the
  mapping file and the map format is unchanged.
- `verify` re-derives the sentinel from the frozen policy rather than trusting
  the engine, so an engine that skipped one aborts the run.

### Added

- Ten numeric properties the collector emits are now declared and preserved
  verbatim: `authorizedsignatures`, `basicconstraintpathlength`, `flags`,
  `lockoutobservationwindow`, `lockoutthreshold`, `machineaccountquota`,
  `minpwdlength`, `pwdhistorylength`, `pwdproperties`, `schemaversion`. Each is
  a configuration value identical across every domain that never changed it.
- Declaring them is what makes the redaction above safe: everything still
  undeclared is `ParseAllProperties` spill rather than a standard field.
- `--keep-undeclared-numbers` on `anonymize` and `inspect` restores verbatim
  passthrough for operators who want the extra context.

### Changed

- `inspect` counts `undeclared-numeric-value` whether or not the redaction is
  on, so the report says what the collection contained either way.

## [0.4.1] - 2026-07-29

Closes three of the gaps 0.4.0 recorded. No change to the anonymization of a
collection that already ran clean: same pseudonyms, same output bytes.

### Security

- Secret-material redaction covers ten more credential attributes: forest trust
  keys (`trustAuthIncoming`, `trustAuthOutgoing`, `initialAuthIncoming`,
  `initialAuthOutgoing`), BitLocker recovery material (`msFVE-RecoveryPassword`,
  `msFVE-KeyPackage`), the legacy LM store (`dBCSPwd`), the Group Policy
  Preferences `cpassword` field, and the bare `password` and `pwd` spellings.
- A trust key is the one worth calling out. It forges tickets across a forest
  edge, which is the edge an attack-path question is usually about.
- Matching stays exact on the whole leaf name, so `pwdlastset` and
  `passwordnotreqd` still take the ordinary path. A test pins that.

### Fixed

- A member that parses but carries no usable `meta` is skipped instead of
  aborting the whole collection. It no longer takes its valid siblings with it.
- The accept predicate now asks for exactly what the engine asks for: a `data`
  array, a `meta` object, and a non-empty `meta.type`. The two disagreeing is
  what caused that abort.
- A collection whose members are *all* skipped is still refused, so nothing can
  inspect clean by virtue of having been entirely discarded.
- The release workflow builds with a pinned compiler version instead of whatever
  `stable` resolved to at tag time. With the existing `--locked`, a tagged build
  now has no floating inputs.

## [0.4.0] - 2026-07-29

Runs on Windows, so a collection can be scrubbed on the machine that produced
it. Also closes the LAPS and gMSA gap, which wrote collected cleartext passwords
into the mapping file as lookup keys.

### Added

- Windows support. `shanon.exe` runs on Windows x86_64, and the anonymization is
  byte-identical to Linux and macOS: same classification, same pseudonyms, same
  verification, same output.
- A Windows backend in `platform`: reparse-point refusal at every path component
  in place of `openat` hops, and `MoveFileExW` without
  `MOVEFILE_REPLACE_EXISTING` as the atomic no-replace publish.
- `platform::DirRoot`, an opaque directory-root handle. No file descriptor or
  `HANDLE` type reaches `pipeline` any more.
- `platform::paths_equal` / `path_within`, the containment-guard comparisons.
  Windows filenames are case-insensitive, so the byte-wise comparison would have
  let a mapping file be written into the output collection under a different
  spelling of the same directory.
- `windows-latest` in the CI test matrix, and `x86_64-pc-windows-msvc` in the
  release matrix, shipped as a `.zip` with the same `<hash>  <file>` checksum
  line as the other targets.
- A `windows-binary` CI job that attaches an unsigned release build to every
  run, so a Windows machine can be handed a binary without cutting a tag.
- `.gitattributes` pinning the whole tree to LF, and the truth and parity
  fixtures to no conversion at all. `core.autocrlf` defaults to true on Windows,
  which rewrote the byte-exact reference vectors at checkout and failed
  `save_bytes_match_reference_interop` against shanon's correct output. Fixture
  bytes are invariant 2's contract and git must not touch them.

- `shanon inspect` now reports *numeric values passed through unchanged*, each
  with its canonical path and an `undeclared-numeric-value` audit code. Booleans
  and nulls are deliberately excluded: a null carries nothing, a boolean one bit,
  and a real collection has enough undeclared booleans to bury the signal.
- `crates/shanon-core/tests/zip.rs`: first test coverage of the archive path,
  input and output. Round trip with no source identifier surviving, non-JSON and
  directory entries ignored, `.JSON` matched case-insensitively, six traversal
  shapes refused, an oversized declared member refused, and five malformed
  archives rejected without a panic.
- `crates/shanon-core/tests/reuse_map.rs`: the catalog gate accepts this
  build's version and refuses an older one, a newer one, and a mapping that
  states none.
- `crates/shanon-core/tests/finding_fingerprint.rs`: one value yields different
  tokens under different salts, the same token under one salt, and never the
  unkeyed digest of any value in the corpus.
- `crates/shanon-core/tests/secret_material.rs`: no secret spelling reaches the
  output collection or the mapping file, a GUID-shaped secret is still redacted,
  and the LAPS expiry attribute is not.
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

- Windows is no longer a permanent non-goal in `CLAUDE.md`.
- `rustix` is now a `cfg(unix)` dependency and `libc` a
  `cfg(all(unix, not(target_os = "linux")))` one. Neither builds on Windows.
- Private file and staging-directory creation moved out of `pipeline` and behind
  `platform::create_private_file` / `create_private_dir`, which is what removed
  the last `std::os::unix` import from portable code.
- The dangling-symlink publish test is `cfg(unix)`. Creating a symlink on
  Windows needs developer mode or `SeCreateSymbolicLinkPrivilege`, so it would
  report a privilege failure rather than the publish refusal it exists to pin.

- `--verbose-failures` now also expands a refused `--reuse-map` load, the same
  split between the frozen line and the sanitized reason the pipeline's own
  aborts already used.
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

- A collected LAPS or gMSA secret was pseudonymized rather than redacted, which
  writes the cleartext password into the mapping file as a lookup key.
  `ms-mcs-admpwd`, the `msLAPS-*` attributes and `msDS-ManagedPassword` are now
  secret material. The expiry and interval attributes are deliberately not.
- The secret-material check now runs before the field's transform is chosen, so
  a secret whose value happens to be SID-, GUID- or OID-shaped is redacted
  instead of being routed to a structured identifier transform and mapped.
- The two copies of the secret-material list, one in `engine` and one in
  `verify`, are now one list in `lib.rs`. The verifier re-derives every leaf
  independently, so a one-sided edit would have aborted every run carrying such
  a field.
- The offender fingerprint in a verification finding is keyed on the run salt.
  It was an unkeyed 48-bit digest: recoverable from a candidate list for a value
  drawn from a guessable domain, and identical across runs and machines, so
  findings from two unrelated collections could be correlated. The docs
  meanwhile presented the tokens as safe to share.
- `--reuse-map` now refuses a mapping minted under a different
  `CATALOG_VERSION`, or one that records no version at all. `from_value`
  discarded the map's `policy` block, so nothing read the version back, and the
  bump to `2` made the disagreement reachable.
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

[Unreleased]: https://github.com/Matixx22/shanon/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Matixx22/shanon/releases/tag/v0.5.0
[0.4.1]: https://github.com/Matixx22/shanon/releases/tag/v0.4.1
[0.4.0]: https://github.com/Matixx22/shanon/releases/tag/v0.4.0
[0.3.0]: https://github.com/Matixx22/shanon/releases/tag/v0.3.0
[0.2.0]: https://github.com/Matixx22/shanon/releases/tag/v0.2.0
