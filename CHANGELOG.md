# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
