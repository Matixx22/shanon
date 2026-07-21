# Contributing to shanon

Thanks for your interest in improving shanon. It's a safety boundary for
security engineers, so correctness and a fail-closed posture matter more than
features. This guide covers how to build, test, and propose changes.

## Ground rules

- **Never commit real data.** No client collections, no mapping files, no raw
  lab AD dumps. `.gitignore` blocks `*.zip` and `*.map.json`; do not weaken those
  rules. Reproductions in issues/PRs must use **synthetic** collections.
- **Fail-closed is a feature.** A change that lets a run publish output when a
  verification check is uncertain is a regression, even if tests pass.
- **A surviving real identifier is a security bug**, not a normal issue — see
  [SECURITY.md](SECURITY.md) for private disclosure.

## Development setup

```sh
git clone https://github.com/Matixx22/shanon
cd shanon
cargo build --workspace
```

Develop on current stable Rust. The project's minimum supported Rust version
(MSRV) is **1.97**, declared as `rust-version` in `Cargo.toml` and verified by a
dedicated CI job — don't use language features newer than that floor.

## Quality gates

Every change must pass the same gates CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run them before you push. Warnings are errors here.

## Making a change

1. Fork and branch from `main` (`git switch -c fix/short-description`).
2. Keep commits focused and write [Conventional Commits](https://www.conventionalcommits.org)
   messages (`fix:`, `feat:`, `docs:`, `test:`, `refactor:`, `chore:`).
3. Add or update tests. New anonymization or verification behavior needs a
   committed, synthetic fixture that pins it field-by-field.
4. Update [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`.
5. Open a PR against `main` and fill out the template.

## What gets reviewed hardest

- Anything touching the verification pass, the policy/catalog, or the publish
  path. These are the confidentiality guarantees.
- New dependencies. Keep the tree small and auditable; justify each addition.
- Error messages. They must stay sanitized — no source secrets or filenames in
  diagnostics.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/Matixx22/shanon/issues/new/choose).
For a suspected leak, do **not** open a public issue — follow
[SECURITY.md](SECURITY.md).
