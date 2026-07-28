# shanon — SharpHound Anonymizer

> Deterministically anonymize Active Directory collection data so you can hand it
> to an LLM — without handing over your client.

[![CI](https://github.com/Matixx22/shanon/actions/workflows/ci.yml/badge.svg)](https://github.com/Matixx22/shanon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.97%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#install)

Anonymize a SharpHound / BloodHound collection so it's safe to send to a public
LLM for Active Directory attack-path reasoning. shanon keeps the exact SharpHound
JSON format (still BloodHound-loadable) and every graph cross-reference, while
remapping every organization-bound identifier. It writes a local mapping file so
the LLM's analysis can be restored to real identities.

**No network. No LLM calls. Never mutates your input.** The mapping file is
client-sensitive — keep it local, never ship it.

> **Scope.** shanon pseudonymizes — it substantially lowers re-identification
> risk, but a collection is not legally anonymous afterward.
> [SECURITY.md](SECURITY.md) states the exact threat model and residual risks.

## Install

```sh
git clone https://github.com/Matixx22/shanon
cd shanon
cargo build --release
# binary at ./target/release/shanon
```

## Usage

### `anonymize`

```
shanon anonymize --input <zip|dir> --out <dir> [--map PATH] [--reuse-map PATH]
                 [--verbose-failures] [--progress | --no-progress]
```

| flag | required | meaning |
| --- | --- | --- |
| `--input` | yes | SharpHound collection: a `.zip` or a directory of `*.json` |
| `--out` | yes | output directory (must not already contain the target) |
| `--map` | no | where to write the reversal map (default `<out>/collection.map.json`) |
| `--reuse-map` | no | reuse salt + prior mappings so pseudonyms stay stable across collections |
| `--verbose-failures` | no | on a leak-gate abort, print every finding before exiting |
| `--progress` | no | draw the progress bar even when stderr is not a terminal |
| `--no-progress` | no | never draw the progress bar |

A run over a real collection takes minutes, so `anonymize` draws a progress bar
on stderr showing each phase — discovery, transform+verify, publish — with a
count and an ETA:

```
discovery        \  48,213 objects  0:41
transform+verify [##########--------------]  43%  41,902/96,426  1:12  eta 1:33
```

It is drawn only when stderr is a terminal, so redirected or piped stderr is
byte-identical to a run without it. Use the flags above to force either way.

```sh
# one-shot: zip in, anonymized zip + map out
shanon anonymize --input goadlight.zip --out ./anon
#   ->  ./anon/collection_anon.zip
#   ->  ./anon/collection.map.json        (reversal keys — keep private)

# stable pseudonyms across two collections of the same environment
shanon anonymize --input dc1.zip --out ./anon1 --map ./env.map.json
shanon anonymize --input dc2.zip --out ./anon2 --reuse-map ./env.map.json
```

Send only the emitted `collection_anon.zip` to the LLM, never its parent output
directory — that may also contain the mapping file. Same input + same salt →
byte-identical output.

### `restore`

```
shanon restore --map <map.json> [--lookup FAKE | --forward REAL | --input FILE]
```

| flag | meaning |
| --- | --- |
| `--map` | the `collection.map.json` produced by `anonymize` (required) |
| `--lookup` | resolve one pseudonym → real value |
| `--forward` | resolve one real value → pseudonym |
| `--input` | bulk mode: substitute every known pseudonym in a file (omit to read stdin) |

```sh
# single pseudonym -> real
shanon restore --map ./anon/collection.map.json --lookup southridge-geafzk36mbevs.local

# bulk: de-anonymize an LLM answer that quotes pseudonyms back at you
shanon restore --map ./anon/collection.map.json --input llm_findings.md
```

### Exit codes

| code | condition |
| --- | --- |
| `0` | success |
| `1` | leak-gate abort, invalid mapping data, or I/O error — no output written |
| `2` | pre-flight refusal (e.g. `--out` already holds a map, or conflicting flags) |

## What gets scrubbed

- Names (user/group/computer/OU/GPO/container), UPNs, SPNs, DNS hostnames, emails
- Organization-specific SID authority values and custom GUIDs
- Domain FQDNs and organization-specific DN components
- Role, product, OS, and vendor fingerprints
- Custom certificate templates, enterprise OIDs, CA names, and certificate material
- Free text and opaque values → deterministic `[REDACTED:…]` mappings

## What is preserved

Only catalog-proven, globally invariant constants are preserved — and only at the
specific object type and field path listed in the catalog. Examples:

- `Domain Admins` retains RID 512 and its canonical account name; its SID
  authority and domain name are still mapped.
- Fixed default-GPO GUIDs, standard protocol/EKU OIDs, and built-in
  certificate-template names, at catalog-permitted paths only.
- Feature/vendor defaults (`Hyper-V Administrators`, `Vault Administrators`) and
  anything custom are mapped, not preserved.

## Safety model

shanon is fail-closed. It classifies every object, freezes a verification state,
transforms each member by object type and field path, then independently verifies
the result against the frozen registry before writing. Verified members go to a
private staging area and are published by atomic rename only after all pass;
existing destinations are refused. Errors report a sanitized fingerprint, never
the source secret or filename.

See [SECURITY.md](SECURITY.md) for the full threat model and what shanon does
**not** protect against.

## Development

```
crates/shanon-core   library: catalog, policy, registry, engine, verification, pipeline
crates/shanon-cli    the `shanon` binary (anonymize / restore)
```

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the build,
test, and PR workflow, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). A real
identifier that survives a run is a **security bug**: report it privately per
[SECURITY.md](SECURITY.md), never as a public issue.

## License

MIT © Mateusz Suchocki. See [LICENSE](LICENSE).
