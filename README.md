<p align="center">
  <img src="assets/banner.svg" alt="shanon: hand your Active Directory collection to an LLM, not your client" width="860">
</p>

<p align="center">
  <a href="https://github.com/Matixx22/shanon/actions/workflows/ci.yml"><img src="https://github.com/Matixx22/shanon/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rustc-1.97%2B-orange.svg" alt="MSRV 1.97"></a>
  <a href="#install"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Linux | macOS | Windows"></a>
</p>

A SharpHound collection is your client's entire directory in clear: every
account, every hostname, every group name. That is why it cannot leave the
engagement, and why you cannot paste it into a chat window.

**shanon** remaps the organization-bound identifiers and leaves the structure
alone. The output is still SharpHound JSON, still loads in BloodHound, and every
graph cross-reference still points where it pointed. The edges are the thing you
are actually reasoning about, and they all survive. A local mapping file turns
any answer back into real names.

```sh
shanon anonymize --input engagement.zip --out ./anon
```

## Why you would use it

Anywhere a collection has to leave the engagement it came from:

- **Ask an LLM about attack paths** without handing over the directory.
- **Get a second opinion.** Share a collection with a colleague or a vendor who
  is not on the engagement.
- **Write it up.** Talks, blog posts and screenshots, without a manual redaction
  pass over every image.
- **Teach with it.** Real graph shape and real edge density, no client in it, so
  a lab or a workshop can run on a live collection instead of a toy one.
- **File a bug.** Attach a reproducer against BloodHound or a collector without
  an NDA conversation first.
- **Keep the graph, drop the client.** Retain the structure for later work when
  the raw collection has to be destroyed.

Because the mapping file stays local, every one of these stays reversible for
you and for nobody else.

## What it looks like

An excerpt from a run over the synthetic collection in [`demo/`](demo/). Every
run picks a fresh random salt, so your pseudonyms will read differently.

**Before**

```json
{
  "name": "SVC_SQL@CONTOSO.LOCAL",
  "distinguishedname": "CN=svc_sql,OU=Service Accounts,DC=CONTOSO,DC=LOCAL",
  "email": "svc_sql@contoso.local",
  "description": "Runs MSSQLSvc on SQL01. Ticket owner: Helpdesk.",
  "serviceprincipalnames": ["MSSQLSvc/sql01.contoso.local:1433"],
  "hasspn": true
}
```

**After**

```json
{
  "name": "kjeffersg46lvu6zae6m@fabrikam-cmw5tqv5maqpm.LOCAL",
  "distinguishedname": "CN=kjeffersg46lvu6zae6m,OU=ppierce4d4g57h6caryy,DC=fabrikam-cmw5tqv5maqpm,DC=LOCAL",
  "email": "kjeffersg46lvu6zae6m@fabrikam-cmw5tqv5maqpm.local",
  "description": "[REDACTED:flnnjhdpxlthi]",
  "serviceprincipalnames": ["MSSQLSvc/HOST-87-GBWGEMP4OJUII.fabrikam-cmw5tqv5maqpm.local:1433"],
  "hasspn": true
}
```

Read what survived, because that is the point:

- `hasspn` is still `true`, the SPN is still an `MSSQLSvc/…:1433`, the DN is
  still a DN. **The account is still visibly kerberoastable.**
- That account appears in four places across three collection members, and every
  one of them got the *same* pseudonym, so the graph edges survive.
- Free text becomes an opaque `[REDACTED:…]` handle rather than a guess at which
  part of the sentence was sensitive.
- `Domain Admins` keeps RID 512 and its canonical name, because that is a global
  constant rather than something about your client, while its SID authority and
  domain are still remapped.

## Install

**Prebuilt binary** (Linux x86_64, macOS Apple Silicon, Windows x86_64). Pick the
current tag from [Releases](https://github.com/Matixx22/shanon/releases):

```sh
VERSION=v0.7.0
TARGET=x86_64-unknown-linux-gnu        # or aarch64-apple-darwin
BASE="https://github.com/Matixx22/shanon/releases/download/$VERSION"

curl -fsSLO "$BASE/shanon-$VERSION-$TARGET.tar.gz"
curl -fsSLO "$BASE/shanon-$VERSION-$TARGET.tar.gz.sha256"
shasum -a 256 -c "shanon-$VERSION-$TARGET.tar.gz.sha256"

tar xzf "shanon-$VERSION-$TARGET.tar.gz"
./shanon --version
```

Windows ships a `.zip` instead, with the same `<hash>  <file>` checksum line:

```powershell
$VERSION = "v0.7.0"
$TARGET  = "x86_64-pc-windows-msvc"
$BASE    = "https://github.com/Matixx22/shanon/releases/download/$VERSION"

Invoke-WebRequest "$BASE/shanon-$VERSION-$TARGET.zip" -OutFile "shanon-$VERSION-$TARGET.zip"
Invoke-WebRequest "$BASE/shanon-$VERSION-$TARGET.zip.sha256" -OutFile "shanon-$VERSION-$TARGET.zip.sha256"

# compare against the published checksum before unpacking
(Get-FileHash -Algorithm SHA256 "shanon-$VERSION-$TARGET.zip").Hash.ToLower()
Get-Content "shanon-$VERSION-$TARGET.zip.sha256"

Expand-Archive "shanon-$VERSION-$TARGET.zip" -DestinationPath .
.\shanon.exe --version
```

**With cargo:**

```sh
cargo install --git https://github.com/Matixx22/shanon shanon-cli
```

**From source** (MSRV 1.97):

```sh
git clone https://github.com/Matixx22/shanon
cd shanon
cargo build --release          # binary at ./target/release/shanon
```

## Quickstart

```sh
# 1. dry run: tells you whether it would work, writes absolutely nothing
shanon inspect --input engagement.zip

# 2. the real thing
shanon anonymize --input engagement.zip --out ./anon
#   ->  ./anon/collection_anon.zip      this is the one you share
#   ->  ./anon/collection.map.json      reversal keys, keep local, never ship

# 3. rewrite the real names in your own question to the same pseudonyms
shanon scrub --map ./anon/collection.map.json --input question.md > question_safe.md

# 4. fold the answer back to real identities
shanon restore --map ./anon/collection.map.json --input llm_findings.md
```

Try it against the committed synthetic collection first:

```sh
shanon inspect --input demo/collection
```

Input can be a `.zip`, a directory of `*.json`, or a single `.json` member. Same
input plus same salt gives byte-identical output. Pass `--map` once and
`--reuse-map` after it to keep pseudonyms stable across several collections of
the same environment.

## Before you share anything

> shanon **pseudonymizes**. It substantially lowers re-identification risk, but a
> collection is not legally anonymous afterward, and structure itself carries
> information: a 40,000-user domain with two DCs still looks like a
> 40,000-user domain with two DCs. [SECURITY.md](SECURITY.md) states the exact
> threat model and residual risks. Read it before you send anything anywhere.

Send only the emitted `collection_anon.zip`, never its parent output directory,
which also holds the mapping file. That file contains the real mappings in the
clear and is as sensitive as the raw collection.

The collection is not the only thing that leaves your machine. Run the question
you are about to ask through [`shanon scrub`](#scrub) as well, and then read it
once more for the names no map could know about.

**No network. No LLM calls. Never mutates your input.**

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the build,
test, and PR workflow, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). A real
identifier that survives a run is a **security bug**: report it privately per
[SECURITY.md](SECURITY.md), never as a public issue.

## License

MIT © Mateusz Suchocki. See [LICENSE](LICENSE).

---

# Reference

Everything below is detail: the full flag surface, what is transformed and what
is kept, and how the safety model works.

## Usage

### `anonymize`

```
shanon anonymize --input <zip|dir|json> --out <dir> [--map PATH] [--reuse-map PATH]
                 [--verbose-failures] [--keep-undeclared-numbers]
                 [--redact-os-strings] [--progress | --no-progress]
                 [--summary | --no-summary]
```

| flag | required | meaning |
| --- | --- | --- |
| `--input` | yes | SharpHound collection: a `.zip`, a directory of `*.json`, or a single `.json` member |
| `--out` | yes | output directory (must not already contain the target) |
| `--map` | no | where to write the reversal map (default `<out>/collection.map.json`) |
| `--reuse-map` | no | reuse salt + prior mappings so pseudonyms stay stable across collections |
| `--verbose-failures` | no | on an abort, print sanitized detail: every leak-gate finding, or the class, member, path and offender fingerprint of a mapping failure |
| `--keep-undeclared-numbers` | no | publish numbers at undeclared paths verbatim instead of replacing them. Widens what leaves the machine; read the `inspect` report first |
| `--redact-os-strings` | no | redact `Properties.operatingsystem` instead of preserving a known Windows product string |
| `--progress` | no | draw the progress bar even when stderr is not a terminal |
| `--no-progress` | no | never draw the progress bar |
| `--summary` | no | print the run summary even when stderr is not a terminal |
| `--no-summary` | no | never print the run summary |

On success it writes a summary to stderr:

```
summary: 5752 objects
  classifications: core_global_default 118, custom 5634
  unknown field paths: 21 distinct
  numeric values passed through: 0 distinct path(s)
  collection: ./anon/collection_anon.zip
  map: ./anon/collection.map.json
```

A run over a real collection takes minutes, so `anonymize` also draws a progress
bar showing each phase (discovery, transform+verify, publish) with a count and
an ETA:

```
discovery        \  48,213 objects  0:41
transform+verify [##########--------------]  43%  41,902/96,426  1:12  eta 1:33
```

Both are drawn only when stderr is a terminal, so a redirected or piped stderr is
byte-identical to a run without them. Use the flags above to force either way.

```sh
# stable pseudonyms across two collections of the same environment
shanon anonymize --input dc1.zip --out ./anon1 --map ./env.map.json
shanon anonymize --input dc2.zip --out ./anon2 --reuse-map ./env.map.json
```

Output members are named `member-NNNNN.json`: the collector's filenames are
themselves organization-bound, so they do not survive either.

### `inspect`

```
shanon inspect --input <zip|dir|json> [--keep-undeclared-numbers]
               [--redact-os-strings] [--format text|json]
               [--progress | --no-progress]
```

A dry run: same discovery, transform and leak-gate verification as `anonymize`,
then stop. **Nothing is written**: no output collection, no mapping file, no
staging directory, so it is safe to point at a collection that must not leave
the machine. Exit `0` if the collection would anonymize cleanly, `1` if it would
abort.

```sh
shanon inspect --input engagement.zip
```

```
members: 7 read, 7 accepted, 0 skipped
objects: 5752

collections:
  users                    type=User           version=6          objects=4000
  computers                type=Computer       version=6          objects=800
  azbase                   type=Unknown        version=6          objects=12  <- unrecognized, contents anonymized opaquely

audit codes:
  malformed-source-value: 600
  unknown-key-path: 33106

unknown field paths (21 distinct):
       800  data[].localgroups[]["[redacted:wx5fedc6e5w56]"]

preflight:
  missing core collection types: domains
  collection type declared by more than one member: users

verdict: this collection would anonymize cleanly
```

The `preflight:` block appears only when it has something to say. It is
advisory and never changes the verdict or the exit code. A collection type
declared by more than one member is what a directory holding several collection
runs looks like from the inside, where the collector's filenames are
deliberately not visible.

`--format json` prints the same report as one sorted JSON document, for a CI
gate or a ticket attachment:

```sh
shanon inspect --input engagement.zip --format json | jq .would_publish
```

Every line is a count, a synthetic `member-NNNNN.json` label, a canonical field
path or a salt-keyed BLAKE2b-6 fingerprint, never a source value and never a
source filename, so the report can be shared for a collection that cannot be.
Keyed matters: the token is stable within a run and reversible by whoever holds
the mapping file, and it is not the digest of a guessable value, so nobody can
recover it from a candidate list or use it to link two collections. That
also means the *names* of unmodeled fields appear as fingerprints rather than
in clear: the path tells you where the drift is, the digest tells you it is the
same field each time.

Reach for it when a run aborts, when a new collector version is in play, or
before spending minutes on a collection that will not finish.

### `scrub`

```
shanon scrub --map <map.json> [--input FILE] [--summary | --no-summary]
```

| flag | meaning |
| --- | --- |
| `--map` | the `collection.map.json` produced by `anonymize` (required) |
| `--input` | the text to scrub (omit to read stdin) |
| `--summary` | print the report even when stderr is not a terminal |
| `--no-summary` | never print the report |

shanon anonymizes the collection, not the sentences you write around it. Ask
"can SVC_SQL reach DC01?" and you have just handed over two names the collection
no longer contains. `scrub` runs your own text through the same map first, so
those names arrive as the pseudonyms the model already saw:

```sh
shanon scrub --map ./anon/collection.map.json --input question.md
#   Can kjeffersg46lvu6zae6m in fabrikam-cmw5tqv5maqpm.LOCAL reach anything?
#   scrubbed: 2 replacements
#     categories: domains 1, accounts 1
#     this replaces only what the map knows; check the rest by hand
```

The scrubbed text goes to stdout and the report to stderr, so you can pipe one
without losing the other. The report is drawn under the same rule as the
`anonymize` summary: only when stderr is a terminal.

Matching is case-insensitive for names, SIDs, hostnames and GUIDs, because you
type `CONTOSO` and the collection stored `contoso`. Whole words only, so a
mapped `alice` does not rewrite `alicent`. Text that already reads in pseudonyms
is left alone, which makes a second pass a no-op and makes it safe to scrub a
draft you have already scrubbed once.

**It replaces what the map knows, and cannot certify the rest.** A hostname you
typed that was never in the collection has no mapping, cannot be substituted,
and passes through in the clear. Read the count, and read your own sentence.

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
shanon restore --map ./anon/collection.map.json --lookup kjeffersg46lvu6zae6m
#   accounts: svc_sql

# bulk: de-anonymize an answer that quotes pseudonyms back at you
shanon restore --map ./anon/collection.map.json --input llm_findings.md
```

`--lookup` and `--forward` resolve one mapped **component** (an account label, a
domain label, a hostname), because that is the granularity the registry binds.
A composite string such as a full UPN or SPN goes through `--input`, which
substitutes every component it recognizes.

### Exit codes

| code | condition |
| --- | --- |
| `0` | success; for `inspect`, the collection would anonymize cleanly |
| `1` | leak-gate abort, invalid mapping data, or I/O error, no output written; for `inspect`, the collection would abort |
| `2` | pre-flight refusal (e.g. `--out` already holds a map, or conflicting flags) |

## What gets anonymized

- Names (user/group/computer/OU/GPO/container), UPNs, SPNs, DNS hostnames, emails
- Organization-specific SID authority values and custom GUIDs
- Domain FQDNs and organization-specific DN components
- Role, product and vendor fingerprints, and any OS string that is not a
  catalog-listed Windows product (see below)
- Custom certificate templates, enterprise OIDs, CA names, and certificate material
- Free text and opaque values → deterministic `[REDACTED:…]` mappings
- The *names* of fields no rule models, not only their values. A custom AD
  attribute is organization-bound in its key as much as its contents
- Numeric values at those same unmodeled paths → a type-stable sentinel

That last one currently catches a few standard SharpHound fields the rule table
does not model yet, including `IsDeleted`, `IsACLProtected`,
`Properties.whencreated` and `FailureReason`: they come back renamed rather than
dropped. No graph edge depends on them, so the collection still loads and still
reasons correctly, but it is not a byte-for-byte SharpHound document. `inspect`
lists exactly which paths a given collection hit.

### Booleans, nulls and numbers

Booleans and nulls are passed through as they are, and so are numbers at the
paths shanon models, where a flag, a count or a timestamp carries no identity.

A number at a path no rule declares is a different animal. SharpHound turns any
attribute whose value parses as an integer into a JSON number, so under
`--collectallproperties` a custom `employeeNumber` arrives as one, and a numeric
employee ID matched against an HR roster re-identifies the account and every
edge it sits on. Those are replaced with a type-stable sentinel, and `shanon
inspect` reports exactly which paths were affected. See
[SECURITY.md](SECURITY.md#what-shanon-does-not-protect-against).

## What is preserved

Only catalog-proven, globally invariant constants are preserved, and only at the
specific object type and field path listed in the catalog. Examples:

- `Domain Admins` retains RID 512 and its canonical account name; its SID
  authority and domain name are still mapped.
- Fixed default-GPO GUIDs, standard protocol/EKU OIDs, and built-in
  certificate-template names, at catalog-permitted paths only.
- `Properties.operatingsystem`, when the value is exactly one of the listed
  Windows product strings (`Windows Server 2019 Standard`, `Windows 10
  Enterprise`, and so on). An unsupported OS is an attack path, and it is a
  Microsoft constant rather than anything about your client. A branded variant
  such as `Windows Server 2019 Datacenter - CONTOSO GOLD IMAGE`, an appliance
  banner, or a case variant matches nothing and is redacted.
  `Properties.operatingsystemversion` stays redacted: build numbers are a long
  tail no table can close. `--redact-os-strings` turns the whole thing off.
- Feature/vendor defaults (`Hyper-V Administrators`, `Vault Administrators`) and
  anything custom are mapped, not preserved.

## Why not just find-and-replace?

Because a directory is a graph, not a word list.

- **Identifiers are composite.** `MSSQLSvc/sql01.contoso.local:1433` is a service
  class, a host, a domain and a port. `S-1-5-21-…-1105` is an authority plus a
  RID that may or may not be a global constant. Each piece has to be decomposed
  and mapped on its own terms, and reassembled in the original shape, or the
  reader stops recognizing what it is looking at.
- **The same thing appears under many spellings.** A user is a UPN here, a
  `samaccountname` there, a DN component, an email local part, a `PrincipalSID`
  in someone else's ACE. Miss the correspondence and the attack path
  disintegrates; the anonymized graph is then worse than useless, it is
  misleading.
- **A missed replacement is silent.** That is the failure that matters, and no
  regex tells you it happened. shanon independently re-derives the expected
  output for every string leaf and compares before anything is published; a
  single divergence aborts the run with no output written at all.
- **You need it back.** A one-way scrub leaves you translating findings by hand,
  at which point you have re-created the mapping file, worse.

## Safety model

shanon is fail-closed. It classifies every object, freezes a verification state,
transforms each member by object type and field path, then independently verifies
the result against the frozen registry before writing. Verified members go to a
private staging area and are published by atomic rename only after all pass;
existing destinations are refused. Errors report a sanitized fingerprint, never
the source secret or filename.

See [SECURITY.md](SECURITY.md) for the full threat model and what shanon does
**not** protect against.

### Platforms

Linux, macOS and Windows. The anonymization is the same everywhere: same
classification, same pseudonyms, same verification, same output bytes. Two
*local filesystem* guarantees are weaker on Windows, because it has no `openat`
and no `umask`: directory input is not descriptor-anchored (ZIP input is
unaffected), and the mapping file inherits its parent directory's ACL instead of
being owner-only from creation. Keep the map under your user profile.
[SECURITY.md](SECURITY.md) spells both out.

## Development

```
crates/shanon-core   library: catalog, policy, registry, engine, verification, pipeline
crates/shanon-cli    the `shanon` binary (anonymize / inspect / restore)
demo/collection      synthetic collection behind the README's before/after
assets/              banner
```

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
