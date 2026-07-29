# Security Policy

`shanon` is a safety boundary: it exists to let you send SharpHound collections
to a public LLM without leaking client-identifying data. This document states
what that boundary covers, what it does not, and how to report a leak.

## What shanon does

- **Deterministic pseudonymization**, not encryption and not a legal anonymity
  guarantee. It remaps organization-bound identifiers (names, UPNs, SPNs, DNS
  hostnames, emails, SIDs, GUIDs, FQDNs, DN components) to stable fakes and
  replaces free-text and opaque values deterministically.
- **Determinism is scoped to one salt.** Every run mints a fresh 32-hex salt from
  OS entropy, so two independent runs of the same collection produce completely
  different pseudonyms and cannot be correlated with each other. `--reuse-map`
  is the deliberate exception: it reuses a prior salt and mapping so pseudonyms
  stay stable across collections.
- **Credential material is redacted, not pseudonymized.** A leaf whose name is a
  known credential attribute is replaced with `[REDACTED]`, so its value is not
  recorded anywhere, including the mapping file. Pseudonymizing one would store
  the cleartext as a lookup key in the map. The list covers the classic
  password and hash attributes plus LAPS (`ms-mcs-admpwd`, the `msLAPS-*`
  attributes) and gMSA (`msDS-ManagedPassword`), and the check runs before the
  field's transform is chosen, so a secret that happens to look like a SID,
  GUID or OID is still redacted. It is a name-based list: a credential under an
  attribute it does not know is pseudonymized like any other string.
- **Contextual preservation.** Only catalog-proven core constants are preserved,
  and only at explicitly permitted object types and field paths. Microsoft
  feature defaults, operating-system/product values, third-party defaults, and
  custom identifiers are transformed by default.
- **Fail-closed.** After complete discovery, shanon freezes the typed registry,
  policy, and catalog evidence. An independent verifier re-resolves every
  string-bearing source leaf and recomputes its exact expected output; non-string
  leaves are checked for topology, type, and value equality. Missing or forged
  decisions, topology changes, partial structured transformations, invalid
  preservation evidence, and structures that cannot preserve confidentiality and
  schema shape abort the run before the collection is published. Invalid schema
  strings and unknown fields are conservatively transformed and audited when that
  can be done safely.
- **Sanitized diagnostics.** Verification failures identify a generic member
  label, a collision-safe path, a policy code, and an offender fingerprint,
  never the original secret or the source filename. Policy audit summaries
  contain counts and canonical paths, not source values.
- **Findings are safe to paste.** The offender fingerprint is keyed on the run
  salt, so it cannot be recovered by hashing a candidate list, and the same
  value produces a different token in every run. Two sets of findings from two
  engagements cannot be correlated by anyone who does not hold both mapping
  files.
- **No network. No LLM calls. Never mutates your input.** The tool itself
  transmits nothing, anywhere.

## What shanon does NOT protect against

- **Structural re-identification.** Graph shape, object counts, ACL patterns,
  and timestamps are preserved on purpose (that is the attack-path signal). A
  determined analyst with side knowledge could still infer an organization from
  structure alone. Treat scrubbed output as *lower* risk, not *zero* risk.
- **The mapping file.** `*.map.json` contains the real↔fake mapping in the
  clear. It is as sensitive as the raw collection. Keep it local, never send it
  to the LLM, never commit it. `.gitignore` blocks `*.map.json` and `*.zip` by
  default; do not remove those rules. Version-1 maps remain loadable; newly
  saved version-2 maps add typed namespaces and policy metadata but are no less
  sensitive.
- **Correlation through a reused map.** `--reuse-map` keeps pseudonyms stable
  across collections, and that stability *is* linkage: any real value present in
  two collections receives the same pseudonym in both. Reusing one map across
  separate engagements therefore lets anything downstream, including the LLM's
  context window, tie those engagements together. Use one map per engagement
  unless you specifically want the collections linked.
- **Your prompt.** shanon scrubs the collection, not the sentences you type
  around it. Do not paste real names into the chat yourself.
- **Two filesystem guarantees on Windows.** The anonymization itself is
  identical on all three platforms: same classification, same pseudonyms, same
  independent verification, same byte output. Two things around it are weaker on
  Windows, both of them local-filesystem properties rather than anything the LLM
  sees.

  First, *directory input is not descriptor-anchored*. Linux and macOS walk a
  directory collection through `openat` hops from a pinned root, so a component
  swapped mid-run cannot redirect the read. Windows has no `openat`, so the
  backend instead refuses a reparse point at every component and opens the member
  with `FILE_FLAG_OPEN_REPARSE_POINT`. That still blocks a symlink or junction
  escape, but the check and the open are two operations, so an attacker who can
  write into your input directory *while a run is in progress* has a race the
  other platforms do not give them. ZIP input is unaffected, and so is the output
  side: publication is still an atomic no-replace `MoveFileExW`.

  Second, *the mapping file is created with the parent directory's ACL*, because
  Windows has no `umask` and no cheap owner-only creation mode. On Linux and
  macOS it is `0o600` from the moment it exists. Write it somewhere already
  restricted, under your user profile rather than `C:\Temp` or a share.

  If your threat model includes a hostile local user on the box you run shanon
  on, run it on Linux or macOS, or feed it the ZIP rather than an extracted
  directory.
- **Policy overrides.** The default CLI does not support raw substring, vendor,
  or unscoped name exemptions. Do not patch around a verification failure with
  a global allowlist; preservation requires exact catalog evidence for the node
  type, field path, identifier, and value.
- **Unknown collector fields.** Unknown strings are conservatively classified by
  shape and otherwise replaced as opaque values, with their canonical paths
  counted in the audit. If a new structure cannot be handled without preserving
  confidentiality and schema shape, the run fails rather than publishing it.
- **Numbers.** The policy classifies string leaves. A number, boolean or null is
  emitted verbatim, and its *key* is anonymized like any other. For the paths
  shanon models this is the intended answer: a schema flag, a count or a
  timestamp carries no identity, and BloodHound needs them intact. But a
  collector that emits an organization-bound value as a JSON number at a path no
  rule declares (a custom `employeeNumber`, `uidNumber`, or asset tag under
  `CollectAllProperties`) is passed straight through.

  This is a real gap, not a theoretical one, and it is not closed by simply
  redacting: replacing a number with a redaction string changes the leaf's JSON
  type, and the output has to stay BloodHound-loadable. Until it is closed,
  `shanon inspect` counts every occurrence as `undeclared-numeric-value` and
  lists the canonical paths under *numeric values passed through unchanged*.
  **Read that section before sending a collection anywhere**, and confirm the
  paths it names are ones you are willing to disclose.

## Before you send anything to an LLM

1. Send **only** the emitted `collection_anon.zip` / `collection_anon/` collection, never the
   parent output directory (it may hold the mapping file).
2. Confirm the run completed without a contextual verification abort.
3. Verify your engagement contract permits third-party LLM processing of
   pseudonymized data at all.

## Dependencies

shanon has a deliberately small dependency tree and pulls in nothing that can
open a socket. A `cargo deny` job runs on every pull request and weekly against
the RustSec advisory database, and also enforces licenses, banned crates, and
source-registry pinning. New dependencies are reviewed by hand.

## Supported versions

Only the latest release is supported. Fixes land on `main` and ship in the next
release; there are no backports to earlier tags.

## Reporting a vulnerability

A leak vector, meaning any real identifier that survives a run without
triggering a contextual verification abort, is a security bug, not a feature
request. Report it privately: open a GitHub security advisory (Security →
Report a vulnerability) rather than a public issue, and include a **synthetic** minimal
collection that reproduces the leak. Never attach real client data to a report.

Expect a first response within seven days.
