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
  label, a collision-safe path, a policy code, and an offender fingerprint —
  never the original secret or the source filename. Policy audit summaries
  contain counts and canonical paths, not source values.
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
  default — do not remove those rules. Version-1 maps remain loadable; newly
  saved version-2 maps add typed namespaces and policy metadata but are no less
  sensitive.
- **Correlation through a reused map.** `--reuse-map` keeps pseudonyms stable
  across collections, and that stability *is* linkage: any real value present in
  two collections receives the same pseudonym in both. Reusing one map across
  separate engagements therefore lets anything downstream — including the LLM's
  context window — tie those engagements together. Use one map per engagement
  unless you specifically want the collections linked.
- **Your prompt.** shanon scrubs the collection, not the sentences you type
  around it. Do not paste real names into the chat yourself.
- **Policy overrides.** The default CLI does not support raw substring, vendor,
  or unscoped name exemptions. Do not patch around a verification failure with
  a global allowlist; preservation requires exact catalog evidence for the node
  type, field path, identifier, and value.
- **Unknown collector fields.** Unknown strings are conservatively classified by
  shape and otherwise replaced as opaque values, with their canonical paths
  counted in the audit. If a new structure cannot be handled without preserving
  confidentiality and schema shape, the run fails rather than publishing it.

## Before you send anything to an LLM

1. Send **only** the emitted `collection_anon.zip` / `collection_anon/` collection — never the
   parent output directory (it may hold the mapping file).
2. Confirm the run completed without a contextual verification abort.
3. Verify your engagement contract permits third-party LLM processing of
   pseudonymized data at all.

## Dependencies

shanon has a deliberately small dependency tree and pulls in nothing that can
open a socket. A `cargo audit` job runs on every pull request and weekly against
the RustSec advisory database; new dependencies are reviewed by hand.

## Supported versions

Only the latest release is supported. Fixes land on `main` and ship in the next
release; there are no backports to earlier tags.

## Reporting a vulnerability

A leak vector — any real identifier that survives a run without triggering a
contextual verification abort — is a security bug, not a feature request. Report
it privately: open a GitHub security advisory (Security → Report a
vulnerability) rather than a public issue, and include a **synthetic** minimal
collection that reproduces the leak. Never attach real client data to a report.

Expect a first response within seven days.
