# Demo collection

`collection/` is a four-member SharpHound / BloodHound CE shaped collection
(`meta.version` 6). It backs the README's before/after example, and it is the
only collection any demo material for this project may be recorded against.

**Every byte of it is invented.** The domain is `CONTOSO.LOCAL`, Microsoft's
documentation placeholder; the domain SID is
`S-1-5-21-1111111111-2222222222-3333333333`; the accounts, hosts, groups and
descriptions were written for this file. It is not a redacted sample of a real
environment, because a redacted sample is precisely the thing this project
exists to argue you cannot produce by hand.

It is deliberately small and deliberately varied. It carries a kerberoastable
service account with an SPN, a built-in RID (500) and a built-in group (512)
that exercise the catalog's preserve-at-declared-paths rule, a custom group with
free-text prose in `description`, an unconstrained-delegation domain
controller, a session, cross-member ACEs and group memberships. That mix is what
makes a five-line README excerpt show something worth looking at.

Run it yourself:

```sh
cargo build --release
./target/release/shanon inspect   --input demo/collection
./target/release/shanon anonymize --input demo/collection --out demo/out
```

`demo/out/` is gitignored. Nothing in this directory should ever be replaced
with real collection data, including "just to check something quickly". Use a
path outside the repository for that.
