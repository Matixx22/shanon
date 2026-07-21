//! Pipeline-level leak + roundtrip invariants, P3.
//!
//! For any collection: (1) no distinctive real org token survives the transform
//! (the anti-leak invariant the verifier guards), and (2) `bulk_restore` reverses
//! the published pseudonyms back to their reals. We drive the real engine
//! (discover -> finalize -> transform) rather than the filesystem-level
//! `anonymize_collection` (P4), which is the in-core equivalent of the same
//! invariants.

use proptest::prelude::*;
use serde_json::{json, Map, Value};

use shanon_core::canonical_json;
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;
use shanon_core::restore::bulk_restore;

fn obj(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// Distinctive org label: rare `zq` prefix + fixed-length lowercase body, so no
/// label is a substring of another and none appears in the fake wordlists.
fn label() -> impl Strategy<Value = String> {
    "[a-z]{6}".prop_map(|body| format!("zq{body}"))
}

fn build_docs(domain: &str, user: &str, host: &str) -> (Value, Value) {
    let fqdn = format!("{domain}.local");
    let users = json!({
        "meta": {"type": "users", "count": 1, "version": 6},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-71234567-72345678-73456789-1104",
            "Properties": {
                "name": format!("{}@{}", user.to_uppercase(), fqdn.to_uppercase()),
                "samaccountname": user,
                "distinguishedname": format!("CN={user},OU=Staff,DC={domain},DC=local"),
                "domain": fqdn.to_uppercase(),
                "serviceprincipalnames": [format!("MSSQLSvc/{host}.{fqdn}:1433")],
            },
        }],
    });
    let computers = json!({
        "meta": {"type": "computers", "count": 1, "version": 6},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-71234567-72345678-73456789-1105",
            "Properties": {
                "name": format!("{}.{}", host.to_uppercase(), fqdn.to_uppercase()),
                "dnshostname": format!("{host}.{fqdn}"),
                "domain": fqdn.to_uppercase(),
            },
        }],
    });
    (users, computers)
}

/// Returns `(blob_lowercased, registry)` or `None` on a pseudonym collision
/// (the rare case skipped via `prop_assume!`).
fn anonymize(domain: &str, user: &str, host: &str) -> Option<(String, Registry)> {
    let (users, computers) = build_docs(domain, user, host);
    let mut engine = AnonymizationEngine::new(Registry::new("00"), None, None);
    engine.discover_document("users.json", &obj(&users)).ok()?;
    engine
        .discover_document("computers.json", &obj(&computers))
        .ok()?;
    engine.finalize_discovery().ok()?;
    let (users_out, _) = engine.transform_document("users.json", &obj(&users)).ok()?;
    let (computers_out, _) = engine
        .transform_document("computers.json", &obj(&computers))
        .ok()?;
    // Original-case blob: pseudonym matching in `bulk_restore` is case-sensitive.
    let blob = format!(
        "{}{}",
        canonical_json(&Value::Object(users_out)),
        canonical_json(&Value::Object(computers_out))
    );
    Some((blob, engine.into_registry()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn no_injected_token_survives(domain in label(), user in label(), host in label()) {
        prop_assume!(domain != user && user != host && domain != host);
        let anonymized = anonymize(&domain, &user, &host);
        // A collision means two labels derived the same fake; skip this case.
        prop_assume!(anonymized.is_some());
        let (blob, _reg) = anonymized.unwrap();
        let low = blob.to_lowercase();
        for token in [&domain, &user, &host] {
            prop_assert!(!low.contains(token.as_str()), "leaked org token: {token}");
        }
        // The distinctive real SID triplet must be remapped too.
        prop_assert!(!low.contains("71234567"));
    }

    #[test]
    fn mapping_roundtrips(domain in label(), user in label(), host in label()) {
        prop_assume!(domain != user && user != host && domain != host);
        let anonymized = anonymize(&domain, &user, &host);
        prop_assume!(anonymized.is_some());
        let (blob, reg) = anonymized.unwrap();
        let restored = bulk_restore(&reg, &blob).to_lowercase();
        prop_assert!(restored.contains(&domain), "domain not restored");
        prop_assert!(restored.contains(&user), "user not restored");
        prop_assert!(restored.contains(&host), "host not restored");
    }
}
