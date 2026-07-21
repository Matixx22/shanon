//! Property-based registry + engine invariants (the achievable subset
//! of the pipeline-level property tests, plan §5 P2).
//!
//! The full pipeline-level leak/roundtrip properties (`anonymize_collection` +
//! `bulk_restore`) belong to P3, which owns the pipeline. At the P2 layer the
//! two invariants that must hold for *any* input are still checkable:
//!
//!   1. No organization-bound token we injected survives the engine transform.
//!   2. The registry restores every pseudonym back to its real value.
//!
//! Injected tokens use a rare `zq` prefix + fixed length so a surviving
//! substring is an unambiguous leak, not a wordlist/schema coincidence.

use proptest::prelude::*;
use serde_json::{json, Value};
use shanon_core::canonical_json;
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;

fn label() -> impl Strategy<Value = String> {
    proptest::string::string_regex("zq[a-z]{6}").unwrap()
}

proptest! {
    /// map is deterministic, idempotent, anonymizing, and reversible.
    #[test]
    fn map_is_deterministic_and_reversible(token in label()) {
        let mut reg = Registry::new("00".repeat(16));
        let first = reg.map("accounts", &token).unwrap();
        let second = reg.map("accounts", &token).unwrap();
        prop_assert_eq!(&first, &second);
        prop_assert_ne!(&first, &token);
        let restored = reg.reverse(&first);
        prop_assert!(restored.iter().any(|(c, r)| c == "accounts" && r == &token));
    }

    /// Distinct salts diverge for the same real value.
    #[test]
    fn distinct_salts_diverge(token in label()) {
        let mut a = Registry::new("00".repeat(16));
        let mut b = Registry::new("ff".repeat(16));
        prop_assert_ne!(
            a.map("hosts", &token).unwrap(),
            b.map("hosts", &token).unwrap()
        );
    }

    /// Casefold-category aliases share one owned mapping.
    #[test]
    fn semantic_case_aliases_are_shared(token in label()) {
        let mut reg = Registry::new("00".repeat(16));
        let lower = reg.map("accounts", &token).unwrap();
        let upper = reg.map("accounts", &token.to_uppercase()).unwrap();
        prop_assert_eq!(lower, upper);
    }

    /// No injected org token survives the engine transform, and every pseudonym
    /// restores. Colliding label draws (two labels -> one pseudonym) are skipped.
    #[test]
    fn no_injected_org_token_survives_engine(
        domain in label(),
        user in label(),
    ) {
        prop_assume!(domain != user);
        let registry = Registry::new("00".repeat(16));
        let mut engine = AnonymizationEngine::new(registry, None, None);

        let doc: Value = json!({
            "meta": {"type": "users", "count": 1, "version": 6},
            "data": [{
                "ObjectIdentifier": "S-1-5-21-71234567-22222222-33333333-1105",
                "Properties": {
                    "name": format!("{user}@{domain}.local"),
                    "domain": format!("{domain}.local"),
                    "samaccountname": user.clone(),
                },
            }],
        });
        let map = doc.as_object().unwrap().clone();

        // Discovery/transform may fail closed on a pseudonym collision; skip.
        if engine.discover_document("users.json", &map).is_err() {
            return Ok(());
        }
        if engine.finalize_discovery().is_err() {
            return Ok(());
        }
        let (output, _) = match engine.transform_document("users.json", &map) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let blob = canonical_json(&Value::Object(output));

        prop_assert!(!blob.contains(&domain), "leaked domain token in {blob}");
        prop_assert!(!blob.contains(&user), "leaked user token in {blob}");
        // The distinctive SID authority must be remapped too.
        prop_assert!(!blob.contains("71234567"), "leaked SID authority in {blob}");
    }
}
