//! `catalog` validated against committed ground truth
//! (`tests/truth/catalog.json`).
//!
//! Every catalog row is compared value-for-value in a canonical (sorted) form,
//! plus the `match_catalog` / `classify_sid` / `is_core_constant` checks and the
//! catalog behavioral assertions below.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use shanon_core::catalog::{
    catalog, classify_sid, is_core_constant, match_catalog, CatalogEntry, IdentifierKind,
    PrivacyClass, CATALOG_VERSION,
};

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn kind_of(s: &str) -> IdentifierKind {
    match s {
        "sid" => IdentifierKind::Sid,
        "rid" => IdentifierKind::Rid,
        "guid" => IdentifierKind::Guid,
        "wkguid" => IdentifierKind::Wkguid,
        "oid" => IdentifierKind::Oid,
        "template" => IdentifierKind::Template,
        "name" => IdentifierKind::Name,
        other => panic!("unknown kind {other}"),
    }
}

/// Canonicalize a Rust entry into the same shape the ground-truth fixtures use.
fn canonical_entry(entry: &CatalogEntry) -> Value {
    let mut preserve: Vec<String> = entry.preserve_paths.clone();
    preserve.sort();
    let mut exact: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, values) in &entry.exact_values {
        exact.insert(path.clone(), values.iter().cloned().collect());
    }
    let mut node_types: Vec<String> = entry.node_types.iter().cloned().collect();
    node_types.sort();
    json!({
        "kind": entry.kind.as_str(),
        "value": entry.value,
        "node_types": node_types,
        "privacy": entry.privacy.as_str(),
        "preserve_paths": preserve,
        "exact_values": exact,
        "source": entry.source,
    })
}

#[test]
fn catalog_version_matches_reference() {
    let t = truth("catalog.json");
    assert_eq!(
        CATALOG_VERSION as u64,
        t["catalog_version"].as_u64().unwrap()
    );
    assert_eq!(catalog().len() as u64, t["entry_count"].as_u64().unwrap());
}

#[test]
fn every_catalog_entry_matches_reference() {
    let t = truth("catalog.json");
    let expected = t["entries"].as_object().unwrap();

    // Same set of rule_ids.
    let mut got_ids: Vec<&str> = catalog().iter().map(|e| e.rule_id.as_str()).collect();
    got_ids.sort_unstable();
    let mut want_ids: Vec<&str> = expected.keys().map(String::as_str).collect();
    want_ids.sort_unstable();
    assert_eq!(got_ids, want_ids, "catalog rule_id set diverged");

    // Same content per rule_id (order-independent, canonicalized).
    for entry in catalog() {
        let want = &expected[&entry.rule_id];
        assert_eq!(
            &canonical_entry(entry),
            want,
            "catalog entry {} diverged",
            entry.rule_id
        );
    }
}

/// A malformed GUID in the catalog is a silently dead row, not a typo.
///
/// A catalog match requires the exact normalized value, so nothing can ever
/// equal a GUID that is a digit short: the real identifier falls through to the
/// `guids` namespace and loses its meaning to the model, while the stored value
/// is unreachable as a `Guid` kind because it cannot match `guid_re` either.
/// Nothing fails, nothing warns — which is exactly why this needs a test.
/// The reference shipped one such row (User-Change-Password); shanon does not.
#[test]
fn access_right_guids_are_well_formed() {
    let groups = [8usize, 4, 4, 4, 12];
    for entry in catalog() {
        if entry.kind != IdentifierKind::Guid {
            continue;
        }
        let parts: Vec<&str> = entry.value.split('-').collect();
        assert_eq!(
            parts.len(),
            groups.len(),
            "catalog entry {} has a GUID with {} group(s): {}",
            entry.rule_id,
            parts.len(),
            entry.value
        );
        for (part, want) in parts.iter().zip(groups) {
            assert_eq!(
                part.len(),
                want,
                "catalog entry {} has a malformed GUID (group {part:?} is {} chars, want {want}): {}",
                entry.rule_id,
                part.len(),
                entry.value
            );
            assert!(
                part.bytes().all(|b| b.is_ascii_hexdigit()),
                "catalog entry {} has a non-hex GUID group {part:?}: {}",
                entry.rule_id,
                entry.value
            );
        }
    }
}

#[test]
fn classify_sid_matches_reference() {
    for pair in truth("catalog.json")["classify_sid"].as_array().unwrap() {
        let sid = pair[0].as_str().unwrap();
        let want = pair[1].as_str().unwrap();
        assert_eq!(classify_sid(sid).as_str(), want, "classify_sid({sid})");
    }
}

#[test]
fn match_catalog_matches_reference() {
    for case in truth("catalog.json")["match_catalog"].as_array().unwrap() {
        let node_type = case["node_type"].as_str().unwrap();
        let kind = kind_of(case["kind"].as_str().unwrap());
        let value = case["value"].as_str().unwrap();
        let got = match_catalog(node_type, kind, value);
        match (&got, &case["match"]) {
            (None, Value::Null) => {}
            (Some(m), want) if want.is_object() => {
                assert_eq!(m.entry.rule_id, want["rule_id"].as_str().unwrap());
                assert_eq!(m.entry.privacy.as_str(), want["privacy"].as_str().unwrap());
                assert_eq!(
                    m.normalized_value,
                    want["normalized_value"].as_str().unwrap()
                );
            }
            _ => panic!(
                "match_catalog({node_type},{value}) mismatch: {got:?} vs {}",
                case["match"]
            ),
        }
    }
}

#[test]
fn is_core_constant_matches_reference() {
    for case in truth("catalog.json")["is_core_constant"]
        .as_array()
        .unwrap()
    {
        let node_type = case["node_type"].as_str().unwrap();
        let kind = kind_of(case["kind"].as_str().unwrap());
        let identifier = case["identifier"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let value = case["value"].as_str();
        let want = case["result"].as_bool().unwrap();
        assert_eq!(
            is_core_constant(node_type, kind, identifier, path, value),
            want,
            "is_core_constant({node_type},{identifier},{path},{value:?})"
        );
    }
}

// --- catalog behavioral assertions ------------------------------------------

#[test]
fn default_domain_policy_guid_requires_gpo_context() {
    let guid = "31b2f340-016d-11d2-945f-00c04fb984f9";
    let m = match_catalog("GPO", IdentifierKind::Guid, guid).expect("GPO match");
    assert_eq!(m.entry.privacy, PrivacyClass::CoreGlobalDefault);
    assert!(match_catalog("User", IdentifierKind::Guid, guid).is_none());
}

#[test]
fn core_sids_are_baseline_safe() {
    for sid in ["S-1-1-0", "S-1-5-18", "S-1-5-32-544"] {
        assert_eq!(classify_sid(sid), PrivacyClass::CoreGlobalDefault, "{sid}");
    }
}

#[test]
fn feature_sids_are_not_baseline_safe() {
    for sid in [
        "S-1-5-32-568",
        "S-1-5-32-574",
        "S-1-5-32-578",
        "S-1-5-32-582",
        "S-1-5-32-585",
    ] {
        assert_eq!(
            classify_sid(sid),
            PrivacyClass::MicrosoftFeatureDefault,
            "{sid}"
        );
    }
}

#[test]
fn name_without_identifier_evidence_never_matches() {
    assert!(match_catalog("Group", IdentifierKind::Name, "Hyper-V Administrators").is_none());
    assert!(match_catalog("Group", IdentifierKind::Name, "Vault Administrators").is_none());
}

#[test]
fn builtin_template_name_requires_template_context() {
    let m = match_catalog("CertTemplate", IdentifierKind::Template, "User").expect("match");
    assert_eq!(m.entry.privacy, PrivacyClass::CoreGlobalDefault);
    assert!(match_catalog("Group", IdentifierKind::Template, "User").is_none());
}

#[test]
fn enterprise_oid_is_not_treated_as_standard() {
    assert!(match_catalog(
        "IssuancePolicy",
        IdentifierKind::Oid,
        "1.3.6.1.4.1.311.999.1"
    )
    .is_none());
}

#[test]
fn identifier_match_does_not_permit_a_different_identifier() {
    let m = match_catalog("Group", IdentifierKind::Sid, "S-1-5-32-544").expect("match");
    assert!(!m.permits("ObjectIdentifier", "S-1-5-32-545"));
}

// --- derived predicates against ground truth -------------------------------

// The derivations, not the rows: which SIDs count as baseline-safe, which names
// are canonical, which RIDs are core, which GUIDs are fixed. The row-for-row
// comparison above cannot catch a derivation that drifts, and each predicate
// normalizes its own argument, so the spellings in the fixture exercise that
// too.
#[test]
fn derived_predicates_match_reference() {
    use shanon_core::catalog::{
        is_builtin_name, is_builtin_rid, is_wellknown_guid, is_wellknown_sid,
    };
    let t = truth("wellknown.json");

    for p in t["sids"].as_array().unwrap() {
        assert_eq!(
            is_wellknown_sid(p[0].as_str().unwrap()),
            p[1].as_bool().unwrap(),
            "sid {}",
            p[0]
        );
    }
    for p in t["names"].as_array().unwrap() {
        assert_eq!(
            is_builtin_name(p[0].as_str().unwrap()),
            p[1].as_bool().unwrap(),
            "name {}",
            p[0]
        );
    }
    for p in t["rids"].as_array().unwrap() {
        assert_eq!(
            is_builtin_rid(p[0].as_i64().unwrap()),
            p[1].as_bool().unwrap(),
            "rid {}",
            p[0]
        );
    }
    for p in t["guids"].as_array().unwrap() {
        assert_eq!(
            is_wellknown_guid(p[0].as_str().unwrap()),
            p[1].as_bool().unwrap(),
            "guid {}",
            p[0]
        );
    }
}
