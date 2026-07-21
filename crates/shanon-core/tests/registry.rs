//! `registry` correctness + interop parity (plan module 7, P2).
//!
//! `seed_and_generation_match_reference` pins the frozen seed contract (§3.1a):
//! pseudonyms must be byte-identical to the committed ground-truth for a fixture
//! set. `save_bytes_match_reference_interop` pins the frozen §3.3 file format:
//! load the committed `seed.map.json`, extend it, and assert the serialized bytes
//! equal the expected output in `seed_extended.expected.json`.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::registry::{normalize_mapping_identity, Registry, RegistryError};

fn parity(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity")
        .join(name)
}

/// The exact ordered operations the reference fixture generator replayed.
const OPS: &[(&str, &str)] = &[
    ("domains", "corp.local"),
    ("domains", "acme.example"),
    ("accounts", "Alice"),
    ("accounts", "administrator"),
    ("hosts", "DC01"),
    ("sids", "S-1-5-21-1111111111-2222222222-3333333333"),
    ("guids", "12345678-1234-1234-1234-123456789abc"),
    ("cert_templates", "WebServer"),
    ("oids", "1.2.3.4"),
    ("opaque", "secretvalue"),
];

#[test]
fn seed_and_generation_match_reference() {
    let truth: Value =
        serde_json::from_slice(&fs::read(parity("registry_seed_truth.json")).unwrap()).unwrap();
    let salt = truth["salt"].as_str().unwrap();
    let mut reg = Registry::new(salt);
    for row in truth["rows"].as_array().unwrap() {
        let category = row["category"].as_str().unwrap();
        let real = row["real"].as_str().unwrap();
        let expected = row["pseudonym"].as_str().unwrap();
        let got = reg.map(category, real).unwrap();
        assert_eq!(got, expected, "pseudonym mismatch for {category} {real}");
    }
}

#[test]
fn save_bytes_match_reference_interop() {
    // Load the reference-written seed map (frozen §3.3 format).
    let seed = Registry::load(&parity("seed.map.json")).unwrap();
    assert_eq!(seed.salt, "0123456789abcdef0123456789abcdef");

    let mut reg = seed;
    for (category, real) in OPS {
        reg.map(category, real).unwrap();
    }
    let got = reg.save_to_string(&"0".repeat(64), "2026-07-21T00:00:00+00:00", None);
    let expected = fs::read_to_string(parity("seed_extended.expected.json")).unwrap();
    assert_eq!(
        got, expected,
        "Rust save bytes must equal the reference save bytes"
    );
}

#[test]
fn rust_written_file_reloads_consistently() {
    // Rust writes, Rust reloads: pseudonyms are stable across the file boundary.
    let mut reg = Registry::new("00".repeat(16));
    let mut expected = Vec::new();
    for (category, real) in OPS {
        expected.push(reg.map(category, real).unwrap());
    }
    let bytes = reg.save_to_string("deadbeef", "2026-01-01T00:00:00+00:00", None);
    let value: Value = serde_json::from_str(&bytes).unwrap();
    let mut reloaded = Registry::from_value(&value).unwrap();
    for ((category, real), want) in OPS.iter().zip(&expected) {
        assert_eq!(reloaded.map(category, real).unwrap(), *want);
    }
}

// ---------------------------------------------------------------------------
// Hardening tests.
// ---------------------------------------------------------------------------

#[test]
fn map_is_stable_within_instance() {
    let mut reg = Registry::new("00".repeat(16));
    let first = reg.map("accounts", "svc-backup").unwrap();
    let second = reg.map("accounts", "svc-backup").unwrap();
    assert_eq!(first, second);
    assert_ne!(first, "svc-backup");
}

#[test]
fn semantic_case_aliases_share_one_owned_mapping() {
    let mut reg = Registry::new("00".repeat(16));
    let lower = reg.map("accounts", "alice").unwrap();
    let upper = reg.map("accounts", "ALICE").unwrap();
    assert_eq!(lower, upper);
    // The canonical (lowercase) spelling wins ownership.
    assert_eq!(
        reg.forward("alice"),
        vec![("accounts".to_string(), lower.clone())]
    );
    assert_eq!(
        reg.reverse(&lower),
        vec![("accounts".to_string(), "alice".to_string())]
    );
}

#[test]
fn map_differs_by_real_value() {
    let mut reg = Registry::new("00".repeat(16));
    assert_ne!(
        reg.map("accounts", "alice").unwrap(),
        reg.map("accounts", "bob").unwrap()
    );
}

#[test]
fn typed_namespaces_do_not_alias_equal_source_strings() {
    let mut reg = Registry::new("00".repeat(16));
    let account = reg.map("accounts", "value").unwrap();
    let opaque = reg.map("opaque", "value").unwrap();
    assert_ne!(account, opaque);
}

#[test]
fn same_salt_same_pseudonym() {
    let mut a = Registry::new("00".repeat(16));
    let mut b = Registry::new("00".repeat(16));
    assert_eq!(
        a.map("hosts", "dc01").unwrap(),
        b.map("hosts", "dc01").unwrap()
    );
}

#[test]
fn distinct_salts_diverge() {
    let mut a = Registry::new("00".repeat(16));
    let mut b = Registry::new("11".repeat(16));
    assert_ne!(
        a.map("hosts", "dc01").unwrap(),
        b.map("hosts", "dc01").unwrap()
    );
}

#[test]
fn fqdn_pseudonym_preserves_safe_suffix_and_shape() {
    let mut reg = Registry::new("00".repeat(16));
    let mapped = reg.map("domains", "corp.local").unwrap();
    assert!(mapped.ends_with(".local"), "{mapped}");
    assert!(mapped.contains('-'));
}

#[test]
fn custom_fqdn_suffix_is_replaced_with_safe_suffix() {
    let mut reg = Registry::new("00".repeat(16));
    let mapped = reg.map("domains", "corp.example.org").unwrap();
    // "org" is not a registry-safe suffix -> forced to ".local".
    assert!(mapped.ends_with(".local"), "{mapped}");
}

#[test]
fn bare_domain_label_remains_bare() {
    let mut reg = Registry::new("00".repeat(16));
    let mapped = reg.map("domains", "corp").unwrap();
    assert!(!mapped.contains('.'), "{mapped}");
}

#[test]
fn custom_oid_maps_to_valid_uuid_oid() {
    let mut reg = Registry::new("00".repeat(16));
    let mapped = reg.map("oids", "1.3.6.1.4.1.311.20.2").unwrap();
    assert!(mapped.starts_with("2.25."), "{mapped}");
}

#[test]
fn unknown_category_is_rejected() {
    let mut reg = Registry::new("00".repeat(16));
    assert!(matches!(
        reg.map("bogus", "x"),
        Err(RegistryError::Value(_))
    ));
}

#[test]
fn constructor_rejects_identity_self_mapping() {
    let mut cats = indexmap_categories(&[("accounts", &[("alice", "alice")])]);
    let err =
        Registry::build("00".repeat(16), Some(std::mem::take(&mut cats)), 2, None).unwrap_err();
    assert!(matches!(err, RegistryError::UnsafeMapping(_)), "{err:?}");
}

#[test]
fn constructor_rejects_duplicate_pseudonym_ownership() {
    let cats = indexmap_categories(&[(
        "accounts",
        &[("alice", "shared-fake"), ("bob", "shared-fake")],
    )]);
    let err = Registry::build("00".repeat(16), Some(cats), 2, None).unwrap_err();
    assert!(
        matches!(err, RegistryError::PseudonymCollision(_)),
        "{err:?}"
    );
}

#[test]
fn constructor_rejects_divergent_preloaded_semantic_aliases() {
    let cats =
        indexmap_categories(&[("accounts", &[("alice", "fake-one"), ("ALICE", "fake-two")])]);
    let err = Registry::build("00".repeat(16), Some(cats), 2, None).unwrap_err();
    assert!(matches!(err, RegistryError::UnsafeMapping(_)), "{err:?}");
}

#[test]
fn frozen_registry_resolves_existing_without_allocation() {
    let mut reg = Registry::new("00".repeat(16));
    let mapped = reg.map("accounts", "alice").unwrap();
    reg.freeze().unwrap();
    assert_eq!(reg.map("accounts", "alice").unwrap(), mapped);
    // A case alias of an already-owned source resolves without allocation.
    assert_eq!(reg.map("accounts", "ALICE").unwrap(), mapped);
}

#[test]
fn frozen_registry_rejects_missing_mapping() {
    let mut reg = Registry::new("00".repeat(16));
    reg.map("accounts", "alice").unwrap();
    reg.freeze().unwrap();
    assert!(matches!(
        reg.map("accounts", "bob"),
        Err(RegistryError::Frozen(_))
    ));
}

#[test]
fn sid_subauthority_avoids_source_terminal() {
    let reg = Registry::new("00".repeat(16));
    let source = "S-1-5-21-1-2-3-1400";
    let sub = reg.sid_subauthority(source);
    assert_ne!(sub, "1400");
    let n: u128 = sub.parse().unwrap();
    assert!((1_000_000..=0xFFFF_FFFF).contains(&n));
    // Deterministic.
    assert_eq!(reg.sid_subauthority(source), sub);
}

#[test]
fn bind_requires_explicit_sid_intent() {
    let mut reg = Registry::new("00".repeat(16));
    let err = reg
        .bind("sids", "S-1-5-21-1-2-3-100", "S-1-5-21-9-9-9-200", None)
        .unwrap_err();
    assert!(matches!(err, RegistryError::Value(_)), "{err:?}");
}

#[test]
fn bind_preserved_terminal_must_match() {
    let mut reg = Registry::new("00".repeat(16));
    // preserve_terminal=true but the terminal differs -> unsafe.
    let err = reg
        .bind(
            "sids",
            "S-1-5-21-1-2-3-100",
            "S-1-5-21-9-9-9-200",
            Some(true),
        )
        .unwrap_err();
    assert!(matches!(err, RegistryError::UnsafeMapping(_)), "{err:?}");
}

#[test]
fn legacy_reverse_alias_from_v1_sid_map_is_reserved() {
    // v1 stored the domain triplet as the key and a full domain SID as value.
    let cats = indexmap_categories(&[(
        "sids",
        &[
            ("100-200-300", "S-1-5-21-11-22-33"),
            ("100-200-300-1105-2205", "S-1-5-21-11-22-33-4405"),
        ],
    )]);
    let reg = Registry::build("00".repeat(16), Some(cats), 1, None).unwrap();
    // The multi-RID descendant becomes a legacy reverse alias, restorable.
    let restored = reg.reverse("S-1-5-21-11-22-33-4405");
    assert!(
        restored.iter().any(|(c, _)| c == "sids"),
        "legacy alias not reserved: {restored:?}"
    );
}

#[test]
fn normalize_guid_canonicalizes_braces_and_case() {
    assert_eq!(
        normalize_mapping_identity("guids", "{ABCDEF01-2345-6789-ABCD-EF0123456789}"),
        normalize_mapping_identity("guids", "abcdef01-2345-6789-abcd-ef0123456789"),
    );
}

#[test]
fn normalize_oid_strips_leading_zeros() {
    assert_eq!(normalize_mapping_identity("oids", "1.02.003"), "1.2.3");
}

// ---------------------------------------------------------------------------

fn indexmap_categories(
    spec: &[(&str, &[(&str, &str)])],
) -> indexmap::IndexMap<String, indexmap::IndexMap<String, String>> {
    let mut cats = indexmap::IndexMap::new();
    for (category, pairs) in spec {
        let mut bucket = indexmap::IndexMap::new();
        for (real, pseudonym) in *pairs {
            bucket.insert((*real).to_string(), (*pseudonym).to_string());
        }
        cats.insert((*category).to_string(), bucket);
    }
    cats
}
