//! `engine` byte-parity against the committed ground-truth fixtures (plan module 8, P2).
//!
//! `engine_truth.json` was produced by running the reference
//! `AnonymizationEngine` over a crafted multi-node collection
//! (discover-all -> finalize -> transform-all, fixed salt). The Rust engine must
//! reproduce each transformed document byte-for-byte (canonical JSON defaults) and
//! the same audit summary.

use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};
use shanon_core::engine::{classify_object, normalize_node_type, AnonymizationEngine};
use shanon_core::canonical_json;
use shanon_core::registry::Registry;

fn parity(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity")
        .join(name)
}

fn obj(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn engine_transforms_match_reference_byte_for_byte() {
    let truth: Value =
        serde_json::from_slice(&fs::read(parity("engine_truth.json")).unwrap()).unwrap();
    let salt = truth["salt"].as_str().unwrap();
    let documents = truth["documents"].as_array().unwrap();

    let registry = Registry::new(salt);
    let mut engine = AnonymizationEngine::new(registry, None, None);

    // Discover every document, in order.
    for doc in documents {
        let member = doc["member"].as_str().unwrap();
        engine
            .discover_document(member, &obj(&doc["input"]))
            .unwrap();
    }
    engine.finalize_discovery().unwrap();

    // Transform every document and compare to the frozen expected bytes.
    for doc in documents {
        let member = doc["member"].as_str().unwrap();
        let expected = doc["expected_output"].as_str().unwrap();
        let (output, _records) = engine
            .transform_document(member, &obj(&doc["input"]))
            .unwrap();
        let got = canonical_json(&Value::Object(output));
        assert_eq!(got, expected, "byte mismatch for {member}");
    }

    // The audit summary must match too (order-independent object equality).
    let expected_audit = &truth["audit_summary"];
    assert_eq!(
        &engine.audit.summary(),
        expected_audit,
        "audit summary mismatch"
    );
}

#[test]
fn normalize_node_type_maps_known_and_unknown() {
    assert_eq!(
        normalize_node_type(Some(&Value::String("Users".into()))),
        "User"
    );
    assert_eq!(
        normalize_node_type(Some(&Value::String("FOREIGNSECURITYPRINCIPALS".into()))),
        "Base"
    );
    assert_eq!(
        normalize_node_type(Some(&Value::String("nonsense".into()))),
        "Unknown"
    );
    assert_eq!(normalize_node_type(None), "Unknown");
    assert_eq!(
        normalize_node_type(Some(&Value::from(7))),
        "Unknown",
        "non-string type is Unknown"
    );
}

#[test]
fn classify_object_scopes_wellknown_sid() {
    // The BUILTIN\\Administrators SID is a global catalog identity for a Group.
    let group: Value = serde_json::json!({
        "ObjectIdentifier": "S-1-5-32-544",
        "Properties": {"name": "ADMINISTRATORS@BUILTIN"}
    });
    let m = classify_object("Group", group.as_object().unwrap());
    assert!(m.is_some(), "well-known builtin SID should classify");

    // An unknown collection type never classifies.
    assert!(classify_object("Unknown", group.as_object().unwrap()).is_none());
}
