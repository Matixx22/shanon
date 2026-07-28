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
use shanon_core::canonical_json;
use shanon_core::engine::{classify_object, normalize_node_type, AnonymizationEngine};
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

/// Pins the numeric pass-through gap so it is a contract rather than an
/// accident, and so closing it has to be a deliberate change to this test.
///
/// `engine::visit` returns every non-string leaf verbatim before the policy is
/// consulted. For a declared path that is intended. For an undeclared one the
/// value is *not* anonymized — only its key is — and the only trace is the
/// audit counter asserted here. See SECURITY.md, "Numbers".
#[test]
fn undeclared_numeric_leaf_passes_through_and_is_counted() {
    let doc: Value = serde_json::json!({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1104",
            "Properties": {
                "name": "ALICE@CONTOSO.LOCAL",
                // Declared: a schema numeric the policy models. Not counted.
                "whencreated": 1690104000,
                // Declared boolean. Not counted, and not a number anyway.
                "enabled": true,
                // Undeclared: no rule names this path. Passed through in clear.
                "employeeNumber": 987654321
            }
        }],
        "meta": {"type": "users", "count": 1, "version": 6}
    });
    let member = "users.json";

    let mut engine = AnonymizationEngine::new(Registry::new("0123456789abcdef"), None, None);
    engine.discover_document(member, &obj(&doc)).unwrap();
    engine.finalize_discovery().unwrap();
    let (output, _records) = engine.transform_document(member, &obj(&doc)).unwrap();

    let props = output["data"][0]["Properties"].as_object().unwrap();

    // The declared numeric and boolean survive under their own key names.
    assert_eq!(props["whencreated"], Value::from(1690104000));
    assert_eq!(props["enabled"], Value::from(true));

    // The undeclared key is mapped, so it is not `employeeNumber` any more...
    assert!(
        !props.contains_key("employeeNumber"),
        "an undeclared key must be anonymized"
    );
    // ...but its value is somewhere in the output, verbatim. That is the gap.
    assert!(
        props.values().any(|v| v.as_u64() == Some(987654321)),
        "undeclared numeric leaf is currently passed through unchanged; \
         if this now fails because it is redacted, that is the fix landing — \
         update SECURITY.md's \"Numbers\" section and the README caveat"
    );

    // And it is counted, with a path that names no real key.
    let summary = engine.audit.summary();
    assert_eq!(
        summary["audit_codes"]["undeclared-numeric-value"],
        Value::from(1),
        "exactly the undeclared numeric is counted, not the declared ones"
    );
    let paths = summary["numeric_passthrough_paths"].as_object().unwrap();
    assert_eq!(paths.len(), 1);
    let path = paths.keys().next().unwrap();
    assert!(
        !path.contains("employeeNumber"),
        "audit path leaked the real key name: {path}"
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
