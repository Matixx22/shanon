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
use shanon_core::policy::PolicyConfig;
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

/// A numeric leaf at a path no rule declares is redacted to a sentinel, and
/// counted.
///
/// `engine::visit` returns booleans and nulls verbatim, and numbers verbatim
/// *only* where a rule declares the path. An undeclared number is
/// `--collectallproperties` spill: SharpHound's `BestGuessConvert` turns any
/// attribute whose value parses as an integer into a JSON number, so a custom
/// `employeeNumber` lands there. Publishing it hands over a re-identification
/// key, so it is replaced rather than passed through.
#[test]
fn undeclared_numeric_leaf_is_redacted_and_counted() {
    let doc: Value = serde_json::json!({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1104",
            "Properties": {
                "name": "ALICE@CONTOSO.LOCAL",
                // Declared: a schema numeric the policy models. Not counted.
                "whencreated": 1690104000,
                // Declared boolean. Not counted, and not a number anyway.
                "enabled": true,
                // Undeclared: no rule names this path. Redacted to a sentinel.
                "employeeNumber": 987654321,
                // Undeclared and already -1, so the sentinel must move to -2
                // rather than silently leaving the value as it found it.
                "customCounter": -1,
                // Undeclared float: the substitution has to stay type-stable,
                // or the output stops being loadable.
                "customRatio": 2.5
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
    // ...and its value is gone too. This is the assertion that matters: the
    // real number must appear nowhere in the serialized output.
    let rendered = serde_json::to_string(&output).unwrap();
    assert!(
        !rendered.contains("987654321"),
        "an undeclared numeric value survived into the output: {rendered}"
    );

    // Type-stable substitution, checked per source type.
    let numbers: Vec<&Value> = props.values().filter(|v| v.is_number()).collect();
    assert!(
        numbers.contains(&&Value::from(-1)),
        "employeeNumber should be the integer sentinel: {props:?}"
    );
    assert!(
        numbers.contains(&&Value::from(-2)),
        "a source of -1 must move to -2, not stay -1: {props:?}"
    );
    assert!(
        numbers
            .iter()
            .any(|v| v.as_f64() == Some(-1.0) && v.to_string().contains('.')),
        "a float must be replaced by a float, not an integer: {props:?}"
    );

    // Counting is unchanged, so `inspect` reports the same paths either way.
    let summary = engine.audit.summary();
    assert_eq!(
        summary["audit_codes"]["undeclared-numeric-value"],
        Value::from(3),
        "exactly the undeclared numerics are counted, not the declared ones"
    );
    let paths = summary["numeric_passthrough_paths"].as_object().unwrap();
    assert_eq!(paths.len(), 3);
    for path in paths.keys() {
        assert!(
            !path.contains("employeeNumber")
                && !path.contains("customCounter")
                && !path.contains("customRatio"),
            "audit path leaked the real key name: {path}"
        );
    }
}

/// The opt-out restores verbatim passthrough, and says so by leaving the value
/// in the clear. Kept adjacent to the test above so the two behaviors are read
/// together.
#[test]
fn the_opt_out_restores_numeric_passthrough() {
    let doc: Value = serde_json::json!({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1104",
            "Properties": {
                "name": "ALICE@CONTOSO.LOCAL",
                "employeeNumber": 987654321
            }
        }],
        "meta": {"type": "users", "count": 1, "version": 6}
    });
    let member = "users.json";

    let config = PolicyConfig {
        redact_undeclared_numbers: false,
        ..PolicyConfig::default()
    };
    let mut engine =
        AnonymizationEngine::new(Registry::new("0123456789abcdef"), Some(config), None);
    engine.discover_document(member, &obj(&doc)).unwrap();
    engine.finalize_discovery().unwrap();
    let (output, _records) = engine.transform_document(member, &obj(&doc)).unwrap();

    let rendered = serde_json::to_string(&output).unwrap();
    assert!(
        rendered.contains("987654321"),
        "the opt-out must restore verbatim passthrough: {rendered}"
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
