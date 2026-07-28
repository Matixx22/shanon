//! Standard SharpHound fields whose *key names* must survive a run.
//!
//! A key no rule declares is organization-bound by assumption: a custom AD
//! attribute leaks in its name as surely as in its contents, so `is_known_key`
//! maps unknown keys through the opaque namespace. That default is correct, but
//! it also caught a handful of fields every collector emits — `IsDeleted`,
//! `IsACLProtected`, `Properties.whencreated`, and the `FailureReason` sibling
//! of every `Collected` flag — because the rule table never declared them. Those
//! came back renamed, so the output was not a SharpHound document even though
//! no graph edge depended on them.
//!
//! Declaring them is only safe because the schema rules are type-gated
//! (`resolve_schema`): a `schema.boolean.*` rule preserves `Value::Bool` and
//! nothing else, a `schema.numeric.*` rule preserves `Value::Number` and nothing
//! else, and anything that does not match falls through to `ReplaceOpaque`. The
//! last test here is the one that matters — it pins that a string smuggled into
//! a boolean path is still redacted, so declaring these paths widened the
//! schema without widening what can escape.
//!
//! All fixtures are synthetic.

use serde_json::{json, Map, Value};
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;
use shanon_core::verify::verify_document_with_progress;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

fn obj(value: Value) -> Map<String, Value> {
    value.as_object().expect("object fixture").clone()
}

/// Discover, transform and independently verify one collection, mirroring
/// `ingestor_shapes.rs` — these fixtures must clear the leak gate, not merely
/// survive the transform.
fn anonymize(document: Map<String, Value>) -> Value {
    let mut engine = AnonymizationEngine::new(Registry::new("test-salt"), None, None);
    let name = "member-00000.json";

    engine
        .discover_document(name, &document)
        .expect("discovery");
    let context = engine.finalize_discovery().expect("finalize");

    let (output, records) = engine
        .transform_document(name, &document)
        .expect("transform");
    let findings = verify_document_with_progress(
        name,
        &document,
        &output,
        &records,
        &mut engine.registry,
        &context,
        None,
    );
    assert!(
        findings.is_empty(),
        "{name} failed the leak gate: {findings:?}"
    );
    Value::Object(output)
}

/// A CE-shaped computer carrying every field this file is about.
fn computers(is_deleted: Value, whencreated: Value, failure_reason: Value) -> Map<String, Value> {
    obj(json!({
        "data": [{
            "Properties": {
                "domain": DOMAIN,
                "name": format!("DC01.{DOMAIN}"),
                "distinguishedname": "CN=DC01,OU=Domain Controllers,DC=SOUTHRIDGE,DC=LOCAL",
                "domainsid": DOMAIN_SID,
                "samaccountname": "DC01$",
                "whencreated": whencreated,
            },
            "ObjectIdentifier": format!("{DOMAIN_SID}-1000"),
            "PrimaryGroupSID": format!("{DOMAIN_SID}-516"),
            "Sessions": {
                "Collected": true,
                "FailureReason": Value::Null,
                "Results": [],
            },
            "LocalGroups": [{
                "ObjectIdentifier": format!("{DOMAIN_SID}-1000-544"),
                "Name": format!("ADMINISTRATORS@DC01.{DOMAIN}"),
                "Collected": false,
                "FailureReason": failure_reason,
                "Results": [],
                "LocalNames": [],
            }],
            "Aces": [],
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "IsDeleted": is_deleted,
            "IsACLProtected": false,
        }],
        "meta": {"methods": 46067, "type": "computers", "count": 1, "version": 6},
    }))
}

fn node(doc: &Value) -> &Value {
    doc.pointer("/data/0").expect("first data object")
}

/// The headline guarantee: every one of these keys reaches the output under its
/// own name. A regression here renames a standard field and the result stops
/// being a SharpHound document.
#[test]
fn standard_field_names_survive_a_run() {
    let out = anonymize(computers(json!(false), json!(1600000000), Value::Null));
    let node = node(&out);

    for pointer in [
        "/IsDeleted",
        "/IsACLProtected",
        "/Properties/whencreated",
        "/Sessions/Collected",
        "/Sessions/FailureReason",
        "/LocalGroups/0/Collected",
        "/LocalGroups/0/FailureReason",
    ] {
        assert!(
            node.pointer(pointer).is_some(),
            "{pointer} did not survive under its own name"
        );
    }
}

/// Structural values pass through verbatim; they carry no organization-bound
/// information and the graph reads them.
#[test]
fn structural_values_are_preserved_verbatim() {
    let out = anonymize(computers(json!(true), json!(1600000000), Value::Null));
    let node = node(&out);

    assert_eq!(node.pointer("/IsDeleted"), Some(&json!(true)));
    assert_eq!(node.pointer("/IsACLProtected"), Some(&json!(false)));
    assert_eq!(node.pointer("/Sessions/Collected"), Some(&json!(true)));
    assert_eq!(
        node.pointer("/LocalGroups/0/Collected"),
        Some(&json!(false))
    );
    assert_eq!(
        node.pointer("/Properties/whencreated"),
        Some(&json!(1600000000))
    );
}

/// A populated `FailureReason` routinely names the host that refused, so the
/// key is declared but the value is opaque — never preserved.
#[test]
fn failure_reason_text_is_redacted() {
    let reason = "Failed to connect to DC01.SOUTHRIDGE.LOCAL: access denied";
    let out = anonymize(computers(json!(false), json!(1600000000), json!(reason)));
    let node = node(&out);

    let value = node
        .pointer("/LocalGroups/0/FailureReason")
        .and_then(Value::as_str)
        .expect("FailureReason survived as a string");
    assert_ne!(value, reason, "the failure text passed through in clear");
    assert!(
        !value.contains("DC01") && !value.contains("SOUTHRIDGE"),
        "the failure text leaked an identifier: {value}"
    );

    // A null one is a null one — the collector's "nothing went wrong".
    assert_eq!(node.pointer("/Sessions/FailureReason"), Some(&Value::Null));
}

/// The reason declaring these paths is safe. `resolve_schema` type-gates every
/// schema rule, so a string at a boolean path does not inherit the boolean's
/// preservation — it falls through to `ReplaceOpaque` like any other unmodeled
/// string. Deleting the type gate must fail here, not in an engagement.
#[test]
fn a_string_at_a_boolean_path_is_still_redacted() {
    let smuggled = "CONTOSO-SECRET-HOSTNAME";
    let out = anonymize(computers(json!(smuggled), json!(1600000000), Value::Null));
    let node = node(&out);

    let value = node
        .pointer("/IsDeleted")
        .and_then(Value::as_str)
        .expect("the smuggled string stayed a string");
    assert_ne!(
        value, smuggled,
        "a string at a schema.boolean path was preserved verbatim"
    );
    assert!(
        !value.contains("CONTOSO"),
        "a string at a schema.boolean path leaked: {value}"
    );
}

/// The same gate on the numeric side.
#[test]
fn a_string_at_a_numeric_path_is_still_redacted() {
    let smuggled = "CONTOSO-SECRET-TIMESTAMP";
    let out = anonymize(computers(json!(false), json!(smuggled), Value::Null));
    let node = node(&out);

    let value = node
        .pointer("/Properties/whencreated")
        .and_then(Value::as_str)
        .expect("the smuggled string stayed a string");
    assert_ne!(
        value, smuggled,
        "a string at a schema.numeric path was preserved verbatim"
    );
    assert!(
        !value.contains("CONTOSO"),
        "a string at a schema.numeric path leaked: {value}"
    );
}
