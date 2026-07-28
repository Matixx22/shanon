//! Values that real ingestors emit but the field rules did not expect.
//!
//! `bloodhound-ce` and `rusthound-ce` write empty strings for attributes they
//! could not read, names whose domain part is missing, and GUID principals in
//! `Aces[].PrincipalSID` for Container / OU / GPO owners. Each of those used to
//! reach a structured transform that could not parse it, and the run aborted
//! with no output — a malformed attribute in one object killed the whole
//! collection.
//!
//! Policy now re-routes an identifier reference to the namespace its value
//! actually belongs to, and redacts anything a structured transform cannot
//! parse. Both are the safe direction: more redaction, never less, and the
//! leak gate is untouched — these fixtures must pass *verification*, not just
//! transform, which is why every case runs the verifier too.
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

/// Discover, transform and independently verify a collection. Panics with the
/// verifier's sanitized findings if any member fails the leak gate.
fn anonymize(documents: Vec<Map<String, Value>>) -> Vec<Value> {
    let mut engine = AnonymizationEngine::new(Registry::new("test-salt"), None, None);
    let names: Vec<String> = (0..documents.len())
        .map(|i| format!("member-{i:05}.json"))
        .collect();

    for (name, doc) in names.iter().zip(&documents) {
        engine.discover_document(name, doc).expect("discovery");
    }
    let context = engine.finalize_discovery().expect("finalize");

    let mut outputs = Vec::new();
    for (name, doc) in names.iter().zip(&documents) {
        let (output, records) = engine.transform_document(name, doc).expect("transform");
        let findings = verify_document_with_progress(
            name,
            doc,
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
        outputs.push(Value::Object(output));
    }
    outputs
}

fn user(properties: Value, aces: Value) -> Value {
    let mut props = obj(json!({
        "domain": DOMAIN,
        "name": format!("JDOE@{DOMAIN}"),
        "distinguishedname": "CN=jdoe,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
        "domainsid": DOMAIN_SID,
        "samaccountname": "jdoe",
    }));
    for (key, value) in obj(properties) {
        props.insert(key, value);
    }
    json!({
        "Properties": props,
        "ObjectIdentifier": format!("{DOMAIN_SID}-1104"),
        "PrimaryGroupSID": format!("{DOMAIN_SID}-513"),
        "Aces": aces,
        "SPNTargets": [],
        "AllowedToDelegate": [],
        "HasSIDHistory": [],
        "IsDeleted": false,
        "IsACLProtected": false,
    })
}

fn users(objects: Vec<Value>) -> Map<String, Value> {
    obj(json!({
        "data": objects,
        "meta": {"methods": 46067, "type": "users", "count": objects.len(), "version": 5},
    }))
}

fn leaf<'a>(doc: &'a Value, pointer: &str) -> &'a str {
    doc.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"))
}

/// An attribute the collector could not read comes through as `""`. Every one
/// of these paths drives a structured transform that cannot parse an empty
/// string.
#[test]
fn empty_attribute_values_are_redacted_not_fatal() {
    for attribute in [
        "distinguishedname",
        "domain",
        "name",
        "samaccountname",
        "domainsid",
        "email",
        "serviceprincipalnames",
    ] {
        let value = if attribute == "serviceprincipalnames" {
            json!({attribute: [""]})
        } else {
            json!({attribute: ""})
        };
        let out = anonymize(vec![users(vec![user(value, json!([]))])]);
        assert_eq!(out.len(), 1, "{attribute}");
    }
}

/// A name whose domain part is missing (`JDOE@`) cannot split into two non-empty
/// halves, so the identity transform could not produce a well-shaped output.
#[test]
fn a_name_with_an_empty_domain_part_is_redacted() {
    let out = anonymize(vec![users(vec![user(json!({"name": "JDOE@"}), json!([]))])]);
    let name = leaf(&out[0], "/data/0/Properties/name");
    assert!(name.starts_with("[REDACTED"), "got {name}");
}

/// A bare name with no domain part at all is still an ordinary identity.
#[test]
fn a_name_with_no_domain_part_is_still_mapped() {
    let out = anonymize(vec![users(vec![user(json!({"name": "JDOE"}), json!([]))])]);
    let name = leaf(&out[0], "/data/0/Properties/name");
    assert!(!name.starts_with("[REDACTED"), "got {name}");
    assert_ne!(name, "JDOE");
}

/// A SID that is not parseable — a trailing separator is the shape that showed
/// up in the wild — must not reach the structured SID transform, which aborted
/// the run with `structured SID output has invalid hierarchy`.
#[test]
fn an_unparseable_sid_reference_is_redacted() {
    let out = anonymize(vec![users(vec![user(
        json!({}),
        json!([{
            "PrincipalSID": format!("{DOMAIN_SID}-1106-"),
            "PrincipalType": "Group",
            "RightName": "GenericAll",
            "IsInherited": false,
        }]),
    )])]);
    let principal = leaf(&out[0], "/data/0/Aces/0/PrincipalSID");
    assert!(principal.starts_with("[REDACTED"), "got {principal}");
}

/// The CE collectors put a GUID in `PrincipalSID` when the principal is a
/// Container, OU or GPO. Redacting it would sever the edge, so it is routed to
/// the GUID namespace instead and must land on the same pseudonym as the
/// container's own `ObjectIdentifier`.
#[test]
fn a_guid_principal_keeps_its_cross_reference() {
    const CONTAINER: &str = "ABCD1234-1111-2222-3333-444455556666";
    let out = anonymize(vec![
        obj(json!({
            "data": [{
                "Properties": {"domain": DOMAIN, "name": format!("USERS@{DOMAIN}"),
                               "distinguishedname": "CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                               "domainsid": DOMAIN_SID},
                "ObjectIdentifier": CONTAINER,
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": false,
                "IsACLProtected": false,
            }],
            "meta": {"methods": 46067, "type": "containers", "count": 1, "version": 5},
        })),
        users(vec![user(
            json!({}),
            json!([{
                "PrincipalSID": CONTAINER,
                "PrincipalType": "Container",
                "RightName": "Owns",
                "IsInherited": false,
            }]),
        )]),
    ]);
    let definition = leaf(&out[0], "/data/0/ObjectIdentifier");
    let principal = leaf(&out[1], "/data/0/Aces/0/PrincipalSID");
    assert_ne!(definition, CONTAINER, "the GUID must still be anonymized");
    assert_eq!(
        definition, principal,
        "the ACE must still point at the container"
    );
}

/// A well-formed collection must be untouched by any of this: the guards only
/// fire on values a rule's operation cannot parse.
#[test]
fn well_formed_values_are_unaffected() {
    let out = anonymize(vec![users(vec![user(
        json!({"serviceprincipalnames": [format!("HTTP/app.{}", DOMAIN.to_lowercase())]}),
        json!([{
            "PrincipalSID": format!("{DOMAIN_SID}-512"),
            "PrincipalType": "Group",
            "RightName": "GenericAll",
            "IsInherited": false,
        }]),
    )])]);
    for pointer in [
        "/data/0/Properties/name",
        "/data/0/Properties/distinguishedname",
        "/data/0/Properties/domain",
        "/data/0/Aces/0/PrincipalSID",
        "/data/0/Properties/serviceprincipalnames/0",
    ] {
        let value = leaf(&out[0], pointer);
        assert!(
            !value.starts_with("[REDACTED"),
            "{pointer} was redacted: {value}"
        );
    }
}
