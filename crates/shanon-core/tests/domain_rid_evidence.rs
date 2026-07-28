//! Domain-RID preservation is a property of a SID, not of the path it was
//! spelled at.
//!
//! The catalog only permits preserving a well-known RID at explicitly declared
//! paths (`ObjectIdentifier`, `Aces[].PrincipalSID`, `Members[].ObjectIdentifier`,
//! `Properties.objectsid`), and a reference additionally needs a sibling
//! `ObjectType` / `PrincipalType` to resolve against. But the registry binds one
//! structured output per SID, so a SID that qualifies at a declared path and
//! also appears at an undeclared one — `PrimaryGroupSID` on every user and
//! computer SharpHound and the BloodHound CE ingestors emit — used to be bound
//! twice with opposite terminal intent and abort the whole run.
//!
//! These fixtures are synthetic. The domain SID and RIDs are the only parts
//! that carry meaning.

use serde_json::{json, Map, Value};
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

fn obj(value: Value) -> Map<String, Value> {
    value.as_object().expect("object fixture").clone()
}

fn users(objects: Vec<Value>) -> Map<String, Value> {
    obj(json!({
        "data": objects,
        "meta": {"methods": 46067, "type": "users", "count": objects.len(), "version": 5},
    }))
}

fn user_with_principal_type(primary_group_rid: &str, ace_rid: &str, principal_type: &str) -> Value {
    json!({
        "Properties": {
            "domain": DOMAIN,
            "name": format!("JDOE@{DOMAIN}"),
            "distinguishedname": "CN=jdoe,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
            "domainsid": DOMAIN_SID,
            "samaccountname": "jdoe",
        },
        "ObjectIdentifier": format!("{DOMAIN_SID}-9001"),
        "PrimaryGroupSID": format!("{DOMAIN_SID}-{primary_group_rid}"),
        "Aces": [{
            "PrincipalSID": format!("{DOMAIN_SID}-{ace_rid}"),
            "PrincipalType": principal_type,
            "RightName": "GenericAll",
            "IsInherited": false,
        }],
        "SPNTargets": [],
        "AllowedToDelegate": [],
        "HasSIDHistory": [],
        "IsDeleted": false,
        "IsACLProtected": false,
    })
}

/// Run one collection end to end through the engine and return the transformed
/// documents in input order.
fn run(documents: Vec<Map<String, Value>>) -> Vec<Value> {
    let mut engine = AnonymizationEngine::new(Registry::new("test-salt"), None, None);
    for (index, doc) in documents.iter().enumerate() {
        engine
            .discover_document(&format!("member-{index:05}.json"), doc)
            .expect("discovery");
    }
    engine.finalize_discovery().expect("finalize");
    documents
        .iter()
        .enumerate()
        .map(|(index, doc)| {
            let (out, _) = engine
                .transform_document(&format!("member-{index:05}.json"), doc)
                .expect("transform");
            Value::Object(out)
        })
        .collect()
}

fn leaf<'a>(doc: &'a Value, pointer: &str) -> &'a str {
    doc.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"))
}

/// The regression. Every well-known RID that can sit on `PrimaryGroupSID` also
/// shows up as an ACE principal in real collections; both occurrences must
/// agree, and both must keep the RID.
///
/// The catalog scopes each RID to a node type, so the ACE only qualifies when
/// its `PrincipalType` matches — 500 and 502 are Users, the rest Groups.
#[test]
fn a_well_known_rid_survives_at_a_declared_and_an_undeclared_path() {
    for (rid, principal_type) in [
        ("500", "User"),
        ("502", "User"),
        ("512", "Group"),
        ("513", "Group"),
        ("515", "Group"),
        ("516", "Group"),
        ("519", "Group"),
    ] {
        let out = run(vec![users(vec![user_with_principal_type(
            rid,
            rid,
            principal_type,
        )])]);
        let primary = leaf(&out[0], "/data/0/PrimaryGroupSID");
        let principal = leaf(&out[0], "/data/0/Aces/0/PrincipalSID");
        assert_eq!(
            primary, principal,
            "rid {rid}: one SID must bind to one output"
        );
        assert!(
            primary.ends_with(&format!("-{rid}")),
            "rid {rid}: catalog RID must survive, got {primary}"
        );
        assert!(
            !primary.starts_with(DOMAIN_SID),
            "rid {rid}: the domain prefix must still be anonymized, got {primary}"
        );
    }
}

/// A catalog RID whose node type does not match the reference has no evidence,
/// so nothing preserves it — but the two occurrences must still agree. Silent
/// agreement, not preservation, is what keeps the run alive.
#[test]
fn a_rid_that_matches_no_catalog_entry_agrees_without_preserving() {
    for (rid, principal_type) in [("1104", "Group"), ("513", "User"), ("500", "Group")] {
        let out = run(vec![users(vec![user_with_principal_type(
            rid,
            rid,
            principal_type,
        )])]);
        let primary = leaf(&out[0], "/data/0/PrimaryGroupSID");
        let principal = leaf(&out[0], "/data/0/Aces/0/PrincipalSID");
        assert_eq!(primary, principal, "rid {rid} as {principal_type}");
        assert!(
            !primary.ends_with(&format!("-{rid}")),
            "rid {rid} as {principal_type}: no evidence, so no preservation, got {primary}"
        );
    }
}

/// Evidence is collection-wide, so it must not depend on which member — or
/// which key within a member — the walk reaches first.
#[test]
fn evidence_is_independent_of_discovery_order() {
    // The ACE that qualifies the RID lives in a later member than the
    // `PrimaryGroupSID` that depends on it.
    let split = run(vec![
        users(vec![json!({
            "Properties": {"domain": DOMAIN, "name": format!("A@{DOMAIN}"),
                           "distinguishedname": "CN=a,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                           "domainsid": DOMAIN_SID, "samaccountname": "a"},
            "ObjectIdentifier": format!("{DOMAIN_SID}-9001"),
            "PrimaryGroupSID": format!("{DOMAIN_SID}-513"),
            "Aces": [],
        })]),
        users(vec![json!({
            "Properties": {"domain": DOMAIN, "name": format!("B@{DOMAIN}"),
                           "distinguishedname": "CN=b,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                           "domainsid": DOMAIN_SID, "samaccountname": "b"},
            "ObjectIdentifier": format!("{DOMAIN_SID}-9002"),
            "Aces": [{"PrincipalSID": format!("{DOMAIN_SID}-513"),
                      "PrincipalType": "Group", "RightName": "GenericAll",
                      "IsInherited": false}],
        })]),
    ]);
    let primary = leaf(&split[0], "/data/0/PrimaryGroupSID");
    let principal = leaf(&split[1], "/data/0/Aces/0/PrincipalSID");
    assert_eq!(primary, principal);
    assert!(primary.ends_with("-513"), "got {primary}");
}

/// SharpHound and both CE ingestors qualify some principals as
/// `<DOMAIN>-<SID>`. `transform_sid` recurses through that prefix and binds the
/// inner SID, so evidence has to be keyed on the inner SID too — otherwise the
/// prefixed spelling disagrees with the bare one about the terminal.
#[test]
fn a_domain_prefixed_spelling_resolves_to_the_same_evidence() {
    let out = run(vec![obj(json!({
        "data": [{
            "Properties": {"domain": DOMAIN, "name": format!("GRP@{DOMAIN}"),
                           "distinguishedname": "CN=grp,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                           "domainsid": DOMAIN_SID},
            "ObjectIdentifier": format!("{DOMAIN_SID}-513"),
            "Members": [{"ObjectIdentifier": format!("{DOMAIN}-{DOMAIN_SID}-513"),
                         "ObjectType": "User"}],
            "Aces": [],
            "IsDeleted": false,
            "IsACLProtected": false,
        }],
        "meta": {"methods": 46067, "type": "groups", "count": 1, "version": 5},
    }))]);
    let definition = leaf(&out[0], "/data/0/ObjectIdentifier");
    let member = leaf(&out[0], "/data/0/Members/0/ObjectIdentifier");
    assert!(definition.ends_with("-513"), "got {definition}");
    assert!(
        member.ends_with(definition),
        "prefixed member {member} must carry the same bound SID as {definition}"
    );
}
