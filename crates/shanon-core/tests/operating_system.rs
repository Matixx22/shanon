//! `Properties.operatingsystem`: stock Microsoft product strings survive, and
//! nothing else does.
//!
//! The field is a first-class attack signal — an unsupported or legacy OS is
//! half of an attack path — so the `schema.operating-system` rule preserves the
//! values Microsoft ships. The value of the rule is entirely in what it refuses:
//! `resolve_schema` matches `allowed_values` exactly, so an appliance banner, an
//! organization-branded gold-image string, or a case variant falls through to
//! `ReplaceOpaque` with the `invalid-schema-string` audit code. Those are the
//! tests that matter here.
//!
//! `Properties.operatingsystemversion` is deliberately left opaque: build
//! numbers are a long tail no table can enumerate fail-closed.
//!
//! All fixtures are synthetic.

use serde_json::{json, Map, Value};
use shanon_core::catalog::PrivacyClass;
use shanon_core::engine::AnonymizationEngine;
use shanon_core::policy::{FieldOperation, FieldPolicy, ObjectContext, PolicyConfig};
use shanon_core::registry::Registry;
use shanon_core::verify::verify_document_with_progress;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";
const PATH: &str = "Properties.operatingsystem";
const KNOWN: &str = "Windows Server 2019 Datacenter";
const VERSION: &str = "10.0 (17763)";

/// The policy an operator gets by asking for the field to be redacted anyway.
fn opt_out() -> PolicyConfig {
    PolicyConfig {
        preserve_os_strings: false,
        ..PolicyConfig::default()
    }
}

fn obj(value: Value) -> Map<String, Value> {
    value.as_object().expect("object fixture").clone()
}

/// Discover, transform and independently verify one collection, mirroring
/// `schema_fields.rs` — these fixtures must clear the leak gate, not merely
/// survive the transform.
fn anonymize(document: Map<String, Value>) -> Value {
    anonymize_with(None, document)
}

fn anonymize_with(config: Option<PolicyConfig>, document: Map<String, Value>) -> Value {
    let mut engine = AnonymizationEngine::new(Registry::new("test-salt"), config, None);
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

/// A CE-shaped computer carrying the two OS fields.
fn computers(operating_system: &str, version: &str) -> Map<String, Value> {
    obj(json!({
        "data": [{
            "Properties": {
                "domain": DOMAIN,
                "name": format!("DC01.{DOMAIN}"),
                "distinguishedname": "CN=DC01,OU=Domain Controllers,DC=SOUTHRIDGE,DC=LOCAL",
                "domainsid": DOMAIN_SID,
                "samaccountname": "DC01$",
                "operatingsystem": operating_system,
                "operatingsystemversion": version,
            },
            "ObjectIdentifier": format!("{DOMAIN_SID}-1000"),
            "PrimaryGroupSID": format!("{DOMAIN_SID}-516"),
            "Aces": [],
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "IsDeleted": false,
            "IsACLProtected": false,
        }],
        "meta": {"methods": 46067, "type": "computers", "count": 1, "version": 6},
    }))
}

fn operating_system_of(out: &Value) -> &str {
    out.pointer("/data/0/Properties/operatingsystem")
        .and_then(Value::as_str)
        .expect("operatingsystem survived as a string")
}

fn computer_context() -> ObjectContext {
    ObjectContext {
        node_type: "Computer".to_string(),
        member: "computers.json".to_string(),
        index: 0,
        object_identifier: Some(format!("{DOMAIN_SID}-1000")),
        privacy: PrivacyClass::Custom,
        catalog_rule_id: None,
    }
}

/// The headline guarantee: a stock product string reaches the output verbatim,
/// so the model can still reason about an unsupported OS.
#[test]
fn a_known_product_string_survives_a_run() {
    let out = anonymize(computers("Windows Server 2019 Datacenter", "10.0 (17763)"));
    assert_eq!(operating_system_of(&out), "Windows Server 2019 Datacenter");
}

/// The key stays declared, so the field is not renamed on its way out.
#[test]
fn the_field_name_survives_a_run() {
    let out = anonymize(computers("Windows 10 Enterprise", "10.0 (19045)"));
    assert!(
        out.pointer("/data/0/Properties/operatingsystem").is_some(),
        "operatingsystem did not survive under its own name"
    );
}

/// An organization that brands its gold image writes the organization's name
/// into the field. Preserving the prefix would leak it, so the whole value goes.
#[test]
fn a_branded_variant_is_redacted() {
    let branded = "Windows Server 2019 Datacenter - CONTOSO GOLD IMAGE";
    let out = anonymize(computers(branded, "10.0 (17763)"));
    let value = operating_system_of(&out);

    assert_ne!(
        value, branded,
        "a branded OS string passed through in clear"
    );
    assert!(
        !value.contains("CONTOSO"),
        "a branded OS string leaked: {value}"
    );
}

/// Appliances and non-Microsoft hosts put free text in the same field, and it
/// routinely names a system. Nothing in the table matches, so it is redacted.
#[test]
fn an_appliance_banner_is_redacted() {
    let banner = "Linux appliance FINANCE-APP-01";
    let out = anonymize(computers(banner, "3.10.0"));
    let value = operating_system_of(&out);

    assert_ne!(value, banner, "an appliance banner passed through in clear");
    assert!(
        !value.contains("FINANCE"),
        "an appliance banner leaked: {value}"
    );
}

/// Matching is exact and case-sensitive — `resolve_schema` compares against
/// `allowed_values` byte for byte, and this pins that decision. A collector that
/// starts emitting a different case must fail here rather than silently widen
/// what escapes.
#[test]
fn a_case_variant_is_not_preserved() {
    let variant = "windows server 2019 datacenter";
    let out = anonymize(computers(variant, "10.0 (17763)"));
    assert_ne!(
        operating_system_of(&out),
        variant,
        "a case variant of a known product string was preserved verbatim"
    );
}

/// Build numbers are a long tail no table can enumerate, so the sibling field
/// stays opaque. This is the deliberate half of the change.
#[test]
fn the_version_field_is_still_redacted() {
    let version = "10.0 (17763)";
    let out = anonymize(computers("Windows Server 2019 Datacenter", version));
    let value = out
        .pointer("/data/0/Properties/operatingsystemversion")
        .and_then(Value::as_str)
        .expect("operatingsystemversion survived as a string");

    assert_ne!(value, version, "operatingsystemversion was preserved");
}

/// The opt-out is a restore, not an approximation.
///
/// With `preserve_os_strings` off, the path goes back to the rule it had before
/// the table existed: same rule id, same operation, same namespace, same `null`
/// audit code — because the false branch rebuilds it from the one entry in
/// `OPAQUE_PATH_URL_PATHS` rather than from a second declaration. The output
/// bytes follow from that: the value gets the same opaque token any other
/// string in the `opaque` namespace gets, which is what the `description`
/// comparison below pins.
#[test]
fn the_opt_out_restores_the_opaque_rule() {
    let policy = FieldPolicy::defaults_with(opt_out());
    let context = computer_context();

    let decision = policy.resolve(&context, PATH, &json!(KNOWN), None);
    assert_eq!(
        decision.rule_id,
        "opaque.path-url.properties.operatingsystem"
    );
    assert_eq!(decision.operation, FieldOperation::ReplaceOpaque);
    assert_eq!(decision.namespace.as_deref(), Some("opaque"));
    assert_eq!(decision.audit_code, None);

    // And no `schema.operating-system` rule is left in the table to shadow it.
    assert!(
        !policy
            .rules()
            .iter()
            .any(|rule| rule.rule_id == "schema.operating-system"),
        "the schema rule survived the opt-out"
    );
}

/// The bytes half of the same guarantee.
#[test]
fn the_opt_out_redacts_a_known_product_string() {
    let out = anonymize_with(Some(opt_out()), computers(KNOWN, VERSION));
    let redacted = operating_system_of(&out);
    assert_ne!(redacted, KNOWN, "the opt-out preserved the product string");

    // The same string at another `opaque` path gets the same token, so the
    // opt-out produces the ordinary opaque replacement and nothing bespoke.
    let mut document = computers("Linux appliance FINANCE-APP-01", VERSION);
    document["data"][0]["Properties"]["description"] = json!(KNOWN);
    let elsewhere = anonymize(document);
    assert_eq!(
        elsewhere.pointer("/data/0/Properties/description"),
        Some(&json!(redacted)),
        "the opt-out token differs from the standard opaque token"
    );
}

/// The policy-level decisions behind all of the above, including the audit code
/// an operator sees for a value the table refused.
#[test]
fn the_rule_records_the_expected_decisions() {
    let policy = FieldPolicy::default();
    let context = computer_context();

    let preserved = policy.resolve(
        &context,
        PATH,
        &json!("Windows Server 2019 Datacenter"),
        None,
    );
    assert_eq!(preserved.rule_id, "schema.operating-system");
    assert_eq!(preserved.operation, FieldOperation::PreserveSchemaValue);
    assert_eq!(preserved.namespace, None);
    assert_eq!(preserved.audit_code, None);

    for refused in [
        "Windows Server 2019 Datacenter - CONTOSO GOLD IMAGE",
        "Linux appliance FINANCE-APP-01",
        "windows server 2019 datacenter",
    ] {
        let decision = policy.resolve(&context, PATH, &json!(refused), None);
        assert_eq!(decision.rule_id, "schema.operating-system", "{refused}");
        assert_eq!(
            decision.operation,
            FieldOperation::ReplaceOpaque,
            "{refused}"
        );
        assert_eq!(decision.namespace.as_deref(), Some("opaque"), "{refused}");
        assert_eq!(
            decision.audit_code.as_deref(),
            Some("invalid-schema-string"),
            "{refused}"
        );
    }
}
