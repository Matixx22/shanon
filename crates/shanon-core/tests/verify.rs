//! `verify` end-to-end against the real engine (plan module 9, P3).
//!
//! The independent contextual verifier must ACCEPT every document the engine
//! itself produced (zero findings) and REJECT any post-hoc tampering. We reuse
//! the frozen `engine_truth.json` collection as a realistic multi-node corpus.

use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;
use shanon_core::verify::verify_document;

fn parity(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity")
        .join(name)
}

fn obj(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

struct Transformed {
    member: String,
    source: Map<String, Value>,
    output: Map<String, Value>,
    records: Vec<shanon_core::policy::DecisionRecord>,
}

fn run_engine() -> (
    Vec<Transformed>,
    Registry,
    shanon_core::engine::VerificationContext,
) {
    let truth: Value =
        serde_json::from_slice(&fs::read(parity("engine_truth.json")).unwrap()).unwrap();
    let salt = truth["salt"].as_str().unwrap();
    let documents = truth["documents"].as_array().unwrap();

    let registry = Registry::new(salt);
    let mut engine = AnonymizationEngine::new(registry, None, None);

    for doc in documents {
        let member = doc["member"].as_str().unwrap();
        engine
            .discover_document(member, &obj(&doc["input"]))
            .unwrap();
    }
    let vctx = engine.finalize_discovery().unwrap();

    let mut out = Vec::new();
    for doc in documents {
        let member = doc["member"].as_str().unwrap().to_string();
        let source = obj(&doc["input"]);
        let (output, records) = engine.transform_document(&member, &source).unwrap();
        out.push(Transformed {
            member,
            source,
            output,
            records,
        });
    }
    let reg = engine.into_registry();
    (out, reg, vctx)
}

#[test]
fn verify_accepts_authentic_engine_output() {
    let (transformed, mut reg, vctx) = run_engine();
    assert!(!transformed.is_empty(), "corpus must have documents");
    for t in &transformed {
        let findings =
            verify_document(&t.member, &t.source, &t.output, &t.records, &mut reg, &vctx);
        assert!(
            findings.is_empty(),
            "verifier rejected authentic output for {}: {:?}",
            t.member,
            findings
        );
    }
}

#[test]
fn verify_rejects_topology_tampering() {
    let (transformed, mut reg, vctx) = run_engine();
    let t = &transformed[0];

    // Drop a top-level key from the output: the root mapping keyset and the
    // dropped subtree paths diverge -> at least one topology finding.
    let mut tampered = t.output.clone();
    let dropped = tampered.keys().next().cloned().unwrap();
    tampered.remove(&dropped);

    let findings = verify_document(&t.member, &t.source, &tampered, &t.records, &mut reg, &vctx);
    assert!(
        !findings.is_empty(),
        "verifier accepted tampered output for {}",
        t.member
    );
    assert!(
        findings.iter().all(|f| f.gate == "contextual-verification"),
        "all findings carry the contextual-verification gate"
    );
}

#[test]
fn verify_rejects_unfrozen_registry() {
    let truth: Value =
        serde_json::from_slice(&fs::read(parity("engine_truth.json")).unwrap()).unwrap();
    let salt = truth["salt"].as_str().unwrap();
    let doc = &truth["documents"].as_array().unwrap()[0];
    let source = obj(&doc["input"]);

    // A never-frozen registry must trip the fail-closed `registry-not-frozen`
    // gate before any comparison work.
    let mut reg = Registry::new(salt);
    let vctx = shanon_core::engine::VerificationContext {
        catalog_template_targets: Default::default(),
        policy: Default::default(),
        catalog_domain_rid_targets: Default::default(),
    };
    let findings = verify_document("m.json", &source, &source, &[], &mut reg, &vctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].policy_code, "registry-not-frozen");
}

/// One document carrying an undeclared numeric leaf, transformed under
/// `policy`. Returns everything `verify_document` needs.
fn transform_with(policy: shanon_core::policy::PolicyConfig) -> Transformed2 {
    let doc: Value = serde_json::json!({
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1104",
            "Properties": {
                "name": "ALICE@CONTOSO.LOCAL",
                // Declared, so it must survive verbatim under either policy.
                "whencreated": 1690104000,
                // Undeclared: the leaf the sentinel exists for.
                "employeeNumber": 987654321
            }
        }],
        "meta": {"type": "users", "count": 1, "version": 6}
    });
    let member = "users.json".to_string();
    let mut engine =
        AnonymizationEngine::new(Registry::new("0123456789abcdef"), Some(policy), None);
    engine.discover_document(&member, &obj(&doc)).unwrap();
    let vctx = engine.finalize_discovery().unwrap();
    let (output, records) = engine.transform_document(&member, &obj(&doc)).unwrap();
    Transformed2 {
        member,
        source: obj(&doc),
        output,
        records,
        reg: engine.registry,
        vctx,
    }
}

struct Transformed2 {
    member: String,
    source: Map<String, Value>,
    output: Map<String, Value>,
    records: Vec<shanon_core::policy::DecisionRecord>,
    reg: Registry,
    vctx: shanon_core::engine::VerificationContext,
}

/// The verifier re-derives the sentinel rather than trusting the engine.
///
/// This is the assertion that makes the redaction load-bearing. An engine that
/// forgot to redact one undeclared number publishes a custom `employeeNumber`
/// in the clear while every other check still passes, so verification has to
/// catch it independently. Simulated by transforming with the redaction off and
/// verifying against a policy that has it on.
#[test]
fn verify_rejects_an_undeclared_number_the_engine_left_in_the_clear() {
    let mut t = transform_with(shanon_core::policy::PolicyConfig {
        redact_undeclared_numbers: false,
        ..Default::default()
    });

    // The engine did leave it verbatim, which is what the opt-out asks for.
    assert!(
        serde_json::to_string(&t.output)
            .unwrap()
            .contains("987654321"),
        "fixture is wrong: the opt-out should have passed the value through"
    );

    // Now hold that output to a policy that requires redaction.
    t.vctx.policy.redact_undeclared_numbers = true;
    let findings = verify_document(
        &t.member, &t.source, &t.output, &t.records, &mut t.reg, &t.vctx,
    );
    assert!(
        findings
            .iter()
            .any(|f| f.policy_code == "undeclared-numeric-not-redacted"),
        "verifier accepted an unredacted undeclared number: {findings:?}"
    );
}

/// The other half: authentic redacted output verifies clean, and the declared
/// numeric beside it is not disturbed.
#[test]
fn verify_accepts_a_properly_redacted_undeclared_number() {
    let mut t = transform_with(shanon_core::policy::PolicyConfig::default());

    assert!(
        !serde_json::to_string(&t.output)
            .unwrap()
            .contains("987654321"),
        "the undeclared number should have been redacted"
    );
    assert_eq!(
        t.output["data"][0]["Properties"]["whencreated"],
        Value::from(1690104000),
        "a declared numeric must not be redacted"
    );

    let findings = verify_document(
        &t.member, &t.source, &t.output, &t.records, &mut t.reg, &t.vctx,
    );
    assert!(
        findings.is_empty(),
        "verifier rejected authentic redacted output: {findings:?}"
    );
}
