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
