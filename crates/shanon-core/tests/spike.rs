//! S1 go/no-go spike proofs.
//!
//! Ground-truth files under `spike/` were produced during development as
//! frozen reference fixtures. These tests replay
//! the two parity contracts against the frozen fixtures.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn spike_dir() -> PathBuf {
    // crates/shanon-core -> ../../spike
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("spike")
}

/// Parse bytes with preserve_order + arbitrary_precision (the production model).
fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("valid JSON")
}

// --- Contract 1: byte-identical json.dumps round-trip -----------------------

#[test]
fn json_roundtrip_matches_reference_on_real_sample() {
    let sample = fs::read(spike_dir().join("sample.json")).unwrap();
    let expected = fs::read_to_string(spike_dir().join("json_roundtrip_expected.txt")).unwrap();

    let value = parse(&sample);
    let got = shanon_core::canonical_json(&value);

    assert_eq!(
        got, expected,
        "Rust re-serialization diverged from the canonical JSON serialization on real SharpHound sample"
    );
    // Sanity: it is genuinely a non-trivial document.
    assert!(expected.len() > 10_000);
}

#[test]
fn json_roundtrip_matches_reference_on_unicode_control_astral_stress() {
    let sample = fs::read(spike_dir().join("stress_input.json")).unwrap();
    let expected = fs::read_to_string(spike_dir().join("stress_roundtrip_expected.txt")).unwrap();

    let value = parse(&sample);
    let got = shanon_core::canonical_json(&value);

    assert_eq!(
        got, expected,
        "ensure_ascii / surrogate-pair escaping diverged from the reference fixtures"
    );
    // Confirm the escaping path actually fired (astral -> surrogate pair).
    assert!(
        expected.contains("\\ud83d\\ude00"),
        "astral emoji not surrogate-escaped"
    );
    assert!(expected.contains("\\u007f"), "DEL (0x7f) not escaped");
    assert!(expected.contains("\\u0000"), "NUL not escaped");
}

// --- Contract 2: pseudonym / digest parity ----------------------------------

#[test]
fn blake2b_seed_and_oid_pseudonym_match_reference_registry() {
    let raw = fs::read_to_string(spike_dir().join("digest_expected.json")).unwrap();
    let expected: Value = serde_json::from_str(&raw).unwrap();

    let salt = expected["salt"].as_str().unwrap();
    let category = expected["category"].as_str().unwrap();
    let semantic_real = expected["semantic_real"].as_str().unwrap();

    // 1. raw digest hex matches hashlib.blake2b(..., digest_size=16).hexdigest()
    let got_hex = shanon_core::pseudonym_digest_hex(salt, category, semantic_real);
    assert_eq!(got_hex, expected["digest_hex"].as_str().unwrap());

    // 2. int.from_bytes(digest, "big") matches
    let got_seed = shanon_core::seed_int(salt, category, semantic_real).to_string();
    assert_eq!(got_seed, expected["seed_int_dec"].as_str().unwrap());

    // 3. full OID pseudonym (Registry.map output) matches: f"2.25.{seed}"
    let got_pseudonym = shanon_core::oid_pseudonym(salt, semantic_real);
    assert_eq!(got_pseudonym, expected["oid_pseudonym"].as_str().unwrap());
}
