//! Property-based fuzz of the policy path grammar (plan P1).
//!
//! Two invariants:
//!   1. Any sequence of object-key / array-index tokens folded through
//!      [`object_path`] / [`array_path`] decodes back through [`path_tokens`] to
//!      the same token structure (keys byte-exact; indices collapse to array
//!      tokens). `canonical_path`/`schema_path` never panic and are idempotent.
//!   2. The committed fixture corpus (`tests/truth/`) is reproduced
//!      byte-for-byte — the cross-impl parity check that guards the
//!      byte-parity contract.

use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;
use serde_json::Value;
use shanon_core::policy::{
    array_path, canonical_path, object_path, path_tokens, schema_path, TokenType,
};

#[derive(Clone, Debug)]
enum Tok {
    Key(String),
    Array(usize),
}

fn tok_strategy() -> impl Strategy<Value = Tok> {
    prop_oneof![
        // Keys drawn from an alphabet that stresses the escape rules and unicode.
        proptest::collection::vec(
            prop::sample::select(vec![
                'a', 'B', '0', '9', '_', ' ', '.', '[', ']', '"', '\\', '/', 'é', '中', 'İ', '-',
            ]),
            0..7,
        )
        .prop_map(|cs| Tok::Key(cs.into_iter().collect())),
        (0usize..10_000).prop_map(Tok::Array),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn object_and_array_paths_round_trip(seq in proptest::collection::vec(tok_strategy(), 1..8)) {
        let mut encoded = String::new();
        for tok in &seq {
            match tok {
                Tok::Key(k) => encoded = object_path(&encoded, k),
                Tok::Array(i) => encoded = array_path(&encoded, *i),
            }
        }

        let tokens = path_tokens(&encoded).expect("generated paths always decode");
        prop_assert_eq!(tokens.len(), seq.len());
        for (got, want) in tokens.iter().zip(&seq) {
            match (got, want) {
                ((TokenType::Key, Some(v)), Tok::Key(k)) => prop_assert_eq!(v, k),
                ((TokenType::Array, None), Tok::Array(_)) => {}
                _ => prop_assert!(false, "token/kind mismatch: {:?} vs {:?}", got, want),
            }
        }

        // Canonical / schema forms never panic and are idempotent.
        let canonical = canonical_path(&encoded);
        prop_assert_eq!(&canonical, &canonical_path(&canonical));
        let schema = schema_path(&encoded);
        prop_assert_eq!(&schema, &schema_path(&schema));
    }
}

#[test]
fn reference_fixture_corpus_is_reproduced() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/truth/policy.json");
    let truth: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();

    for case in truth["path_grammar"].as_array().unwrap() {
        let mut encoded = String::new();
        for tok in case["seq"].as_array().unwrap() {
            if tok[0].as_str().unwrap() == "key" {
                encoded = object_path(&encoded, tok[1].as_str().unwrap());
            } else {
                encoded = array_path(&encoded, tok[1].as_u64().unwrap() as usize);
            }
        }
        assert_eq!(encoded, case["encoded"].as_str().unwrap());
        assert_eq!(
            canonical_path(&encoded),
            case["canonical"].as_str().unwrap()
        );
        assert_eq!(schema_path(&encoded), case["schema"].as_str().unwrap());
    }
}
