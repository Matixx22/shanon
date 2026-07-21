//! `fields` ignore-case helpers + v1 token matcher against the committed ground-truth fixtures.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::fields::{
    canonical_re_ignorecase_literal, deduplicate_ignorecase, find_real_tokens,
    re_ignorecase_signature, real_token_pattern, sweep_string, TokenRegistry,
};

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Mirrors the `StubRegistry` reference fixture contract: one insertion-
/// ordered `accounts` bucket of real→fake, `all_real_tokens` = its keys.
struct StubRegistry {
    pairs: Vec<(String, String)>,
}
impl TokenRegistry for StubRegistry {
    fn all_real_tokens(&self) -> Vec<String> {
        self.pairs.iter().map(|(r, _)| r.clone()).collect()
    }
    fn category_pairs(&self) -> Vec<(String, String)> {
        self.pairs.clone()
    }
}

#[test]
fn ignorecase_signatures_match_reference() {
    for case in truth("fields_signatures.json").as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let expected_sig: Vec<String> = case["signature"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            re_ignorecase_signature(input),
            expected_sig,
            "signature({input:?})"
        );
        assert_eq!(
            canonical_re_ignorecase_literal(input),
            case["canonical"].as_str().unwrap(),
            "canonical({input:?})"
        );
    }
}

#[test]
fn dedup_matches_reference() {
    for case in truth("fields_dedup.json").as_array().unwrap() {
        let input: Vec<String> = case["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let expected: Vec<String> = case["output"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(deduplicate_ignorecase(&input), expected, "dedup({input:?})");
    }
}

#[test]
fn token_artefacts_match_reference() {
    for scenario in truth("fields_tokens.json").as_array().unwrap() {
        // Preserve JSON object insertion order for the token bucket.
        let pairs: Vec<(String, String)> = scenario["tokens"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let reg = StubRegistry { pairs };

        let expected_source = scenario["pattern_source"].as_str();
        assert_eq!(
            real_token_pattern(&reg).as_deref(),
            expected_source,
            "pattern source mismatch"
        );

        for tc in scenario["texts"].as_array().unwrap() {
            let text = tc["text"].as_str().unwrap();
            let expected_found: Vec<String> = tc["found"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let got_found: Vec<String> = find_real_tokens(&reg, text).into_iter().collect();
            assert_eq!(got_found, expected_found, "find_real_tokens({text:?})");

            assert_eq!(
                sweep_string(&reg, text),
                tc["swept"].as_str().unwrap(),
                "sweep_string({text:?})"
            );
        }
    }
}
