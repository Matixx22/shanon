//! `patterns::factor_literals` byte-exact against the committed ground-truth
//! fixtures, plus the case-insensitive single-char equivalence table.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::ignorecase::chars_overlap_ignorecase;
use shanon_core::patterns::factor_literals;

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn factor_literals_matches_reference_byte_for_byte() {
    let cases = truth("patterns_factor.json");
    let arr = cases.as_array().unwrap();
    assert!(arr.len() > 250, "expected the full factor corpus");
    for case in arr {
        let literals: Vec<String> = case["literals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let refs: Vec<&str> = literals.iter().map(String::as_str).collect();
        let expected = case["source"].as_str().unwrap();
        assert_eq!(
            factor_literals(&refs),
            expected,
            "factor_literals({literals:?}) diverged"
        );
    }
}

#[test]
fn re_ignorecase_overlap_matches_reference() {
    let data = truth("re_ignorecase_overlaps.json");
    let chars: Vec<char> = data["chars"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| char::from_u32(v.as_u64().unwrap() as u32).unwrap())
        .collect();
    let expected: BTreeSet<(u32, u32)> = data["overlaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let a = p[0].as_u64().unwrap() as u32;
            let b = p[1].as_u64().unwrap() as u32;
            (a, b)
        })
        .collect();

    for (i, &a) in chars.iter().enumerate() {
        for &b in &chars[i + 1..] {
            let want = expected.contains(&(a as u32, b as u32));
            let got = chars_overlap_ignorecase(a, b);
            assert_eq!(
                got, want,
                "overlap(U+{:04X}, U+{:04X}) got={got} want={want}",
                a as u32, b as u32
            );
        }
    }
    // Reflexive sanity: every char overlaps itself.
    for &c in &chars {
        assert!(chars_overlap_ignorecase(c, c));
    }
}
