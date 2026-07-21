//! `casefold` against the committed ground-truth fixtures (ground truth committed under
//! `tests/truth/`).

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::casefold::casefold;

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn casefold_matches_reference() {
    let cases = truth("casefold.json");
    let mut checked = 0;
    for pair in cases.as_array().unwrap() {
        let input = pair[0].as_str().unwrap();
        let expected = pair[1].as_str().unwrap();
        assert_eq!(
            casefold(input),
            expected,
            "casefold({input:?}) mismatch (chars: {:?})",
            input.chars().map(|c| c as u32).collect::<Vec<_>>()
        );
        checked += 1;
    }
    assert!(checked > 500, "expected a wide casefold corpus");
}
