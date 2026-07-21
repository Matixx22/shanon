//! Unicode full case folding.
//!
//! Applies Unicode **full** case folding (CaseFolding.txt
//! status `C` + `F`) with **no** canonical normalization. The `caseless` crate's
//! `default_case_fold_str` implements exactly that mapping. Validated against
//! the committed ground-truth fixtures in
//! `tests/casefold.rs`.
//!
//! This matters for the registry `_normalize_mapping_identity` step (§3.1a caveat)
//! and for `fields`' ignorecase signatures — Rust's `str::to_lowercase()` is
//! *simple* lowercasing and diverges from full case folding on e.g. `ß`, `İ`, `ﬅ`.

/// Return the Unicode full case fold of `s`.
pub fn casefold(s: &str) -> String {
    caseless::default_case_fold_str(s)
}
