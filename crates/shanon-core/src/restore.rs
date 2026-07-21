//! Restore helpers: reverse-substitute pseudonyms back to real identifiers.

use std::collections::HashMap;

use indexmap::IndexMap;
use regex::Regex;

use crate::patterns::factor_literals;
use crate::registry::Registry;

/// Reverse every pseudonym in `text` to its owning real value (`bulk_restore`).
/// First category/insertion owner wins for cross-category duplicates; among
/// equally long pseudonyms, ownership order is retained.
pub fn bulk_restore(reg: &Registry, text: &str) -> String {
    let mut replacements: IndexMap<String, String> = IndexMap::new();
    for (fake, real) in reg.restoration_owners() {
        if !fake.is_empty() {
            replacements.entry(fake).or_insert(real);
        }
    }
    if replacements.is_empty() {
        return text.to_string();
    }

    // Longest pseudonyms first; `sort_by` is stable, so equal-length keys keep
    // their ownership (insertion) order.
    let mut fakes: Vec<String> = replacements.keys().cloned().collect();
    fakes.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let refs: Vec<&str> = fakes.iter().map(String::as_str).collect();
    let pattern = Regex::new(&factor_literals(&refs)).expect("factored literals compile");

    let lookup: HashMap<&str, &str> = replacements
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    pattern
        .replace_all(text, |caps: &regex::Captures| {
            lookup.get(&caps[0]).copied().unwrap_or("").to_string()
        })
        .into_owned()
}

/// Every source that could produce this pseudonym (`lookup`).
pub fn lookup(reg: &Registry, pseudonym: &str) -> Vec<(String, String)> {
    reg.reverse(pseudonym)
}

/// Every pseudonym a real value maps to across categories (`forward`).
pub fn forward(reg: &Registry, real: &str) -> Vec<(String, String)> {
    reg.forward(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_restore_reverses_mappings_longest_first() {
        let mut reg = Registry::new("00");
        let d = reg.map(crate::components::DOMAINS, "corp.local").unwrap();
        let a = reg.map(crate::components::ACCOUNTS, "alice").unwrap();
        let text = format!("user {a} in {d}");
        let restored = bulk_restore(&reg, &text);
        assert!(restored.contains("alice"), "restored: {restored}");
        assert!(restored.contains("corp.local"), "restored: {restored}");
        assert!(!restored.contains(&a));
    }

    #[test]
    fn bulk_restore_is_identity_without_mappings() {
        let reg = Registry::new("00");
        assert_eq!(
            bulk_restore(&reg, "nothing to restore"),
            "nothing to restore"
        );
    }
}
