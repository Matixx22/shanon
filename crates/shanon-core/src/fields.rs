//! Compatibility helpers around the field-aware engine.
//!
//! Implemented here (module 3, P0):
//!   * the `re.IGNORECASE`-equivalent signature/canonicalization helpers
//!     (`_re_ignorecase_signature`, `_canonical_re_ignorecase_literal`,
//!     `_deduplicate_ignorecase`),
//!   * the v1 exact-token compatibility matcher (`real_token_pattern`,
//!     `find_real_tokens`, `sweep_string`).
//!
//! NOT here: `walk` (delegates to `AnonymizationEngine`, module 8) —
//! lands in P2 with the engine.
//!
//! Full Unicode case folding is essential: these signatures fold with
//! [`crate::casefold`], not `to_lowercase`.

use std::collections::BTreeSet;
use std::collections::HashMap;

use fancy_regex::Regex as FancyRegex;

use crate::casefold::casefold;
use crate::patterns::factor_literals;

/// `_RE_IGNORECASE_CANONICAL_OVERRIDES`: each variant maps to
/// the first spelling of its ignore-case group.
fn ignorecase_override(c: char) -> Option<char> {
    match c {
        'i' | 'I' | '\u{130}' | '\u{131}' => Some('i'),
        '\u{390}' => Some('\u{390}'),                // ΐ
        '\u{3b0}' => Some('\u{3b0}'),                // ΰ
        '\u{fb05}' | '\u{fb06}' => Some('\u{fb05}'), // ﬅ ﬆ
        _ => None,
    }
}

/// Per-character signature for Unicode case-insensitive matching (`_re_ignorecase_signature`).
pub fn re_ignorecase_signature(literal: &str) -> Vec<String> {
    literal
        .chars()
        .map(|c| {
            let base = ignorecase_override(c).unwrap_or(c);
            casefold(&base.to_string())
        })
        .collect()
}

/// Choose one same-width spelling per ignore-case char
/// (`_canonical_re_ignorecase_literal`).
pub fn canonical_re_ignorecase_literal(literal: &str) -> String {
    let mut out = String::new();
    for c in literal.chars() {
        if let Some(ov) = ignorecase_override(c) {
            out.push(ov);
            continue;
        }
        let folded = casefold(&c.to_string());
        if folded.chars().count() == 1 {
            out.push_str(&folded);
            continue;
        }
        let lowered: String = c.to_lowercase().collect();
        if lowered.chars().count() == 1 {
            out.push_str(&lowered);
        } else {
            out.push(c);
        }
    }
    out
}

/// `_deduplicate_ignorecase`: drop later duplicates that share a signature,
/// emitting the canonical spelling of the first occurrence.
pub fn deduplicate_ignorecase(literals: &[String]) -> Vec<String> {
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut out = Vec::new();
    for literal in literals {
        let signature = re_ignorecase_signature(literal);
        if seen.contains(&signature) {
            continue;
        }
        seen.insert(signature);
        out.push(canonical_re_ignorecase_literal(literal));
    }
    out
}

/// The registry surface `fields`' token matcher needs. Implemented by the
/// concrete `Registry` in P2; stubbed in tests.
pub trait TokenRegistry {
    /// All real source tokens (`all_real_tokens()`).
    fn all_real_tokens(&self) -> Vec<String>;
    /// `(real, fake)` pairs in `categories.values()` × `bucket.items()`
    /// iteration order (first-wins into the replacement map).
    fn category_pairs(&self) -> Vec<(String, String)>;
}

/// Built artefacts: the compiled matcher and the signature→fake replacement map.
pub struct TokenArtefacts {
    /// The regex source string (matches `pattern.pattern`); `None` when
    /// there are no tokens.
    pub pattern_source: Option<String>,
    compiled: Option<FancyRegex>,
    replacements: HashMap<Vec<String>, String>,
}

fn build_token_artefacts(reg: &dyn TokenRegistry) -> TokenArtefacts {
    // sorted((token for token in all_real_tokens() if token),
    //        key=lambda t: (-len(t), t.casefold()))
    let mut candidates: Vec<String> = reg
        .all_real_tokens()
        .into_iter()
        .filter(|t| !t.is_empty())
        .collect();
    candidates.sort_by(|a, b| {
        let la = a.chars().count();
        let lb = b.chars().count();
        // -len ascending == len descending
        lb.cmp(&la).then_with(|| casefold(a).cmp(&casefold(b)))
    });
    let tokens = deduplicate_ignorecase(&candidates);

    let mut replacements: HashMap<Vec<String>, String> = HashMap::new();
    for (real, fake) in reg.category_pairs() {
        replacements
            .entry(re_ignorecase_signature(&real))
            .or_insert(fake);
    }

    if tokens.is_empty() {
        return TokenArtefacts {
            pattern_source: None,
            compiled: None,
            replacements,
        };
    }

    let token_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let factored = factor_literals(&token_refs);
    let pattern_source = format!("(?<![A-Za-z0-9_])(?:{factored})(?![A-Za-z0-9_])");
    // re.IGNORECASE -> prepend the inline flag for fancy-regex.
    let compiled =
        FancyRegex::new(&format!("(?i){pattern_source}")).expect("v1 token pattern must compile");

    TokenArtefacts {
        pattern_source: Some(pattern_source),
        compiled: Some(compiled),
        replacements,
    }
}

/// Return the v1 exact-token compatibility pattern source (`real_token_pattern`).
pub fn real_token_pattern(reg: &dyn TokenRegistry) -> Option<String> {
    build_token_artefacts(reg).pattern_source
}

/// Find exact registry source tokens in `text` (`find_real_tokens`).
pub fn find_real_tokens(reg: &dyn TokenRegistry, text: &str) -> BTreeSet<String> {
    let artefacts = build_token_artefacts(reg);
    let mut out = BTreeSet::new();
    if let Some(re) = &artefacts.compiled {
        for m in re.find_iter(text) {
            let m = m.expect("v1 token match");
            out.insert(m.as_str().to_string());
        }
    }
    out
}

/// Replace exact registry tokens in `text` (`sweep_string`).
pub fn sweep_string(reg: &dyn TokenRegistry, text: &str) -> String {
    let artefacts = build_token_artefacts(reg);
    let re = match (&artefacts.compiled, text.is_empty()) {
        (Some(re), false) => re,
        _ => return text.to_string(),
    };

    let mut result = String::new();
    let mut last = 0usize;
    for m in re.find_iter(text) {
        let m = m.expect("v1 token match");
        result.push_str(&text[last..m.start()]);
        let signature = re_ignorecase_signature(m.as_str());
        match artefacts.replacements.get(&signature) {
            Some(fake) => result.push_str(fake),
            None => result.push_str(m.as_str()),
        }
        last = m.end();
    }
    result.push_str(&text[last..]);
    result
}
