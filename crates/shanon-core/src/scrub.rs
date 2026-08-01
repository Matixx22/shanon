//! Forward-direction bulk substitution: real identifiers -> their pseudonyms.
//!
//! [`crate::restore`] folds the model's answer back to real names. This is the
//! other half of that round trip, and it protects the step in between: the
//! question you type. shanon anonymizes the collection, not the sentences you
//! write around it, so an operator who asks "can SVC_SQL reach DC01?" leaks two
//! identifiers the collection no longer contains. Running that text through the
//! same map first rewrites them to the pseudonyms the model already saw.
//!
//! What this is **not**: a guarantee. Scrubbing replaces what the map knows and
//! nothing else. A hostname you typed that was never in the collection has no
//! mapping, cannot be substituted, and passes through in the clear. The report
//! says how much was replaced; it cannot certify the remainder. SECURITY.md
//! states that limit in the same terms.
//!
//! ## Why two passes
//!
//! Categories differ in how identity is normalized ([`normalize_mapping_identity`]):
//! six casefold, `oids` canonicalizes dotted integers, and `opaque` is exact.
//! So the scan runs twice.
//!
//! 1. **Exact**, over `opaque` and `oids`. `opaque` sources are whole free-text
//!    field values, and a description such as `Runs MSSQLSvc on SQL01` contains
//!    identifiers that pass 2 also maps. It has to win, because the collection
//!    replaced the whole value with one handle; substituting the host inside it
//!    first would leave a mangled string matching nothing the model was given.
//! 2. **Case-insensitive**, over the six casefold categories, because a human
//!    types `CONTOSO`, `contoso` and `Contoso` for the same domain.
//!
//! Neither pass trusts the literal it matched: every hit is resolved through
//! [`Registry::forward`], which re-normalizes per category. A hit the category
//! turns out not to own is counted and left in the clear rather than mapped to a
//! pseudonym belonging to something else.
//!
//! ## Regex audit (§R2)
//!
//! `regex` only, and no lookaround, so this adds no `fancy-regex` use. Word
//! boundaries are checked against the source text by byte offset in
//! [`is_bounded`] instead of being expressed in the pattern, and a rejected
//! match resumes the scan one character later rather than after the match, so a
//! shorter alternative at the same position is still reachable.

use indexmap::{IndexMap, IndexSet};
use regex::Regex;

use crate::components::{ACCOUNTS, CERT_TEMPLATES, DOMAINS, GUIDS, HOSTS, OIDS, OPAQUE, SIDS};
use crate::patterns::factor_literals;
use crate::registry::{Registry, CATEGORIES};

/// Categories matched verbatim, in [`CATEGORIES`] order.
const EXACT_CATEGORIES: [&str; 2] = [OIDS, OPAQUE];
/// Categories matched without regard to case, in [`CATEGORIES`] order.
const FOLDED_CATEGORIES: [&str; 6] = [DOMAINS, SIDS, ACCOUNTS, HOSTS, GUIDS, CERT_TEMPLATES];

/// What a scrub did, in counts and category names only.
///
/// Deliberately value-free (invariant 7): this is printed next to text the
/// operator is about to hand to a model, and a report naming what it replaced
/// would leak exactly what the replacement removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Substitutions made, across every category.
    pub replacements: usize,
    /// Per-category counts in [`CATEGORIES`] order, zero counts omitted.
    pub per_category: Vec<(String, usize)>,
    /// Hits that matched a source literal but resolved to no mapping, and were
    /// therefore left in the clear.
    ///
    /// Expected to be zero. It is a canary for the one place the pattern and the
    /// registry can disagree: `(?i)` implements Unicode *simple* case folding
    /// and [`crate::casefold`] implements *full* case folding, so a pathological
    /// spelling can match the alternation and then own no mapping. Passing that
    /// text through silently is what the count exists to prevent.
    pub unresolved: usize,
}

/// Is `[start, end)` in `text` bounded by non-word characters on both sides?
///
/// Word characters are `[A-Za-z0-9_]`, the same class `crate::fields` uses, so
/// the two boundary definitions in the crate agree. Non-ASCII neighbours count
/// as boundaries: that widens what gets replaced, which is the safe direction
/// for a leak the operator would otherwise ship.
fn is_bounded(text: &str, start: usize, end: usize) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(word) && !after.is_some_and(word)
}

/// Byte offset of the character after the one starting at `offset`.
fn next_char_boundary(text: &str, offset: usize) -> usize {
    match text[offset..].chars().next() {
        Some(c) => offset + c.len_utf8(),
        None => text.len(),
    }
}

/// Byte spans in `text` already occupied by a pseudonym this map minted.
///
/// Load-bearing, not an optimization. A pseudonym is not required to be
/// disjoint from its own source: the registry only forbids a mapping that
/// leaves the value unchanged, so `contoso` legitimately becomes
/// `contoso-4aisw7g6lyfdm`, source and all. Without this, scrubbing that
/// pseudonym again would rewrite the stem and produce a token the collection
/// does not contain. Everything inside one of these spans is therefore inert,
/// which also makes a scrub idempotent and makes it safe to run over text that
/// already mixes real names with the model's own wording.
fn pseudonym_spans(reg: &Registry, text: &str) -> Vec<(usize, usize)> {
    let mut pseudonyms: IndexSet<String> = IndexSet::new();
    for (pseudonym, _) in reg.restoration_owners() {
        if !pseudonym.is_empty() {
            pseudonyms.insert(pseudonym);
        }
    }
    let Some(pattern) = compile_pass(&pseudonyms, false) else {
        return Vec::new();
    };
    pattern
        .find_iter(text)
        .map(|found| (found.start(), found.end()))
        .collect()
}

/// Compile the alternation for one pass, longest literal first.
///
/// Length ordering makes the leftmost-first alternation prefer the most specific
/// source at a position, exactly as `crate::restore::bulk_restore` does in the
/// other direction. `sort_by_key` is stable, so equal-length literals keep
/// registry allocation order and the pattern stays deterministic.
fn compile_pass(literals: &IndexSet<String>, ignore_case: bool) -> Option<Regex> {
    if literals.is_empty() {
        return None;
    }
    let mut ordered: Vec<&str> = literals.iter().map(String::as_str).collect();
    ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let source = factor_literals(&ordered);
    let source = if ignore_case {
        format!("(?i){source}")
    } else {
        source
    };
    Some(Regex::new(&source).expect("factored literals compile"))
}

/// Replace every bounded, resolvable hit in `text` for one pass.
fn run_pass(
    reg: &Registry,
    text: &str,
    pattern: &Regex,
    allowed: &[&str],
    counts: &mut IndexMap<String, usize>,
    unresolved: &mut usize,
) -> String {
    let protected = pseudonym_spans(reg, text);
    let overlaps_pseudonym = |start: usize, end: usize| {
        protected
            .iter()
            .any(|(from, to)| start < *to && *from < end)
    };

    let mut out = String::with_capacity(text.len());
    let mut pos = 0usize;
    while pos < text.len() {
        let Some(found) = pattern.find(&text[pos..]) else {
            break;
        };
        let start = pos + found.start();
        let end = pos + found.end();
        let resolved = if is_bounded(text, start, end) && !overlaps_pseudonym(start, end) {
            reg.forward(&text[start..end])
                .into_iter()
                .find(|(category, _)| allowed.contains(&category.as_str()))
        } else {
            None
        };
        match resolved {
            Some((category, pseudonym)) => {
                out.push_str(&text[pos..start]);
                out.push_str(&pseudonym);
                *counts.entry(category).or_insert(0) += 1;
                pos = end;
            }
            None => {
                // Boundary rejected, inside a pseudonym, or a spelling this
                // category does not own. Resume one character in, so a shorter
                // literal at a later offset inside this match is still
                // reachable. Only the last of the three is anomalous: the other
                // two are the scrubber declining on purpose.
                if is_bounded(text, start, end) && !overlaps_pseudonym(start, end) {
                    *unresolved += 1;
                }
                let resume = next_char_boundary(text, start);
                out.push_str(&text[pos..resume]);
                pos = resume;
            }
        }
    }
    out.push_str(&text[pos..]);
    out
}

/// Rewrite every real value in `text` that `reg` knows to its pseudonym.
///
/// Returns the rewritten text and a value-free [`ScrubReport`]. Text containing
/// nothing the map knows comes back unchanged.
pub fn bulk_scrub(reg: &Registry, text: &str) -> (String, ScrubReport) {
    let mut exact: IndexSet<String> = IndexSet::new();
    let mut folded: IndexSet<String> = IndexSet::new();
    for (category, real, pseudonym) in reg.scrub_sources() {
        if real.is_empty() || pseudonym.is_empty() {
            continue;
        }
        if EXACT_CATEGORIES.contains(&category.as_str()) {
            exact.insert(real);
        } else if FOLDED_CATEGORIES.contains(&category.as_str()) {
            // Both spellings, because the two folds are not the same fold.
            // `(?i)` is Unicode simple case folding and cannot match `straße`
            // from the full-folded `strasse`, so indexing only the folded form
            // would miss the source as written. The set collapses the pair
            // wherever they agree, which is almost always.
            folded.insert(crate::casefold::casefold(&real));
            folded.insert(real);
        }
    }

    let mut counts: IndexMap<String, usize> = IndexMap::new();
    let mut unresolved = 0usize;
    let mut current = text.to_string();
    if let Some(pattern) = compile_pass(&exact, false) {
        current = run_pass(
            reg,
            &current,
            &pattern,
            &EXACT_CATEGORIES,
            &mut counts,
            &mut unresolved,
        );
    }
    if let Some(pattern) = compile_pass(&folded, true) {
        current = run_pass(
            reg,
            &current,
            &pattern,
            &FOLDED_CATEGORIES,
            &mut counts,
            &mut unresolved,
        );
    }

    let per_category: Vec<(String, usize)> = CATEGORIES
        .iter()
        .filter_map(|category| {
            counts
                .get(*category)
                .filter(|count| **count > 0)
                .map(|count| ((*category).to_string(), *count))
        })
        .collect();
    let report = ScrubReport {
        replacements: per_category.iter().map(|(_, count)| count).sum(),
        per_category,
        unresolved,
    };
    (current, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_without_mappings_is_returned_unchanged() {
        let reg = Registry::new("00");
        let (out, report) = bulk_scrub(&reg, "nothing to scrub");
        assert_eq!(out, "nothing to scrub");
        assert_eq!(report, ScrubReport::default());
    }

    #[test]
    fn a_mapped_account_is_replaced_and_counted() {
        let mut reg = Registry::new("00");
        let fake = reg.map(ACCOUNTS, "svc_sql").unwrap();
        let (out, report) = bulk_scrub(&reg, "can svc_sql reach anything?");
        assert_eq!(out, format!("can {fake} reach anything?"));
        assert_eq!(report.replacements, 1);
        assert_eq!(report.per_category, vec![(ACCOUNTS.to_string(), 1)]);
    }

    #[test]
    fn a_longer_word_containing_a_mapping_is_left_alone() {
        let mut reg = Registry::new("00");
        let fake = reg.map(ACCOUNTS, "alice").unwrap();
        let (out, report) = bulk_scrub(&reg, "alicent and alice_bot and alice");
        assert_eq!(out, format!("alicent and alice_bot and {fake}"));
        assert_eq!(report.replacements, 1);
    }

    #[test]
    fn a_casefold_category_matches_any_spelling() {
        let mut reg = Registry::new("00");
        let fake = reg.map(DOMAINS, "contoso").unwrap();
        let (out, report) = bulk_scrub(&reg, "CONTOSO and Contoso and contoso");
        assert_eq!(out, format!("{fake} and {fake} and {fake}"));
        assert_eq!(report.replacements, 3);
        assert_eq!(report.unresolved, 0);
    }

    #[test]
    fn an_exact_category_does_not_match_a_case_variant() {
        let mut reg = Registry::new("00");
        let fake = reg.map(OPAQUE, "Ticket owner: Helpdesk").unwrap();
        let (out, report) = bulk_scrub(&reg, "Ticket owner: Helpdesk / TICKET OWNER: HELPDESK");
        assert_eq!(out, format!("{fake} / TICKET OWNER: HELPDESK"));
        assert_eq!(report.replacements, 1);
        // The exact pattern never matches the variant, so nothing is resolved
        // and rejected: the counter stays clean.
        assert_eq!(report.unresolved, 0);
    }

    /// `(?i)` folds simply and [`crate::casefold`] folds fully, so a source
    /// whose two folds differ has to be reachable by both spellings.
    #[test]
    fn a_source_with_divergent_folds_matches_either_spelling() {
        let mut reg = Registry::new("00");
        let fake = reg.map(ACCOUNTS, "straße").unwrap();
        let (out, report) = bulk_scrub(&reg, "straße and STRASSE");
        assert_eq!(out, format!("{fake} and {fake}"));
        assert_eq!(report.replacements, 2);
        assert_eq!(report.unresolved, 0);
    }

    #[test]
    fn free_text_wins_over_the_identifiers_inside_it() {
        let mut reg = Registry::new("00");
        let host = reg.map(HOSTS, "sql01").unwrap();
        let opaque = reg.map(OPAQUE, "Runs MSSQLSvc on sql01").unwrap();
        let (out, _) = bulk_scrub(&reg, "note: Runs MSSQLSvc on sql01, plus sql01 alone");
        assert_eq!(out, format!("note: {opaque}, plus {host} alone"));
    }

    #[test]
    fn a_scrub_round_trips_through_restore() {
        let mut reg = Registry::new("00");
        reg.map(ACCOUNTS, "svc_sql").unwrap();
        reg.map(HOSTS, "sql01").unwrap();
        reg.map(DOMAINS, "contoso").unwrap();
        let text = "does svc_sql on sql01 in contoso have a path?";
        let (scrubbed, _) = bulk_scrub(&reg, text);
        assert_ne!(scrubbed, text);
        assert_eq!(crate::restore::bulk_restore(&reg, &scrubbed), text);
    }
}
