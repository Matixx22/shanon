//! Forward-direction bulk substitution (`scrub`).
//!
//! The module's own unit tests pin the matching rules. These pin the properties
//! an operator depends on when they pipe a question through a map: that the
//! result is stable under a second pass, that a pseudonym already in the text is
//! left alone, and that scrubbing composes with restoring in both orders.

use shanon_core::components::{ACCOUNTS, DOMAINS, HOSTS, OPAQUE};
use shanon_core::registry::Registry;
use shanon_core::restore::bulk_restore;
use shanon_core::scrub::bulk_scrub;

/// A registry with one of everything the scrubber treats differently.
fn seeded() -> Registry {
    let mut reg = Registry::new("0123456789abcdef0123456789abcdef");
    reg.map(DOMAINS, "contoso").unwrap();
    reg.map(ACCOUNTS, "svc_sql").unwrap();
    reg.map(ACCOUNTS, "jdoe").unwrap();
    reg.map(HOSTS, "sql01").unwrap();
    reg.map(OPAQUE, "Runs MSSQLSvc. Ticket owner: Helpdesk.")
        .unwrap();
    reg
}

/// Running a scrubbed text through the scrubber again must not move it. An
/// operator who edits and re-scrubs a prompt would otherwise get a different
/// document each time, and pseudonyms would stop matching the collection.
#[test]
fn scrubbing_is_stable_under_a_second_pass() {
    let reg = seeded();
    let text = "does svc_sql on sql01 in contoso reach jdoe?";
    let (once, first) = bulk_scrub(&reg, text);
    let (twice, second) = bulk_scrub(&reg, &once);
    assert_eq!(once, twice);
    assert_eq!(first.replacements, 4);
    assert_eq!(second.replacements, 0);
}

/// A domain pseudonym keeps its source as a readable stem, so
/// `contoso` becomes `contoso-<suffix>` and the source is a literal substring of
/// its own replacement. Nothing in the registry forbids that, and a scrubber
/// that matched inside a pseudonym would rewrite the stem on a second pass and
/// mint a token appearing nowhere in the collection.
#[test]
fn a_pseudonym_that_contains_its_own_source_is_not_rewritten_again() {
    let reg = seeded();
    let domain = reg.forward("contoso")[0].1.clone();
    assert!(
        domain.contains("contoso"),
        "fixture assumes a stem-preserving domain pseudonym, got {domain}"
    );
    let (out, report) = bulk_scrub(&reg, &format!("the domain is {domain}"));
    assert_eq!(out, format!("the domain is {domain}"));
    assert_eq!(report.replacements, 0);
    assert_eq!(report.unresolved, 0);
}

/// Text that already speaks in pseudonyms, which is what comes back from the
/// model, must survive a scrub untouched.
#[test]
fn a_pseudonym_in_the_input_is_not_rewritten() {
    let reg = seeded();
    let pseudonym = &reg.forward("svc_sql")[0].1;
    let text = format!("the model said {pseudonym} is kerberoastable");
    let (out, report) = bulk_scrub(&reg, &text);
    assert_eq!(out, text);
    assert_eq!(report.replacements, 0);
}

/// Scrub then restore returns the operator's own wording for every value the
/// registry stores under the spelling they used.
#[test]
fn scrub_and_restore_compose_back_to_the_source_text() {
    let reg = seeded();
    let text = "path from svc_sql to jdoe via sql01 in contoso";
    let (scrubbed, report) = bulk_scrub(&reg, text);
    assert_eq!(report.replacements, 4);
    assert_eq!(bulk_restore(&reg, &scrubbed), text);
}

/// Every category the registry can hold is reachable, and the report counts
/// them separately in `CATEGORIES` order rather than as one total.
#[test]
fn the_report_breaks_replacements_down_by_category() {
    let reg = seeded();
    let (_, report) = bulk_scrub(
        &reg,
        "contoso / svc_sql / sql01 / Runs MSSQLSvc. Ticket owner: Helpdesk.",
    );
    assert_eq!(
        report.per_category,
        vec![
            (DOMAINS.to_string(), 1),
            (ACCOUNTS.to_string(), 1),
            (HOSTS.to_string(), 1),
            (OPAQUE.to_string(), 1),
        ]
    );
    assert_eq!(report.replacements, 4);
    assert_eq!(report.unresolved, 0);
}

/// An empty registry and empty text are both no-ops rather than panics: the
/// scrubber compiles no pattern when it has no literals.
#[test]
fn an_empty_map_and_an_empty_text_are_both_no_ops() {
    let empty = Registry::new("00");
    assert_eq!(bulk_scrub(&empty, "anything at all").0, "anything at all");
    assert_eq!(bulk_scrub(&seeded(), "").0, "");
}

/// Adjacent hits separated by a single non-word character must both land. The
/// scan resumes at the end of an accepted match, so an off-by-one there would
/// silently drop every second identifier in a comma-separated list.
#[test]
fn adjacent_hits_are_all_replaced() {
    let reg = seeded();
    let (out, report) = bulk_scrub(&reg, "svc_sql,jdoe,sql01");
    assert_eq!(report.replacements, 3);
    assert!(!out.contains("svc_sql"), "{out}");
    assert!(!out.contains("jdoe"), "{out}");
    assert!(!out.contains("sql01"), "{out}");
}

/// A hit whose boundary check fails must not consume the text after it: a
/// shorter, properly bounded source starting later in the same run still has to
/// be found. This is the case a naive `replace_all` gets wrong.
#[test]
fn a_boundary_rejection_does_not_swallow_a_later_hit() {
    let mut reg = Registry::new("00");
    reg.map(ACCOUNTS, "sql").unwrap();
    let (out, report) = bulk_scrub(&reg, "sql01 then sql");
    let pseudonym = &reg.forward("sql")[0].1;
    assert_eq!(out, format!("sql01 then {pseudonym}"));
    assert_eq!(report.replacements, 1);
}
