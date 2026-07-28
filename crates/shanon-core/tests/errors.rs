//! The CLI's stderr / exit-code contract, including the sanitized detail that
//! `--verbose-failures` adds to the mapping-abort classes.
//!
//! The default rendering is a frozen interop surface (invariant 2): every
//! assertion below that pins an exact `stderr()` string is pinning bytes that
//! must not move. The verbose rendering is additive and must stay sanitized
//! (invariant 7) — it may carry a fingerprint of an offender, never the
//! offender itself, and never a source filename.

use shanon_core::engine::AbortLocator;
use shanon_core::pipeline::ShanonError;

const MAPPING_ABORT: &str = "ABORTED - invalid or conflicting mapping data; no output written";

fn locator() -> AbortLocator {
    AbortLocator {
        member: Some("member-00001.json".to_string()),
        node_type: "User".to_string(),
        path: "data[0].PrimaryGroupSID".to_string(),
        offender: "58b27013110a".to_string(),
    }
}

fn located(inner: ShanonError) -> ShanonError {
    ShanonError::Located(Box::new(inner), locator())
}

/// A locator is diagnostic state only: attaching one must not move a single
/// byte of the default stderr surface, for any wrapped class.
#[test]
fn a_locator_never_changes_default_stderr() {
    let cases = [
        ShanonError::PseudonymCollision("pseudonym collision: x".into()),
        ShanonError::UnsafeMapping("unsafe mapping: x".into()),
        ShanonError::PublicationIdentity("x".into()),
        ShanonError::Runtime("x".into()),
        ShanonError::Value("x".into()),
        ShanonError::Io("x".into()),
        ShanonError::FileExists("x".into()),
    ];
    for bare in cases {
        let wrapped = located(bare.clone());
        assert_eq!(bare.stderr(), wrapped.stderr());
        assert_eq!(bare.exit_code(), wrapped.exit_code());
    }
}

/// Without the flag, the four mapping-abort classes still collapse to the one
/// fixed line. This is the byte-for-byte contract the parity replay depends on.
#[test]
fn mapping_aborts_collapse_to_one_line_by_default() {
    for e in [
        ShanonError::PseudonymCollision("pseudonym collision: a".into()),
        ShanonError::UnsafeMapping("unsafe mapping: b".into()),
        ShanonError::PublicationIdentity("c".into()),
        ShanonError::Runtime("d".into()),
    ] {
        assert_eq!(e.stderr(), MAPPING_ABORT);
        assert_eq!(located(e).stderr(), MAPPING_ABORT);
    }
}

/// The regression this whole surface exists for: before, a mapping abort under
/// `--verbose-failures` printed the same mute line as without it, so a failing
/// collection gave the operator nothing to act on.
#[test]
fn verbose_expands_a_located_mapping_abort() {
    let e = located(ShanonError::UnsafeMapping(
        "unsafe mapping: preloaded \"sids\" mapping conflicts with structured output".into(),
    ));
    assert_eq!(
        e.stderr_verbose(),
        concat!(
            "ABORTED - invalid or conflicting mapping data; no output written\n",
            "\n",
            "mapping-abort:\n",
            "- member-00001.json data[0].PrimaryGroupSID unsafe-mapping 58b27013110a\n",
            "  node-type: User\n",
            "  reason: unsafe mapping: preloaded \"sids\" mapping conflicts with structured output",
        )
    );
}

/// An abort raised outside a leaf walk has no locator. Verbose must still
/// surface the class and the reason rather than degrading to the mute line.
#[test]
fn verbose_expands_an_unlocated_mapping_abort() {
    let e = ShanonError::Runtime("discovery is already finalized".into());
    assert_eq!(
        e.stderr_verbose(),
        concat!(
            "ABORTED - invalid or conflicting mapping data; no output written\n",
            "\n",
            "mapping-abort:\n",
            "- runtime\n",
            "  reason: discovery is already finalized",
        )
    );
}

/// Classes that already carried their detail must render identically with and
/// without the flag — the flag adds diagnostics, it does not restyle output.
#[test]
fn verbose_is_a_no_op_for_classes_that_already_report_detail() {
    for e in [
        ShanonError::Value("bad thing".into()),
        ShanonError::Io("bad thing".into()),
        ShanonError::FileExists("bad thing".into()),
        ShanonError::CleanupWarning("bad thing".into()),
        ShanonError::Verification(None),
        ShanonError::VerboseVerification(Vec::new()),
    ] {
        assert_eq!(e.stderr(), e.stderr_verbose());
    }
}

/// The verbose block must be derivable entirely from sanitized inputs. The
/// engine hands over a fingerprint, so no offending value can appear even if a
/// caller builds a locator by hand from a real one.
#[test]
fn verbose_detail_carries_no_source_value() {
    let e = ShanonError::Located(
        Box::new(ShanonError::PseudonymCollision(
            "pseudonym collision in \"sids\" mapping".into(),
        )),
        AbortLocator {
            member: Some("member-00007.json".to_string()),
            node_type: "Group".to_string(),
            path: "data[3].Members[2].ObjectIdentifier".to_string(),
            offender: "6c6c8ebb2876".to_string(),
        },
    );
    let text = e.stderr_verbose();
    assert!(text.contains("pseudonym-collision"), "{text}");
    assert!(text.contains("member-00007.json"), "{text}");
    assert!(
        text.contains("data[3].Members[2].ObjectIdentifier"),
        "{text}"
    );
    assert!(text.contains("6c6c8ebb2876"), "{text}");
    // The locator is the only channel for offender identity, and it is a digest.
    assert!(!text.contains("S-1-5-21"), "{text}");
}

/// `unlocated` and `locator` are how callers reach past the wrapper; nesting
/// must not hide either.
#[test]
fn accessors_see_through_nesting() {
    let e = located(located(ShanonError::Runtime("x".into())));
    assert!(matches!(e.unlocated(), ShanonError::Runtime(_)));
    assert_eq!(
        e.locator().map(|l| l.path.as_str()),
        Some("data[0].PrimaryGroupSID")
    );
}
