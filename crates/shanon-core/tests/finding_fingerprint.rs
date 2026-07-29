//! The offender token in a finding is keyed on the run salt.
//!
//! Findings are the one channel that carries anything about a source value out
//! of a failed run, and they are pasted into tickets, chat and issue trackers.
//! An unkeyed 48-bit digest of a value drawn from a guessable domain (a
//! hostname, a sAMAccountName) is recoverable by anyone who can enumerate that
//! domain, and it is stable across runs and machines, so the same account
//! yields the same token in two collections that were never meant to be
//! linkable. Keying the digest on the salt leaves it deterministic for the
//! holder of the mapping file and inert for everyone else.

use serde_json::{json, Map, Value};
use shanon_core::engine::AnonymizationEngine;
use shanon_core::registry::Registry;
use shanon_core::verify::{verify_document, VerificationFinding};

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

fn source() -> Map<String, Value> {
    json!({
        "data": [{
            "Properties": {
                "domain": DOMAIN,
                "name": format!("JDOE@{DOMAIN}"),
                "domainsid": DOMAIN_SID,
                "samaccountname": "jdoe"
            },
            "ObjectIdentifier": format!("{DOMAIN_SID}-1104"),
            "Aces": [],
            "IsDeleted": false,
            "IsACLProtected": false,
            "ContainedBy": null
        }],
        "meta": {"methods": 0, "type": "users", "count": 1, "version": 6}
    })
    .as_object()
    .unwrap()
    .clone()
}

/// Transform the corpus under `salt`, tamper one output leaf, and return the
/// findings the verifier raises for it.
fn findings_under(salt: &str) -> Vec<VerificationFinding> {
    let source = source();
    let mut engine = AnonymizationEngine::new(Registry::new(salt), None, None);
    engine.discover_document("users.json", &source).unwrap();
    let vctx = engine.finalize_discovery().unwrap();
    let (mut output, records) = engine.transform_document("users.json", &source).unwrap();
    let mut reg = engine.into_registry();

    // Overwrite a transformed leaf with something the verifier cannot have
    // derived. The finding it raises carries the *source* value's token.
    output["data"][0]["Properties"]["samaccountname"] = json!("tampered");

    let findings = verify_document("users.json", &source, &output, &records, &mut reg, &vctx);
    assert!(
        !findings.is_empty(),
        "tampered output must produce a finding"
    );
    findings
}

fn offenders(salt: &str) -> Vec<String> {
    findings_under(salt)
        .into_iter()
        .map(|f| f.offender)
        .collect()
}

/// Two runs of the same collection under different salts must not produce the
/// same token for the same value. This is the correlation property: findings
/// from two engagements cannot be joined.
#[test]
fn the_same_value_under_two_salts_yields_two_tokens() {
    let a = offenders("0123456789abcdef0123456789abcdef");
    let b = offenders("fedcba9876543210fedcba9876543210");
    assert_eq!(
        a.len(),
        b.len(),
        "the same tampering must fail the same way"
    );
    assert!(
        a.iter().zip(&b).all(|(x, y)| x != y),
        "tokens repeated across salts: {a:?} vs {b:?}"
    );
}

/// Keyed does not mean random: within one salt the token is stable, so it can
/// still be compared across two failures of the same run and reversed by
/// whoever holds the mapping.
#[test]
fn the_same_value_under_one_salt_yields_one_token() {
    let salt = "0123456789abcdef0123456789abcdef";
    assert_eq!(offenders(salt), offenders(salt));
}

/// Invariant 7 and the frozen finding shape: still 12 lowercase hex chars, and
/// still never the value itself.
#[test]
fn the_token_keeps_its_shape_and_leaks_nothing() {
    for f in findings_under("0123456789abcdef0123456789abcdef") {
        assert_eq!(f.offender.len(), 12, "{f:?}");
        assert!(
            f.offender
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{f:?}"
        );
        for secret in [DOMAIN, DOMAIN_SID, "jdoe", "JDOE"] {
            let rendered = format!("{f:?}");
            assert!(
                !rendered.contains(secret),
                "a finding carried {secret:?}: {rendered}"
            );
        }
    }
}

/// The specific regression: the old token was `blake2b(value, digest_size=6)`
/// with no key, so anyone holding a candidate list could reproduce it, and
/// `jdoe` is exactly such a candidate. These are the unkeyed digests of every
/// value this corpus contains, `blake2b(value, digest_size=6).hexdigest()`.
/// No salt may reproduce any of them, whichever leaf the finding names.
#[test]
fn no_token_is_the_unkeyed_digest_of_a_value() {
    const UNKEYED: [&str; 7] = [
        "c3b57dd6b4c0", // jdoe
        "78ebcc3de68f", // SOUTHRIDGE.LOCAL
        "de8f5e32c29f", // the domain SID
        "fad34e4303ae", // JDOE@SOUTHRIDGE.LOCAL
        "d906f0566192", // the object identifier
        "1ece6451a970", // the tampered output value
        "ddd9c40767f9", // the empty string, which findings with no leaf use
    ];
    for salt in [
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
        "",
    ] {
        for offender in offenders(salt) {
            assert!(
                !UNKEYED.contains(&offender.as_str()),
                "an unkeyed digest came back as {offender} under salt {salt:?}"
            );
        }
    }
}
