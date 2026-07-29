//! The `--reuse-map` catalog gate.
//!
//! A mapping file records the catalog version it was minted under. Reusing it
//! against a build with a different catalog means the two collections disagree
//! about which values the catalog preserves, and the disagreement is silent:
//! both runs succeed, both publish, and only a cross-collection comparison
//! shows one preserved a value the other pseudonymized. The gate refuses the
//! reuse instead, including when the mapping states no version at all.

use serde_json::{json, Value};
use shanon_core::catalog::CATALOG_VERSION;
use shanon_core::pipeline::{ensure_reuse_map_compatible, ShanonError};
use shanon_core::registry::Registry;

const SALT: &str = "0123456789abcdef0123456789abcdef";

fn map_value(policy: Option<Value>) -> Value {
    let mut doc = json!({
        "salt": SALT,
        "format_version": 2,
        "categories": {"accounts": {"jdoe": "asmithab2c3d4e5f6a7b8"}}
    });
    if let Some(policy) = policy {
        doc.as_object_mut().unwrap().insert("policy".into(), policy);
    }
    doc
}

fn load(policy: Option<Value>) -> Registry {
    Registry::from_value(&map_value(policy)).expect("a well-formed mapping loads")
}

fn refusal(registry: &Registry) -> ShanonError {
    ensure_reuse_map_compatible(registry).expect_err("the gate must refuse this mapping")
}

/// The mapping this build writes is the mapping this build accepts back.
#[test]
fn a_map_from_this_catalog_version_is_accepted() {
    let registry = load(Some(json!({
        "profile": "core-global-defaults",
        "catalog_version": CATALOG_VERSION,
    })));
    assert_eq!(registry.source_catalog_version(), Some(CATALOG_VERSION));
    assert!(ensure_reuse_map_compatible(&registry).is_ok());
}

/// The case the `CATALOG_VERSION` bump to 2 made reachable: a version-1 map
/// reused now disagrees with its own sibling collection about the corrected
/// User-Change-Password GUID.
#[test]
fn a_map_from_an_older_catalog_version_is_refused() {
    let registry = load(Some(json!({
        "profile": "core-global-defaults",
        "catalog_version": 1,
    })));
    assert_eq!(registry.source_catalog_version(), Some(1));
    let err = refusal(&registry);
    assert!(
        matches!(err, ShanonError::UnsafeMapping(_)),
        "expected an unsafe-mapping refusal, got {err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

/// A future version is refused for the same reason a past one is: the gate
/// asserts agreement, not recency.
#[test]
fn a_map_from_a_newer_catalog_version_is_refused() {
    let registry = load(Some(json!({"catalog_version": CATALOG_VERSION + 1})));
    assert!(matches!(refusal(&registry), ShanonError::UnsafeMapping(_)));
}

/// Fail-closed (invariant 1): silence is not agreement. A mapping with no
/// policy block, no `catalog_version`, or an unusable one is refused rather
/// than assumed current.
#[test]
fn a_map_that_states_no_catalog_version_is_refused() {
    for policy in [
        None,
        Some(json!({})),
        Some(json!({"profile": "core-global-defaults"})),
        Some(json!({"catalog_version": "2"})),
        Some(json!({"catalog_version": -1})),
        Some(json!({"catalog_version": null})),
    ] {
        let registry = load(policy.clone());
        assert_eq!(
            registry.source_catalog_version(),
            None,
            "policy {policy:?} should read back as no version"
        );
        assert!(
            matches!(refusal(&registry), ShanonError::UnsafeMapping(_)),
            "policy {policy:?} must be refused"
        );
    }
}

/// A registry built rather than loaded carries no source policy, so it can
/// never be mistaken for a mapping that agreed with this catalog.
#[test]
fn a_constructed_registry_has_no_source_policy() {
    let registry = Registry::new(SALT);
    assert!(registry.source_policy().is_none());
    assert!(registry.source_catalog_version().is_none());
}

/// Invariant 2: retaining the loaded policy block must not change a single
/// byte of what `save` writes. `save` takes the policy it writes as an
/// argument, and the retained one is read-only state.
#[test]
fn retaining_the_loaded_policy_does_not_change_the_saved_bytes() {
    let with_policy = load(Some(json!({"catalog_version": CATALOG_VERSION})));
    let without_policy = load(None);
    assert_eq!(
        with_policy.save_to_string("hash", "1970-01-01T00:00:00Z", None),
        without_policy.save_to_string("hash", "1970-01-01T00:00:00Z", None),
    );
    let written = with_policy.save_to_string("hash", "1970-01-01T00:00:00Z", None);
    assert!(
        !written.contains("catalog_version"),
        "the loaded policy block leaked into the saved mapping: {written}"
    );
}
