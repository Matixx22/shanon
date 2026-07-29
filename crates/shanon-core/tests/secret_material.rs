//! Secret material never reaches the output collection or the mapping file.
//!
//! A credential-bearing leaf is replaced with a constant instead of being
//! pseudonymized. The distinction matters because pseudonymizing writes the
//! real value into the mapping file as a lookup key: the collection would look
//! clean while the map beside it held the cleartext password.
//!
//! The classic attribute names were covered. LAPS and gMSA were not, and those
//! are the ones a collector run with `--collectallproperties` actually brings
//! back from a domain where the operator can read them.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use shanon_core::pipeline::anonymize_collection;
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::Registry;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

/// One secret per attribute spelling, each value unique so a survivor can be
/// traced back to the attribute that leaked it.
const SECRETS: [(&str, &str); 9] = [
    ("ms-mcs-admpwd", "L3gacyLapsPw!"),
    ("mslaps-password", "{\"n\":\"admin\",\"p\":\"W1nLapsPw!\"}"),
    ("mslaps-encryptedpassword", "AQAAAEncryptedLapsBlob=="),
    (
        "mslaps-encryptedpasswordhistory",
        "AQAAAEncryptedLapsHist==",
    ),
    ("mslaps-encrypteddsrmpassword", "AQAAAEncryptedDsrmPw=="),
    (
        "mslaps-encrypteddsrmpasswordhistory",
        "AQAAAEncryptedDsrmHist==",
    ),
    ("msds-managedpassword", "AQAAAGmsaBlobBase64=="),
    ("nthash", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    // A secret whose value happens to be GUID-shaped. The policy fallback
    // routes such a string to the GUID transform, which pseudonymizes it and
    // writes the cleartext into the map, so the redaction check has to run
    // ahead of the operation dispatch rather than inside one arm of it.
    ("unicodepwd", "8a2f4e10-9c3b-4d5e-8f70-112233445566"),
];

/// Present in the corpus and *not* secret: the LAPS expiry and the gMSA
/// interval carry a timestamp, and an over-broad prefix match would swallow
/// them.
const NOT_SECRETS: [(&str, &str); 2] = [
    ("ms-mcs-admpwdexpirationtime", "133012345678901234"),
    ("msds-managedpasswordinterval", "30"),
];

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("shanon-secret-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A one-member computers collection carrying every secret spelling under
/// `Properties`, plus one inside a nested array element.
fn collection(root: &Path) -> PathBuf {
    let dir = root.join("collection");
    fs::create_dir_all(&dir).expect("collection dir");

    let mut properties = serde_json::Map::new();
    properties.insert("domain".into(), json!(DOMAIN));
    properties.insert("name".into(), json!(format!("WS01.{DOMAIN}")));
    properties.insert("domainsid".into(), json!(DOMAIN_SID));
    properties.insert("samaccountname".into(), json!("WS01$"));
    for (key, value) in SECRETS.into_iter().chain(NOT_SECRETS) {
        properties.insert(key.into(), json!(value));
    }

    let doc = json!({
        "data": [{
            "Properties": properties,
            "ObjectIdentifier": format!("{DOMAIN_SID}-1105"),
            "Aces": [],
            "IsDeleted": false,
            "IsACLProtected": false,
            "ContainedBy": null
        }],
        "meta": {"methods": 0, "type": "computers", "count": 1, "version": 6}
    });
    fs::write(
        dir.join("computers.json"),
        serde_json::to_vec(&doc).unwrap(),
    )
    .expect("member");
    dir
}

/// Run a full anonymize and return (collection bytes, mapping bytes).
fn anonymize(scratch: &Scratch) -> (String, String) {
    let input = collection(&scratch.0);
    let out = scratch.path("out");
    let map = scratch.path("collection.map.json");
    anonymize_collection(
        &input,
        &out,
        Registry::new("test-salt"),
        true,
        PolicyConfig::default(),
        PolicyAudit::new(),
        Some(&map),
        None,
        None,
    )
    .expect("a collection carrying secret material still anonymizes");

    // The published member carries whatever name the pipeline assigns, not the
    // source filename, so read the one member the collection has.
    let published = out.join("collection_anon");
    let member = fs::read_dir(&published)
        .expect("output collection")
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("one published member");
    (
        fs::read_to_string(&member).expect("output member"),
        fs::read_to_string(&map).expect("mapping file"),
    )
}

/// The headline property: no secret value survives, in either artifact.
#[test]
fn no_secret_value_reaches_the_collection_or_the_map() {
    let scratch = Scratch::new("values");
    let (collection, map) = anonymize(&scratch);
    for (key, secret) in SECRETS {
        assert!(
            !collection.contains(secret),
            "{key} survived into the output collection"
        );
        assert!(
            !map.contains(secret),
            "{key} was written into the mapping file in the clear, which is \
             what pseudonymizing a credential does"
        );
    }
}

/// Redacted, specifically, rather than mapped: the value is replaced with the
/// constant, so nothing about it is recorded anywhere.
#[test]
fn every_secret_spelling_is_redacted() {
    let scratch = Scratch::new("redacted");
    let (collection, _) = anonymize(&scratch);
    let parsed: Value = serde_json::from_str(&collection).unwrap();
    let properties = &parsed["data"][0]["Properties"];
    let redacted: Vec<&str> = properties
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v.as_str())
        .filter(|s| *s == "[REDACTED]")
        .collect();
    assert_eq!(
        redacted.len(),
        SECRETS.len(),
        "expected one plain [REDACTED] per secret attribute, got {redacted:?} in {properties}"
    );
}

/// The negative half: the match is on the whole leaf key, not a prefix of it,
/// so an expiry timestamp and a rotation interval take the ordinary path. They
/// are pseudonymized, which means they appear in the map as sources, and a
/// pseudonym rather than the redaction constant in the collection.
#[test]
fn a_timestamp_attribute_is_not_treated_as_a_secret() {
    let scratch = Scratch::new("timestamps");
    let (collection, map) = anonymize(&scratch);
    for (key, value) in NOT_SECRETS {
        assert!(
            map.contains(value),
            "{key} was redacted rather than mapped, so the match is matching \
             more than the exact attribute name"
        );
    }
    let parsed: Value = serde_json::from_str(&collection).unwrap();
    let properties = parsed["data"][0]["Properties"].as_object().unwrap().clone();
    let opaque = properties
        .values()
        .filter_map(|v| v.as_str())
        .filter(|s| s.starts_with("[REDACTED:"))
        .count();
    assert_eq!(
        opaque,
        NOT_SECRETS.len(),
        "expected exactly the non-secret attributes to be pseudonymized: {properties:?}"
    );
}
