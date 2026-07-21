//! `policy` validated against the committed ground-truth fixtures (`tests/truth/policy.json`)
//! plus direct assertions that exercise custom
//! policies and structural behavior.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use shanon_core::catalog::PrivacyClass;
use shanon_core::policy::{
    array_path, canonical_path, object_path, path_tokens, DecisionRecord, FieldDecision,
    FieldOperation, FieldPolicy, FieldRule, ObjectContext, PolicyAudit, PolicyConfig, TokenType,
};

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn op_of(s: &str) -> FieldOperation {
    for op in [
        FieldOperation::PreserveConstant,
        FieldOperation::MapIdentity,
        FieldOperation::MapReference,
        FieldOperation::ParseDn,
        FieldOperation::ParseSpn,
        FieldOperation::ParseComposite,
        FieldOperation::MapCustomIdentifier,
        FieldOperation::ReplaceOpaque,
        FieldOperation::PreserveSchemaValue,
    ] {
        if op.as_str() == s {
            return op;
        }
    }
    panic!("unknown operation {s}")
}

fn privacy_of(s: &str) -> PrivacyClass {
    match s {
        "core_global_default" => PrivacyClass::CoreGlobalDefault,
        "microsoft_feature_default" => PrivacyClass::MicrosoftFeatureDefault,
        "third_party_default" => PrivacyClass::ThirdPartyDefault,
        "custom" => PrivacyClass::Custom,
        "unknown" => PrivacyClass::Unknown,
        other => panic!("unknown privacy {other}"),
    }
}

fn context(node_type: &str, privacy: PrivacyClass, catalog_rule_id: Option<&str>) -> ObjectContext {
    ObjectContext {
        node_type: node_type.to_string(),
        member: "groups.json".to_string(),
        index: 0,
        object_identifier: Some("S-1-5-21-1-2-3-1100".to_string()),
        privacy,
        catalog_rule_id: catalog_rule_id.map(str::to_string),
    }
}

// ===========================================================================
// Ground-truth fixture parity
// ===========================================================================

#[test]
fn path_grammar_matches_reference() {
    for case in truth("policy.json")["path_grammar"].as_array().unwrap() {
        // Rebuild the encoded path by folding object_path/array_path.
        let mut encoded = String::new();
        for tok in case["seq"].as_array().unwrap() {
            let kind = tok[0].as_str().unwrap();
            if kind == "key" {
                encoded = object_path(&encoded, tok[1].as_str().unwrap());
            } else {
                encoded = array_path(&encoded, tok[1].as_u64().unwrap() as usize);
            }
        }
        assert_eq!(
            encoded,
            case["encoded"].as_str().unwrap(),
            "encoded mismatch"
        );

        // Decoded tokens.
        let tokens = path_tokens(&encoded).expect("valid path");
        let want_tokens = case["tokens"].as_array().unwrap();
        assert_eq!(
            tokens.len(),
            want_tokens.len(),
            "token count for {encoded:?}"
        );
        for (got, want) in tokens.iter().zip(want_tokens) {
            match got {
                (TokenType::Key, Some(v)) => {
                    assert_eq!(want[0].as_str().unwrap(), "key");
                    assert_eq!(v.as_str(), want[1].as_str().unwrap());
                }
                (TokenType::Array, None) => {
                    assert_eq!(want[0].as_str().unwrap(), "array");
                    assert!(want[1].is_null());
                }
                other => panic!("unexpected token {other:?}"),
            }
        }

        assert_eq!(
            canonical_path(&encoded),
            case["canonical"].as_str().unwrap()
        );
        assert_eq!(
            shanon_core::policy::schema_path(&encoded),
            case["schema"].as_str().unwrap()
        );
        let got_prefixes: Vec<String> = shanon_core::policy::key_path_prefixes(&encoded);
        let want_prefixes: Vec<&str> = case["prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(got_prefixes, want_prefixes, "prefixes for {encoded:?}");
    }
}

#[test]
fn resolve_matches_reference() {
    let default = FieldPolicy::default();
    let feature_on = FieldPolicy::defaults_with(PolicyConfig {
        preserve_microsoft_feature_defaults: true,
        ..PolicyConfig::default()
    });

    for case in truth("policy.json")["resolve"].as_array().unwrap() {
        let policy = match case["config"].as_str().unwrap() {
            "default" => &default,
            "feature_on" => &feature_on,
            other => panic!("unknown config {other}"),
        };
        let ctx = context(
            case["node_type"].as_str().unwrap(),
            privacy_of(case["privacy"].as_str().unwrap()),
            case["catalog_rule_id"].as_str(),
        );
        let value = &case["value"];
        let reference_node_type = case["reference_node_type"].as_str();
        let decision = policy.resolve(
            &ctx,
            case["path"].as_str().unwrap(),
            value,
            reference_node_type,
        );
        let want = &case["decision"];

        let label = format!("{} @ {}", case["path"], case["value"]);
        assert_eq!(
            decision.rule_id,
            want["rule_id"].as_str().unwrap(),
            "rule_id {label}"
        );
        assert_eq!(
            decision.operation,
            op_of(want["operation"].as_str().unwrap()),
            "operation {label}"
        );
        assert_eq!(
            decision.namespace.as_deref(),
            want["namespace"].as_str(),
            "namespace {label}"
        );
        assert_eq!(
            decision.privacy.as_str(),
            want["privacy"].as_str().unwrap(),
            "privacy {label}"
        );
        assert_eq!(
            decision.audit_code.as_deref(),
            want["audit_code"].as_str(),
            "audit_code {label}"
        );
    }
}

#[test]
fn audit_summary_matches_reference() {
    let ctx = context("Group", PrivacyClass::Custom, None);
    let decision = FieldDecision {
        rule_id: "fallback.unknown-string".to_string(),
        operation: FieldOperation::ReplaceOpaque,
        namespace: Some("opaque".to_string()),
        privacy: PrivacyClass::Custom,
        audit_code: Some("unknown-string-path".to_string()),
        evidence: None,
    };
    let mut audit = PolicyAudit::new();
    audit.record_object_classification(PrivacyClass::Custom);
    for (path, source) in [
        ("Novel.Zeta", "Contoso secret"),
        ("Novel.Alpha", "Fabrikam secret"),
    ] {
        audit.record(&DecisionRecord {
            context: ctx.clone(),
            path: path.to_string(),
            decision: decision.clone(),
            source_value: source.to_string(),
            output_value: "[REDACTED]".to_string(),
        });
    }
    audit.record_unknown_key("Dynamic.Key");

    assert_eq!(audit.summary(), truth("policy.json")["audit_summary"]);
}

// ===========================================================================
// Direct assertions (custom policies / structural behavior)
// ===========================================================================

fn field_rule(
    rule_id: &str,
    node_types: &[&str],
    path: &str,
    operation: FieldOperation,
    namespace: Option<&str>,
) -> FieldRule {
    FieldRule {
        rule_id: rule_id.to_string(),
        node_types: node_types
            .iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>(),
        path: path.to_string(),
        operation,
        namespace: namespace.map(str::to_string),
        allowed_values: None,
    }
}

#[test]
fn canonical_path_casefolds_segments_and_removes_array_indexes() {
    assert_eq!(
        canonical_path("Aces[12].PrincipalSID"),
        "aces[].principalsid"
    );
    assert_eq!(
        canonical_path("Links[0].Edges[34].TargetGUID"),
        "links[].edges[].targetguid"
    );
    assert_eq!(canonical_path("Properties.Name"), "properties.name");
}

#[test]
fn path_tokens_escape_literal_separators_without_aliasing_structure() {
    let nested = object_path(&object_path("", "Properties"), "name");
    let literal = object_path("", "Properties.name");
    let array = array_path(&object_path("", "Novel"), 0);
    let literal_brackets = object_path("", "Novel[0]");
    let escaped = object_path("", "quote\" slash\\ dots. brackets[]");

    assert_eq!(nested, "Properties.name");
    assert_eq!(literal, r#"["Properties.name"]"#);
    assert_eq!(array, "Novel[0]");
    assert_eq!(literal_brackets, r#"["Novel[0]"]"#);
    assert_eq!(canonical_path(&nested), "properties.name");
    assert_eq!(canonical_path(&literal), r#"["properties.name"]"#);
    assert_eq!(canonical_path(&array), "novel[]");
    assert_eq!(canonical_path(&literal_brackets), r#"["novel[0]"]"#);
    assert_eq!(
        canonical_path(&escaped),
        r#"["quote\" slash\\ dots. brackets[]"]"#
    );
}

#[test]
fn exact_node_rule_precedes_wildcard_rule() {
    let policy = FieldPolicy::new(
        vec![
            field_rule(
                "wildcard",
                &["*"],
                "Properties.Name",
                FieldOperation::ReplaceOpaque,
                None,
            ),
            field_rule(
                "group-name",
                &["Group"],
                "properties.name",
                FieldOperation::MapIdentity,
                Some("accounts"),
            ),
        ],
        PolicyConfig::default(),
    )
    .unwrap();

    let ctx_group = context("Group", PrivacyClass::Custom, None);
    let ctx_user = context("User", PrivacyClass::Custom, None);
    assert_eq!(
        policy
            .resolve(&ctx_group, "PROPERTIES.name", &json!("Vault"), None)
            .rule_id,
        "group-name"
    );
    assert_eq!(
        policy
            .resolve(&ctx_user, "properties.name", &json!("Vault"), None)
            .rule_id,
        "wildcard"
    );
}

#[test]
fn known_paths_and_prefixes_are_scoped_to_exact_or_wildcard_node_type() {
    let policy = FieldPolicy::new(
        vec![
            field_rule(
                "wildcard",
                &["*"],
                "Shared.Items[].Value",
                FieldOperation::ReplaceOpaque,
                None,
            ),
            field_rule(
                "group-only",
                &["Group"],
                "GroupOnly.Secret",
                FieldOperation::ReplaceOpaque,
                None,
            ),
        ],
        PolicyConfig::default(),
    )
    .unwrap();

    let user = context("User", PrivacyClass::Custom, None);
    let group = context("Group", PrivacyClass::Custom, None);
    assert!(policy.is_known_prefix(&user, "Shared"));
    assert!(!policy.is_known_prefix(&user, "Shared[0].Items"));
    assert!(policy.is_known_path(&user, "Shared.Items[0].Value"));
    assert!(policy.is_known_prefix(&group, "GroupOnly"));
    assert!(policy.is_known_path(&group, "GroupOnly.Secret"));
    assert!(!policy.is_known_prefix(&user, "GroupOnly"));
    assert!(!policy.is_known_path(&user, "GroupOnly.Secret"));
    assert!(!policy.is_known_prefix(&group, "FutureIndex"));
    assert!(!policy.is_known_prefix(&group, "grouponly"));
    assert!(!policy.is_known_path(&group, "GroupOnly.secret"));
}

#[test]
fn feature_profiles_are_disabled_by_default() {
    let config = PolicyConfig::default();
    assert!(config.preserve_core_global_defaults);
    assert!(!config.preserve_microsoft_feature_defaults);
    assert!(!config.preserve_third_party_defaults);
}

#[test]
fn policy_audit_summary_contains_no_source_values() {
    let ctx = context("Group", PrivacyClass::Custom, None);
    let decision = FieldDecision {
        rule_id: "fallback.unknown-string".to_string(),
        operation: FieldOperation::ReplaceOpaque,
        namespace: Some("opaque".to_string()),
        privacy: PrivacyClass::Custom,
        audit_code: Some("unknown-string-path".to_string()),
        evidence: None,
    };
    let mut audit = PolicyAudit::new();
    for (path, source) in [
        ("Novel.Zeta", "Contoso secret"),
        ("Novel.Alpha", "Fabrikam secret"),
    ] {
        audit.record(&DecisionRecord {
            context: ctx.clone(),
            path: path.to_string(),
            decision: decision.clone(),
            source_value: source.to_string(),
            output_value: "[REDACTED]".to_string(),
        });
    }
    let summary = audit.summary();
    assert_eq!(summary["privacy_classes"], json!({"custom": 2}));
    assert_eq!(summary["operations"], json!({"replace_opaque": 2}));
    assert_eq!(summary["rule_ids"], json!({"fallback.unknown-string": 2}));
    assert_eq!(summary["audit_codes"], json!({"unknown-string-path": 2}));
    let unknown: Vec<&str> = summary["unknown_paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(unknown, ["novel.alpha", "novel.zeta"]);
    let repr = summary.to_string().to_lowercase();
    assert!(!repr.contains("contoso"));
    assert!(!repr.contains("fabrikam"));
}
