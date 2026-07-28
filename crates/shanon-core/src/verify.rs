//! Independent, field-decision-aware verification of transformed documents.
//!
//! The verifier re-resolves policy and re-derives the exact expected output for
//! every string leaf **without trusting the engine's transform records**, then
//! compares. Any divergence is reported as a sanitized [`VerificationFinding`]
//! whose `offender` is a BLAKE2b-6 fingerprint (§3.1a) —
//! real source/output values are never retained. The finding's textual shape
//! (`gate`, `member`, `path`, `policy_code`, `offender`) is part of the
//! byte-parity/error contract: the CLI formats it into the aborted-leak block.

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};

use crate::casefold::casefold;
use crate::catalog::{match_catalog, IdentifierKind, PrivacyClass};
use crate::components::{
    transform_ad_local_group_name, transform_dn, transform_dnshostname, transform_domain,
    transform_email, transform_guid, transform_name_token, transform_oid, transform_samaccountname,
    transform_sid, transform_spn, transform_upn_name, ACCOUNTS, CERT_TEMPLATES, DOMAINS, GUIDS,
    HOSTS, OIDS, OPAQUE, SIDS,
};
use crate::engine::{
    classify_object, normalize_node_type, DomainRidTargetEvidence, TemplateTargetEvidence,
    VerificationContext,
};
use crate::policy::{
    array_path, canonical_path, object_path, redact_functional_level_number, DecisionRecord,
    FieldDecision, FieldOperation, FieldPolicy, ObjectContext,
};
use crate::progress::{self, ProgressSink};
use crate::registry::Registry;

// ---------------------------------------------------------------------------
// Shape matchers (module-level regexes).
// ---------------------------------------------------------------------------

fn sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:.+-)?S-\d+-\d+(?:-\d+)+$").unwrap())
}

fn guid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)^(?:",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            r"|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
            r"|[0-9a-f]{32}",
            r")$",
        ))
        .unwrap()
    })
}

fn oid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]+(?:\.[0-9]+){2,}$").unwrap())
}

fn domain_rid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$").unwrap())
}

fn redacted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\[REDACTED(?::[a-z2-7]+)?\]$").unwrap())
}

fn array_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[0-9]+\]$").unwrap())
}

fn secret_material_keys() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "cleartextpassword",
            "lmhash",
            "lmpwdhistory",
            "nthash",
            "ntpwdhistory",
            "sfupassword",
            "supplementalcredentials",
            "unicodepassword",
            "unicodepwd",
            "unixpassword",
            "userpassword",
        ]
        .into_iter()
        .collect()
    })
}

// ---------------------------------------------------------------------------
// Finding + leaf.
// ---------------------------------------------------------------------------

/// One sanitized verifier failure; source and output values are never retained
/// (`VerificationFinding`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationFinding {
    pub gate: String,
    pub member: String,
    pub path: String,
    pub policy_code: String,
    pub offender: String,
}

#[derive(Clone)]
struct SourceLeaf {
    policy_path: String,
    value: String,
    context: ObjectContext,
    reference_node_type: Option<String>,
}

/// `blake2b(value, digest_size=6).hexdigest()` (§3.1a leak-gate token).
fn fingerprint(value: &str) -> String {
    use blake2::digest::consts::U6;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U6>::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(12);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn finding(member: &str, path: &str, policy_code: &str, source_value: &str) -> VerificationFinding {
    VerificationFinding {
        gate: "contextual-verification".to_string(),
        member: member.to_string(),
        path: path.to_string(),
        policy_code: policy_code.to_string(),
        offender: fingerprint(source_value),
    }
}

fn join(path: &str, child: &str) -> String {
    object_path(path, child)
}

// ---------------------------------------------------------------------------
// Context construction.
// ---------------------------------------------------------------------------

fn document_context(member: &str, source: &Map<String, Value>) -> ObjectContext {
    let node_type = match source.get("meta").and_then(|v| v.as_object()) {
        Some(meta) => normalize_node_type(meta.get("type")),
        None => normalize_node_type(None),
    };
    let privacy = if node_type == "Unknown" {
        PrivacyClass::Unknown
    } else {
        PrivacyClass::Custom
    };
    ObjectContext {
        node_type,
        member: member.to_string(),
        index: usize::MAX,
        object_identifier: None,
        privacy,
        catalog_rule_id: None,
    }
}

fn object_contexts(member: &str, source: &Map<String, Value>) -> Vec<ObjectContext> {
    let meta = source.get("meta").and_then(|v| v.as_object());
    let data = source.get("data").and_then(|v| v.as_array());
    let (meta, data) = match (meta, data) {
        (Some(m), Some(d)) => (m, d),
        _ => return Vec::new(),
    };
    let node_type = normalize_node_type(meta.get("type"));
    let mut contexts = Vec::new();
    for (index, item) in data.iter().enumerate() {
        let item = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let identifier = item
            .get("ObjectIdentifier")
            .and_then(|v| v.as_str())
            .map(String::from);
        let matched = if node_type == "Unknown" {
            None
        } else {
            classify_object(&node_type, item)
        };
        let (privacy, catalog_rule_id) = if node_type == "Unknown" {
            (PrivacyClass::Unknown, None)
        } else if let Some(m) = &matched {
            (m.entry.privacy, Some(m.entry.rule_id.clone()))
        } else {
            (PrivacyClass::Custom, None)
        };
        contexts.push(ObjectContext {
            node_type: node_type.clone(),
            member: member.to_string(),
            index,
            object_identifier: identifier,
            privacy,
            catalog_rule_id,
        });
    }
    contexts
}

// ---------------------------------------------------------------------------
// Projected source (`_project_contextual_source` / `_projected_source`).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn project_contextual_source(
    member: &str,
    value: &Value,
    context: &ObjectContext,
    policy_path: &str,
    record_path: &str,
    field_policy: &FieldPolicy,
    reg: &mut Registry,
    leaves: &mut IndexMap<String, SourceLeaf>,
    findings: &mut Vec<VerificationFinding>,
    reference_node_type: Option<&str>,
) -> Value {
    match value {
        Value::Object(map) => {
            let mut sibling_object_type: Option<&str> = None;
            let mut sibling_principal_type: Option<&str> = None;
            for (key, child) in map {
                let folded = casefold(key);
                if let Some(s) = child.as_str() {
                    if folded == "objecttype" {
                        sibling_object_type = Some(s);
                    } else if folded == "principaltype" {
                        sibling_principal_type = Some(s);
                    }
                }
            }
            let sibling_reference_type = sibling_principal_type
                .or(sibling_object_type)
                .map(str::to_string);
            let mut projected = Map::new();
            for (key, child) in map {
                let policy_child = join(policy_path, key);
                let projected_key = if field_policy.is_known_key(context, policy_path, key) {
                    key.clone()
                } else {
                    match reg.map(OPAQUE, key) {
                        Ok(k) => k,
                        Err(_) => {
                            findings.push(finding(
                                member,
                                record_path,
                                "registry-mapping-missing",
                                key,
                            ));
                            continue;
                        }
                    }
                };
                if projected.contains_key(&projected_key) {
                    findings.push(finding(member, record_path, "output-key-collision", key));
                    continue;
                }
                let projected_child = join(record_path, &projected_key);
                let child_value = project_contextual_source(
                    member,
                    child,
                    context,
                    &policy_child,
                    &projected_child,
                    field_policy,
                    reg,
                    leaves,
                    findings,
                    sibling_reference_type.as_deref(),
                );
                projected.insert(projected_key, child_value);
            }
            Value::Object(projected)
        }
        Value::Array(items) => {
            let mut projected_list = Vec::with_capacity(items.len());
            for (index, child) in items.iter().enumerate() {
                projected_list.push(project_contextual_source(
                    member,
                    child,
                    context,
                    &array_path(policy_path, index),
                    &array_path(record_path, index),
                    field_policy,
                    reg,
                    leaves,
                    findings,
                    None,
                ));
            }
            Value::Array(projected_list)
        }
        Value::String(s) => {
            leaves.insert(
                record_path.to_string(),
                SourceLeaf {
                    policy_path: policy_path.to_string(),
                    value: s.clone(),
                    context: context.clone(),
                    reference_node_type: reference_node_type.map(str::to_string),
                },
            );
            value.clone()
        }
        _ => value.clone(),
    }
}

fn projected_source(
    member: &str,
    source: &Map<String, Value>,
    field_policy: &FieldPolicy,
    reg: &mut Registry,
    findings: &mut Vec<VerificationFinding>,
    progress: Option<&ProgressSink>,
) -> (Map<String, Value>, IndexMap<String, SourceLeaf>) {
    let mut leaves: IndexMap<String, SourceLeaf> = IndexMap::new();
    let mut projected: Map<String, Value> = Map::new();
    let doc_context = document_context(member, source);

    if let Some(meta) = source.get("meta") {
        let meta_projected = project_contextual_source(
            member,
            meta,
            &doc_context,
            "meta",
            "meta",
            field_policy,
            reg,
            &mut leaves,
            findings,
            None,
        );
        projected.insert("meta".to_string(), meta_projected);
    }

    let contexts = object_contexts(member, source);
    if let Some(data) = source.get("data").and_then(|v| v.as_array()) {
        let mut projected_data = Vec::with_capacity(data.len());
        for (index, item) in data.iter().enumerate() {
            let context = contexts.get(index).unwrap_or(&doc_context);
            projected_data.push(project_contextual_source(
                member,
                item,
                context,
                "",
                &array_path("data", index),
                field_policy,
                reg,
                &mut leaves,
                findings,
                None,
            ));
            // Mirrors the engine's per-object tick, so a member costs the same
            // number of work units to verify as it did to transform.
            progress::tick(progress);
        }
        projected.insert("data".to_string(), Value::Array(projected_data));
    } else if let Some(data) = source.get("data") {
        projected.insert("data".to_string(), data.clone());
    }

    let mut projected_root_keys: HashSet<String> = projected.keys().cloned().collect();
    for (key, value) in source {
        if key == "meta" || key == "data" {
            continue;
        }
        let policy_path = object_path("", key);
        let projected_key = if field_policy.is_known_key(&doc_context, "", key) {
            key.clone()
        } else {
            match reg.map(OPAQUE, key) {
                Ok(k) => k,
                Err(_) => {
                    findings.push(finding(member, "", "registry-mapping-missing", key));
                    continue;
                }
            }
        };
        if projected_root_keys.contains(&projected_key) {
            findings.push(finding(member, "", "output-key-collision", key));
            continue;
        }
        projected_root_keys.insert(projected_key.clone());
        let record_path = object_path("", &projected_key);
        let child = project_contextual_source(
            member,
            value,
            &doc_context,
            &policy_path,
            &record_path,
            field_policy,
            reg,
            &mut leaves,
            findings,
            None,
        );
        projected.insert(projected_key, child);
    }

    (projected, leaves)
}

// ---------------------------------------------------------------------------
// Flat value model (`_flat_values`).
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
enum Flat {
    Mapping(BTreeSet<String>),
    List(usize),
    Str(String),
    Int(String),
    Float(String),
    Bool(bool),
    Null,
}

#[derive(PartialEq, Eq)]
enum Ty {
    Tuple,
    Str,
    Int,
    Float,
    Bool,
    Null,
}

impl Flat {
    fn ty(&self) -> Ty {
        match self {
            Flat::Mapping(_) | Flat::List(_) => Ty::Tuple,
            Flat::Str(_) => Ty::Str,
            Flat::Int(_) => Ty::Int,
            Flat::Float(_) => Ty::Float,
            Flat::Bool(_) => Ty::Bool,
            Flat::Null => Ty::Null,
        }
    }
}

fn number_is_float(token: &str) -> bool {
    token.contains('.') || token.contains('e') || token.contains('E')
}

fn flat_scalar(value: &Value) -> Flat {
    match value {
        Value::String(s) => Flat::Str(s.clone()),
        Value::Bool(b) => Flat::Bool(*b),
        Value::Null => Flat::Null,
        Value::Number(n) => {
            let token = n.to_string();
            if number_is_float(&token) {
                Flat::Float(token)
            } else {
                Flat::Int(token)
            }
        }
        _ => unreachable!("flat_scalar called on container"),
    }
}

fn flat_values(value: &Value, path: &str, out: &mut IndexMap<String, Flat>) {
    match value {
        Value::Object(map) => {
            let keys: BTreeSet<String> = map.keys().cloned().collect();
            out.insert(path.to_string(), Flat::Mapping(keys));
            for (key, child) in map {
                flat_values(child, &join(path, key), out);
            }
        }
        Value::Array(items) => {
            out.insert(path.to_string(), Flat::List(items.len()));
            for (index, child) in items.iter().enumerate() {
                flat_values(child, &array_path(path, index), out);
            }
        }
        other => {
            out.insert(path.to_string(), flat_scalar(other));
        }
    }
}

// ---------------------------------------------------------------------------
// Target evidence validation.
// ---------------------------------------------------------------------------

fn validated_template_targets(
    member: &str,
    ctx: &VerificationContext,
    findings: &mut Vec<VerificationFinding>,
) -> IndexMap<String, TemplateTargetEvidence> {
    let policy = FieldPolicy::defaults_with(ctx.policy.clone());
    let mut valid: IndexMap<String, TemplateTargetEvidence> = IndexMap::new();
    for (key, evidence) in &ctx.catalog_template_targets {
        let matched = match_catalog(
            "CertTemplate",
            IdentifierKind::Template,
            &evidence.source_value,
        );
        let candidate_context = ObjectContext {
            node_type: "CertTemplate".to_string(),
            member: member.to_string(),
            index: usize::MAX,
            object_identifier: None,
            privacy: matched
                .as_ref()
                .map(|m| m.entry.privacy)
                .unwrap_or(PrivacyClass::Unknown),
            catalog_rule_id: matched.as_ref().map(|m| m.entry.rule_id.clone()),
        };
        let decision = policy.resolve(
            &candidate_context,
            &evidence.path,
            &Value::String(evidence.source_value.clone()),
            None,
        );
        let canon = canonical_path(&evidence.path);
        let is_valid = *key == evidence.canonical_identity
            && *key == casefold(&evidence.source_value)
            && evidence.node_type == "CertTemplate"
            && (canon == "properties.name" || canon == "properties.templatename")
            && matched
                .as_ref()
                .map(|m| m.entry.rule_id == evidence.catalog_rule_id)
                .unwrap_or(false)
            && decision.operation == FieldOperation::PreserveConstant;
        if is_valid {
            valid.insert(key.clone(), evidence.clone());
        } else {
            findings.push(finding(
                member,
                &format!(
                    "verification_context.catalog_template_targets[{}]",
                    fingerprint(key)
                ),
                "invalid-target-evidence",
                &evidence.source_value,
            ));
        }
    }
    valid
}

fn validated_domain_rid_targets(
    member: &str,
    ctx: &VerificationContext,
    findings: &mut Vec<VerificationFinding>,
) -> IndexMap<String, DomainRidTargetEvidence> {
    let mut valid: IndexMap<String, DomainRidTargetEvidence> = IndexMap::new();
    for (key, evidence) in &ctx.catalog_domain_rid_targets {
        let caps = domain_rid_re().captures(&evidence.source_identifier);
        let catalog_match = caps.as_ref().and_then(|c| {
            match_catalog(
                &evidence.node_type,
                IdentifierKind::Rid,
                c.get(1).unwrap().as_str(),
            )
        });
        let is_valid = *key == evidence.source_identifier.to_uppercase()
            && catalog_match
                .as_ref()
                .map(|m| {
                    m.entry.rule_id == evidence.catalog_rule_id
                        && m.entry.privacy == PrivacyClass::CoreGlobalDefault
                })
                .unwrap_or(false);
        if is_valid {
            valid.insert(key.clone(), evidence.clone());
        } else {
            findings.push(finding(
                member,
                &format!(
                    "verification_context.catalog_domain_rid_targets[{}]",
                    fingerprint(key)
                ),
                "invalid-target-evidence",
                &evidence.source_identifier,
            ));
        }
    }
    valid
}

// ---------------------------------------------------------------------------
// Expected-decision / expected-output re-derivation.
// ---------------------------------------------------------------------------

fn template_candidate(
    context: &ObjectContext,
    path: &str,
    value: &str,
) -> Option<(String, String)> {
    let lookup_path = canonical_path(path);
    let rule_id = context.catalog_rule_id.as_deref()?;
    if context.node_type != "CertTemplate"
        || !(lookup_path == "properties.name" || lookup_path == "properties.templatename")
    {
        return None;
    }
    let identity = if lookup_path == "properties.name" {
        value.rsplit_once('@').map(|(h, _)| h).unwrap_or(value)
    } else {
        value
    };
    let matched = match_catalog("CertTemplate", IdentifierKind::Template, identity)?;
    if matched.entry.rule_id != rule_id {
        return None;
    }
    Some((casefold(identity), identity.to_string()))
}

fn expected_decision(
    field_policy: &FieldPolicy,
    leaf: &SourceLeaf,
    targets: &IndexMap<String, TemplateTargetEvidence>,
    domain_rid_targets: &IndexMap<String, DomainRidTargetEvidence>,
) -> (FieldDecision, Option<TemplateTargetEvidence>) {
    let mut decision = field_policy.resolve(
        &leaf.context,
        &leaf.policy_path,
        &Value::String(leaf.value.clone()),
        leaf.reference_node_type.as_deref(),
    );

    if let Some(domain_rid_target) = domain_rid_targets.get(&leaf.value.to_uppercase()) {
        let op_ok = matches!(
            decision.operation,
            FieldOperation::MapCustomIdentifier | FieldOperation::MapReference
        );
        let ns_ok = matches!(
            decision.namespace.as_deref(),
            Some(SIDS) | Some("identifiers") | Some("sids_preserve_rid")
        );
        if op_ok && ns_ok {
            decision.namespace = Some("sids_preserve_rid".to_string());
            decision.evidence = Some(format!(
                "discovered-domain-rid-target:{}",
                domain_rid_target.catalog_rule_id
            ));
        }
    }

    let mut target: Option<TemplateTargetEvidence> = None;
    if decision.operation == FieldOperation::MapReference
        && decision.namespace.as_deref() == Some(CERT_TEMPLATES)
    {
        if let Some(t) = targets.get(&casefold(&leaf.value)) {
            target = Some(t.clone());
            decision.evidence = Some(format!("discovered-template-target:{}", t.catalog_rule_id));
        }
    }

    if let Some((canon_identity, _)) =
        template_candidate(&leaf.context, &leaf.policy_path, &leaf.value)
    {
        target = targets.get(&canon_identity).cloned();
    }
    if let Some(t) = &target {
        decision.evidence = Some(format!("discovered-template-target:{}", t.catalog_rule_id));
    } else if decision.operation == FieldOperation::PreserveConstant
        && leaf.context.node_type == "CertTemplate"
        && {
            let canon = canonical_path(&leaf.policy_path);
            canon == "properties.name" || canon == "properties.templatename"
        }
    {
        decision.operation = FieldOperation::MapIdentity;
        decision.namespace = Some(CERT_TEMPLATES.to_string());
        decision.evidence = None;
    }

    (decision, target)
}

fn template_mapping(
    reg: &mut Registry,
    value: &str,
    targets: &IndexMap<String, TemplateTargetEvidence>,
    preserve: bool,
) -> Result<String, ()> {
    if let Some(target) = targets.get(&casefold(value)) {
        return Ok(target.source_value.clone());
    }
    if preserve {
        return Ok(value.to_string());
    }
    let folded = casefold(value);
    let owner = reg
        .category_reals_sorted(CERT_TEMPLATES)
        .into_iter()
        .find(|source| casefold(source) == folded)
        .unwrap_or_else(|| value.to_string());
    reg.map(CERT_TEMPLATES, &owner).map_err(|_| ())
}

fn map_identity(
    reg: &mut Registry,
    field_policy: &FieldPolicy,
    leaf: &SourceLeaf,
    decision: &FieldDecision,
    targets: &IndexMap<String, TemplateTargetEvidence>,
) -> Result<String, ()> {
    let value = &leaf.value;
    let lookup_path = canonical_path(&leaf.policy_path);
    if lookup_path == "properties.name" && value.contains('@') {
        let (identity, domain) = value.rsplit_once('@').unwrap();
        let mut preserve_identity = field_policy
            .resolve(
                &leaf.context,
                &leaf.policy_path,
                &Value::String(identity.to_string()),
                None,
            )
            .operation
            == FieldOperation::PreserveConstant;
        let mapped_identity = if decision.namespace.as_deref() == Some(CERT_TEMPLATES) {
            preserve_identity = template_candidate(&leaf.context, &leaf.policy_path, identity)
                .is_some()
                && targets.contains_key(&casefold(identity));
            template_mapping(reg, identity, targets, preserve_identity)?
        } else {
            let mapped = transform_name_token(reg, identity, preserve_identity);
            check_registry(reg)?;
            mapped
        };
        let mapped_domain = transform_domain(reg, domain);
        check_registry(reg)?;
        return Ok(format!("{mapped_identity}@{mapped_domain}"));
    }
    match decision.namespace.as_deref() {
        Some(DOMAINS) => {
            let out = transform_domain(reg, value);
            check_registry(reg)?;
            Ok(out)
        }
        Some(HOSTS) => {
            let out = transform_dnshostname(reg, value);
            check_registry(reg)?;
            Ok(out)
        }
        Some(CERT_TEMPLATES) => template_mapping(reg, value, targets, false),
        Some(ACCOUNTS) => {
            let out = if lookup_path == "properties.samaccountname" {
                transform_samaccountname(reg, value)
            } else if lookup_path == "properties.userprincipalname" {
                transform_upn_name(reg, value)
            } else if lookup_path == "properties.email" || lookup_path == "properties.mail" {
                let mapped = transform_email(reg, value);
                check_registry(reg)?;
                if mapped != *value || value.contains('@') {
                    mapped
                } else {
                    transform_name_token(reg, value, false)
                }
            } else {
                transform_name_token(reg, value, false)
            };
            check_registry(reg)?;
            Ok(out)
        }
        _ => Err(()),
    }
}

fn map_custom_identifier(
    reg: &mut Registry,
    value: &str,
    decision: &FieldDecision,
) -> Result<String, ()> {
    if sid_re().is_match(value) {
        let out = transform_sid(
            reg,
            value,
            decision.namespace.as_deref() == Some("sids_preserve_rid"),
        );
        check_registry(reg)?;
        return Ok(out);
    }
    if guid_re().is_match(value) {
        let out = transform_guid(reg, value, false);
        check_registry(reg)?;
        return Ok(out);
    }
    if oid_re().is_match(value) {
        let out = transform_oid(reg, value, false);
        check_registry(reg)?;
        return Ok(out);
    }
    reg.map(OPAQUE, value).map_err(|_| ())
}

fn map_reference(
    reg: &mut Registry,
    value: &str,
    decision: &FieldDecision,
    targets: &IndexMap<String, TemplateTargetEvidence>,
) -> Result<String, ()> {
    let out = match decision.namespace.as_deref() {
        Some("sids_preserve_rid") => transform_sid(reg, value, true),
        Some(SIDS) => transform_sid(reg, value, false),
        Some(GUIDS) => transform_guid(reg, value, false),
        Some(OIDS) => transform_oid(reg, value, false),
        Some(CERT_TEMPLATES) => return template_mapping(reg, value, targets, false),
        Some(ACCOUNTS) => transform_name_token(reg, value, false),
        Some(DOMAINS) => transform_domain(reg, value),
        Some(HOSTS) => transform_dnshostname(reg, value),
        Some("identifiers") => return map_custom_identifier(reg, value, decision),
        _ => return Err(()),
    };
    check_registry(reg)?;
    Ok(out)
}

fn check_registry(reg: &mut Registry) -> Result<(), ()> {
    if reg.take_trait_error().is_some() {
        Err(())
    } else {
        Ok(())
    }
}

fn expected_output(
    reg: &mut Registry,
    field_policy: &FieldPolicy,
    leaf: &SourceLeaf,
    decision: &FieldDecision,
    target: &Option<TemplateTargetEvidence>,
    targets: &IndexMap<String, TemplateTargetEvidence>,
) -> Result<String, ()> {
    match decision.operation {
        FieldOperation::PreserveConstant | FieldOperation::PreserveSchemaValue => Ok(target
            .as_ref()
            .map(|t| t.source_value.clone())
            .unwrap_or_else(|| leaf.value.clone())),
        FieldOperation::MapIdentity => map_identity(reg, field_policy, leaf, decision, targets),
        FieldOperation::MapReference => map_reference(reg, &leaf.value, decision, targets),
        FieldOperation::ParseDn => {
            let ctx = leaf.context.clone();
            let policy_path = leaf.policy_path.clone();
            let preserve = |_attribute: &str, rdn: &str| -> bool {
                field_policy
                    .resolve(&ctx, &policy_path, &Value::String(rdn.to_string()), None)
                    .operation
                    == FieldOperation::PreserveConstant
            };
            let out = transform_dn(reg, &leaf.value, Some(&preserve));
            check_registry(reg)?;
            Ok(out)
        }
        FieldOperation::ParseSpn => {
            let transformed = transform_spn(reg, &leaf.value);
            check_registry(reg)?;
            if transformed != leaf.value {
                Ok(transformed)
            } else {
                reg.map(OPAQUE, &leaf.value).map_err(|_| ())
            }
        }
        FieldOperation::ParseComposite => {
            let mut preserve_group = false;
            if leaf.value.contains('@') {
                let group = leaf.value.rsplit_once('@').unwrap().0;
                preserve_group = field_policy
                    .resolve(
                        &leaf.context,
                        &leaf.policy_path,
                        &Value::String(group.to_string()),
                        None,
                    )
                    .operation
                    == FieldOperation::PreserveConstant;
            }
            let out = transform_ad_local_group_name(reg, &leaf.value, preserve_group);
            check_registry(reg)?;
            Ok(out)
        }
        FieldOperation::MapCustomIdentifier => map_custom_identifier(reg, &leaf.value, decision),
        FieldOperation::ReplaceOpaque => {
            if leaf.value.is_empty() {
                return Ok(leaf.value.clone());
            }
            let last_segment = leaf
                .policy_path
                .rsplit_once('.')
                .map(|(_, b)| b)
                .unwrap_or(&leaf.policy_path);
            let leaf_key = casefold(&array_suffix_re().replace(last_segment, ""));
            if secret_material_keys().contains(leaf_key.as_str()) {
                return Ok("[REDACTED]".to_string());
            }
            reg.map(OPAQUE, &leaf.value).map_err(|_| ())
        }
    }
}

fn output_mismatch_code(decision: &FieldDecision, actual: Option<&Flat>, source: &str) -> String {
    if decision.operation == FieldOperation::MapReference {
        return "reference-mapping-mismatch".to_string();
    }
    if decision.operation == FieldOperation::MapIdentity {
        if let Some(Flat::Str(s)) = actual {
            if s == source {
                return "identity-not-transformed".to_string();
            }
        }
    }
    "mapped-value-mismatch".to_string()
}

fn output_shape_valid(
    leaf: &SourceLeaf,
    decision: &FieldDecision,
    output_value: Option<&Flat>,
) -> bool {
    let output = match output_value {
        Some(Flat::Str(s)) => s.as_str(),
        _ => return false,
    };
    let source = &leaf.value;
    match decision.operation {
        FieldOperation::MapCustomIdentifier | FieldOperation::MapReference => {
            if sid_re().is_match(source) {
                return sid_re().is_match(output);
            }
            if guid_re().is_match(source) {
                return guid_re().is_match(output);
            }
            if oid_re().is_match(source) {
                return oid_re().is_match(output);
            }
            true
        }
        FieldOperation::MapIdentity => {
            if source.contains('@') {
                let parts: Vec<&str> = output.split('@').collect();
                parts.len() == 2 && parts.iter().all(|p| !p.is_empty())
            } else if matches!(decision.namespace.as_deref(), Some(DOMAINS) | Some(HOSTS)) {
                !output.is_empty() && output.split('.').all(|p| !p.is_empty())
            } else {
                true
            }
        }
        FieldOperation::ParseDn => output.split(',').all(|rdn| {
            rdn.split('+').all(|component| {
                component.contains('=') && component.splitn(2, '=').all(|p| !p.is_empty())
            })
        }),
        FieldOperation::ParseSpn => {
            let components: Vec<&str> = output.split('/').collect();
            matches!(components.len(), 2 | 3) && components.iter().all(|c| !c.is_empty())
        }
        FieldOperation::ParseComposite if source.contains('@') => {
            let group_and_host: Vec<&str> = output.rsplitn(2, '@').collect();
            group_and_host.len() == 2 && group_and_host.iter().all(|p| !p.is_empty())
        }
        FieldOperation::ReplaceOpaque if !source.is_empty() => redacted_re().is_match(output),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Source-shape validation.
// ---------------------------------------------------------------------------

fn source_validation_findings(
    member: &str,
    source: &Map<String, Value>,
) -> Vec<VerificationFinding> {
    let mut findings = Vec::new();
    let meta = match source.get("meta").and_then(|v| v.as_object()) {
        Some(m) => m,
        None => return vec![finding(member, "meta", "source-invalid-meta", "")],
    };
    match meta.get("type") {
        Some(Value::String(s)) if !s.is_empty() => {}
        Some(Value::String(s)) => {
            findings.push(finding(member, "meta.type", "source-invalid-meta-type", s));
        }
        _ => {
            findings.push(finding(member, "meta.type", "source-invalid-meta-type", ""));
        }
    }
    let data = match source.get("data").and_then(|v| v.as_array()) {
        Some(d) => d,
        None => {
            findings.push(finding(member, "data", "source-invalid-data", ""));
            return findings;
        }
    };
    let count_ok = match meta.get("count") {
        Some(Value::Number(n)) if !number_is_float(&n.to_string()) => {
            n.as_i64().map(|c| c == data.len() as i64).unwrap_or(false)
        }
        _ => false,
    };
    if !count_ok {
        findings.push(finding(
            member,
            "meta.count",
            "source-invalid-meta-count",
            "",
        ));
    }
    for (index, item) in data.iter().enumerate() {
        if !item.is_object() {
            let offender = item.as_str().unwrap_or("");
            findings.push(finding(
                member,
                &array_path("data", index),
                "source-invalid-data-item",
                offender,
            ));
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Top-level verification.
// ---------------------------------------------------------------------------

/// Re-resolve policy and exact output without trusting transform records
/// (`verify_document`).
pub fn verify_document(
    member: &str,
    source: &Map<String, Value>,
    output: &Map<String, Value>,
    records: &[DecisionRecord],
    reg: &mut Registry,
    verification_context: &VerificationContext,
) -> Vec<VerificationFinding> {
    verify_document_with_progress(
        member,
        source,
        output,
        records,
        reg,
        verification_context,
        None,
    )
}

/// [`verify_document`], ticking `progress` once per top-level `data` object.
///
/// The sink is write-only: no finding, decision, or comparison ever reads it
/// back, so the returned findings are identical with or without one installed.
pub fn verify_document_with_progress(
    member: &str,
    source: &Map<String, Value>,
    output: &Map<String, Value>,
    records: &[DecisionRecord],
    reg: &mut Registry,
    verification_context: &VerificationContext,
    progress: Option<&ProgressSink>,
) -> Vec<VerificationFinding> {
    let mut findings: Vec<VerificationFinding> = Vec::new();

    if reg.validate_trust_root().is_err() {
        findings.push(finding(member, "", "unsafe-registry", ""));
        return findings;
    }
    if !reg.is_frozen() {
        findings.push(finding(member, "", "registry-not-frozen", ""));
        return findings;
    }

    let source_findings = source_validation_findings(member, source);
    if !source_findings.is_empty() {
        return source_findings;
    }

    let before = reg.verification_snapshot();

    let targets = validated_template_targets(member, verification_context, &mut findings);
    let domain_rid_targets =
        validated_domain_rid_targets(member, verification_context, &mut findings);
    let field_policy = FieldPolicy::defaults_with(verification_context.policy.clone());
    let (projected, leaves) =
        projected_source(member, source, &field_policy, reg, &mut findings, progress);

    let mut source_flat: IndexMap<String, Flat> = IndexMap::new();
    flat_values(&Value::Object(projected), "", &mut source_flat);
    let mut output_flat: IndexMap<String, Flat> = IndexMap::new();
    flat_values(&Value::Object(output.clone()), "", &mut output_flat);

    let mut union: BTreeSet<String> = BTreeSet::new();
    union.extend(source_flat.keys().cloned());
    union.extend(output_flat.keys().cloned());
    for path in &union {
        let in_source = source_flat.contains_key(path);
        let in_output = output_flat.contains_key(path);
        if !in_source || !in_output {
            let offender = match source_flat.get(path) {
                Some(Flat::Str(s)) => s.clone(),
                _ => String::new(),
            };
            findings.push(finding(
                member,
                if in_source { path } else { "" },
                "source-output-topology-mismatch",
                &offender,
            ));
            continue;
        }
        let s = &source_flat[path];
        let o = &output_flat[path];
        if s.ty() != o.ty() {
            let offender = match s {
                Flat::Str(v) => v.clone(),
                _ => String::new(),
            };
            findings.push(finding(member, path, "value-type-mismatch", &offender));
        } else if canonical_path(path).ends_with("properties.functionallevel")
            && matches!(s, Flat::Int(_) | Flat::Float(_))
        {
            let src_token = match s {
                Flat::Int(t) | Flat::Float(t) => t.as_str(),
                _ => unreachable!(),
            };
            let out_token = match o {
                Flat::Int(t) | Flat::Float(t) => t.as_str(),
                _ => unreachable!(),
            };
            let src_val: Value = serde_json::from_str(src_token).unwrap_or(Value::Null);
            let out_val: Value = serde_json::from_str(out_token).unwrap_or(Value::Null);
            let expected = redact_functional_level_number(&src_val).ok();
            if expected.as_ref() != Some(&out_val) {
                findings.push(finding(member, path, "schema-value-mismatch", ""));
            }
        } else if !matches!(s, Flat::Str(_) | Flat::Mapping(_) | Flat::List(_)) && s != o {
            findings.push(finding(member, path, "schema-value-mismatch", ""));
        } else if matches!(s, Flat::Mapping(_) | Flat::List(_)) && s != o {
            findings.push(finding(member, path, "source-output-topology-mismatch", ""));
        }
    }

    let mut records_by_path: IndexMap<String, Vec<&DecisionRecord>> = IndexMap::new();
    for record in records {
        records_by_path
            .entry(record.path.clone())
            .or_default()
            .push(record);
    }

    for (path, output_value) in &output_flat {
        if matches!(output_value, Flat::Str(_))
            && !leaves.contains_key(path)
            && records_by_path
                .get(path)
                .map(|r| r.is_empty())
                .unwrap_or(true)
        {
            findings.push(finding(
                member,
                if source_flat.contains_key(path) {
                    path
                } else {
                    ""
                },
                "record-missing",
                "",
            ));
        }
    }

    for (path, leaf) in &leaves {
        let path_records = records_by_path.get(path).cloned().unwrap_or_default();
        if path_records.is_empty() {
            findings.push(finding(member, path, "record-missing", &leaf.value));
            continue;
        }
        if path_records.len() != 1 {
            findings.push(finding(member, path, "record-duplicate", &leaf.value));
            continue;
        }
        let record = path_records[0];
        let (expected_decision_value, target) =
            expected_decision(&field_policy, leaf, &targets, &domain_rid_targets);
        if record.context != leaf.context || record.decision != expected_decision_value {
            findings.push(finding(member, path, "policy-record-mismatch", &leaf.value));
        }
        let actual = output_flat.get(path);
        let actual_str = match actual {
            Some(Flat::Str(s)) => Some(s.clone()),
            _ => None,
        };
        if record.source_value != leaf.value || Some(&record.output_value) != actual_str.as_ref() {
            findings.push(finding(member, path, "policy-record-mismatch", &leaf.value));
        }
        reg.take_trait_error();
        let expected = match expected_output(
            reg,
            &field_policy,
            leaf,
            &expected_decision_value,
            &target,
            &targets,
        ) {
            Ok(s) if reg.take_trait_error().is_none() => s,
            _ => {
                findings.push(finding(
                    member,
                    path,
                    "registry-mapping-missing",
                    &leaf.value,
                ));
                continue;
            }
        };
        let actual_matches = actual_str.as_deref() == Some(expected.as_str());
        if !actual_matches {
            findings.push(finding(
                member,
                path,
                &output_mismatch_code(&expected_decision_value, actual, &leaf.value),
                &leaf.value,
            ));
        }
        if !output_shape_valid(leaf, &expected_decision_value, actual) {
            findings.push(finding(member, path, "output-shape-mismatch", &leaf.value));
        }
    }

    for (path, path_records) in &records_by_path {
        if !leaves.contains_key(path) {
            let source_value = path_records
                .first()
                .map(|r| r.source_value.as_str())
                .unwrap_or("");
            findings.push(finding(member, "", "record-extra", source_value));
        }
    }

    let after = reg.verification_snapshot();
    if after.changed_from(&before) {
        findings.push(finding(member, "", "registry-state-changed", ""));
    }
    findings
}
