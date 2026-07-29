//! Object classification and document normalization.
//! (module 8, P2).
//!
//! The engine is a generic JSON walker over [`serde_json::Value`] (parsed with
//! `preserve_order` + `arbitrary_precision`, §3.1a) — there are **no typed
//! structs per SharpHound kind** (§3.4/R4). Object-key insertion order is
//! preserved end-to-end (`serde_json::Map` is `IndexMap`-backed under
//! `preserve_order`), which output byte-parity depends on (§3.2). Dynamic
//! object-key anonymization (commit b09d3c0) is covered: unknown keys are mapped
//! into the `opaque` namespace and audited.
//!
//! Registry allocation flows through the infallible `RegistryOps` transforms,
//! so after every registry-driving step the engine drains
//! [`Registry::take_trait_error`] via [`AnonymizationEngine::check_registry`] and
//! surfaces it as an [`EngineError`].

use std::collections::HashSet;
use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};

use crate::casefold::casefold;
use crate::catalog::{match_catalog, CatalogMatch, IdentifierKind, PrivacyClass};
use crate::components::{
    sid_identity, transform_ad_local_group_name, transform_dn, transform_dnshostname,
    transform_domain, transform_email, transform_guid, transform_name_token, transform_oid,
    transform_samaccountname, transform_sid, transform_spn, transform_upn_name, ACCOUNTS,
    CERT_TEMPLATES, DOMAINS, GUIDS, HOSTS, OIDS, OPAQUE, SIDS,
};
use crate::policy::{
    array_path, canonical_path, object_path, redact_functional_level_number, DecisionRecord,
    FieldDecision, FieldOperation, FieldPolicy, ObjectContext, PolicyAudit, PolicyConfig,
};
use crate::progress::{self, ProgressSink};
use crate::registry::{Registry, RegistryError};

// ---------------------------------------------------------------------------
// Static tables / regexes (module constants).
// ---------------------------------------------------------------------------

/// `NODE_TYPES`: casefolded SharpHound collection type -> node type.
fn node_type_for(meta_type_casefold: &str) -> &'static str {
    match meta_type_casefold {
        "adlocalgroups" => "ADLocalGroup",
        "aiacas" => "AIACA",
        "base" => "Base",
        "certtemplates" => "CertTemplate",
        "computers" => "Computer",
        "containers" => "Container",
        "domains" => "Domain",
        "enterprisecas" => "EnterpriseCA",
        "foreignsecurityprincipals" => "Base",
        "gpos" => "GPO",
        "groups" => "Group",
        "issuancepolicies" => "IssuancePolicy",
        "meta" => "Meta",
        "ntauthstores" => "NTAuthStore",
        "ous" => "OU",
        "rootcas" => "RootCA",
        "users" => "User",
        _ => "Unknown",
    }
}

fn domain_sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$").unwrap())
}

fn sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:.+-)?S-\d+-\d+(?:-\d+)+$").unwrap())
}

fn guid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}|[0-9a-f]{32})$",
        )
        .unwrap()
    })
}

fn oid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]+(?:\.[0-9]+){2,}$").unwrap())
}

/// `_VisitMode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum VisitMode {
    Discover,
    Transform,
}

// ---------------------------------------------------------------------------
// Evidence + verification context.
// ---------------------------------------------------------------------------

/// `TemplateTargetEvidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateTargetEvidence {
    pub canonical_identity: String,
    pub source_value: String,
    pub catalog_rule_id: String,
    pub node_type: String,
    pub path: String,
}

/// `DomainRidTargetEvidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRidTargetEvidence {
    pub source_identifier: String,
    pub catalog_rule_id: String,
    pub node_type: String,
}

/// `VerificationContext`: an immutable collection-wide evidence snapshot for
/// independent verification (P3 leak gates consume this surface).
#[derive(Clone, Debug)]
pub struct VerificationContext {
    pub catalog_template_targets: IndexMap<String, TemplateTargetEvidence>,
    pub policy: PolicyConfig,
    pub catalog_domain_rid_targets: IndexMap<String, DomainRidTargetEvidence>,
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Where an abort fired, in sanitized form.
///
/// Holds no source value and no source filename (invariant 7): only the
/// synthetic member name the pipeline already assigns, the classified node
/// type, the record path, and a BLAKE2b-6 fingerprint of the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortLocator {
    /// Synthetic member name (`member-00001.json`), never the source filename.
    pub member: Option<String>,
    pub node_type: String,
    /// Record path into the member document, e.g. `data[0].Aces[0].PrincipalSID`.
    pub path: String,
    /// Salt-keyed `blake2b(..., digest_size=6)` of the offender, as in a
    /// leak-gate finding.
    pub offender: String,
}

/// Engine failure surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Propagated `Registry` failure (collision, unsafe mapping, …).
    Registry(RegistryError),
    /// `ValueError` (bad document shape, unsupported namespace/operation).
    Value(String),
    /// `PseudonymCollisionError` (object-key projection collision).
    PseudonymCollision(String),
    /// `RuntimeError` (discovery lifecycle violation).
    Runtime(String),
    /// Any of the above with the leaf it fired on attached. Displays exactly
    /// like the error it wraps, so no existing message text moves; the locator
    /// is reachable only through [`EngineError::locator`].
    Located(Box<EngineError>, AbortLocator),
}

impl EngineError {
    /// The wrapped error, with any locator peeled off.
    pub fn unlocated(&self) -> &EngineError {
        match self {
            EngineError::Located(inner, _) => inner.unlocated(),
            other => other,
        }
    }

    /// The attached locator, if this error was raised at a known leaf.
    pub fn locator(&self) -> Option<&AbortLocator> {
        match self {
            EngineError::Located(_, locator) => Some(locator),
            _ => None,
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Registry(e) => write!(f, "{e}"),
            EngineError::Value(m) => write!(f, "{m}"),
            EngineError::PseudonymCollision(m) => write!(f, "pseudonym collision: {m}"),
            EngineError::Runtime(m) => write!(f, "{m}"),
            // Byte-identical to the wrapped error: the locator is additive
            // diagnostic state, never part of the frozen stderr surface.
            EngineError::Located(inner, _) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<RegistryError> for EngineError {
    fn from(e: RegistryError) -> Self {
        EngineError::Registry(e)
    }
}

type Result<T> = std::result::Result<T, EngineError>;

// ---------------------------------------------------------------------------
// Free functions.
// ---------------------------------------------------------------------------

/// `normalize_node_type`: normalize a SharpHound type without widening unknowns.
pub fn normalize_node_type(meta_type: Option<&Value>) -> String {
    match meta_type.and_then(|v| v.as_str()) {
        None => "Unknown".to_string(),
        Some(s) => node_type_for(&casefold(s)).to_string(),
    }
}

fn properties(obj: &Map<String, Value>) -> Option<&Map<String, Value>> {
    obj.get("Properties").and_then(|v| v.as_object())
}

/// `classify_object`: first authoritative catalog identity match, strongest
/// evidence first. Names never stand in for WKGUID evidence and an unknown
/// collection type never inherits `Base` scope.
pub fn classify_object(node_type: &str, obj: &Map<String, Value>) -> Option<CatalogMatch<'static>> {
    if node_type == "Unknown" {
        return None;
    }

    if let Some(object_identifier) = obj.get("ObjectIdentifier").and_then(|v| v.as_str()) {
        if let Some(full_sid) = match_catalog(node_type, IdentifierKind::Sid, object_identifier) {
            return Some(full_sid);
        }
        if let Some(caps) = domain_sid_re().captures(object_identifier) {
            let rid = caps.get(1).unwrap().as_str();
            if let Some(domain_rid) = match_catalog(node_type, IdentifierKind::Rid, rid) {
                return Some(domain_rid);
            }
        }
        if let Some(fixed_guid) = match_catalog(node_type, IdentifierKind::Guid, object_identifier)
        {
            if fixed_guid.permits("ObjectIdentifier", object_identifier) {
                return Some(fixed_guid);
            }
        }
    }

    let props = properties(obj);
    if let Some(props) = props {
        if let Some(wkguid) = props.get("wkguid").and_then(|v| v.as_str()) {
            if let Some(m) = match_catalog(node_type, IdentifierKind::Wkguid, wkguid) {
                return Some(m);
            }
        }
        if let Some(template_name) = props.get("templatename").and_then(|v| v.as_str()) {
            if let Some(m) = match_catalog(node_type, IdentifierKind::Template, template_name) {
                return Some(m);
            }
        }
        if node_type == "CertTemplate" {
            if let Some(qualified_name) = props.get("name").and_then(|v| v.as_str()) {
                if let Some((identity, domain)) = qualified_name.rsplit_once('@') {
                    if !identity.is_empty() && !domain.is_empty() {
                        if let Some(m) =
                            match_catalog(node_type, IdentifierKind::Template, identity)
                        {
                            return Some(m);
                        }
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// AnonymizationEngine
// ---------------------------------------------------------------------------

/// Build immutable object contexts for SharpHound documents.
pub struct AnonymizationEngine {
    pub registry: Registry,
    pub policy: PolicyConfig,
    pub audit: PolicyAudit,
    field_policy: FieldPolicy,
    template_originals: IndexMap<String, String>,
    preloaded_template_keys: HashSet<String>,
    catalog_template_targets: IndexMap<String, TemplateTargetEvidence>,
    catalog_domain_rid_targets: IndexMap<String, DomainRidTargetEvidence>,
    template_mappings_finalized: bool,
    verification_context: Option<VerificationContext>,
    /// Optional write-only progress channel. Never read back, so installing one
    /// cannot change a single output byte (invariants 1 and 3).
    progress: Option<ProgressSink>,
    /// Synthetic name of the member being walked, for abort locators only.
    current_member: Option<String>,
    /// Sanitized locator for the leaf currently being transformed. Diagnostic
    /// state: read only when building an error, never when producing output.
    abort_locator: Option<AbortLocator>,
}

impl AnonymizationEngine {
    /// Construct an engine (`AnonymizationEngine::new`).
    pub fn new(
        registry: Registry,
        policy: Option<PolicyConfig>,
        audit: Option<PolicyAudit>,
    ) -> Self {
        let policy = policy.unwrap_or_default();
        let audit = audit.unwrap_or_default();
        let field_policy = FieldPolicy::defaults_with(policy.clone());
        let mut template_originals: IndexMap<String, String> = IndexMap::new();
        for source in registry.category_reals_sorted(CERT_TEMPLATES) {
            let key = Self::template_key(&source);
            template_originals.entry(key).or_insert(source);
        }
        let preloaded_template_keys: HashSet<String> = template_originals.keys().cloned().collect();
        AnonymizationEngine {
            registry,
            policy,
            audit,
            field_policy,
            template_originals,
            preloaded_template_keys,
            catalog_template_targets: IndexMap::new(),
            catalog_domain_rid_targets: IndexMap::new(),
            template_mappings_finalized: false,
            verification_context: None,
            progress: None,
            current_member: None,
            abort_locator: None,
        }
    }

    /// Consume the engine, returning the underlying registry.
    pub fn into_registry(self) -> Registry {
        self.registry
    }

    /// Install a write-only progress channel, ticked once per top-level `data`
    /// object in both discovery and transform.
    ///
    /// The engine only ever writes to the sink; it never reads one back, so the
    /// documents this engine produces are byte-identical with or without it.
    pub fn set_progress_sink(&mut self, sink: ProgressSink) {
        self.progress = Some(sink);
    }

    fn template_key(value: &str) -> String {
        casefold(value)
    }

    /// Record where the walk currently is, so a deferred registry failure can
    /// name its leaf. `value` is fingerprinted immediately and never retained.
    fn mark_leaf(&mut self, context: &ObjectContext, record_path: &str, value: &str) {
        self.abort_locator = Some(AbortLocator {
            member: self.current_member.clone(),
            node_type: context.node_type.clone(),
            path: record_path.to_string(),
            offender: crate::verify::fingerprint(&self.registry.salt, value),
        });
    }

    /// Attach the current leaf locator to an error, if one is known.
    fn locate(&self, e: EngineError) -> EngineError {
        match (&self.abort_locator, &e) {
            // Never double-wrap: the innermost locator is the precise one.
            (_, EngineError::Located(_, _)) => e,
            (Some(locator), _) => EngineError::Located(Box::new(e), locator.clone()),
            (None, _) => e,
        }
    }

    /// Drain a deferred registry error from the infallible transform bridge.
    fn check_registry(&mut self) -> Result<()> {
        match self.registry.take_trait_error() {
            None => Ok(()),
            Some(e) => Err(self.locate(EngineError::Registry(e))),
        }
    }

    fn remember_template(&mut self, value: &str) -> Result<()> {
        let key = Self::template_key(value);
        match self.template_originals.get(&key).cloned() {
            None => {
                if self.registry.is_frozen() {
                    // Preserve the frozen missing-allocation error.
                    self.registry.map(CERT_TEMPLATES, value)?;
                }
                self.template_originals.insert(key, value.to_string());
                Ok(())
            }
            Some(current) => {
                if self.registry.is_frozen() || self.preloaded_template_keys.contains(&key) {
                    return Ok(());
                }
                let winner = std::cmp::min(current, value.to_string());
                self.template_originals.insert(key, winner);
                Ok(())
            }
        }
    }

    fn catalog_template_candidate(
        &self,
        context: &ObjectContext,
        path: &str,
        value: &str,
    ) -> Option<TemplateTargetEvidence> {
        let lookup_path = canonical_path(path);
        let rule_id = context.catalog_rule_id.as_deref()?;
        if context.node_type != "CertTemplate"
            || !(lookup_path == "properties.name" || lookup_path == "properties.templatename")
        {
            return None;
        }
        let identity: &str = if lookup_path == "properties.name" {
            value
                .rsplit_once('@')
                .map(|(head, _)| head)
                .unwrap_or(value)
        } else {
            value
        };
        let m = match_catalog(&context.node_type, IdentifierKind::Template, identity)?;
        if m.entry.rule_id != rule_id {
            return None;
        }
        let key = Self::template_key(identity);
        Some(TemplateTargetEvidence {
            canonical_identity: key,
            source_value: identity.to_string(),
            catalog_rule_id: rule_id.to_string(),
            node_type: context.node_type.clone(),
            path: lookup_path,
        })
    }

    fn remember_catalog_template_target(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &str,
    ) -> bool {
        let candidate = match self.catalog_template_candidate(context, path, value) {
            None => return false,
            Some(c) => c,
        };
        let key = candidate.canonical_identity.clone();
        let replace = match self.catalog_template_targets.get(&key) {
            None => true,
            Some(current) => {
                Self::template_target_order(&candidate) < Self::template_target_order(current)
            }
        };
        if replace {
            self.catalog_template_targets.insert(key, candidate);
        }
        true
    }

    fn template_target(&self, key: &str) -> Option<TemplateTargetEvidence> {
        match &self.verification_context {
            Some(ctx) => ctx.catalog_template_targets.get(key).cloned(),
            None => self.catalog_template_targets.get(key).cloned(),
        }
    }

    fn remember_domain_rid_target(&mut self, context: &ObjectContext) {
        let identifier = match &context.object_identifier {
            None => return,
            Some(id) => id.clone(),
        };
        let rule_id = match &context.catalog_rule_id {
            None => return,
            Some(id) => id.clone(),
        };
        // A `<DOMAIN>-<SID>` object identifier still defines the inner SID.
        let identifier = sid_identity(&identifier).to_string();
        let caps = match domain_sid_re().captures(&identifier) {
            None => return,
            Some(c) => c,
        };
        let rid = caps.get(1).unwrap().as_str();
        let catalog_match = match match_catalog(&context.node_type, IdentifierKind::Rid, rid) {
            None => return,
            Some(m) => m,
        };
        if catalog_match.entry.rule_id != rule_id
            || catalog_match.entry.privacy != PrivacyClass::CoreGlobalDefault
        {
            return;
        }
        let key = identifier.to_uppercase();
        self.catalog_domain_rid_targets.insert(
            key,
            DomainRidTargetEvidence {
                source_identifier: identifier,
                catalog_rule_id: rule_id,
                node_type: context.node_type.clone(),
            },
        );
    }

    /// Record a domain-RID preservation decision reached at a *reference* (or
    /// at any classified identifier path) as collection-wide evidence.
    ///
    /// The catalog only permits preserving a RID at explicitly declared paths,
    /// and a reference additionally needs a sibling `ObjectType` /
    /// `PrincipalType` to resolve against. Both are properties of the
    /// *occurrence*, but a SID's pseudonym is a property of the *identity*: the
    /// registry binds one structured output per SID. So a SID that qualifies at
    /// `Aces[].PrincipalSID` and also appears at an undeclared path such as
    /// `PrimaryGroupSID` used to be bound twice with opposite terminal intent,
    /// aborting the whole run with `preloaded "sids" mapping conflicts with
    /// structured output`. Publishing the decision here lets
    /// [`Self::apply_discovered_domain_rid_evidence`] replay it at every other
    /// occurrence, and lets `finalize_discovery` settle the binding before the
    /// registry freezes — so the answer no longer depends on which path the
    /// walk happened to reach first.
    fn remember_referenced_domain_rid(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &str,
        decision: &FieldDecision,
        reference_node_type: Option<&str>,
    ) {
        if !matches!(
            decision.operation,
            FieldOperation::MapCustomIdentifier | FieldOperation::MapReference
        ) {
            return;
        }
        let identity = sid_identity(value);
        let key = identity.to_uppercase();
        // A definition already spoke for this SID; it stays authoritative.
        if self.catalog_domain_rid_targets.contains_key(&key) {
            return;
        }
        let is_reference = decision.operation == FieldOperation::MapReference;
        let matched = match self.field_policy.catalog_domain_rid_match(
            context,
            path,
            value,
            is_reference,
            reference_node_type,
        ) {
            None => return,
            Some(m) => m,
        };
        self.catalog_domain_rid_targets.insert(
            key,
            DomainRidTargetEvidence {
                source_identifier: identity.to_string(),
                catalog_rule_id: matched.rule_id,
                node_type: matched.node_type,
            },
        );
    }

    fn apply_discovered_domain_rid_evidence(
        &self,
        value: &str,
        decision: FieldDecision,
    ) -> FieldDecision {
        // Keyed on the SID the registry actually binds, so a `<DOMAIN>-<SID>`
        // spelling resolves to the same evidence as the bare SID.
        let key = sid_identity(value).to_uppercase();
        let target = match &self.verification_context {
            Some(ctx) => ctx.catalog_domain_rid_targets.get(&key).cloned(),
            None => self.catalog_domain_rid_targets.get(&key).cloned(),
        };
        let target = match target {
            None => return decision,
            Some(t) => t,
        };
        let op_ok = matches!(
            decision.operation,
            FieldOperation::MapCustomIdentifier | FieldOperation::MapReference
        );
        let ns_ok = matches!(
            decision.namespace.as_deref(),
            Some(SIDS) | Some("identifiers") | Some("sids_preserve_rid")
        );
        if !op_ok || !ns_ok {
            return decision;
        }
        let mut decision = decision;
        decision.namespace = Some("sids_preserve_rid".to_string());
        decision.evidence = Some(format!(
            "discovered-domain-rid-target:{}",
            target.catalog_rule_id
        ));
        decision
    }

    fn template_target_order(evidence: &TemplateTargetEvidence) -> (i32, String) {
        (
            if evidence.path == "properties.templatename" {
                0
            } else {
                1
            },
            evidence.source_value.clone(),
        )
    }

    fn finalize_template_mappings(&mut self) -> Result<()> {
        if self.template_mappings_finalized {
            return Ok(());
        }
        let mut keys: Vec<String> = self.template_originals.keys().cloned().collect();
        keys.sort();
        let entries: Vec<(String, String)> = keys
            .into_iter()
            .filter(|key| !self.catalog_template_targets.contains_key(key))
            .map(|key| {
                (
                    CERT_TEMPLATES.to_string(),
                    self.template_originals[&key].clone(),
                )
            })
            .collect();
        self.registry.map_many(&entries)?;
        self.template_mappings_finalized = true;
        Ok(())
    }

    fn map_template(&mut self, value: &str, preserve: bool) -> Result<String> {
        let key = Self::template_key(value);
        if let Some(target) = self.template_target(&key) {
            return Ok(target.source_value);
        }
        if preserve {
            return Ok(value.to_string());
        }
        let owner = self
            .template_originals
            .get(&key)
            .cloned()
            .unwrap_or_else(|| value.to_string());
        Ok(self.registry.map(CERT_TEMPLATES, &owner)?)
    }

    fn discover_template_value(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &str,
    ) -> Result<()> {
        if canonical_path(path) == "properties.name" && value.contains('@') {
            let (identity, domain) = value.rsplit_once('@').unwrap();
            let identity = identity.to_string();
            let domain = domain.to_string();
            let preserve_identity = self
                .field_policy
                .resolve(context, path, &Value::String(identity.clone()), None)
                .operation
                == FieldOperation::PreserveConstant;
            let recorded = preserve_identity
                && self.remember_catalog_template_target(context, path, &identity);
            if !recorded {
                self.remember_template(&identity)?;
            }
            transform_domain(&mut self.registry, &domain);
            self.check_registry()?;
            return Ok(());
        }
        self.remember_template(value)
    }

    /// Validate a collection document and describe each top-level object
    /// (`contexts_for_document`).
    pub fn contexts_for_document(
        &mut self,
        member: &str,
        doc: &Map<String, Value>,
        audit_unknown_node_type: bool,
    ) -> Result<Vec<ObjectContext>> {
        let meta = doc
            .get("meta")
            .and_then(|v| v.as_object())
            .ok_or_else(|| EngineError::Value("SharpHound document has no 'meta' object".into()))?;
        let meta_type = meta.get("type").and_then(|v| v.as_str());
        let meta_type = match meta_type {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Err(EngineError::Value(
                    "SharpHound document has no valid 'meta.type'".into(),
                ))
            }
        };
        let data = doc
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::Value("SharpHound document has no 'data' array".into()))?;

        let node_type = normalize_node_type(Some(&Value::String(meta_type.to_string())));
        let mut contexts = Vec::with_capacity(data.len());
        for (index, item) in data.iter().enumerate() {
            let item = item.as_object().ok_or_else(|| {
                EngineError::Value(format!("SharpHound data item {index} is not an object"))
            })?;
            let object_identifier = item
                .get("ObjectIdentifier")
                .and_then(|v| v.as_str())
                .map(String::from);
            let catalog_match = classify_object(&node_type, item);
            let privacy = if node_type == "Unknown" {
                PrivacyClass::Unknown
            } else {
                match &catalog_match {
                    Some(m) => m.entry.privacy,
                    None => PrivacyClass::Custom,
                }
            };
            if node_type == "Unknown" && audit_unknown_node_type {
                self.audit.record_code("unknown-node-type");
            }
            contexts.push(ObjectContext {
                node_type: node_type.clone(),
                member: member.to_string(),
                index,
                object_identifier,
                privacy,
                catalog_rule_id: catalog_match.map(|m| m.entry.rule_id.clone()),
            });
        }
        Ok(contexts)
    }

    fn document_context(&self, member: &str, doc: &Map<String, Value>) -> ObjectContext {
        let node_type = normalize_node_type(
            doc.get("meta")
                .and_then(|v| v.as_object())
                .and_then(|m| m.get("type")),
        );
        let privacy = if node_type == "Unknown" {
            PrivacyClass::Unknown
        } else {
            PrivacyClass::Custom
        };
        ObjectContext {
            node_type,
            member: member.to_string(),
            index: usize::MAX, // sentinel value, never a real array index.
            object_identifier: None,
            privacy,
            catalog_rule_id: None,
        }
    }

    fn project_output_key(
        &mut self,
        context: &ObjectContext,
        parent_path: &str,
        key: &str,
    ) -> Result<(String, bool)> {
        if self.field_policy.is_known_key(context, parent_path, key) {
            return Ok((key.to_string(), false));
        }
        let mapped = self.registry.map(OPAQUE, key)?;
        Ok((mapped, true))
    }

    fn map_identity(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &str,
        decision: &FieldDecision,
    ) -> Result<String> {
        let namespace = decision.namespace.as_deref();
        let lookup_path = canonical_path(path);

        if lookup_path == "properties.name" && value.contains('@') {
            let (identity, domain) = value.rsplit_once('@').unwrap();
            let identity = identity.to_string();
            let domain = domain.to_string();
            let preserve_identity = self
                .field_policy
                .resolve(context, path, &Value::String(identity.clone()), None)
                .operation
                == FieldOperation::PreserveConstant;
            let mapped_identity = if namespace == Some(CERT_TEMPLATES) {
                let preserve = self
                    .catalog_template_candidate(context, path, &identity)
                    .is_some();
                self.map_template(&identity, preserve)?
            } else {
                let out = transform_name_token(&mut self.registry, &identity, preserve_identity);
                self.check_registry()?;
                out
            };
            let mapped_domain = transform_domain(&mut self.registry, &domain);
            self.check_registry()?;
            return Ok(format!("{mapped_identity}@{mapped_domain}"));
        }

        let out = match namespace {
            Some(DOMAINS) => {
                let out = transform_domain(&mut self.registry, value);
                self.check_registry()?;
                out
            }
            Some(HOSTS) => {
                let out = transform_dnshostname(&mut self.registry, value);
                self.check_registry()?;
                out
            }
            Some(CERT_TEMPLATES) => self.map_template(value, false)?,
            Some(ACCOUNTS) => {
                let out = if lookup_path == "properties.samaccountname" {
                    transform_samaccountname(&mut self.registry, value)
                } else if lookup_path == "properties.userprincipalname" {
                    transform_upn_name(&mut self.registry, value)
                } else if lookup_path == "properties.email" || lookup_path == "properties.mail" {
                    let mapped = transform_email(&mut self.registry, value);
                    if mapped != value || value.contains('@') {
                        mapped
                    } else {
                        transform_name_token(&mut self.registry, value, false)
                    }
                } else {
                    transform_name_token(&mut self.registry, value, false)
                };
                self.check_registry()?;
                out
            }
            _ => {
                return Err(EngineError::Value(format!(
                    "unsupported identity namespace {:?}",
                    namespace
                )))
            }
        };
        Ok(out)
    }

    fn map_custom_identifier(&mut self, value: &str, decision: &FieldDecision) -> Result<String> {
        let out = if sid_re().is_match(value) {
            let preserve = decision.namespace.as_deref() == Some("sids_preserve_rid");
            let out = transform_sid(&mut self.registry, value, preserve);
            self.check_registry()?;
            out
        } else if guid_re().is_match(value) {
            let out = transform_guid(&mut self.registry, value, false);
            self.check_registry()?;
            out
        } else if oid_re().is_match(value) {
            let out = transform_oid(&mut self.registry, value, false);
            self.check_registry()?;
            out
        } else {
            self.registry.map(OPAQUE, value)?
        };
        Ok(out)
    }

    fn map_reference(&mut self, value: &str, decision: &FieldDecision) -> Result<String> {
        let namespace = decision.namespace.as_deref();
        let out = match namespace {
            Some("sids_preserve_rid") => {
                let out = transform_sid(&mut self.registry, value, true);
                self.check_registry()?;
                out
            }
            Some(SIDS) => {
                let out = transform_sid(&mut self.registry, value, false);
                self.check_registry()?;
                out
            }
            Some(GUIDS) => {
                let out = transform_guid(&mut self.registry, value, false);
                self.check_registry()?;
                out
            }
            Some(OIDS) => {
                let out = transform_oid(&mut self.registry, value, false);
                self.check_registry()?;
                out
            }
            Some(CERT_TEMPLATES) => self.map_template(value, false)?,
            Some(ACCOUNTS) => {
                let out = transform_name_token(&mut self.registry, value, false);
                self.check_registry()?;
                out
            }
            Some(DOMAINS) => {
                let out = transform_domain(&mut self.registry, value);
                self.check_registry()?;
                out
            }
            Some(HOSTS) => {
                let out = transform_dnshostname(&mut self.registry, value);
                self.check_registry()?;
                out
            }
            Some("identifiers") => self.map_custom_identifier(value, decision)?,
            _ => {
                return Err(EngineError::Value(format!(
                    "unsupported reference namespace {:?}",
                    namespace
                )))
            }
        };
        Ok(out)
    }

    fn apply_string_operation(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &str,
        decision: &FieldDecision,
    ) -> Result<String> {
        // Ahead of the dispatch, not inside `ReplaceOpaque`: a secret is a
        // secret whichever operation the policy resolved for its path. The
        // empty-value case keeps the old `ReplaceOpaque` behavior of returning
        // the value unchanged, so no output byte moves for an empty leaf.
        if !value.is_empty() && crate::is_secret_material_path(path) {
            return Ok(crate::REDACTED.to_string());
        }
        match decision.operation {
            FieldOperation::PreserveConstant | FieldOperation::PreserveSchemaValue => {
                Ok(value.to_string())
            }
            FieldOperation::MapIdentity => self.map_identity(context, path, value, decision),
            FieldOperation::MapReference => self.map_reference(value, decision),
            FieldOperation::ParseDn => {
                // Disjoint field borrows: the closure reads `field_policy`, the
                // transform writes `registry`.
                let field_policy = &self.field_policy;
                let reg = &mut self.registry;
                let preserve = |_attr: &str, rdn: &str| {
                    field_policy
                        .resolve(context, path, &Value::String(rdn.to_string()), None)
                        .operation
                        == FieldOperation::PreserveConstant
                };
                let out = transform_dn(reg, value, Some(&preserve));
                self.check_registry()?;
                Ok(out)
            }
            FieldOperation::ParseSpn => {
                let transformed = transform_spn(&mut self.registry, value);
                self.check_registry()?;
                if transformed != value {
                    Ok(transformed)
                } else {
                    Ok(self.registry.map(OPAQUE, value)?)
                }
            }
            FieldOperation::ParseComposite => {
                let mut preserve_group = false;
                if value.contains('@') {
                    let group = value.rsplit_once('@').unwrap().0.to_string();
                    preserve_group = self
                        .field_policy
                        .resolve(context, path, &Value::String(group), None)
                        .operation
                        == FieldOperation::PreserveConstant;
                }
                let out = transform_ad_local_group_name(&mut self.registry, value, preserve_group);
                self.check_registry()?;
                Ok(out)
            }
            FieldOperation::MapCustomIdentifier => self.map_custom_identifier(value, decision),
            FieldOperation::ReplaceOpaque => {
                if value.is_empty() {
                    return Ok(value.to_string());
                }
                Ok(self.registry.map(OPAQUE, value)?)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn visit(
        &mut self,
        context: &ObjectContext,
        path: &str,
        value: &Value,
        mode: VisitMode,
        records: &mut Vec<DecisionRecord>,
        record_path: Option<&str>,
        reference_node_type: Option<&str>,
    ) -> Result<Value> {
        let source_path: String = record_path.unwrap_or(path).to_string();

        if let Value::Object(map) = value {
            // Sibling ObjectType/PrincipalType provides a reference node type.
            let mut object_type: Option<String> = None;
            let mut principal_type: Option<String> = None;
            for (key, child) in map {
                let folded = casefold(key);
                if let Some(child) = child.as_str() {
                    if folded == "objecttype" {
                        object_type = Some(child.to_string());
                    } else if folded == "principaltype" {
                        principal_type = Some(child.to_string());
                    }
                }
            }
            let sibling_reference_node_type = principal_type.or(object_type);

            let mut projected_mapping = Map::new();
            let mut projected_keys: HashSet<String> = HashSet::new();
            for (key, child) in map {
                let policy_child_path = object_path(path, key);
                let (projected_key, dynamic) = self.project_output_key(context, path, key)?;
                if !projected_keys.insert(projected_key.clone()) {
                    self.mark_leaf(context, &object_path(&source_path, key), key);
                    return Err(self.locate(EngineError::PseudonymCollision(
                        "object key projection collision".into(),
                    )));
                }
                let projected_path = object_path(&source_path, &projected_key);
                let output_key = if mode == VisitMode::Discover {
                    key.clone()
                } else {
                    projected_key.clone()
                };
                let child_out = self.visit(
                    context,
                    &policy_child_path,
                    child,
                    mode,
                    records,
                    Some(&projected_path),
                    sibling_reference_node_type.as_deref(),
                )?;
                projected_mapping.insert(output_key, child_out);
                if dynamic && mode == VisitMode::Transform {
                    self.audit.record_unknown_key(&projected_path);
                }
            }
            return Ok(Value::Object(projected_mapping));
        }

        if let Value::Array(items) = value {
            let mut out = Vec::with_capacity(items.len());
            for (index, child) in items.iter().enumerate() {
                let child_path = array_path(path, index);
                let child_record_path = array_path(&source_path, index);
                out.push(self.visit(
                    context,
                    &child_path,
                    child,
                    mode,
                    records,
                    Some(&child_record_path),
                    None,
                )?);
            }
            return Ok(Value::Array(out));
        }

        // Scalar leaf.
        let value_str = match value {
            Value::String(s) => s.clone(),
            _ => {
                if canonical_path(path) == "properties.functionallevel"
                    && matches!(value, Value::Number(_))
                {
                    return redact_functional_level_number(value)
                        .map_err(|e| EngineError::Value(e.to_string()));
                }
                // Booleans and nulls are emitted verbatim: they never reach the
                // policy, so nothing anonymizes them. That is correct for both.
                // A null carries nothing by construction, and a boolean carries
                // one bit that cannot identify anyone.
                //
                // Numbers are verbatim only where a rule declares the path — a
                // schema flag, a count, a password-policy setting carries no
                // identity, and `NUMERIC_PATHS` says which those are. Where no
                // rule declares it, the number is `--collectallproperties`
                // spill: SharpHound's `BestGuessConvert` turns any attribute
                // whose value parses as an integer into a JSON number, so a
                // custom `employeeNumber` or `uidNumber` lands exactly here. It
                // is replaced with a type-stable sentinel, because publishing it
                // hands over a re-identification key: match one against an HR
                // roster and the pseudonyms for that account's name, UPN and DN
                // fall with it.
                //
                // Counted either way, so `shanon inspect` reports the same paths
                // whether or not the redaction is on.
                if matches!(value, Value::Number(_)) && !self.field_policy.declares(context, path) {
                    if mode == VisitMode::Transform {
                        self.audit.record_undeclared_numeric(&source_path);
                    }
                    if self.field_policy.config().redact_undeclared_numbers {
                        return crate::policy::redact_undeclared_number(value)
                            .map_err(|e| EngineError::Value(e.to_string()));
                    }
                }
                return Ok(value.clone());
            }
        };

        self.mark_leaf(context, &source_path, &value_str);

        let mut decision = self
            .field_policy
            .resolve(context, path, value, reference_node_type);
        if mode == VisitMode::Discover {
            self.remember_referenced_domain_rid(
                context,
                path,
                &value_str,
                &decision,
                reference_node_type,
            );
        }
        decision = self.apply_discovered_domain_rid_evidence(&value_str, decision);

        if mode == VisitMode::Discover
            && sid_re().is_match(&value_str)
            && self
                .registry
                .forward(&value_str)
                .iter()
                .any(|(category, _)| category == SIDS)
        {
            // A reuse map already owns this complete SID; defer terminal intent.
            return Ok(value.clone());
        }

        if mode == VisitMode::Discover && decision.operation == FieldOperation::PreserveConstant {
            if self.remember_catalog_template_target(context, path, &value_str) {
                return Ok(value.clone());
            }
            if context.node_type == "CertTemplate"
                && matches!(
                    canonical_path(path).as_str(),
                    "properties.name" | "properties.templatename"
                )
            {
                self.discover_template_value(context, path, &value_str)?;
                return Ok(value.clone());
            }
        }

        if mode == VisitMode::Discover
            && decision.namespace.as_deref() == Some(CERT_TEMPLATES)
            && matches!(
                decision.operation,
                FieldOperation::MapIdentity | FieldOperation::MapReference
            )
        {
            self.discover_template_value(context, path, &value_str)?;
            return Ok(value.clone());
        }

        if mode == VisitMode::Transform
            && decision.operation == FieldOperation::MapReference
            && decision.namespace.as_deref() == Some(CERT_TEMPLATES)
        {
            if let Some(target) = self.template_target(&Self::template_key(&value_str)) {
                decision.evidence = Some(format!(
                    "discovered-template-target:{}",
                    target.catalog_rule_id
                ));
            }
        }

        let definition = self.catalog_template_candidate(context, path, &value_str);
        let target = definition
            .as_ref()
            .and_then(|d| self.template_target(&d.canonical_identity));
        if let Some(target) = &target {
            decision.evidence = Some(format!(
                "discovered-template-target:{}",
                target.catalog_rule_id
            ));
        } else if mode == VisitMode::Transform
            && decision.operation == FieldOperation::PreserveConstant
            && context.node_type == "CertTemplate"
            && matches!(
                canonical_path(path).as_str(),
                "properties.name" | "properties.templatename"
            )
        {
            decision.operation = FieldOperation::MapIdentity;
            decision.namespace = Some(CERT_TEMPLATES.to_string());
            decision.evidence = None;
        }

        let output = match &target {
            Some(t) if decision.operation == FieldOperation::PreserveConstant => {
                t.source_value.clone()
            }
            _ => self
                .apply_string_operation(context, path, &value_str, &decision)
                .map_err(|e| self.locate(e))?,
        };

        if mode == VisitMode::Discover {
            return Ok(value.clone());
        }

        let record = DecisionRecord {
            context: context.clone(),
            path: source_path,
            decision,
            source_value: value_str,
            output_value: output.clone(),
        };
        self.audit.record(&record);
        records.push(record);
        Ok(Value::String(output))
    }

    /// Apply the shared policy visitor to a single contextual node
    /// (`visit_node`).
    pub fn visit_node(
        &mut self,
        context: &ObjectContext,
        node: &Value,
        path: &str,
        discover: bool,
    ) -> Result<(Value, Vec<DecisionRecord>)> {
        if discover {
            self.ensure_discovery_open()?;
        }
        let mut records = Vec::new();
        let mode = if discover {
            VisitMode::Discover
        } else {
            VisitMode::Transform
        };
        let output = self.visit(context, path, node, mode, &mut records, None, None)?;
        Ok((output, records))
    }

    fn process_document(
        &mut self,
        member: &str,
        doc: &Map<String, Value>,
        mode: VisitMode,
    ) -> Result<(Map<String, Value>, Vec<DecisionRecord>)> {
        self.current_member = Some(member.to_string());
        self.abort_locator = None;
        let contexts = self.contexts_for_document(member, doc, mode == VisitMode::Discover)?;
        if mode == VisitMode::Discover {
            for context in &contexts {
                self.remember_domain_rid_target(context);
            }
        }
        let document_context = self.document_context(member, doc);
        let mut records: Vec<DecisionRecord> = Vec::new();
        let mut output = Map::new();

        let meta = doc
            .get("meta")
            .expect("meta validated in contexts_for_document");
        let meta_out = self.visit(
            &document_context,
            "meta",
            meta,
            mode,
            &mut records,
            None,
            None,
        )?;
        output.insert("meta".to_string(), meta_out);

        let data = doc
            .get("data")
            .and_then(|v| v.as_array())
            .expect("data validated in contexts_for_document");
        let mut data_out = Vec::with_capacity(data.len());
        for (context, item) in contexts.iter().zip(data.iter()) {
            let record_path = array_path("data", context.index);
            data_out.push(self.visit(
                context,
                "",
                item,
                mode,
                &mut records,
                Some(&record_path),
                None,
            )?);
            // One work unit per top-level object, in both modes. Emitted after
            // the visit so a tick always means completed work.
            progress::tick(self.progress.as_ref());
        }
        output.insert("data".to_string(), Value::Array(data_out));

        let mut projected_root_keys: HashSet<String> = ["meta".to_string(), "data".to_string()]
            .into_iter()
            .collect();
        for (key, value) in doc {
            if key == "meta" || key == "data" {
                continue;
            }
            let root_path = object_path("", key);
            let (projected_key, dynamic) = self.project_output_key(&document_context, "", key)?;
            if !projected_root_keys.insert(projected_key.clone()) {
                self.mark_leaf(&document_context, &root_path, key);
                return Err(self.locate(EngineError::PseudonymCollision(
                    "object key projection collision".into(),
                )));
            }
            let projected_path = object_path("", &projected_key);
            let output_key = if mode == VisitMode::Discover {
                key.clone()
            } else {
                projected_key.clone()
            };
            let value_out = self.visit(
                &document_context,
                &root_path,
                value,
                mode,
                &mut records,
                Some(&projected_path),
                None,
            )?;
            output.insert(output_key, value_out);
            if dynamic && mode == VisitMode::Transform {
                self.audit.record_unknown_key(&projected_path);
            }
        }

        if mode == VisitMode::Discover {
            for context in &contexts {
                self.audit.record_object_classification(context.privacy);
            }
        }
        Ok((output, records))
    }

    /// Allocate every typed mapping while returning source-equivalent JSON
    /// (`discover_document`).
    pub fn discover_document(
        &mut self,
        member: &str,
        doc: &Map<String, Value>,
    ) -> Result<(Map<String, Value>, Vec<DecisionRecord>)> {
        self.ensure_discovery_open()?;
        self.process_document(member, doc, VisitMode::Discover)
    }

    fn ensure_discovery_open(&self) -> Result<()> {
        if self.verification_context.is_some() || self.registry.is_frozen() {
            return Err(EngineError::Runtime(
                "discovery is already finalized".into(),
            ));
        }
        Ok(())
    }

    /// Allocate deferred mappings and freeze one immutable evidence snapshot
    /// (`finalize_discovery`).
    pub fn finalize_discovery(&mut self) -> Result<VerificationContext> {
        if let Some(ctx) = &self.verification_context {
            return Ok(ctx.clone());
        }
        self.finalize_template_mappings()?;
        if self.policy.preserve_core_global_defaults {
            let mut sources: Vec<String> =
                self.catalog_domain_rid_targets.keys().cloned().collect();
            sources.sort();
            for source_identifier in sources {
                transform_sid(&mut self.registry, &source_identifier, true);
                self.check_registry()?;
            }
        }
        let context = VerificationContext {
            catalog_template_targets: self.catalog_template_targets.clone(),
            policy: self.policy.clone(),
            catalog_domain_rid_targets: self.catalog_domain_rid_targets.clone(),
        };
        self.registry.freeze()?;
        self.verification_context = Some(context.clone());
        Ok(context)
    }

    /// Transform one collection with one record for every string leaf
    /// (`transform_document`).
    pub fn transform_document(
        &mut self,
        member: &str,
        doc: &Map<String, Value>,
    ) -> Result<(Map<String, Value>, Vec<DecisionRecord>)> {
        if self.verification_context.is_none() {
            self.finalize_discovery()?;
        }
        self.process_document(member, doc, VisitMode::Transform)
    }
}
