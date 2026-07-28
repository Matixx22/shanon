//! Immutable, path-aware policy decisions for SharpHound fields.
//!
//! ## Path grammar (byte-parity contract)
//! [`object_path`] / [`array_path`] build collision-safe display paths and
//! [`path_tokens`] decodes them; the key-escaping rules must match exactly
//! because they drive verification-finding paths (§3.1a). Key escaping
//! reuses `serde_json::to_string`, which produces the `ensure_ascii=false`-style
//! escaping (control chars + `"`/`\` escaped, non-ASCII kept
//! literal). Decoding operates over a `Vec<char>` so index arithmetic is
//! code-point based (`raw_decode` returns a *character* count).
//! Round-trip + cross-impl parity is fuzzed in `tests/policy_pathgrammar.rs`.
//!
//! ## Determinism (§3.2)
//! Rule lookup, `known_paths`, and `known_prefixes` are pure membership maps
//! that never drive output order, so they use `HashMap`/`HashSet`. Audit
//! summaries and the catalog table (via [`crate::catalog`]) carry the
//! order-sensitive state, emitted through sorted iteration / `IndexMap`.
//!
//! Values arrive as [`serde_json::Value`]; string / bool / numeric checks map to
//! `Value::String` / `Value::Bool` / `Value::Number` respectively (a JSON bool
//! is never a number).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::casefold::casefold;
use crate::catalog::{catalog, match_catalog, CatalogEntry, IdentifierKind, PrivacyClass};
use crate::components::sid_identity;

// ===========================================================================
// Enums / dataclasses
// ===========================================================================

/// `FieldOperation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldOperation {
    PreserveConstant,
    MapIdentity,
    MapReference,
    ParseDn,
    ParseSpn,
    ParseComposite,
    MapCustomIdentifier,
    ReplaceOpaque,
    PreserveSchemaValue,
}

impl FieldOperation {
    /// The `FieldOperation` value string.
    pub fn as_str(self) -> &'static str {
        match self {
            FieldOperation::PreserveConstant => "preserve_constant",
            FieldOperation::MapIdentity => "map_identity",
            FieldOperation::MapReference => "map_reference",
            FieldOperation::ParseDn => "parse_dn",
            FieldOperation::ParseSpn => "parse_spn",
            FieldOperation::ParseComposite => "parse_composite",
            FieldOperation::MapCustomIdentifier => "map_custom_identifier",
            FieldOperation::ReplaceOpaque => "replace_opaque",
            FieldOperation::PreserveSchemaValue => "preserve_schema_value",
        }
    }
}

/// `PolicyConfig` — profile toggles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub preserve_core_global_defaults: bool,
    pub preserve_microsoft_feature_defaults: bool,
    pub preserve_third_party_defaults: bool,
    pub unknown_fields: String,
    pub strict: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            preserve_core_global_defaults: true,
            preserve_microsoft_feature_defaults: false,
            preserve_third_party_defaults: false,
            unknown_fields: "anonymize_and_warn".to_string(),
            strict: true,
        }
    }
}

/// `ObjectContext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectContext {
    pub node_type: String,
    pub member: String,
    pub index: usize,
    pub object_identifier: Option<String>,
    pub privacy: PrivacyClass,
    pub catalog_rule_id: Option<String>,
}

/// `FieldRule`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldRule {
    pub rule_id: String,
    pub node_types: HashSet<String>,
    pub path: String,
    pub operation: FieldOperation,
    pub namespace: Option<String>,
    pub allowed_values: Option<HashSet<String>>,
}

/// `FieldDecision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecision {
    pub rule_id: String,
    pub operation: FieldOperation,
    pub namespace: Option<String>,
    pub privacy: PrivacyClass,
    pub audit_code: Option<String>,
    pub evidence: Option<String>,
}

/// `DecisionRecord`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionRecord {
    pub context: ObjectContext,
    pub path: String,
    pub decision: FieldDecision,
    pub source_value: String,
    pub output_value: String,
}

// ===========================================================================
// Path grammar
// ===========================================================================

/// Characters that force an object key to be bracket-escaped
/// (`_PATH_ESCAPE_CHARACTERS`).
const PATH_ESCAPE_CHARACTERS: [char; 5] = ['.', '[', ']', '"', '\\'];

/// One token kind produced by [`path_tokens`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    Key,
    Array,
}

/// Error decoding a display path (`_path_tokens` raises `ValueError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    TrailingSeparator,
    EmptyToken,
    UnterminatedArray,
    NonNumericArray,
    UnterminatedQuoted,
    InvalidQuoted,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            PathError::TrailingSeparator => "path cannot end with a separator",
            PathError::EmptyToken => "invalid empty path token",
            PathError::UnterminatedArray => "array path token has no closing bracket",
            PathError::NonNumericArray => "array path token must be numeric or empty",
            PathError::UnterminatedQuoted => "quoted path token has no closing bracket",
            PathError::InvalidQuoted => "quoted path token must be a string",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PathError {}

/// Escape one object key for embedding in a display path
/// (`_encoded_object_key`).
fn encoded_object_key(key: &str) -> String {
    if !key.is_empty() && !key.chars().any(|c| PATH_ESCAPE_CHARACTERS.contains(&c)) {
        key.to_string()
    } else {
        // `json.dumps(key, ensure_ascii=False)` == serde_json string encoding.
        format!(
            "[{}]",
            serde_json::to_string(key).expect("string always serializes")
        )
    }
}

/// Append one collision-safe object-key token to a display path (`object_path`).
pub fn object_path(path: &str, key: &str) -> String {
    let encoded = encoded_object_key(key);
    if path.is_empty() || encoded.starts_with('[') {
        format!("{path}{encoded}")
    } else {
        format!("{path}.{encoded}")
    }
}

/// Append one array-index token, distinct from every object-key token
/// (`array_path`). The index is unsigned, so a negative-index guard is
/// unrepresentable.
pub fn array_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

/// Decode one JSON string from the start of `rest` (which begins with `"`),
/// returning the value and the number of **bytes** consumed.
fn decode_json_string(rest: &str) -> Result<(String, usize), PathError> {
    let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<String>();
    match stream.next() {
        Some(Ok(value)) => Ok((value, stream.byte_offset())),
        _ => Err(PathError::InvalidQuoted),
    }
}

/// Tokenize a display path (`_path_tokens`). Operates over code points so the
/// index arithmetic is code-point based.
pub fn path_tokens(path: &str) -> Result<Vec<(TokenType, Option<String>)>, PathError> {
    let chars: Vec<char> = path.chars().collect();
    let n = chars.len();
    let mut tokens: Vec<(TokenType, Option<String>)> = Vec::new();
    let mut index = 0;
    while index < n {
        if chars[index] == '.' {
            index += 1;
            if index >= n {
                return Err(PathError::TrailingSeparator);
            }
        }
        if chars[index] == '[' {
            if index + 1 < n && chars[index + 1] == '"' {
                let rest: String = chars[index + 1..].iter().collect();
                let (key, consumed_bytes) = decode_json_string(&rest)?;
                let consumed = rest[..consumed_bytes].chars().count();
                let closing = index + 1 + consumed;
                if closing >= n || chars[closing] != ']' {
                    return Err(PathError::UnterminatedQuoted);
                }
                tokens.push((TokenType::Key, Some(key)));
                index = closing + 1;
                continue;
            }
            let closing = match chars[index + 1..].iter().position(|&c| c == ']') {
                Some(offset) => index + 1 + offset,
                None => return Err(PathError::UnterminatedArray),
            };
            let numeric: String = chars[index + 1..closing].iter().collect();
            if !numeric.is_empty() && !numeric.chars().all(|c| c.is_ascii_digit()) {
                return Err(PathError::NonNumericArray);
            }
            tokens.push((TokenType::Array, None));
            index = closing + 1;
            continue;
        }
        let mut end = index;
        while end < n && chars[end] != '.' && chars[end] != '[' {
            end += 1;
        }
        if end == index {
            return Err(PathError::EmptyToken);
        }
        let key: String = chars[index..end].iter().collect();
        tokens.push((TokenType::Key, Some(key)));
        index = end;
    }
    Ok(tokens)
}

/// Return a collision-safe, case-folded policy lookup path (`canonical_path`).
///
/// # Panics
/// Panics on a malformed path (raises `ValueError`); policy inputs are
/// always well-formed. Use [`path_tokens`] directly to handle untrusted input.
pub fn canonical_path(path: &str) -> String {
    let mut canonical = String::new();
    for (token_type, value) in path_tokens(path).expect("canonical_path: malformed path") {
        match token_type {
            TokenType::Array => canonical.push_str("[]"),
            TokenType::Key => {
                canonical = object_path(&canonical, &casefold(&value.expect("key token")));
            }
        }
    }
    canonical
}

/// Normalize array indexes while preserving exact schema-key spelling
/// (`_schema_path`).
pub fn schema_path(path: &str) -> String {
    let mut normalized = String::new();
    for (token_type, value) in path_tokens(path).expect("schema_path: malformed path") {
        match token_type {
            TokenType::Array => normalized.push_str("[]"),
            TokenType::Key => {
                normalized = object_path(&normalized, &value.expect("key token"));
            }
        }
    }
    normalized
}

/// Return every exact-spelling object-key endpoint in a schema path
/// (`_key_path_prefixes`).
pub fn key_path_prefixes(path: &str) -> Vec<String> {
    let schema = schema_path(path);
    let mut prefixes: Vec<String> = Vec::new();
    let mut prefix = String::new();
    for (token_type, value) in path_tokens(&schema).expect("key_path_prefixes: malformed path") {
        match token_type {
            TokenType::Array => prefix.push_str("[]"),
            TokenType::Key => {
                prefix = object_path(&prefix, &value.expect("key token"));
                prefixes.push(prefix.clone());
            }
        }
    }
    prefixes
}

/// Return a type-stable sentinel for a legacy numeric functional level
/// (`redact_functional_level_number`). `int` stays `int`, `float` stays `float`.
pub fn redact_functional_level_number(value: &Value) -> Result<Value, PolicyError> {
    match value {
        Value::Number(n) => {
            let token = n.to_string();
            if token.contains('.') || token.contains('e') || token.contains('E') {
                let f: f64 = token.parse().map_err(|_| PolicyError::NonNumeric)?;
                Ok(if f == -1.0 {
                    serde_json::json!(-2.0)
                } else {
                    serde_json::json!(-1.0)
                })
            } else {
                let i: i64 = token.parse().map_err(|_| PolicyError::NonNumeric)?;
                Ok(if i == -1 {
                    serde_json::json!(-2)
                } else {
                    serde_json::json!(-1)
                })
            }
        }
        _ => Err(PolicyError::NonNumeric),
    }
}

// ===========================================================================
// Compiled shape matchers (audited: no lookaround, port to `regex`)
// ===========================================================================

fn sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^S-\d+-\d+(?:-\d+)+$").unwrap())
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

/// `_NORMALIZED_OBJECT_TYPES`: casefolded object type -> canonical spelling.
fn normalized_object_types() -> &'static HashMap<String, String> {
    static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    MAP.get_or_init(|| {
        OBJECT_TYPES
            .iter()
            .map(|t| (casefold(t), (*t).to_string()))
            .collect()
    })
}

// ===========================================================================
// FieldPolicy
// ===========================================================================

/// Error building a [`FieldPolicy`] (`FieldPolicy.__init__` raises).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    NoNodeTypes(String),
    DuplicateRule { node_type: String, path: String },
    NonNumeric,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::NoNodeTypes(id) => write!(f, "field rule {id:?} has no node types"),
            PolicyError::DuplicateRule { node_type, path } => {
                write!(f, "duplicate field rule for {node_type:?} and {path:?}")
            }
            PolicyError::NonNumeric => f.write_str("functional level must be numeric"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// An immutable index of contextual field rules (`FieldPolicy`).
#[derive(Clone, Debug)]
pub struct FieldPolicy {
    config: PolicyConfig,
    rules: Vec<FieldRule>,
    index: HashMap<(String, String), FieldRule>,
    known_paths: HashMap<String, HashSet<String>>,
    known_prefixes: HashMap<String, HashSet<String>>,
}

impl Default for FieldPolicy {
    fn default() -> Self {
        FieldPolicy::new(default_rules(), PolicyConfig::default()).expect("default rules are valid")
    }
}

impl FieldPolicy {
    /// Build a policy from `rules` (`FieldPolicy.__init__`).
    pub fn new(rules: Vec<FieldRule>, config: PolicyConfig) -> Result<Self, PolicyError> {
        let mut index: HashMap<(String, String), FieldRule> = HashMap::new();
        let mut known_paths: HashMap<String, HashSet<String>> = HashMap::new();
        let mut known_prefixes: HashMap<String, HashSet<String>> = HashMap::new();

        for rule in &rules {
            if rule.node_types.is_empty() {
                return Err(PolicyError::NoNodeTypes(rule.rule_id.clone()));
            }
            for node_type in &rule.node_types {
                let rule_path = canonical_path(&rule.path);
                let key = (node_type.clone(), rule_path);
                if index.contains_key(&key) {
                    return Err(PolicyError::DuplicateRule {
                        node_type: node_type.clone(),
                        path: rule.path.clone(),
                    });
                }
                index.insert(key, rule.clone());
                known_paths
                    .entry(node_type.clone())
                    .or_default()
                    .insert(schema_path(&rule.path));
                known_prefixes
                    .entry(node_type.clone())
                    .or_default()
                    .extend(key_path_prefixes(&rule.path));
            }
        }

        for (node_type, schema) in KNOWN_SCHEMA_PATH_ALIASES {
            known_paths
                .entry((*node_type).to_string())
                .or_default()
                .insert(schema_path(schema));
            known_prefixes
                .entry((*node_type).to_string())
                .or_default()
                .extend(key_path_prefixes(schema));
        }

        Ok(FieldPolicy {
            config,
            rules,
            index,
            known_paths,
            known_prefixes,
        })
    }

    /// The default policy with a caller-supplied config (`FieldPolicy.default`).
    pub fn defaults_with(config: PolicyConfig) -> Self {
        FieldPolicy::new(default_rules(), config).expect("default rules are valid")
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn rules(&self) -> &[FieldRule] {
        &self.rules
    }

    /// Whether an exact leaf path is declared for this node or globally
    /// (`is_known_path`).
    pub fn is_known_path(&self, context: &ObjectContext, path: &str) -> bool {
        let lookup = schema_path(path);
        self.known_paths
            .get(&context.node_type)
            .is_some_and(|s| s.contains(&lookup))
            || self
                .known_paths
                .get("*")
                .is_some_and(|s| s.contains(&lookup))
    }

    /// Whether a mapping key is a declared path prefix in this context
    /// (`is_known_prefix`).
    pub fn is_known_prefix(&self, context: &ObjectContext, path: &str) -> bool {
        let lookup = schema_path(path);
        self.known_prefixes
            .get(&context.node_type)
            .is_some_and(|s| s.contains(&lookup))
            || self
                .known_prefixes
                .get("*")
                .is_some_and(|s| s.contains(&lookup))
    }

    /// Whether `key` is schema-declared beneath `parent_path` (`is_known_key`).
    pub fn is_known_key(&self, context: &ObjectContext, parent_path: &str, key: &str) -> bool {
        self.is_known_prefix(context, &object_path(parent_path, key))
    }

    fn profile_preserves(&self, privacy: PrivacyClass) -> bool {
        match privacy {
            PrivacyClass::CoreGlobalDefault => self.config.preserve_core_global_defaults,
            PrivacyClass::MicrosoftFeatureDefault => {
                self.config.preserve_microsoft_feature_defaults
            }
            PrivacyClass::ThirdPartyDefault => self.config.preserve_third_party_defaults,
            _ => false,
        }
    }

    /// First preserve-path of `entry` whose canonical form equals `path`'s
    /// (`_catalog_path`).
    fn catalog_path(entry: &CatalogEntry, path: &str) -> Option<String> {
        let wanted = canonical_path(path);
        entry
            .preserve_paths
            .iter()
            .find(|candidate| canonical_path(candidate) == wanted)
            .cloned()
    }

    fn entry_permits(&self, entry: &CatalogEntry, path: &str, value: &str) -> bool {
        match Self::catalog_path(entry, path) {
            None => false,
            Some(catalog_path) => {
                self.profile_preserves(entry.privacy) && entry.permits(&catalog_path, value)
            }
        }
    }

    fn catalog_permits(&self, context: &ObjectContext, path: &str, value: &str) -> bool {
        if let Some(rule_id) = &context.catalog_rule_id {
            if let Some(entry) = catalog().iter().find(|entry| {
                &entry.rule_id == rule_id
                    && entry.node_types.contains(&context.node_type)
                    && entry.privacy == context.privacy
            }) {
                if self.entry_permits(entry, path, value) {
                    return true;
                }
            }
        }

        let kinds: &[IdentifierKind] = if sid_re().is_match(value) {
            &[IdentifierKind::Sid]
        } else if guid_re().is_match(value) {
            &[IdentifierKind::Guid, IdentifierKind::Wkguid]
        } else if oid_re().is_match(value) {
            &[IdentifierKind::Oid]
        } else {
            &[IdentifierKind::Template, IdentifierKind::Name]
        };

        for &kind in kinds {
            if let Some(m) = match_catalog(&context.node_type, kind, value) {
                if self.entry_permits(m.entry, path, value) {
                    return true;
                }
            }
        }
        false
    }

    /// The catalog entry that permits preserving this SID's RID at this path,
    /// if any.
    ///
    /// A definition resolves against the object's own catalog classification; a
    /// reference resolves against the node type its sibling `ObjectType` /
    /// `PrincipalType` declares. Both branches are path-scoped, which is why
    /// the answer alone is not enough to decide a mapping: the engine records
    /// every match as collection-wide evidence so that occurrences of the same
    /// SID at *undeclared* paths do not disagree with it. See
    /// `AnonymizationEngine::remember_domain_rid_target`.
    pub(crate) fn catalog_domain_rid_match(
        &self,
        context: &ObjectContext,
        path: &str,
        value: &str,
        is_reference: bool,
        reference_node_type: Option<&str>,
    ) -> Option<DomainRidMatch> {
        // `<DOMAIN>-<SID>` binds its inner SID, so the RID is read from there.
        let caps = domain_rid_re().captures(sid_identity(value))?;
        let rid = caps.get(1).expect("capture group 1").as_str();

        if is_reference {
            let target = normalized_object_types()
                .get(&casefold(reference_node_type?))
                .cloned()?;
            return catalog()
                .iter()
                .find(|candidate| {
                    candidate.kind == IdentifierKind::Rid
                        && candidate.node_types.contains(&target)
                        && self.entry_permits(candidate, path, rid)
                })
                .map(|entry| DomainRidMatch {
                    rule_id: entry.rule_id.clone(),
                    node_type: target.clone(),
                });
        }

        let rule_id = context.catalog_rule_id.as_ref()?;
        catalog()
            .iter()
            .find(|candidate| {
                &candidate.rule_id == rule_id
                    && candidate.kind == IdentifierKind::Rid
                    && candidate.node_types.contains(&context.node_type)
                    && candidate.privacy == context.privacy
            })
            .filter(|entry| self.entry_permits(entry, path, rid))
            .map(|entry| DomainRidMatch {
                rule_id: entry.rule_id.clone(),
                node_type: context.node_type.clone(),
            })
    }

    fn catalog_permits_domain_rid(
        &self,
        context: &ObjectContext,
        path: &str,
        value: &str,
        is_reference: bool,
        reference_node_type: Option<&str>,
    ) -> bool {
        self.catalog_domain_rid_match(context, path, value, is_reference, reference_node_type)
            .is_some()
    }

    fn decision(
        &self,
        context: &ObjectContext,
        rule_id: &str,
        operation: FieldOperation,
        namespace: Option<&str>,
        audit_code: Option<&str>,
    ) -> FieldDecision {
        FieldDecision {
            rule_id: rule_id.to_string(),
            operation,
            namespace: namespace.map(str::to_string),
            privacy: context.privacy,
            audit_code: audit_code.map(str::to_string),
            evidence: None,
        }
    }

    fn resolve_schema(
        &self,
        context: &ObjectContext,
        rule: &FieldRule,
        value: &Value,
    ) -> FieldDecision {
        let valid_string = match (value.as_str(), &rule.allowed_values) {
            (Some(s), Some(allowed)) => allowed.contains(s),
            _ => false,
        };
        let valid_typed_value = if rule.rule_id.starts_with("schema.boolean.") {
            matches!(value, Value::Bool(_))
        } else if rule.rule_id.starts_with("schema.numeric.") {
            matches!(value, Value::Number(_))
        } else {
            rule.allowed_values.is_none() && matches!(value, Value::Bool(_) | Value::Number(_))
        };
        if valid_string || valid_typed_value {
            return self.decision(
                context,
                &rule.rule_id,
                FieldOperation::PreserveSchemaValue,
                rule.namespace.as_deref(),
                None,
            );
        }
        let code = if value.is_string() {
            "invalid-schema-string"
        } else {
            "invalid-schema-value"
        };
        self.decision(
            context,
            &rule.rule_id,
            FieldOperation::ReplaceOpaque,
            Some("opaque"),
            Some(code),
        )
    }

    /// Resolve the field decision for `value` at `path` (`resolve`).
    pub fn resolve(
        &self,
        context: &ObjectContext,
        path: &str,
        value: &Value,
        reference_node_type: Option<&str>,
    ) -> FieldDecision {
        let lookup_path = canonical_path(path);
        let rule = self
            .index
            .get(&(context.node_type.clone(), lookup_path.clone()))
            .or_else(|| self.index.get(&("*".to_string(), lookup_path.clone())));

        if let Some(rule) = rule {
            if rule.operation == FieldOperation::PreserveSchemaValue {
                return self.resolve_schema(context, rule, value);
            }
            if let Some(s) = value.as_str() {
                if self.catalog_permits(context, path, s) {
                    return self.decision(
                        context,
                        &rule.rule_id,
                        FieldOperation::PreserveConstant,
                        None,
                        None,
                    );
                }
            }
            let mut namespace = rule.namespace.clone();
            if let Some(s) = value.as_str() {
                if matches!(
                    rule.operation,
                    FieldOperation::MapCustomIdentifier | FieldOperation::MapReference
                ) && self.catalog_permits_domain_rid(
                    context,
                    path,
                    s,
                    rule.operation == FieldOperation::MapReference,
                    reference_node_type,
                ) {
                    namespace = Some("sids_preserve_rid".to_string());
                }
            }
            // A rule declares the shape it expects at a path. Ingestors do not
            // always honour it: the CE collectors emit empty strings for absent
            // attributes, names with an empty domain part, and GUID principals
            // in `Aces[].PrincipalSID`. Re-route to the namespace the value
            // actually is, or fall back to `opaque` — never hand a structured
            // transform a value it cannot parse, which used to abort the run.
            if let Some(s) = value.as_str() {
                if let Some(routed) = routed_identifier_namespace(rule.operation, &namespace, s) {
                    namespace = Some(routed);
                } else if !source_shape_supports(rule.operation, &namespace, s) {
                    return self.decision(
                        context,
                        &rule.rule_id,
                        FieldOperation::ReplaceOpaque,
                        Some("opaque"),
                        Some("malformed-source-value"),
                    );
                }
            }

            return FieldDecision {
                rule_id: rule.rule_id.clone(),
                operation: rule.operation,
                namespace,
                privacy: context.privacy,
                audit_code: None,
                evidence: None,
            };
        }

        if let Some(s) = value.as_str() {
            if sid_re().is_match(s) {
                return self.decision(
                    context,
                    "fallback.sid",
                    FieldOperation::MapCustomIdentifier,
                    Some("sids"),
                    Some("unknown-sid-path"),
                );
            }
            if guid_re().is_match(s) {
                return self.decision(
                    context,
                    "fallback.guid",
                    FieldOperation::MapCustomIdentifier,
                    Some("guids"),
                    Some("unknown-guid-path"),
                );
            }
            if oid_re().is_match(s) {
                return self.decision(
                    context,
                    "fallback.oid",
                    FieldOperation::MapCustomIdentifier,
                    Some("oids"),
                    Some("unknown-oid-path"),
                );
            }
            return self.decision(
                context,
                "fallback.unknown-string",
                FieldOperation::ReplaceOpaque,
                Some("opaque"),
                Some("unknown-string-path"),
            );
        }

        self.decision(
            context,
            "fallback.unknown-value",
            FieldOperation::ReplaceOpaque,
            Some("opaque"),
            Some("unknown-value-path"),
        )
    }
}

// ===========================================================================
// PolicyAudit
// ===========================================================================

/// The namespace an identifier *reference* should use given what the value
/// actually is, when that disagrees with the namespace its rule declared.
///
/// `map_custom_identifier` already dispatches on the value's shape, but
/// `map_reference` dispatches on the namespace, so a GUID sitting in
/// `Aces[].PrincipalSID` — which the BloodHound CE collectors emit for
/// Container, OU and GPO principals — was mapped through the SID transform and
/// came back a SID, failing the leak gate's output-shape check. Routing it to
/// `guids` keeps the cross-reference intact: the ACE and the container's own
/// `ObjectIdentifier` resolve to the same pseudonym.
///
/// Returns `None` when the declared namespace already fits, when the value is
/// not an identifier at all (the caller then falls back to `opaque`), or when
/// the operation is not a reference.
fn routed_identifier_namespace(
    operation: FieldOperation,
    namespace: &Option<String>,
    value: &str,
) -> Option<String> {
    if operation != FieldOperation::MapReference {
        return None;
    }
    let declared = namespace.as_deref()?;
    let actual = if sid_re().is_match(value) {
        "sids"
    } else if guid_re().is_match(value) {
        "guids"
    } else if oid_re().is_match(value) {
        "oids"
    } else {
        return None;
    };
    // `sids_preserve_rid` is a SID namespace with extra intent; leave it alone.
    let declared_is_sid = declared == "sids" || declared == "sids_preserve_rid";
    let fits = match actual {
        "sids" => declared_is_sid,
        other => declared == other,
    };
    if fits || !matches!(declared, "sids" | "sids_preserve_rid" | "guids" | "oids") {
        return None;
    }
    Some(actual.to_string())
}

/// Whether a source value can satisfy the operation its rule declares.
///
/// Mirrors the leak gate's `output_shape_valid` checks, applied to the source.
/// A value that fails here cannot produce a well-shaped output, so the run
/// would abort on it; the caller anonymizes it opaquely instead, which is the
/// safe direction — more redaction, never less.
fn source_shape_supports(
    operation: FieldOperation,
    namespace: &Option<String>,
    value: &str,
) -> bool {
    match operation {
        FieldOperation::ParseDn => {
            !value.is_empty()
                && value.split(',').all(|rdn| {
                    rdn.split('+').all(|component| {
                        component.contains('=') && component.splitn(2, '=').all(|p| !p.is_empty())
                    })
                })
        }
        FieldOperation::ParseSpn => {
            let components: Vec<&str> = value.split('/').collect();
            matches!(components.len(), 2 | 3) && components.iter().all(|c| !c.is_empty())
        }
        FieldOperation::ParseComposite if value.contains('@') => {
            let parts: Vec<&str> = value.rsplitn(2, '@').collect();
            parts.len() == 2 && parts.iter().all(|p| !p.is_empty())
        }
        FieldOperation::MapIdentity => {
            if value.contains('@') {
                let parts: Vec<&str> = value.split('@').collect();
                parts.len() == 2 && parts.iter().all(|p| !p.is_empty())
            } else if matches!(namespace.as_deref(), Some("domains") | Some("hosts")) {
                !value.is_empty() && value.split('.').all(|p| !p.is_empty())
            } else {
                true
            }
        }
        FieldOperation::MapCustomIdentifier | FieldOperation::MapReference => {
            // A structured SID transform needs a parseable SID; anything else
            // at an identifier path is routed by shape or redacted.
            !matches!(
                namespace.as_deref(),
                Some("sids") | Some("sids_preserve_rid")
            ) || sid_re().is_match(value)
        }
        _ => true,
    }
}

/// The catalog entry backing one domain-RID preservation decision, and the node
/// type it was resolved against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRidMatch {
    pub rule_id: String,
    pub node_type: String,
}

/// Aggregate policy decisions without retaining source or output values
/// (`PolicyAudit`).
#[derive(Clone, Debug, Default)]
pub struct PolicyAudit {
    object_classifications: HashMap<PrivacyClass, u64>,
    privacy_classes: HashMap<PrivacyClass, u64>,
    operations: HashMap<FieldOperation, u64>,
    rule_ids: HashMap<String, u64>,
    audit_codes: HashMap<String, u64>,
    unknown_paths: HashMap<String, u64>,
}

impl PolicyAudit {
    pub fn new() -> Self {
        PolicyAudit::default()
    }

    /// Count one object once at the discovery boundary
    /// (`record_object_classification`).
    pub fn record_object_classification(&mut self, privacy: PrivacyClass) {
        *self.object_classifications.entry(privacy).or_insert(0) += 1;
    }

    /// Increment one audit code directly, without touching the unknown-path
    /// index (mirrors `self.audit_codes[code] += 1`, e.g. the engine's
    /// `unknown-node-type` bump).
    pub fn record_code(&mut self, code: &str) {
        *self.audit_codes.entry(code.to_string()).or_insert(0) += 1;
    }

    /// Audit a dynamic key using only its mapped output path
    /// (`record_unknown_key`).
    pub fn record_unknown_key(&mut self, projected_path: &str) {
        *self
            .audit_codes
            .entry("unknown-key-path".to_string())
            .or_insert(0) += 1;
        *self
            .unknown_paths
            .entry(canonical_path(projected_path))
            .or_insert(0) += 1;
    }

    /// Record one decision (`record`).
    pub fn record(&mut self, record: &DecisionRecord) {
        let decision = &record.decision;
        *self.privacy_classes.entry(decision.privacy).or_insert(0) += 1;
        *self.operations.entry(decision.operation).or_insert(0) += 1;
        *self.rule_ids.entry(decision.rule_id.clone()).or_insert(0) += 1;
        if let Some(code) = &decision.audit_code {
            *self.audit_codes.entry(code.clone()).or_insert(0) += 1;
            if code.starts_with("unknown-") {
                *self
                    .unknown_paths
                    .entry(canonical_path(&record.path))
                    .or_insert(0) += 1;
            }
        }
    }

    /// Sorted aggregate summary (`summary`), as a `serde_json::Value` object so
    /// insertion order (top-level layout + sorted keys) is deterministic.
    pub fn summary(&self) -> Value {
        fn enum_map<K: Copy + Eq + std::hash::Hash>(
            counts: &HashMap<K, u64>,
            as_str: impl Fn(K) -> &'static str,
        ) -> Value {
            let mut items: Vec<(&'static str, u64)> =
                counts.iter().map(|(k, v)| (as_str(*k), *v)).collect();
            items.sort_by(|a, b| a.0.cmp(b.0));
            let mut map = serde_json::Map::new();
            for (k, v) in items {
                map.insert(k.to_string(), Value::from(v));
            }
            Value::Object(map)
        }
        fn str_map(counts: &HashMap<String, u64>) -> Value {
            let mut items: Vec<(&String, u64)> = counts.iter().map(|(k, v)| (k, *v)).collect();
            items.sort_by(|a, b| a.0.cmp(b.0));
            let mut map = serde_json::Map::new();
            for (k, v) in items {
                map.insert(k.clone(), Value::from(v));
            }
            Value::Object(map)
        }

        let mut top = serde_json::Map::new();
        top.insert(
            "object_classifications".to_string(),
            enum_map(&self.object_classifications, PrivacyClass::as_str),
        );
        top.insert(
            "privacy_classes".to_string(),
            enum_map(&self.privacy_classes, PrivacyClass::as_str),
        );
        top.insert(
            "operations".to_string(),
            enum_map(&self.operations, FieldOperation::as_str),
        );
        top.insert("rule_ids".to_string(), str_map(&self.rule_ids));
        top.insert("audit_codes".to_string(), str_map(&self.audit_codes));
        top.insert("unknown_paths".to_string(), str_map(&self.unknown_paths));
        Value::Object(top)
    }
}

// ===========================================================================
// Static rule data (module constants + `_default_rules`)
// ===========================================================================

const RIGHT_NAMES: &[&str] = &[
    "AddAllowedToAct",
    "AddKeyCredentialLink",
    "AddMember",
    "AddSelf",
    "AllExtendedRights",
    "AllowedToAct",
    "AllowedToDelegate",
    "CoerceToTGT",
    "DumpSMSAPassword",
    "Enroll",
    "EnrollOnBehalfOf",
    "ForceChangePassword",
    "GenericAll",
    "GenericRead",
    "GenericWrite",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "GoldenCert",
    "ManageCA",
    "ManageCertificates",
    "ManageCertTemplates",
    "Owns",
    "ReadGMSAPassword",
    "ReadLAPSPassword",
    "ReadMSAPassword",
    "SQLAdmin",
    "SyncLAPSPassword",
    "WriteAccountRestrictions",
    "WriteAltSecurityIdentities",
    "WriteDacl",
    "WriteGPLink",
    "WriteOwner",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",
    "WritePublicInformation",
    "WriteSPN",
];

const CA_RIGHT_NAMES: &[&str] = &["Enroll", "ManageCA", "ManageCertificates", "Owns"];

const OBJECT_TYPES: &[&str] = &[
    "ADLocalGroup",
    "ADLocalUser",
    "AIACA",
    "Base",
    "CertTemplate",
    "Computer",
    "Configuration",
    "Container",
    "Domain",
    "EnterpriseCA",
    "GPO",
    "Group",
    "IssuancePolicy",
    "NTAuthStore",
    "OU",
    "RootCA",
    "User",
];

const GPO_STATUSES: &[&str] = &[
    "All Enabled",
    "All Settings Disabled",
    "Computer Configuration Disabled",
    "Computer Settings Disabled",
    "User Configuration Disabled",
    "User Settings Disabled",
];

const TRUST_DIRECTIONS: &[&str] = &["Bidirectional", "Disabled", "Inbound", "Outbound"];

const TRUST_TYPES: &[&str] = &[
    "CrossLink",
    "External",
    "Forest",
    "Kerberos",
    "ParentChild",
    "TreeRoot",
    "Unknown",
];

const GROUP_TYPES: &[&str] = &["Global", "DomainLocal", "Universal"];
const USER_RIGHT_PRIVILEGES: &[&str] = &["SeRemoteInteractiveLogonRight"];
const ENROLLMENT_ACCESS_TYPES: &[&str] = &["AccessAllowedCallback", "AccessDeniedCallback"];

const META_TYPES: &[&str] = &[
    "adlocalgroups",
    "aiacas",
    "base",
    "certtemplates",
    "computers",
    "containers",
    "domains",
    "enterprisecas",
    "foreignsecurityprincipals",
    "gpos",
    "groups",
    "issuancepolicies",
    "meta",
    "ntauthstores",
    "ous",
    "rootcas",
    "users",
];

const KNOWN_SCHEMA_PATH_ALIASES: &[(&str, &str)] = &[("*", "Properties.gPCFileSysPath")];

const SID_REFERENCE_PATHS: &[&str] = &[
    "Aces[].PrincipalSID",
    "PrimaryGroupSID",
    "HasSIDHistory[]",
    "MemberOf[]",
    "Sessions.Results[].UserSID",
    "Sessions.Results[].ComputerSID",
    "PrivilegedSessions.Results[].UserSID",
    "PrivilegedSessions.Results[].ComputerSID",
    "RegistrySessions.Results[].UserSID",
    "RegistrySessions.Results[].ComputerSID",
    "NtlmSessions.Result.Sessions[].AccountSid",
    "DomainSID",
    "ForestRootIdentifier",
    "SPNTargets[].ComputerSID",
    "Properties.domainsid",
    "Properties.primarygroupsid",
    "Properties.objectsid",
    "Trusts[].TargetDomainSid",
    "CARegistryData.CASecurity.Data[].PrincipalSID",
    "Properties.CARegistryData.CASecurity.Data[].PrincipalSID",
];

const IDENTIFIER_REFERENCE_PATHS: &[&str] = &[
    "Members[].ObjectIdentifier",
    "ChildObjects[].ObjectIdentifier",
    "AllowedToDelegate[].ObjectIdentifier",
    "AllowedToAct[].ObjectIdentifier",
    "HasSIDHistory[].ObjectIdentifier",
    "MemberOf[].ObjectIdentifier",
    "DumpSMSAPassword[].ObjectIdentifier",
    "LocalGroups[].ObjectIdentifier",
    "LocalGroups[].Results[].ObjectIdentifier",
    "HostingComputer",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Agent.ObjectIdentifier",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Targets[].ObjectIdentifier",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Template.ObjectIdentifier",
    "ContainedBy.ObjectIdentifier",
    "EnabledCertTemplates[].ObjectIdentifier",
    "GPOChanges.AffectedComputers[].ObjectIdentifier",
    "GPOChanges.LocalAdmins[].ObjectIdentifier",
    "GPOChanges.RemoteDesktopUsers[].ObjectIdentifier",
    "GPOChanges.DcomUsers[].ObjectIdentifier",
    "GPOChanges.PSRemoteUsers[].ObjectIdentifier",
    "GroupLink.ObjectIdentifier",
    "LocalGroups[].LocalNames[].ObjectId",
    "UserRights[].Results[].ObjectIdentifier",
    "UserRights[].LocalNames[].ObjectId",
];

const OPAQUE_PATH_URL_PATHS: &[&str] = &[
    "Properties.profilepath",
    "Properties.homedirectory",
    "Properties.scriptpath",
    "Properties.logonscript",
    "Properties.gpcpath",
    "Properties.gpcfilesyspath",
    "Properties.url",
    "Properties.uri",
    "Properties.certchain[]",
    "Properties.certchain",
    "Properties.operatingsystem",
    "Properties.operatingsystemversion",
    "Properties.description",
    "Properties.displayname",
    "Properties.info",
    "Properties.title",
    "NtlmSessions.Result.Sessions[].SourceIp",
    "NtlmSessions.Result.Sessions[].SourcePort",
    "NtlmSessions.Result.Sessions[].PackageName",
];

/// Collector diagnostics: `null` when the block collected, otherwise a free-text
/// reason that routinely names the host or account that refused. The sibling
/// `.Collected` flag and `.Results[]` members are already declared; without
/// these the diagnostic's *key* is unmodeled, so it is mapped along with every
/// other unknown key and a standard SharpHound field comes back renamed.
/// Declared as opaque rather than preserved: the value carries no graph edge and
/// can carry a hostname.
const OPAQUE_DIAGNOSTIC_PATHS: &[&str] = &[
    "Sessions.FailureReason",
    "PrivilegedSessions.FailureReason",
    "RegistrySessions.FailureReason",
    "LocalGroups[].FailureReason",
    "UserRights[].FailureReason",
];

const OID_IDENTIFIER_PATHS: &[&str] = &[
    "Properties.oid",
    "Properties.ekus[]",
    "Properties.applicationpolicies[]",
    "Properties.certificateapplicationpolicy[]",
    "Properties.certificatepolicies[]",
    "Properties.certificatepolicy[]",
    "Properties.effectiveekus[]",
    "Properties.issuancepolicies[]",
];

const GUID_IDENTIFIER_PATHS: &[&str] = &[
    "Properties.objectguid",
    "Properties.wkguid",
    "Links[].GUID",
    "Aces[].RightGuid",
];

const OBJECT_TYPE_PATHS: &[&str] = &[
    "Members[].ObjectType",
    "ChildObjects[].ObjectType",
    "AllowedToDelegate[].ObjectType",
    "AllowedToAct[].ObjectType",
    "HasSIDHistory[].ObjectType",
    "MemberOf[].ObjectType",
    "DumpSMSAPassword[].ObjectType",
    "LocalGroups[].Results[].ObjectType",
    "Aces[].PrincipalType",
    "CARegistryData.CASecurity.Data[].PrincipalType",
    "Properties.CARegistryData.CASecurity.Data[].PrincipalType",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Agent.ObjectType",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Targets[].ObjectType",
    "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].Template.ObjectType",
    "ContainedBy.ObjectType",
    "EnabledCertTemplates[].ObjectType",
    "GPOChanges.AffectedComputers[].ObjectType",
    "GPOChanges.LocalAdmins[].ObjectType",
    "GPOChanges.RemoteDesktopUsers[].ObjectType",
    "GPOChanges.DcomUsers[].ObjectType",
    "GPOChanges.PSRemoteUsers[].ObjectType",
    "GroupLink.ObjectType",
    "UserRights[].Results[].ObjectType",
];

const NUMERIC_PATHS: &[&str] = &[
    "meta.version",
    "meta.count",
    "meta.methods",
    "Properties.admincount",
    "Properties.lastlogon",
    "Properties.lastlogontimestamp",
    "Properties.pwdlastset",
    "Properties.samaccounttype",
    "Properties.useraccountcontrol",
    "Properties.whencreated",
    "Properties.whenchanged",
    "SPNTargets[].Port",
];

const BOOLEAN_PATHS: &[&str] = &[
    "Properties.enabled",
    "Properties.hasspn",
    "Properties.highvalue",
    "Properties.isaclprotected",
    "Properties.isdc",
    "Properties.owned",
    "Properties.passwordnotreqd",
    "Properties.pwdneverexpires",
    "Properties.sensitive",
    "Properties.smartcardrequired",
    "Properties.trustedtoauth",
    "Properties.unconstraineddelegation",
    "Links[].IsEnforced",
    "Aces[].IsInherited",
    "Trusts[].SidFilteringEnabled",
    "Trusts[].IsTransitive",
    "Sessions.Collected",
    "PrivilegedSessions.Collected",
    "RegistrySessions.Collected",
    "LocalGroups[].Collected",
    "UserRights[].Collected",
    "IsDeleted",
    "IsACLProtected",
];

fn set_of(values: &[&str]) -> HashSet<String> {
    values.iter().map(|s| (*s).to_string()).collect()
}

#[allow(clippy::too_many_arguments)]
fn rule(
    rule_id: &str,
    path: &str,
    operation: FieldOperation,
    namespace: Option<&str>,
    allowed_values: Option<&[&str]>,
    node_types: &[&str],
) -> FieldRule {
    FieldRule {
        rule_id: rule_id.to_string(),
        node_types: set_of(node_types),
        path: path.to_string(),
        operation,
        namespace: namespace.map(str::to_string),
        allowed_values: allowed_values.map(set_of),
    }
}

/// Build the default field rules (`_default_rules`).
pub fn default_rules() -> Vec<FieldRule> {
    use FieldOperation::*;
    let star: &[&str] = &["*"];
    let mut rules: Vec<FieldRule> = vec![
        rule(
            "identifier.object",
            "ObjectIdentifier",
            MapCustomIdentifier,
            None,
            None,
            star,
        ),
        rule(
            "common.properties-name",
            "Properties.name",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.domain",
            "Properties.domain",
            MapIdentity,
            Some("domains"),
            None,
            star,
        ),
        rule(
            "identity.target-domain-name",
            "Properties.targetdomainname",
            MapIdentity,
            Some("domains"),
            None,
            star,
        ),
        rule(
            "identity.sam-account-name",
            "Properties.samaccountname",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.user-principal-name",
            "Properties.userprincipalname",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.dns-host-name",
            "Properties.dnshostname",
            MapIdentity,
            Some("hosts"),
            None,
            star,
        ),
        rule(
            "identity.email",
            "Properties.email",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.mail",
            "Properties.mail",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "dn.distinguished-name",
            "Properties.distinguishedname",
            ParseDn,
            None,
            None,
            star,
        ),
        rule(
            "dn.manager",
            "Properties.manager",
            ParseDn,
            None,
            None,
            star,
        ),
        rule(
            "spn.service-principal-name",
            "Properties.serviceprincipalnames[]",
            ParseSpn,
            None,
            None,
            star,
        ),
        rule(
            "template.internal-name",
            "Properties.templatename",
            MapIdentity,
            Some("cert_templates"),
            None,
            star,
        ),
        rule(
            "template.published-reference",
            "Properties.templates[]",
            MapReference,
            Some("cert_templates"),
            None,
            star,
        ),
        rule(
            "template.unresolved-reference",
            "Properties.unresolvedpublishedtemplates[]",
            MapReference,
            Some("cert_templates"),
            None,
            star,
        ),
        rule(
            "identity.ca-name",
            "Properties.caname",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.certificate-name",
            "Properties.certname",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
    ];

    for path in SID_REFERENCE_PATHS {
        rules.push(rule(
            &format!("reference.sid.{}", canonical_path(path)),
            path,
            MapReference,
            Some("sids"),
            None,
            star,
        ));
    }
    for path in IDENTIFIER_REFERENCE_PATHS {
        rules.push(rule(
            &format!("reference.identifier.{}", canonical_path(path)),
            path,
            MapReference,
            Some("identifiers"),
            None,
            star,
        ));
    }
    for path in OPAQUE_PATH_URL_PATHS {
        rules.push(rule(
            &format!("opaque.path-url.{}", canonical_path(path)),
            path,
            ReplaceOpaque,
            Some("opaque"),
            None,
            star,
        ));
    }
    for path in OPAQUE_DIAGNOSTIC_PATHS {
        rules.push(rule(
            &format!("opaque.diagnostic.{}", canonical_path(path)),
            path,
            ReplaceOpaque,
            Some("opaque"),
            None,
            star,
        ));
    }
    for path in OID_IDENTIFIER_PATHS {
        rules.push(rule(
            &format!("identifier.oid.{}", canonical_path(path)),
            path,
            MapCustomIdentifier,
            Some("oids"),
            None,
            star,
        ));
    }
    for path in GUID_IDENTIFIER_PATHS {
        rules.push(rule(
            &format!("identifier.guid.{}", canonical_path(path)),
            path,
            MapCustomIdentifier,
            Some("guids"),
            None,
            star,
        ));
    }

    rules.extend([
        rule(
            "schema.ace-right-name",
            "Aces[].RightName",
            PreserveSchemaValue,
            None,
            Some(RIGHT_NAMES),
            star,
        ),
        rule(
            "schema.ca-security-right-name",
            "CARegistryData.CASecurity.Data[].RightName",
            PreserveSchemaValue,
            None,
            Some(CA_RIGHT_NAMES),
            star,
        ),
        rule(
            "schema.properties-ca-security-right-name",
            "Properties.CARegistryData.CASecurity.Data[].RightName",
            PreserveSchemaValue,
            None,
            Some(CA_RIGHT_NAMES),
            star,
        ),
        rule(
            "identifier.ace-object-type",
            "Aces[].ObjectType",
            MapCustomIdentifier,
            Some("guids"),
            None,
            star,
        ),
        rule(
            "identifier.ace-object-type-guid",
            "Aces[].ObjectTypeGuid",
            MapCustomIdentifier,
            Some("guids"),
            None,
            star,
        ),
        rule(
            "identifier.ace-inherited-object-type",
            "Aces[].InheritedObjectType",
            MapCustomIdentifier,
            Some("guids"),
            None,
            star,
        ),
        rule(
            "identifier.ace-inherited-object-type-guid",
            "Aces[].InheritedObjectTypeGuid",
            MapCustomIdentifier,
            Some("guids"),
            None,
            star,
        ),
        rule(
            "schema.gpo-status",
            "Properties.gpostatus",
            PreserveSchemaValue,
            None,
            Some(GPO_STATUSES),
            star,
        ),
        rule(
            "schema.group-type",
            "Properties.grouptype",
            PreserveSchemaValue,
            None,
            Some(GROUP_TYPES),
            star,
        ),
        rule(
            "schema.group-scope",
            "Properties.groupscope",
            PreserveSchemaValue,
            None,
            Some(GROUP_TYPES),
            star,
        ),
        rule(
            "opaque.functional-level",
            "Properties.functionallevel",
            ReplaceOpaque,
            Some("opaque"),
            None,
            star,
        ),
        rule(
            "schema.user-right-privilege",
            "UserRights[].Privilege",
            PreserveSchemaValue,
            None,
            Some(USER_RIGHT_PRIVILEGES),
            star,
        ),
        rule(
            "schema.enrollment-agent-access-type",
            "CARegistryData.EnrollmentAgentRestrictions.Restrictions[].AccessType",
            PreserveSchemaValue,
            None,
            Some(ENROLLMENT_ACCESS_TYPES),
            star,
        ),
        rule(
            "schema.properties-enrollment-agent-access-type",
            "Properties.CARegistryData.EnrollmentAgentRestrictions.Restrictions[].AccessType",
            PreserveSchemaValue,
            None,
            Some(ENROLLMENT_ACCESS_TYPES),
            star,
        ),
        rule(
            "schema.spn-target-service",
            "SPNTargets[].Service",
            PreserveSchemaValue,
            None,
            Some(&["SQLAdmin"]),
            star,
        ),
        rule(
            "schema.foreign-security-principal-type",
            "Properties.type",
            PreserveSchemaValue,
            None,
            Some(&["foreignsecurityprincipal"]),
            &["Base"],
        ),
        rule(
            "schema.trust-direction",
            "Trusts[].TrustDirection",
            PreserveSchemaValue,
            None,
            Some(TRUST_DIRECTIONS),
            star,
        ),
        rule(
            "schema.trust-type",
            "Trusts[].TrustType",
            PreserveSchemaValue,
            None,
            Some(TRUST_TYPES),
            star,
        ),
        rule(
            "schema.meta-type",
            "meta.type",
            PreserveSchemaValue,
            None,
            Some(META_TYPES),
            star,
        ),
    ]);

    for path in OBJECT_TYPE_PATHS {
        rules.push(rule(
            &format!("schema.object-type.{}", canonical_path(path)),
            path,
            PreserveSchemaValue,
            None,
            Some(OBJECT_TYPES),
            star,
        ));
    }
    for path in NUMERIC_PATHS {
        rules.push(rule(
            &format!("schema.numeric.{}", canonical_path(path)),
            path,
            PreserveSchemaValue,
            None,
            None,
            star,
        ));
    }
    for path in BOOLEAN_PATHS {
        rules.push(rule(
            &format!("schema.boolean.{}", canonical_path(path)),
            path,
            PreserveSchemaValue,
            None,
            None,
            star,
        ));
    }

    rules.extend([
        rule(
            "identity.trust-target-domain-name",
            "Trusts[].TargetDomainName",
            MapReference,
            Some("domains"),
            None,
            star,
        ),
        rule(
            "identity.ntlm-account-name",
            "NtlmSessions.Result.Sessions[].AccountName",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.ntlm-account-domain",
            "NtlmSessions.Result.Sessions[].AccountDomain",
            MapIdentity,
            Some("domains"),
            None,
            star,
        ),
        rule(
            "identity.ntlm-source-host",
            "NtlmSessions.Result.Sessions[].SourceHost",
            MapIdentity,
            Some("hosts"),
            None,
            star,
        ),
        rule(
            "identity.local-group-local-name",
            "LocalGroups[].LocalNames[].PrincipalName",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.user-right-local-name",
            "UserRights[].LocalNames[].PrincipalName",
            MapIdentity,
            Some("accounts"),
            None,
            star,
        ),
        rule(
            "identity.local-groups-result-name",
            "LocalGroups[].Name",
            ParseComposite,
            None,
            None,
            star,
        ),
        rule(
            "identity.domain-name",
            "Properties.name",
            MapIdentity,
            Some("domains"),
            None,
            &["Domain"],
        ),
        rule(
            "identity.computer-name",
            "Properties.name",
            MapIdentity,
            Some("hosts"),
            None,
            &["Computer"],
        ),
        rule(
            "identity.template-name",
            "Properties.name",
            MapIdentity,
            Some("cert_templates"),
            None,
            &["CertTemplate"],
        ),
        rule(
            "identity.local-group-composite",
            "Properties.name",
            ParseComposite,
            None,
            None,
            &["ADLocalGroup"],
        ),
    ]);

    rules
}
