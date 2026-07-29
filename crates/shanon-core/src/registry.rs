//! Deterministic pseudonym store (module 7, P2).
//!
//! Pseudonyms are seeded by `blake2b(salt || category || semantic_real)` so the
//! same real value maps to the same pseudonym within a run, while a different
//! salt yields a different pseudonym. The seed layout and the on-disk mapping
//! format are frozen interop contracts (§3.1a / §3.3). [`Registry`] implements both
//! [`crate::components::RegistryOps`] and [`crate::fields::TokenRegistry`].
//!
//! ## Full case folding
//! Semantic identity uses [`crate::casefold`], never `to_lowercase` (§3.1a).
//!
//! ## Determinism (§3.2)
//! Every map that influences output order is an [`IndexMap`], preserving
//! insertion order (allocation order). [`Registry::all_real_tokens`]
//! resolves the latent tie-break P0 flagged: token membership is a set, and the
//! `fields` matcher then sorts by `(-len, casefold)`, which is unstable on true
//! ties (same length AND same casefold, different raw spelling). This impl
//! returns a Vec in a **total order over the raw spelling** (Rust `str` Ord =
//! Unicode scalar order). Because the `fields` sort is stable, that fixed input
//! order makes the compiled token alternation deterministic across runs.
//!
//! ## Fallible trait bridge
//! `RegistryOps`/`TokenRegistry` are infallible (`-> String`) by P0 contract,
//! but the underlying operations can fail (collisions, unsafe mappings). The
//! inherent [`Registry::map`]/[`Registry::bind`] return `Result`; the trait
//! impls record the first error via [`Registry::take_trait_error`] and return an
//! empty placeholder so the engine can abort the whole document afterwards.

use std::fmt;
use std::sync::OnceLock;

use indexmap::{IndexMap, IndexSet};
use regex::Regex;

use crate::casefold::casefold;
use crate::components::RegistryOps;
use crate::components::{ACCOUNTS, CERT_TEMPLATES, DOMAINS, GUIDS, HOSTS, OIDS, OPAQUE, SIDS};
use crate::fields::TokenRegistry;

/// Category iteration order (`_CATEGORIES`). Drives `reverse`, trust
/// fingerprints, and category-pair iteration.
pub const CATEGORIES: [&str; 8] = [
    DOMAINS,
    SIDS,
    ACCOUNTS,
    HOSTS,
    GUIDS,
    CERT_TEMPLATES,
    OIDS,
    OPAQUE,
];

const CASEFOLD_CATEGORIES: [&str; 6] = [DOMAINS, SIDS, ACCOUNTS, HOSTS, GUIDS, CERT_TEMPLATES];
const SAFE_DOMAIN_SUFFIXES: [&str; 4] = ["example", "invalid", "local", "test"];

const COMPANIES_TXT: &str = include_str!("data/companies.txt");
const SURNAMES_TXT: &str = include_str!("data/surnames.txt");

/// Forward mapping bucket: `real -> pseudonym` (insertion-ordered).
type Bucket = IndexMap<String, String>;
/// Every category's forward bucket, keyed and iterated in [`CATEGORIES`] order.
type Categories = IndexMap<String, Bucket>;

// ---------------------------------------------------------------------------
// Errors (PseudonymCollisionError, UnsafeMappingError, ValueError,
// RuntimeError, TypeError).
// ---------------------------------------------------------------------------

/// Registry failure surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// `PseudonymCollisionError`.
    PseudonymCollision(String),
    /// `UnsafeMappingError` (a `ValueError` variant).
    UnsafeMapping(String),
    /// `ValueError` (unknown category, unsupported format version).
    Value(String),
    /// `RuntimeError` (allocation attempted on a frozen registry).
    Frozen(String),
    /// `TypeError` (missing structured SID intent).
    Type(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::PseudonymCollision(m) => write!(f, "pseudonym collision: {m}"),
            RegistryError::UnsafeMapping(m) => write!(f, "unsafe mapping: {m}"),
            RegistryError::Value(m) => write!(f, "{m}"),
            RegistryError::Frozen(m) => write!(f, "{m}"),
            RegistryError::Type(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RegistryError {}

type Result<T> = std::result::Result<T, RegistryError>;

// ---------------------------------------------------------------------------
// Module-level helpers.
// ---------------------------------------------------------------------------

fn domain_sid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^S-1-5-21-(\d+)-(\d+)-(\d+)$").unwrap())
}

fn legacy_domain_sid_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\d+)-(\d+)-(\d+)$").unwrap())
}

/// Canonicalize a non-negative integer string (`str(int(component))`): strip
/// leading zeros without overflowing on pathologically long OID/SID arcs.
fn canon_int(s: &str) -> String {
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `[0-9]+(?:\.[0-9]+)+` — two or more dotted all-digit components.
fn is_dotted_numeric(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `_normalize_mapping_identity`: category-specific semantic identity.
pub fn normalize_mapping_identity(category: &str, value: &str) -> String {
    if category == GUIDS {
        let core = if value.starts_with('{') && value.ends_with('}') && value.chars().count() >= 2 {
            &value[1..value.len() - 1]
        } else {
            value
        };
        let compact: String = core.chars().filter(|c| *c != '-').collect();
        if compact.len() == 32 && compact.bytes().all(|b| b.is_ascii_hexdigit()) {
            return casefold(&compact);
        }
        return casefold(value);
    }
    if category == OIDS && is_dotted_numeric(value) {
        return value
            .split('.')
            .map(canon_int)
            .collect::<Vec<_>>()
            .join(".");
    }
    if CASEFOLD_CATEGORIES.contains(&category) {
        return casefold(value);
    }
    value.to_string()
}

/// `_source_spelling_key`: prefer a canonical lowercase spelling, ties stable.
fn source_spelling_key(value: &str) -> (String, bool, String) {
    let cf = casefold(value);
    (cf.clone(), value != cf, value.to_string())
}

/// Choose the preferred spelling among `candidates` via [`source_spelling_key`].
fn min_by_spelling<'a, I>(candidates: I) -> &'a str
where
    I: IntoIterator<Item = &'a str>,
{
    candidates
        .into_iter()
        .min_by(|a, b| source_spelling_key(a).cmp(&source_spelling_key(b)))
        .expect("non-empty alias set")
}

/// `_domain_sid_components`: parse one domain SID's numeric arcs.
fn domain_sid_components(value: &str, require_canonical: bool) -> Option<Vec<u128>> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() < 8 || parts[0].to_uppercase() != "S" {
        return None;
    }
    if require_canonical && parts[0] != "S" {
        return None;
    }
    let mut numeric: Vec<u128> = Vec::with_capacity(parts.len() - 1);
    for component in &parts[1..] {
        if component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let parsed: u128 = component.parse().ok()?;
        if require_canonical && *component != parsed.to_string() {
            return None;
        }
        numeric.push(parsed);
    }
    if numeric[..3] != [1, 5, 21] {
        return None;
    }
    if require_canonical && numeric[3..].iter().any(|c| *c > 0xFFFF_FFFF) {
        return None;
    }
    Some(numeric)
}

/// `_consistent_sid_hierarchy`.
fn consistent_sid_hierarchy(
    real: &str,
    existing: &str,
    requested: &str,
    preserve_terminal: bool,
) -> bool {
    let real_parts = domain_sid_components(real, false);
    let existing_parts = domain_sid_components(existing, false);
    let requested_parts = domain_sid_components(requested, false);
    let (real_parts, existing_parts, requested_parts) =
        match (real_parts, existing_parts, requested_parts) {
            (Some(r), Some(e), Some(q)) => (r, e, q),
            _ => return false,
        };
    if existing_parts.len() != real_parts.len() || requested_parts.len() != real_parts.len() {
        return false;
    }
    let last = real_parts.len() - 1;
    if existing_parts[..last] != requested_parts[..last] {
        return false;
    }
    let existing_preserves = existing_parts[last] == real_parts[last];
    if preserve_terminal {
        existing_preserves
    } else {
        !existing_preserves
    }
}

/// `_upgrade_version_one_sid_mappings`: rebuild v1 fragment SID keys into
/// reversible owners; returns `(upgraded_forward, legacy_reverse_aliases)`.
fn upgrade_version_one_sid_mappings(mapping: &Bucket) -> Result<(Bucket, Bucket)> {
    // authority -> (source_domain, pseudonym)
    let mut authorities: IndexMap<String, (String, String)> = IndexMap::new();
    for (source, pseudonym) in mapping {
        if let Some(caps) = legacy_domain_sid_key_re().captures(source) {
            if domain_sid_re().is_match(pseudonym) {
                let authority = format!("{}-{}-{}", &caps[1], &caps[2], &caps[3]);
                authorities.insert(
                    authority.clone(),
                    (format!("S-1-5-21-{authority}"), pseudonym.clone()),
                );
            }
        }
    }

    if authorities.is_empty() {
        return Ok((mapping.clone(), Bucket::new()));
    }

    let mut upgraded: Bucket = mapping
        .iter()
        .filter(|(source, _)| legacy_domain_sid_key_re().captures(source).is_none())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut legacy_reverse_aliases: Bucket = Bucket::new();
    for (_authority, (source_domain, mapped_domain)) in &authorities {
        upgraded.insert(source_domain.clone(), mapped_domain.clone());
        let source_prefix = format!("{source_domain}-");
        for (source, legacy_pseudonym) in mapping {
            if source
                .to_uppercase()
                .starts_with(&source_prefix.to_uppercase())
                && domain_sid_re().is_match(legacy_pseudonym)
            {
                let descendant = &source[source_prefix.len()..];
                if descendant.contains('-') {
                    upgraded.shift_remove(source);
                    let legacy_rid = legacy_pseudonym.rsplit('-').next().unwrap();
                    let historical = format!("{mapped_domain}-{legacy_rid}");
                    if let Some(owner) = legacy_reverse_aliases.get(&historical) {
                        if owner != source {
                            return Err(RegistryError::PseudonymCollision(
                                "legacy reverse alias has ambiguous ownership".into(),
                            ));
                        }
                    }
                    legacy_reverse_aliases.insert(historical, source.clone());
                    continue;
                }
                let legacy_rid = legacy_pseudonym.rsplit('-').next().unwrap();
                upgraded.insert(source.clone(), format!("{mapped_domain}-{legacy_rid}"));
            }
        }
    }
    Ok((upgraded, legacy_reverse_aliases))
}

fn empty_categories() -> Categories {
    let mut cats = Categories::new();
    for category in CATEGORIES {
        cats.insert(category.to_string(), Bucket::new());
    }
    cats
}

fn load_wordlist(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Deterministic pseudonym store.
#[derive(Debug, Clone)]
pub struct Registry {
    /// Deterministic seed salt (hex string).
    pub salt: String,
    /// Original load-time format version (1 or 2). `save` always writes 2.
    pub format_version: i64,
    /// The `policy` block of the mapping file this registry was loaded from,
    /// retained verbatim so a reuse gate can read it back. Never serialized:
    /// [`Registry::save_to_string`] takes the policy block it writes as an
    /// argument, so the on-disk bytes are unaffected.
    source_policy: Option<serde_json::Value>,
    categories: Categories,
    owners: Categories,
    normalized_owners: Categories,
    normalized_sources: Categories,
    legacy_reverse_aliases: Categories,
    normalized_legacy_reverse_aliases: Categories,
    preloaded_sources: IndexSet<(String, String)>,
    companies: Vec<String>,
    surnames: Vec<String>,
    version: u64,
    frozen: bool,
    frozen_snapshot: Option<String>,
    trait_error: Option<RegistryError>,
}

impl Registry {
    /// Construct a registry with an explicit salt and no preloaded mappings.
    pub fn new(salt: impl Into<String>) -> Registry {
        Registry::build(salt.into(), None, 2, None).expect("empty registry is always valid")
    }

    /// Construct a registry with a cryptographically random 16-byte (32 hex
    /// char) salt (`Registry.new` = a 32-hex-char random token). P2 deferred
    /// the RNG source to the CLI/pipeline entry; wired here with OS entropy.
    pub fn new_random() -> Registry {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy for salt");
        let mut salt = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in bytes {
            salt.push(HEX[(b >> 4) as usize] as char);
            salt.push(HEX[(b & 0xf) as usize] as char);
        }
        Registry::new(salt)
    }

    /// Full constructor (`Registry::build`).
    pub fn build(
        salt: String,
        categories: Option<Categories>,
        format_version: i64,
        legacy_reverse_aliases: Option<Categories>,
    ) -> Result<Registry> {
        if format_version != 1 && format_version != 2 {
            return Err(RegistryError::Value(format!(
                "unsupported format version {format_version}"
            )));
        }
        let mut validated = empty_categories();
        let mut validated_aliases = empty_categories();

        if let Some(aliases) = legacy_reverse_aliases {
            for (category, mapping) in aliases {
                if !CATEGORIES.contains(&category.as_str()) {
                    return Err(RegistryError::Value(format!(
                        "unknown category {category:?}"
                    )));
                }
                validated_aliases.insert(category, mapping);
            }
        }

        if let Some(cats) = categories {
            for (category, mapping) in cats {
                if !CATEGORIES.contains(&category.as_str()) {
                    return Err(RegistryError::Value(format!(
                        "unknown category {category:?}"
                    )));
                }
                let mut copied = mapping;
                if category == SIDS && format_version == 1 {
                    let (upgraded, migrated_aliases) = upgrade_version_one_sid_mappings(&copied)?;
                    copied = upgraded;
                    let sids_aliases = validated_aliases.get_mut(SIDS).unwrap();
                    for (pseudonym, real) in migrated_aliases {
                        if let Some(owner) = sids_aliases.get(&pseudonym) {
                            if *owner != real {
                                return Err(RegistryError::PseudonymCollision(
                                    "legacy reverse alias has ambiguous ownership".into(),
                                ));
                            }
                        }
                        sids_aliases.insert(pseudonym, real);
                    }
                }
                validated.insert(category, copied);
            }
        }

        let (owners, normalized_owners, normalized_sources) = Self::validated_indexes(&validated)?;
        let normalized_legacy =
            Self::validated_legacy_reverse_aliases(&validated_aliases, &normalized_owners)?;

        let mut preloaded_sources: IndexSet<(String, String)> = IndexSet::new();
        for category in CATEGORIES {
            for normalized in normalized_sources[category].keys() {
                preloaded_sources.insert((category.to_string(), normalized.clone()));
            }
        }

        Ok(Registry {
            salt,
            format_version,
            source_policy: None,
            categories: validated,
            owners,
            normalized_owners,
            normalized_sources,
            legacy_reverse_aliases: validated_aliases,
            normalized_legacy_reverse_aliases: normalized_legacy,
            preloaded_sources,
            companies: load_wordlist(COMPANIES_TXT),
            surnames: load_wordlist(SURNAMES_TXT),
            version: 0,
            frozen: false,
            frozen_snapshot: None,
            trait_error: None,
        })
    }

    /// Load a mapping file (`Registry::load`). Reads the frozen §3.3
    /// format written by either implementation.
    pub fn load(
        path: &std::path::Path,
    ) -> std::result::Result<Registry, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let data: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok(Registry::from_value(&data)?)
    }

    /// Build from a parsed mapping document (the JSON `Registry::load` consumes).
    pub fn from_value(data: &serde_json::Value) -> Result<Registry> {
        let salt = data
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RegistryError::Value("mapping file has no salt".into()))?
            .to_string();
        let format_version = data
            .get("format_version")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        let categories = value_to_categories(data.get("categories"));
        let legacy = value_to_categories(data.get("legacy_reverse_aliases"));
        let mut registry = Registry::build(salt, categories, format_version, legacy)?;
        registry.source_policy = data.get("policy").cloned();
        Ok(registry)
    }

    /// The `policy` block of the mapping file this registry was loaded from,
    /// or `None` for a registry that was constructed rather than loaded, or
    /// loaded from a mapping file that carries no policy block.
    pub fn source_policy(&self) -> Option<&serde_json::Value> {
        self.source_policy.as_ref()
    }

    /// `policy.catalog_version` of the mapping file this registry was loaded
    /// from. `None` when the block, the field, or a numeric value is missing,
    /// which the reuse gate treats exactly like a disagreement.
    pub fn source_catalog_version(&self) -> Option<u32> {
        self.source_policy
            .as_ref()?
            .get("catalog_version")?
            .as_u64()?
            .try_into()
            .ok()
    }

    /// Serialize the mapping payload exactly as
    /// `Registry::save` writes it (§3.3): canonical JSON with `indent=2,
    /// sort_keys=true` and `ensure_ascii=true`. `created` is supplied by the
    /// caller (the pipeline) so the bytes stay deterministic and testable; the
    /// atomic no-clobber publication machinery is pipeline-scoped (P3).
    pub fn save_to_string(
        &self,
        input_hash: &str,
        created: &str,
        policy: Option<serde_json::Value>,
    ) -> String {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "created".into(),
            serde_json::Value::String(created.to_string()),
        );
        payload.insert("format_version".into(), serde_json::Value::from(2));
        payload.insert(
            "input_hash".into(),
            serde_json::Value::String(input_hash.to_string()),
        );
        payload.insert("salt".into(), serde_json::Value::String(self.salt.clone()));

        let mut cats = serde_json::Map::new();
        for category in CATEGORIES {
            let mut bucket = serde_json::Map::new();
            for (real, pseudonym) in &self.categories[category] {
                bucket.insert(real.clone(), serde_json::Value::String(pseudonym.clone()));
            }
            cats.insert(category.to_string(), serde_json::Value::Object(bucket));
        }
        payload.insert("categories".into(), serde_json::Value::Object(cats));

        let mut aliases = serde_json::Map::new();
        for category in CATEGORIES {
            let bucket = &self.legacy_reverse_aliases[category];
            if bucket.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (pseudonym, real) in bucket {
                obj.insert(pseudonym.clone(), serde_json::Value::String(real.clone()));
            }
            aliases.insert(category.to_string(), serde_json::Value::Object(obj));
        }
        payload.insert(
            "legacy_reverse_aliases".into(),
            serde_json::Value::Object(aliases),
        );

        if let Some(policy) = policy {
            payload.insert("policy".into(), policy);
        }

        crate::canonical_json_sorted(&serde_json::Value::Object(payload))
    }

    /// Write the mapping to `path` in the frozen §3.3 format.
    pub fn save(
        &self,
        path: &std::path::Path,
        input_hash: &str,
        created: &str,
        policy: Option<serde_json::Value>,
    ) -> std::io::Result<()> {
        std::fs::write(path, self.save_to_string(input_hash, created, policy))
    }

    // -- seeded generation --------------------------------------------------

    fn seed_int(&self, category: &str, real: &str) -> u128 {
        crate::seed_int(
            &self.salt,
            category,
            &normalize_mapping_identity(category, real),
        )
    }

    /// `_fingerprint`: unpadded lowercase base32 of the high 64 seed bits.
    fn fingerprint(&self, category: &str, real: &str) -> String {
        let seed = self.seed_int(category, real).to_be_bytes();
        base32_nopad_lower(&seed[..8])
    }

    /// `_domain_suffix`: keep one syntactically safe FQDN suffix.
    fn domain_suffix(real: &str) -> String {
        match real.rsplit_once('.') {
            None => String::new(),
            Some((_, suffix)) => {
                let suffix = suffix.to_lowercase();
                if SAFE_DOMAIN_SUFFIXES.contains(&suffix.as_str()) {
                    format!(".{suffix}")
                } else {
                    ".local".to_string()
                }
            }
        }
    }

    fn generate(&self, category: &str, real: &str) -> Result<String> {
        let seed = self.seed_int(category, real);
        let fingerprint = self.fingerprint(category, real);
        let out = match category {
            DOMAINS => {
                let company = &self.companies[(seed % self.companies.len() as u128) as usize];
                format!("{company}-{fingerprint}{}", Self::domain_suffix(real))
            }
            ACCOUNTS => {
                let surname: String = self.surnames[(seed % self.surnames.len() as u128) as usize]
                    .chars()
                    .take(6)
                    .collect();
                let alphabet = b"abcdefghijklmnopqrstuvwxyz";
                let initial = alphabet[((seed / 97) % 26) as usize] as char;
                format!("{initial}{surname}{fingerprint}")
            }
            HOSTS => {
                let number = (seed % 90) + 10;
                format!("HOST-{number}-{}", fingerprint.to_uppercase())
            }
            SIDS => {
                let a = seed & 0xFFFF_FFFF;
                let b = (seed >> 16) & 0xFFFF_FFFF;
                let c = (seed >> 32) & 0xFFFF_FFFF;
                format!("S-1-5-21-{a}-{b}-{c}")
            }
            GUIDS => {
                let hexs = format!("{seed:032x}");
                format!(
                    "{}-{}-{}-{}-{}",
                    &hexs[0..8],
                    &hexs[8..12],
                    &hexs[12..16],
                    &hexs[16..20],
                    &hexs[20..32]
                )
            }
            CERT_TEMPLATES => format!("Template-{fingerprint}"),
            OIDS => format!("2.25.{seed}"),
            OPAQUE => format!("[REDACTED:{fingerprint}]"),
            _ => {
                return Err(RegistryError::Value(format!(
                    "unknown category {category:?}"
                )))
            }
        };
        Ok(out)
    }

    /// Whether this registry rejects allocation of new mappings.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Real source keys of one category, sorted (Unicode scalar order). Used by
    /// the engine to seed its deterministic template-alias index.
    pub fn category_reals_sorted(&self, category: &str) -> Vec<String> {
        let mut reals: Vec<String> = match self.categories.get(category) {
            Some(bucket) => bucket.keys().cloned().collect(),
            None => Vec::new(),
        };
        reals.sort();
        reals
    }

    /// Take the first error recorded through the infallible trait bridge.
    pub fn take_trait_error(&mut self) -> Option<RegistryError> {
        self.trait_error.take()
    }

    // -- index validation ---------------------------------------------------

    #[allow(clippy::type_complexity)]
    fn validated_indexes(categories: &Categories) -> Result<(Categories, Categories, Categories)> {
        let mut owners = empty_categories();
        let mut normalized_owners = empty_categories();
        let mut normalized_sources = empty_categories();

        for category in CATEGORIES {
            let bucket = categories.get(category).ok_or_else(|| {
                RegistryError::UnsafeMapping(format!("mapping category {category:?} is missing"))
            })?;
            for (real, pseudonym) in bucket {
                let normalized_real = normalize_mapping_identity(category, real);
                let normalized_pseudonym = normalize_mapping_identity(category, pseudonym);
                if normalized_real == normalized_pseudonym {
                    return Err(RegistryError::UnsafeMapping(format!(
                        "mapping in {category:?} leaves its source unchanged"
                    )));
                }
                if let Some(source_owner) =
                    normalized_sources[category].get(&normalized_real).cloned()
                {
                    if bucket[&source_owner] != *pseudonym {
                        return Err(RegistryError::UnsafeMapping(format!(
                            "divergent semantic aliases in {category:?} mapping"
                        )));
                    }
                    let preferred =
                        min_by_spelling([source_owner.as_str(), real.as_str()]).to_string();
                    if preferred != source_owner {
                        owners[category].insert(pseudonym.clone(), preferred.clone());
                        normalized_owners[category]
                            .insert(normalized_pseudonym.clone(), preferred.clone());
                        normalized_sources[category].insert(normalized_real.clone(), preferred);
                    }
                    continue;
                }
                if normalized_owners[category].contains_key(&normalized_pseudonym) {
                    return Err(RegistryError::PseudonymCollision(format!(
                        "duplicate pseudonym ownership in {category:?} mapping"
                    )));
                }
                owners[category].insert(pseudonym.clone(), real.clone());
                normalized_owners[category].insert(normalized_pseudonym, real.clone());
                normalized_sources[category].insert(normalized_real, real.clone());
            }
        }
        Ok((owners, normalized_owners, normalized_sources))
    }

    fn validated_legacy_reverse_aliases(
        aliases: &Categories,
        normalized_owners: &Categories,
    ) -> Result<Categories> {
        let mut normalized_aliases = empty_categories();
        for category in CATEGORIES {
            let bucket = &aliases[category];
            if category != SIDS && !bucket.is_empty() {
                return Err(RegistryError::UnsafeMapping(
                    "legacy reverse aliases are supported only for SIDs".into(),
                ));
            }
            for (pseudonym, real) in bucket {
                let normalized_pseudonym = normalize_mapping_identity(category, pseudonym);
                let normalized_real = normalize_mapping_identity(category, real);
                let pseudonym_parts = domain_sid_components(pseudonym, true);
                let real_parts = domain_sid_components(real, true);
                let valid = matches!((&pseudonym_parts, &real_parts), (Some(p), Some(r))
                    if p.len() == 7 && r.len() > p.len());
                if !valid {
                    return Err(RegistryError::UnsafeMapping(
                        "legacy reverse alias has invalid SID hierarchy".into(),
                    ));
                }
                if pseudonym.is_empty() || normalized_pseudonym == normalized_real {
                    return Err(RegistryError::UnsafeMapping(
                        "legacy reverse alias leaves its source unchanged".into(),
                    ));
                }
                if normalized_owners[category].contains_key(&normalized_pseudonym) {
                    return Err(RegistryError::PseudonymCollision(
                        "legacy reverse alias collides with forward ownership".into(),
                    ));
                }
                if let Some(owner) = normalized_aliases[category].get(&normalized_pseudonym) {
                    if owner != real {
                        return Err(RegistryError::PseudonymCollision(
                            "legacy reverse alias has ambiguous ownership".into(),
                        ));
                    }
                }
                normalized_aliases[category].insert(normalized_pseudonym, real.clone());
            }
        }
        Ok(normalized_aliases)
    }

    fn trust_root_fingerprint(&self) -> String {
        // Deterministic canonical encoding — only ever compared to itself, so it
        // need not match the canonical JSON serialization bytes.
        const US: char = '\u{1f}';
        const RS: char = '\u{1e}';
        let mut buf = String::new();
        let sections: [(&str, &Categories); 6] = [
            ("categories", &self.categories),
            ("owners", &self.owners),
            ("normalized_owners", &self.normalized_owners),
            ("normalized_sources", &self.normalized_sources),
            ("legacy_reverse_aliases", &self.legacy_reverse_aliases),
            (
                "normalized_legacy_reverse_aliases",
                &self.normalized_legacy_reverse_aliases,
            ),
        ];
        for (label, section) in sections {
            buf.push_str(label);
            buf.push(RS);
            for category in CATEGORIES {
                buf.push_str(category);
                buf.push(RS);
                let mut items: Vec<(&String, &String)> = section[category].iter().collect();
                items.sort();
                for (k, v) in items {
                    buf.push_str(k);
                    buf.push(US);
                    buf.push_str(v);
                    buf.push(US);
                }
                buf.push(RS);
            }
        }
        blake2b128_hex(buf.as_bytes())
    }

    /// `validate_trust_root`: reject an inconsistent forward/reverse index.
    pub fn validate_trust_root(&self) -> Result<()> {
        let (owners, normalized_owners, normalized_sources) =
            Self::validated_indexes(&self.categories)?;
        if categories_ne(&self.owners, &owners)
            || categories_ne(&self.normalized_owners, &normalized_owners)
            || categories_ne(&self.normalized_sources, &normalized_sources)
        {
            return Err(RegistryError::UnsafeMapping(
                "mapping reverse-owner index is inconsistent".into(),
            ));
        }
        let alias_rebuilt = Self::validated_legacy_reverse_aliases(
            &self.legacy_reverse_aliases,
            &normalized_owners,
        )?;
        if categories_ne(&self.normalized_legacy_reverse_aliases, &alias_rebuilt) {
            return Err(RegistryError::UnsafeMapping(
                "normalized legacy reverse alias index is inconsistent".into(),
            ));
        }
        if self.frozen {
            let fingerprint = self.trust_root_fingerprint();
            if self.frozen_snapshot.as_deref() != Some(fingerprint.as_str()) {
                return Err(RegistryError::UnsafeMapping(
                    "frozen mapping snapshot changed".into(),
                ));
            }
        }
        Ok(())
    }

    /// `freeze`: validate and lock the forward and reverse trust roots.
    pub fn freeze(&mut self) -> Result<()> {
        if self.frozen {
            return self.validate_trust_root();
        }
        let (owners, normalized_owners, normalized_sources) =
            Self::validated_indexes(&self.categories)?;
        let normalized_legacy = Self::validated_legacy_reverse_aliases(
            &self.legacy_reverse_aliases,
            &normalized_owners,
        )?;
        self.owners = owners;
        self.normalized_owners = normalized_owners;
        self.normalized_sources = normalized_sources;
        self.normalized_legacy_reverse_aliases = normalized_legacy;
        self.frozen_snapshot = Some(self.trust_root_fingerprint());
        self.frozen = true;
        Ok(())
    }

    // -- allocation ---------------------------------------------------------

    /// Allocate or resolve the pseudonym for `real` in `category` (`map`).
    pub fn map(&mut self, category: &str, real: &str) -> Result<String> {
        if !CATEGORIES.contains(&category) {
            return Err(RegistryError::Value(format!(
                "unknown category {category:?}"
            )));
        }
        let normalized_real = normalize_mapping_identity(category, real);
        if let Some(source_owner) = self.normalized_sources[category]
            .get(&normalized_real)
            .cloned()
        {
            let pseudonym = self.categories[category][&source_owner].clone();
            if normalize_mapping_identity(category, real)
                == normalize_mapping_identity(category, &pseudonym)
            {
                return Err(RegistryError::UnsafeMapping(format!(
                    "mapping in {category:?} leaves its source unchanged"
                )));
            }
            if !self.frozen {
                let preferred = min_by_spelling([source_owner.as_str(), real]).to_string();
                if preferred != source_owner {
                    let normalized_pseudonym = normalize_mapping_identity(category, &pseudonym);
                    self.categories[category].shift_remove(&source_owner);
                    self.categories[category].insert(preferred.clone(), pseudonym.clone());
                    self.owners[category].insert(pseudonym.clone(), preferred.clone());
                    self.normalized_owners[category]
                        .insert(normalized_pseudonym, preferred.clone());
                    self.normalized_sources[category].insert(normalized_real, preferred);
                }
            }
            return Ok(pseudonym);
        }
        if self.frozen {
            return Err(RegistryError::Frozen(format!(
                "mapping missing in frozen registry for category {category:?}"
            )));
        }
        let candidate = self.generate(category, real)?;
        let normalized_candidate = normalize_mapping_identity(category, &candidate);
        if normalized_candidate == normalize_mapping_identity(category, real) {
            return Err(RegistryError::UnsafeMapping(format!(
                "mapping in {category:?} leaves its source unchanged"
            )));
        }
        if self.normalized_owners[category].contains_key(&normalized_candidate)
            || self.normalized_legacy_reverse_aliases[category].contains_key(&normalized_candidate)
        {
            return Err(RegistryError::PseudonymCollision(format!(
                "pseudonym collision in {category:?} mapping"
            )));
        }
        self.categories[category].insert(real.to_string(), candidate.clone());
        self.owners[category].insert(candidate.clone(), real.to_string());
        self.normalized_owners[category].insert(normalized_candidate, real.to_string());
        self.normalized_sources[category].insert(normalized_real, real.to_string());
        self.version += 1;
        Ok(candidate)
    }

    /// Own an explicitly structured pseudonym for one identity (`bind`).
    pub fn bind(
        &mut self,
        category: &str,
        real: &str,
        pseudonym: &str,
        preserve_terminal: Option<bool>,
    ) -> Result<String> {
        if !CATEGORIES.contains(&category) {
            return Err(RegistryError::Value(format!(
                "unknown category {category:?}"
            )));
        }
        if category == SIDS {
            let preserve = match preserve_terminal {
                Some(p) => p,
                None => {
                    return Err(RegistryError::Value(
                        "structured SID binding requires explicit intent".into(),
                    ))
                }
            };
            let real_parts = domain_sid_components(real, false);
            let pseudonym_parts = domain_sid_components(pseudonym, false);
            let ok =
                matches!((&real_parts, &pseudonym_parts), (Some(r), Some(p)) if p.len() == r.len());
            if !ok {
                return Err(RegistryError::UnsafeMapping(
                    "structured SID output has invalid hierarchy".into(),
                ));
            }
            let real_parts = real_parts.unwrap();
            let pseudonym_parts = pseudonym_parts.unwrap();
            let terminal_preserved = pseudonym_parts.last() == real_parts.last();
            if preserve && !terminal_preserved {
                return Err(RegistryError::UnsafeMapping(
                    "preserved SID terminal changed".into(),
                ));
            }
            if !preserve && terminal_preserved {
                return Err(RegistryError::UnsafeMapping(
                    "custom SID terminal was not anonymized".into(),
                ));
            }
        } else if preserve_terminal.is_some() {
            return Err(RegistryError::Value(
                "terminal preservation intent applies only to SIDs".into(),
            ));
        }

        let normalized_real = normalize_mapping_identity(category, real);
        if let Some(source_owner) = self.normalized_sources[category]
            .get(&normalized_real)
            .cloned()
        {
            let existing = self.categories[category][&source_owner].clone();
            if normalize_mapping_identity(category, &existing)
                == normalize_mapping_identity(category, pseudonym)
            {
                return Ok(existing);
            }
            let consistent_sid = if category == SIDS {
                consistent_sid_hierarchy(real, &existing, pseudonym, preserve_terminal.unwrap())
            } else {
                false
            };
            if consistent_sid {
                return Ok(existing);
            }
            if self
                .preloaded_sources
                .contains(&(category.to_string(), normalized_real.clone()))
                || self.frozen
            {
                return Err(RegistryError::UnsafeMapping(format!(
                    "preloaded {category:?} mapping conflicts with structured output"
                )));
            }
            let normalized_pseudonym = normalize_mapping_identity(category, pseudonym);
            let collision_owner = self.normalized_owners[category]
                .get(&normalized_pseudonym)
                .cloned();
            let legacy_collision_owner =
                self.normalized_legacy_reverse_aliases[category].get(&normalized_pseudonym);
            if collision_owner
                .as_deref()
                .map(|o| o != source_owner)
                .unwrap_or(false)
                || legacy_collision_owner.is_some()
            {
                return Err(RegistryError::PseudonymCollision(format!(
                    "pseudonym collision in {category:?} mapping"
                )));
            }
            let normalized_existing = normalize_mapping_identity(category, &existing);
            self.owners[category].shift_remove(&existing);
            self.normalized_owners[category].shift_remove(&normalized_existing);
            self.categories[category].insert(source_owner.clone(), pseudonym.to_string());
            self.owners[category].insert(pseudonym.to_string(), source_owner.clone());
            self.normalized_owners[category].insert(normalized_pseudonym, source_owner);
            self.version += 1;
            return Ok(pseudonym.to_string());
        }
        if self.frozen {
            return Err(RegistryError::Frozen(format!(
                "mapping missing in frozen registry for category {category:?}"
            )));
        }
        let normalized_pseudonym = normalize_mapping_identity(category, pseudonym);
        if normalized_real == normalized_pseudonym {
            return Err(RegistryError::UnsafeMapping(format!(
                "mapping in {category:?} leaves its source unchanged"
            )));
        }
        if self.normalized_owners[category].contains_key(&normalized_pseudonym)
            || self.normalized_legacy_reverse_aliases[category].contains_key(&normalized_pseudonym)
        {
            return Err(RegistryError::PseudonymCollision(format!(
                "pseudonym collision in {category:?} mapping"
            )));
        }
        self.categories[category].insert(real.to_string(), pseudonym.to_string());
        self.owners[category].insert(pseudonym.to_string(), real.to_string());
        self.normalized_owners[category].insert(normalized_pseudonym, real.to_string());
        self.normalized_sources[category].insert(normalized_real, real.to_string());
        self.version += 1;
        Ok(pseudonym.to_string())
    }

    /// `sid_subauthority`: a neutral deterministic 32-bit custom subauthority.
    pub fn sid_subauthority(&self, real: &str) -> String {
        let seed = self.seed_int(SIDS, real);
        let span: u128 = 2u128.pow(32) - 1_000_000;
        let mut candidate = 1_000_000 + seed % span;
        let source_terminal: i128 = real
            .rsplit('-')
            .next()
            .and_then(|t| t.parse::<i128>().ok())
            .unwrap_or(-1);
        if candidate as i128 == source_terminal {
            candidate = 1_000_000 + ((candidate - 1_000_000 + 1) % span);
        }
        candidate.to_string()
    }

    /// Atomically allocate a batch after validating every candidate (`map_many`).
    pub fn map_many(
        &mut self,
        entries: &[(String, String)],
    ) -> Result<IndexMap<(String, String), String>> {
        for (category, _real) in entries {
            if !CATEGORIES.contains(&category.as_str()) {
                return Err(RegistryError::Value(format!(
                    "unknown category {category:?}"
                )));
            }
        }
        let (
            mut validated_owners,
            mut validated_normalized_owners,
            mut validated_normalized_sources,
        ) = Self::validated_indexes(&self.categories)?;

        let mut results: IndexMap<(String, String), String> = IndexMap::new();
        // (category, normalized_real) -> set of raw aliases (insertion ordered)
        let mut pending_aliases: IndexMap<(String, String), IndexSet<String>> = IndexMap::new();
        let mut existing_aliases: IndexMap<(String, String), IndexSet<String>> = IndexMap::new();

        for (category, real) in entries {
            let normalized_real = normalize_mapping_identity(category, real);
            if let Some(source_owner) = validated_normalized_sources[category].get(&normalized_real)
            {
                results.insert(
                    (category.clone(), real.clone()),
                    self.categories[category][source_owner].clone(),
                );
                let set = existing_aliases
                    .entry((category.clone(), normalized_real))
                    .or_default();
                set.insert(source_owner.clone());
                set.insert(real.clone());
            } else {
                pending_aliases
                    .entry((category.clone(), normalized_real))
                    .or_default()
                    .insert(real.clone());
            }
        }

        let pending: Vec<(String, String)> = pending_aliases
            .iter()
            .map(|((category, _), aliases)| {
                (
                    category.clone(),
                    min_by_spelling(aliases.iter().map(String::as_str)).to_string(),
                )
            })
            .collect();

        let planned_renames: Vec<(String, String, String, String)> = existing_aliases
            .iter()
            .filter_map(|((category, normalized_real), aliases)| {
                let source_owner = validated_normalized_sources[category][normalized_real].clone();
                let preferred = min_by_spelling(aliases.iter().map(String::as_str)).to_string();
                if preferred != source_owner {
                    Some((
                        category.clone(),
                        normalized_real.clone(),
                        source_owner,
                        preferred,
                    ))
                } else {
                    None
                }
            })
            .collect();

        if self.frozen {
            if let Some((category, _)) = pending.first() {
                return Err(RegistryError::Frozen(format!(
                    "mapping missing in frozen registry for category {category:?}"
                )));
            }
            self.validate_trust_root()?;
            return Ok(results);
        }

        let mut planned_values: IndexMap<(String, String), String> = IndexMap::new();
        let mut planned_normalized_owners: Categories = empty_categories();
        for (category, real) in &pending {
            let candidate = self.generate(category, real)?;
            let normalized_candidate = normalize_mapping_identity(category, &candidate);
            if normalized_candidate == normalize_mapping_identity(category, real) {
                return Err(RegistryError::UnsafeMapping(format!(
                    "mapping in {category:?} leaves its source unchanged"
                )));
            }
            let mut owner = validated_normalized_owners[category]
                .get(&normalized_candidate)
                .cloned();
            let legacy_owner =
                self.normalized_legacy_reverse_aliases[category].get(&normalized_candidate);
            if owner.is_none() {
                owner = planned_normalized_owners[category]
                    .get(&normalized_candidate)
                    .cloned();
            }
            if owner.as_deref().map(|o| o != real).unwrap_or(false) || legacy_owner.is_some() {
                return Err(RegistryError::PseudonymCollision(format!(
                    "pseudonym collision in {category:?} mapping"
                )));
            }
            planned_values.insert((category.clone(), real.clone()), candidate.clone());
            planned_normalized_owners[category].insert(normalized_candidate, real.clone());
        }

        for (category, normalized_real, source_owner, preferred) in &planned_renames {
            let pseudonym = self.categories[category][source_owner].clone();
            self.categories[category].shift_remove(source_owner);
            self.categories[category].insert(preferred.clone(), pseudonym.clone());
            validated_owners[category].insert(pseudonym.clone(), preferred.clone());
            let normalized_pseudonym = normalize_mapping_identity(category, &pseudonym);
            validated_normalized_owners[category].insert(normalized_pseudonym, preferred.clone());
            validated_normalized_sources[category]
                .insert(normalized_real.clone(), preferred.clone());
        }

        for ((category, real), candidate) in &planned_values {
            self.categories[category].insert(real.clone(), candidate.clone());
            validated_owners[category].insert(candidate.clone(), real.clone());
            let normalized_candidate = normalize_mapping_identity(category, candidate);
            validated_normalized_owners[category].insert(normalized_candidate, real.clone());
            let normalized_real = normalize_mapping_identity(category, real);
            validated_normalized_sources[category].insert(normalized_real, real.clone());
            self.version += 1;
        }

        for (category, real) in entries {
            let normalized_real = normalize_mapping_identity(category, real);
            let source_owner = validated_normalized_sources[category][&normalized_real].clone();
            results.insert(
                (category.clone(), real.clone()),
                self.categories[category][&source_owner].clone(),
            );
        }
        self.owners = validated_owners;
        self.normalized_owners = validated_normalized_owners;
        self.normalized_sources = validated_normalized_sources;
        Ok(results)
    }

    /// `map_template`.
    pub fn map_template(&mut self, real: &str) -> Result<String> {
        self.map(CERT_TEMPLATES, real)
    }

    /// `map_oid`.
    pub fn map_oid(&mut self, real: &str) -> Result<String> {
        self.map(OIDS, real)
    }

    /// `map_opaque`.
    pub fn map_opaque(&mut self, real: &str) -> Result<String> {
        self.map(OPAQUE, real)
    }

    /// `reverse`: every source that could produce this pseudonym.
    pub fn reverse(&self, pseudonym: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for category in CATEGORIES {
            let normalized = normalize_mapping_identity(category, pseudonym);
            let owner = self.normalized_owners[category]
                .get(&normalized)
                .or_else(|| self.normalized_legacy_reverse_aliases[category].get(&normalized));
            if let Some(owner) = owner {
                result.push((category.to_string(), owner.clone()));
            }
        }
        result
    }

    /// `restoration_owners`: pseudonym/source pairs incl. validated legacy aliases.
    pub fn restoration_owners(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for category in CATEGORIES {
            for (pseudonym, real) in &self.owners[category] {
                out.push((pseudonym.clone(), real.clone()));
            }
            for (pseudonym, real) in &self.legacy_reverse_aliases[category] {
                out.push((pseudonym.clone(), real.clone()));
            }
        }
        out
    }

    /// `forward`: every pseudonym `real` maps to across categories.
    pub fn forward(&self, real: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for category in CATEGORIES {
            let normalized = normalize_mapping_identity(category, real);
            if let Some(owner) = self.normalized_sources[category].get(&normalized) {
                result.push((
                    category.to_string(),
                    self.categories[category][owner].clone(),
                ));
            }
        }
        result
    }

    /// All real source tokens in a deterministic total order (see module docs).
    pub fn all_real_tokens(&self) -> Vec<String> {
        let mut set: IndexSet<String> = IndexSet::new();
        for category in CATEGORIES {
            for real in self.categories[category].keys() {
                set.insert(real.clone());
            }
        }
        for category in CATEGORIES {
            for real in self.legacy_reverse_aliases[category].values() {
                set.insert(real.clone());
            }
        }
        let mut tokens: Vec<String> = set.into_iter().collect();
        tokens.sort();
        tokens
    }

    /// `name_real_tokens`: name-bearing category reals (deterministically sorted).
    pub fn name_real_tokens(&self) -> Vec<String> {
        let mut set: IndexSet<String> = IndexSet::new();
        for category in [DOMAINS, ACCOUNTS, HOSTS] {
            for real in self.categories[category].keys() {
                set.insert(real.clone());
            }
        }
        let mut tokens: Vec<String> = set.into_iter().collect();
        tokens.sort();
        tokens
    }

    /// Capture the mutable mapping state the contextual-verification gate
    /// compares before/after (`reg.categories`, `reg._owners`, `reg._version`,
    /// `reg.is_frozen`, in the verification gate). The snapshot is opaque; use
    /// [`RegistrySnapshot::changed_from`] to detect any drift.
    pub fn verification_snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot {
            categories: self.categories.clone(),
            owners: self.owners.clone(),
            version: self.version,
            frozen: self.frozen,
        }
    }

    fn bridge(&mut self, result: Result<String>, fallback: &str) -> String {
        match result {
            Ok(s) => s,
            Err(e) => {
                if self.trait_error.is_none() {
                    self.trait_error = Some(e);
                }
                fallback.to_string()
            }
        }
    }
}

/// Opaque snapshot of the registry's mutable mapping state, used by the
/// contextual-verification gate to assert the verifier never mutated the
/// registry (`registry-state-changed`).
#[derive(Clone)]
pub struct RegistrySnapshot {
    categories: Categories,
    owners: Categories,
    version: u64,
    frozen: bool,
}

impl RegistrySnapshot {
    /// True when any observed field diverges from `before`
    /// (`after_* != before_* or version/frozen changed`).
    pub fn changed_from(&self, before: &RegistrySnapshot) -> bool {
        self.version != before.version
            || self.frozen != before.frozen
            || categories_ne(&self.categories, &before.categories)
            || categories_ne(&self.owners, &before.owners)
    }
}

fn categories_ne(a: &Categories, b: &Categories) -> bool {
    for category in CATEGORIES {
        let ba = &a[category];
        let bb = &b[category];
        if ba.len() != bb.len() {
            return true;
        }
        for (k, v) in ba {
            if bb.get(k) != Some(v) {
                return true;
            }
        }
    }
    false
}

fn value_to_categories(value: Option<&serde_json::Value>) -> Option<Categories> {
    let obj = value?.as_object()?;
    let mut cats = Categories::new();
    for (category, mapping) in obj {
        let mut bucket = Bucket::new();
        if let Some(map) = mapping.as_object() {
            for (real, pseudonym) in map {
                if let Some(p) = pseudonym.as_str() {
                    bucket.insert(real.clone(), p.to_string());
                }
            }
        }
        cats.insert(category.clone(), bucket);
    }
    Some(cats)
}

/// Unpadded lowercase RFC 4648 base32 (`b32encode(...).rstrip("=").lower()`).
fn base32_nopad_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out.to_lowercase()
}

fn blake2b128_hex(data: &[u8]) -> String {
    use blake2::digest::consts::U16;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U16>::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Trait bridges (infallible P0 contracts).
// ---------------------------------------------------------------------------

impl RegistryOps for Registry {
    fn map(&mut self, category: &str, real: &str) -> String {
        let result = Registry::map(self, category, real);
        self.bridge(result, real)
    }

    fn bind(
        &mut self,
        category: &str,
        real: &str,
        pseudonym: &str,
        preserve_terminal: Option<bool>,
    ) -> String {
        let result = Registry::bind(self, category, real, pseudonym, preserve_terminal);
        self.bridge(result, pseudonym)
    }

    fn sid_subauthority(&mut self, real: &str) -> String {
        Registry::sid_subauthority(self, real)
    }
}

impl TokenRegistry for Registry {
    fn all_real_tokens(&self) -> Vec<String> {
        Registry::all_real_tokens(self)
    }

    fn category_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        for category in CATEGORIES {
            for (real, pseudonym) in &self.categories[category] {
                pairs.push((real.clone(), pseudonym.clone()));
            }
        }
        pairs
    }
}
