//! Authoritative, context-scoped Active Directory default catalog.
//!
//! Kept **data-driven** (§3.4 / Risk R4): the catalog is a flat table of
//! [`CatalogEntry`] rows built from static data tables, never a
//! typed-struct-per-SharpHound-kind. A catalog match requires an exact node
//! type, identifier kind, and normalized identifier; it permits preserving a
//! value only at an explicitly declared path (and, where present, for an exact
//! canonical value).
//!
//! The module owns a process-global [`catalog`] table and implements
//! [`WellKnownCatalog`] via the zero-sized [`Catalog`] handle, closing the P0
//! abstraction.
//!
//! ## Determinism notes (§3.2)
//! * `preserve_paths` and `exact_values` derive from sets whose natural
//!   iteration order is undefined. They are consumed only as membership sets /
//!   path-keyed maps (`permits`, `_catalog_path` first-canonical-match), never as
//!   ordered output — no real path aliases within an entry — so any stable order
//!   is correct. We store `exact_values` as an [`IndexMap`] and
//!   `node_types` as a `BTreeSet` for tidy, deterministic iteration.
//! * `_normalize` uses ASCII SIDs/GUIDs (`to_uppercase`/`to_lowercase` over
//!   that domain); NAME/TEMPLATE fold via
//!   [`casefold`], the one Unicode-correct case.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use indexmap::IndexMap;

use crate::casefold::casefold;
use crate::wellknown::WellKnownCatalog;

/// Catalog schema version (`CATALOG_VERSION = 1`);
/// stamped into the collection map, so its value and integer
/// semantics are part of the output contract.
pub const CATALOG_VERSION: u32 = 1;

/// Privacy classification of an identity. The string
/// spellings are the serialized contract (audit summaries, map metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyClass {
    CoreGlobalDefault,
    MicrosoftFeatureDefault,
    ThirdPartyDefault,
    Custom,
    Unknown,
}

impl PrivacyClass {
    /// The `PrivacyClass` value string.
    pub fn as_str(self) -> &'static str {
        match self {
            PrivacyClass::CoreGlobalDefault => "core_global_default",
            PrivacyClass::MicrosoftFeatureDefault => "microsoft_feature_default",
            PrivacyClass::ThirdPartyDefault => "third_party_default",
            PrivacyClass::Custom => "custom",
            PrivacyClass::Unknown => "unknown",
        }
    }
}

/// Kind of identifier a catalog entry classifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentifierKind {
    Sid,
    Rid,
    Guid,
    Wkguid,
    Oid,
    Template,
    Name,
}

impl IdentifierKind {
    /// The `IdentifierKind` value string.
    pub fn as_str(self) -> &'static str {
        match self {
            IdentifierKind::Sid => "sid",
            IdentifierKind::Rid => "rid",
            IdentifierKind::Guid => "guid",
            IdentifierKind::Wkguid => "wkguid",
            IdentifierKind::Oid => "oid",
            IdentifierKind::Template => "template",
            IdentifierKind::Name => "name",
        }
    }
}

/// One catalog row (`CatalogEntry`). `value` is already `_normalize`d;
/// `exact_values` values are stored case-folded (as `_exact_values` builds them).
#[derive(Clone, Debug)]
pub struct CatalogEntry {
    pub rule_id: String,
    pub kind: IdentifierKind,
    pub value: String,
    pub node_types: BTreeSet<String>,
    pub privacy: PrivacyClass,
    pub preserve_paths: Vec<String>,
    pub exact_values: IndexMap<String, BTreeSet<String>>,
    pub source: String,
}

impl CatalogEntry {
    /// Whether catalog evidence permits `value` at `path`
    /// (`CatalogMatch.permits`, which uses only entry state).
    pub fn permits(&self, path: &str, value: &str) -> bool {
        if !self.preserve_paths.iter().any(|p| p == path) {
            return false;
        }
        match self.exact_values.get(path) {
            None => true,
            Some(allowed) => allowed.contains(&casefold(value)),
        }
    }
}

/// A successful catalog match (`CatalogMatch`).
#[derive(Clone, Debug)]
pub struct CatalogMatch<'a> {
    pub entry: &'a CatalogEntry,
    pub normalized_value: String,
}

impl CatalogMatch<'_> {
    /// See [`CatalogEntry::permits`].
    pub fn permits(&self, path: &str, value: &str) -> bool {
        self.entry.permits(path, value)
    }
}

/// Normalize an identifier for lookup (`_normalize`).
pub fn normalize(kind: IdentifierKind, value: &str) -> String {
    match kind {
        IdentifierKind::Name | IdentifierKind::Template => casefold(value),
        IdentifierKind::Guid | IdentifierKind::Wkguid => value.to_lowercase(),
        IdentifierKind::Sid => value.to_uppercase(),
        _ => value.to_string(),
    }
}

/// The process-global catalog table (module-level `CATALOG`).
pub fn catalog() -> &'static [CatalogEntry] {
    static CAT: OnceLock<Vec<CatalogEntry>> = OnceLock::new();
    CAT.get_or_init(build_catalog).as_slice()
}

/// Return an exact catalog match within the supplied node context
/// (`match_catalog`).
pub fn match_catalog(
    node_type: &str,
    kind: IdentifierKind,
    value: &str,
) -> Option<CatalogMatch<'static>> {
    let normalized = normalize(kind, value);
    for entry in catalog() {
        if entry.kind == kind && entry.value == normalized && entry.node_types.contains(node_type) {
            return Some(CatalogMatch {
                entry,
                normalized_value: normalized,
            });
        }
    }
    None
}

/// Classify a full SID without treating domain-relative RIDs as global
/// (`classify_sid`).
pub fn classify_sid(sid: &str) -> PrivacyClass {
    let normalized = normalize(IdentifierKind::Sid, sid);
    if normalized.starts_with("S-1-5-21-") {
        return PrivacyClass::Custom;
    }
    for entry in catalog() {
        if entry.kind == IdentifierKind::Sid && entry.value == normalized {
            return entry.privacy;
        }
    }
    PrivacyClass::Unknown
}

/// Whether catalog evidence permits this exact value at this path
/// (`is_core_constant`). `value` is `None` when the identifier itself is the
/// candidate.
pub fn is_core_constant(
    node_type: &str,
    kind: IdentifierKind,
    identifier: &str,
    path: &str,
    value: Option<&str>,
) -> bool {
    match match_catalog(node_type, kind, identifier) {
        None => false,
        Some(m) => {
            let candidate = value.unwrap_or(identifier);
            m.entry.privacy == PrivacyClass::CoreGlobalDefault && m.permits(path, candidate)
        }
    }
}

/// The set of exact canonical core catalog names (`_CORE_CANONICAL_NAMES`,
/// computed here where `CATALOG` lives).
fn core_canonical_names() -> &'static BTreeSet<String> {
    static NAMES: OnceLock<BTreeSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        const CANONICAL_NAME_PATHS: [&str; 2] = ["Properties.name", "Properties.samaccountname"];
        let mut set = BTreeSet::new();
        for entry in catalog() {
            let kind_ok = matches!(
                entry.kind,
                IdentifierKind::Sid
                    | IdentifierKind::Rid
                    | IdentifierKind::Wkguid
                    | IdentifierKind::Template
            );
            if !(kind_ok && entry.privacy == PrivacyClass::CoreGlobalDefault) {
                continue;
            }
            for (path, values) in &entry.exact_values {
                if CANONICAL_NAME_PATHS.contains(&path.as_str())
                    || entry.kind == IdentifierKind::Template
                {
                    set.extend(values.iter().cloned());
                }
            }
        }
        set
    })
}

/// Zero-sized handle over the global [`catalog`] that satisfies the P0
/// [`WellKnownCatalog`] abstraction.
#[derive(Clone, Copy, Debug, Default)]
pub struct Catalog;

impl Catalog {
    pub fn new() -> Self {
        Catalog
    }
}

impl WellKnownCatalog for Catalog {
    fn sid_is_core_global_default(&self, sid: &str) -> bool {
        classify_sid(sid) == PrivacyClass::CoreGlobalDefault
    }

    fn is_core_canonical_name(&self, folded_name: &str) -> bool {
        core_canonical_names().contains(folded_name)
    }

    fn is_core_rid(&self, rid: &str) -> bool {
        catalog().iter().any(|e| {
            e.kind == IdentifierKind::Rid
                && e.value == rid
                && e.privacy == PrivacyClass::CoreGlobalDefault
        })
    }

    fn is_wellknown_guid(&self, normalized_guid: &str) -> bool {
        catalog().iter().any(|e| {
            e.kind == IdentifierKind::Guid
                && e.value == normalized_guid
                && (e.rule_id == "guid.null" || e.rule_id.starts_with("gpo."))
                && e.privacy == PrivacyClass::CoreGlobalDefault
        })
    }
}

// ---------------------------------------------------------------------------
// Data tables (module constants).
// ---------------------------------------------------------------------------

const ALL_NODE_TYPES: [&str; 15] = [
    "ADLocalGroup",
    "AIACA",
    "Base",
    "CertTemplate",
    "Computer",
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

const SID_PATHS: [&str; 4] = [
    "ObjectIdentifier",
    "Aces[].PrincipalSID",
    "Members[].ObjectIdentifier",
    "Properties.objectsid",
];

const NAME_PATHS: [&str; 2] = ["Properties.name", "Properties.samaccountname"];

const TEMPLATE_PATHS: [&str; 4] = [
    "Properties.name",
    "Properties.templatename",
    "Properties.templates[]",
    "Properties.unresolvedpublishedtemplates[]",
];

const OID_PATHS: [&str; 8] = [
    "Properties.oid",
    "Properties.ekus[]",
    "Properties.applicationpolicies[]",
    "Properties.certificateapplicationpolicy[]",
    "Properties.certificatepolicies[]",
    "Properties.certificatepolicy[]",
    "Properties.effectiveekus[]",
    "Properties.issuancepolicies[]",
];

const ACE_GUID_PATHS: [&str; 5] = [
    "Aces[].ObjectType",
    "Aces[].ObjectTypeGuid",
    "Aces[].InheritedObjectType",
    "Aces[].InheritedObjectTypeGuid",
    "Aces[].RightGuid",
];

/// `_WELL_KNOWN_SID_NAMES` — SID -> friendly name.
const WELL_KNOWN_SID_NAMES: &[(&str, &str)] = &[
    ("S-1-0-0", "Nobody"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2-0", "Local"),
    ("S-1-2-1", "Console Logon"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-3-2", "Creator Owner Server"),
    ("S-1-3-3", "Creator Group Server"),
    ("S-1-3-4", "Owner Rights"),
    ("S-1-5-1", "Dialup"),
    ("S-1-5-2", "Network"),
    ("S-1-5-3", "Batch"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-8", "Proxy"),
    ("S-1-5-9", "Enterprise Domain Controllers"),
    ("S-1-5-10", "Principal Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-12", "Restricted Code"),
    ("S-1-5-13", "Terminal Server User"),
    ("S-1-5-14", "Remote Interactive Logon"),
    ("S-1-5-15", "This Organization"),
    ("S-1-5-17", "IUSR"),
    ("S-1-5-18", "Local System"),
    ("S-1-5-19", "Local Service"),
    ("S-1-5-20", "Network Service"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-547", "Power Users"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-552", "Replicator"),
    ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access"),
    ("S-1-5-32-555", "Remote Desktop Users"),
    ("S-1-5-32-556", "Network Configuration Operators"),
    ("S-1-5-32-558", "Performance Monitor Users"),
    ("S-1-5-32-559", "Performance Log Users"),
    ("S-1-5-32-560", "Windows Authorization Access Group"),
    ("S-1-5-32-562", "Distributed COM Users"),
    ("S-1-5-32-573", "Event Log Readers"),
    ("S-1-5-32-579", "Access Control Assistance Operators"),
    ("S-1-5-32-581", "System Managed Accounts Group"),
    ("S-1-5-32-583", "Device Owners"),
    ("S-1-5-113", "Local account"),
    (
        "S-1-5-114",
        "Local account and member of Administrators group",
    ),
];

/// `_EXISTING_NON_DOMAIN_SIDS`.
const EXISTING_NON_DOMAIN_SIDS: &[&str] = &[
    "S-1-0-0",
    "S-1-1-0",
    "S-1-2-0",
    "S-1-2-1",
    "S-1-3-0",
    "S-1-3-1",
    "S-1-3-2",
    "S-1-3-3",
    "S-1-3-4",
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-14",
    "S-1-5-15",
    "S-1-5-17",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-32-544",
    "S-1-5-32-545",
    "S-1-5-32-546",
    "S-1-5-32-547",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-32-553",
    "S-1-5-32-554",
    "S-1-5-32-555",
    "S-1-5-32-556",
    "S-1-5-32-557",
    "S-1-5-32-558",
    "S-1-5-32-559",
    "S-1-5-32-560",
    "S-1-5-32-561",
    "S-1-5-32-562",
    "S-1-5-32-568",
    "S-1-5-32-569",
    "S-1-5-32-573",
    "S-1-5-32-574",
    "S-1-5-32-575",
    "S-1-5-32-576",
    "S-1-5-32-577",
    "S-1-5-32-578",
    "S-1-5-32-579",
    "S-1-5-32-580",
    "S-1-5-32-581",
    "S-1-5-32-582",
    "S-1-5-32-583",
    "S-1-5-32-584",
    "S-1-5-32-585",
    "S-1-5-113",
    "S-1-5-114",
];

/// `_FEATURE_SIDS`.
const FEATURE_SIDS: &[&str] = &[
    "S-1-5-32-553",
    "S-1-5-32-557",
    "S-1-5-32-561",
    "S-1-5-32-568",
    "S-1-5-32-569",
    "S-1-5-32-574",
    "S-1-5-32-575",
    "S-1-5-32-576",
    "S-1-5-32-577",
    "S-1-5-32-578",
    "S-1-5-32-580",
    "S-1-5-32-582",
    "S-1-5-32-585",
];

/// `_RID_NAMES` — (rid, slug, name, node_type). Order = declaration order.
const RID_NAMES: &[(u32, &str, &str, &str)] = &[
    (500, "administrator", "Administrator", "User"),
    (501, "guest", "Guest", "User"),
    (502, "krbtgt", "krbtgt", "User"),
    (512, "domain-admins", "Domain Admins", "Group"),
    (513, "domain-users", "Domain Users", "Group"),
    (514, "domain-guests", "Domain Guests", "Group"),
    (515, "domain-computers", "Domain Computers", "Group"),
    (516, "domain-controllers", "Domain Controllers", "Group"),
    (517, "cert-publishers", "Cert Publishers", "Group"),
    (518, "schema-admins", "Schema Admins", "Group"),
    (519, "enterprise-admins", "Enterprise Admins", "Group"),
    (
        520,
        "group-policy-creator-owners",
        "Group Policy Creator Owners",
        "Group",
    ),
    (
        521,
        "read-only-domain-controllers",
        "Read-only Domain Controllers",
        "Group",
    ),
    (
        522,
        "cloneable-domain-controllers",
        "Cloneable Domain Controllers",
        "Group",
    ),
    (525, "protected-users", "Protected Users", "Group"),
    (526, "key-admins", "Key Admins", "Group"),
    (
        527,
        "enterprise-key-admins",
        "Enterprise Key Admins",
        "Group",
    ),
];

/// `_WKGUIDS` — (slug, name, guid, node_type).
const WKGUIDS: &[(&str, &str, &str, &str)] = &[
    (
        "computers",
        "Computers",
        "aa312825768811d1aded00c04fd8d5cd",
        "Container",
    ),
    (
        "deleted-objects",
        "Deleted Objects",
        "18e2ea80684f11d2b9aa00c04f79f805",
        "Container",
    ),
    (
        "domain-controllers",
        "Domain Controllers",
        "a361b2ffffd211d1aa4b00c04fd7d83a",
        "OU",
    ),
    (
        "foreign-security-principals",
        "Foreign Security Principals",
        "22b70c67d56e4efb91e9300fca3dc1aa",
        "Container",
    ),
    (
        "infrastructure",
        "Infrastructure",
        "2fbac1870ade11d297c400c04fd8d5cd",
        "Container",
    ),
    (
        "lost-and-found",
        "LostAndFound",
        "ab8153b7768811d1aded00c04fd8d5cd",
        "Container",
    ),
    (
        "microsoft-program-data",
        "Microsoft Program Data",
        "f4be92a4c777485e878e9421d53087db",
        "Container",
    ),
    (
        "ntds-quotas",
        "NTDS Quotas",
        "6227f0af1fc2410d8e3bb10615bb5b0f",
        "Container",
    ),
    (
        "program-data",
        "Program Data",
        "09460c08ae1e4a4ea0f64aee7daa1e5a",
        "Container",
    ),
    (
        "system",
        "System",
        "ab1d30f3768811d1aded00c04fd8d5cd",
        "Container",
    ),
    (
        "users",
        "Users",
        "a9d1ca15768811d1aded00c04fd8d5cd",
        "Container",
    ),
    (
        "managed-service-accounts",
        "Managed Service Accounts",
        "1eb93889e40c45df9f0c64d23bbb6237",
        "Container",
    ),
];

/// `_CERTIFICATE_TEMPLATES`.
const CERTIFICATE_TEMPLATES: &[&str] = &[
    "Administrator",
    "Authenticated Session",
    "Basic EFS",
    "CA Exchange",
    "CEP Encryption",
    "Code Signing",
    "Computer",
    "Cross-Certification Authority",
    "Directory E-mail Replication",
    "Domain Controller",
    "Domain Controller Authentication",
    "EFS Recovery Agent",
    "Enrollment Agent",
    "Enrollment Agent (Computer)",
    "Exchange Enrollment Agent (Offline request)",
    "Exchange Signature Only",
    "Exchange User",
    "IPSEC",
    "IPSEC (Offline request)",
    "Kerberos Authentication",
    "Key Recovery Agent",
    "OCSP Response Signing",
    "RAS and IAS Server",
    "Root Certification Authority",
    "Router (Offline request)",
    "Smartcard Logon",
    "Smartcard User",
    "Subordinate Certification Authority",
    "Trust List Signing",
    "User",
    "User Signature Only",
    "Web Server",
    "Workstation Authentication",
];

/// `_STANDARD_OIDS`.
const STANDARD_OIDS: &[&str] = &[
    "2.5.29.37.0",
    "1.3.6.1.5.5.7.3.1",
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.5.7.3.3",
    "1.3.6.1.5.5.7.3.4",
    "1.3.6.1.5.5.7.3.8",
    "1.3.6.1.5.5.7.3.9",
    "1.3.6.1.5.2.3.5",
    "1.3.6.1.4.1.311.20.2.1",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.4.1.311.10.3.4",
    "1.3.6.1.4.1.311.10.3.4.1",
];

/// `_ACCESS_RIGHT_GUIDS`.
const ACCESS_RIGHT_GUIDS: &[&str] = &[
    "00299570-246d-11d0-a768-00aa006e0529",
    "ab721a53-1e2f-11d0-9819-00aa0040529",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2",
];

// ---------------------------------------------------------------------------
// Builder (mirrors `_catalog_entries`).
// ---------------------------------------------------------------------------

fn node_set(types: &[&str]) -> BTreeSet<String> {
    types.iter().map(|s| s.to_string()).collect()
}

/// Build one `exact_values` map, case-folding every value (`_exact_values`).
/// Each catalog path maps to a single canonical value; repeated paths union.
fn exact_values(pairs: &[(&str, &str)]) -> IndexMap<String, BTreeSet<String>> {
    let mut map: IndexMap<String, BTreeSet<String>> = IndexMap::new();
    for (path, value) in pairs {
        map.entry((*path).to_string())
            .or_default()
            .insert(casefold(value));
    }
    map
}

#[allow(clippy::too_many_arguments)]
fn entry(
    rule_id: String,
    kind: IdentifierKind,
    value: &str,
    node_types: &[&str],
    privacy: PrivacyClass,
    preserve_paths: &[&str],
    source: &str,
    exact: IndexMap<String, BTreeSet<String>>,
) -> CatalogEntry {
    CatalogEntry {
        rule_id,
        kind,
        value: normalize(kind, value),
        node_types: node_set(node_types),
        privacy,
        preserve_paths: preserve_paths.iter().map(|s| s.to_string()).collect(),
        exact_values: exact,
        source: source.to_string(),
    }
}

fn build_catalog() -> Vec<CatalogEntry> {
    let mut entries: Vec<CatalogEntry> = Vec::new();

    // guid.null
    let null_guid = "00000000-0000-0000-0000-000000000000";
    let mut null_preserve: Vec<&str> = vec!["ObjectIdentifier"];
    null_preserve.extend_from_slice(&ACE_GUID_PATHS);
    let mut null_exact: Vec<(&str, &str)> = vec![("ObjectIdentifier", null_guid)];
    for path in ACE_GUID_PATHS {
        null_exact.push((path, null_guid));
    }
    entries.push(entry(
        "guid.null".to_string(),
        IdentifierKind::Guid,
        null_guid,
        &ALL_NODE_TYPES,
        PrivacyClass::CoreGlobalDefault,
        &null_preserve,
        "RFC 4122 nil UUID",
        exact_values(&null_exact),
    ));

    // GPOs
    let gpos: &[(&str, &str)] = &[
        (
            "default-domain-policy",
            "31b2f340-016d-11d2-945f-00c04fb984f9",
        ),
        (
            "default-domain-controllers-policy",
            "6ac1786c-016f-11d2-945f-00c04fb984f9",
        ),
    ];
    for (slug, guid) in gpos {
        entries.push(entry(
            format!("gpo.{slug}"),
            IdentifierKind::Guid,
            guid,
            &["GPO"],
            PrivacyClass::CoreGlobalDefault,
            &["ObjectIdentifier"],
            "Microsoft [MS-GPOD] default Group Policy Objects",
            exact_values(&[("ObjectIdentifier", guid)]),
        ));
        entries.push(entry(
            format!("gpo-link.{slug}"),
            IdentifierKind::Guid,
            guid,
            &["Container", "Domain", "OU"],
            PrivacyClass::CoreGlobalDefault,
            &["Links[].GUID"],
            "Microsoft [MS-GPOD] default Group Policy Objects",
            exact_values(&[("Links[].GUID", guid)]),
        ));
    }

    // SIDs (sorted, `sorted(_EXISTING_NON_DOMAIN_SIDS)`)
    let mut sids: Vec<&str> = EXISTING_NON_DOMAIN_SIDS.to_vec();
    sids.sort_unstable();
    for sid in sids {
        let privacy = if FEATURE_SIDS.contains(&sid) {
            PrivacyClass::MicrosoftFeatureDefault
        } else {
            PrivacyClass::CoreGlobalDefault
        };
        let name = WELL_KNOWN_SID_NAMES
            .iter()
            .find(|(s, _)| *s == sid)
            .map(|(_, n)| *n);

        let mut exact: Vec<(&str, &str)> = Vec::new();
        for path in SID_PATHS {
            exact.push((path, sid));
        }
        let mut preserve: Vec<&str> = SID_PATHS.to_vec();
        if let Some(name) = name {
            for path in NAME_PATHS {
                exact.push((path, name));
            }
            preserve.extend_from_slice(&NAME_PATHS);
        }
        let rule_id = format!(
            "sid.{}",
            casefold(sid).replace("s-1-", "").replace('-', ".")
        );
        entries.push(entry(
            rule_id,
            IdentifierKind::Sid,
            sid,
            &ALL_NODE_TYPES,
            privacy,
            &preserve,
            "Microsoft well-known security identifiers",
            exact_values(&exact),
        ));
    }

    // RIDs
    for (rid, slug, name, node_type) in RID_NAMES {
        let rid_str = rid.to_string();
        let mut exact: Vec<(&str, &str)> = Vec::new();
        for path in SID_PATHS {
            exact.push((path, &rid_str));
        }
        for path in NAME_PATHS {
            exact.push((path, name));
        }
        let mut preserve: Vec<&str> = SID_PATHS.to_vec();
        preserve.extend_from_slice(&NAME_PATHS);
        entries.push(entry(
            format!("rid.{slug}"),
            IdentifierKind::Rid,
            &rid_str,
            &[node_type],
            PrivacyClass::CoreGlobalDefault,
            &preserve,
            "Microsoft default domain security principals",
            exact_values(&exact),
        ));
    }

    // WKGUIDs
    for (slug, name, guid, node_type) in WKGUIDS {
        let mut exact: Vec<(&str, &str)> = vec![("Properties.wkguid", guid)];
        for path in NAME_PATHS {
            exact.push((path, name));
        }
        let mut preserve: Vec<&str> = vec!["Properties.wkguid"];
        preserve.extend_from_slice(&NAME_PATHS);
        entries.push(entry(
            format!("wkguid.{slug}"),
            IdentifierKind::Wkguid,
            guid,
            &[node_type],
            PrivacyClass::CoreGlobalDefault,
            &preserve,
            "Microsoft [MS-ADTS] well-known objects",
            exact_values(&exact),
        ));
    }

    // Certificate templates
    for (index, name) in CERTIFICATE_TEMPLATES.iter().enumerate() {
        let mut exact: Vec<(&str, &str)> = Vec::new();
        for path in TEMPLATE_PATHS {
            exact.push((path, name));
        }
        entries.push(entry(
            format!("template.builtin-{:02}", index + 1),
            IdentifierKind::Template,
            name,
            &["CertTemplate"],
            PrivacyClass::CoreGlobalDefault,
            &TEMPLATE_PATHS,
            "Microsoft built-in certificate template internal names",
            exact_values(&exact),
        ));
    }

    // Standard OIDs
    for (index, oid) in STANDARD_OIDS.iter().enumerate() {
        let mut exact: Vec<(&str, &str)> = Vec::new();
        for path in OID_PATHS {
            exact.push((path, oid));
        }
        entries.push(entry(
            format!("oid.standard-{:02}", index + 1),
            IdentifierKind::Oid,
            oid,
            &["CertTemplate", "IssuancePolicy"],
            PrivacyClass::CoreGlobalDefault,
            &OID_PATHS,
            "IETF and Microsoft standard certificate OIDs",
            exact_values(&exact),
        ));
    }

    // Access-right GUIDs
    for (index, guid) in ACCESS_RIGHT_GUIDS.iter().enumerate() {
        let mut exact: Vec<(&str, &str)> = Vec::new();
        for path in ACE_GUID_PATHS {
            exact.push((path, guid));
        }
        entries.push(entry(
            format!("access-right.predefined-{:02}", index + 1),
            IdentifierKind::Guid,
            guid,
            &ALL_NODE_TYPES,
            PrivacyClass::CoreGlobalDefault,
            &ACE_GUID_PATHS,
            "Microsoft [MS-ADTS] predefined control access rights",
            exact_values(&exact),
        ));
    }

    entries
}
