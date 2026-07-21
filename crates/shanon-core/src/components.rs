//! Structure-aware transforms for composite AD identifiers.
//!
//! Pseudonym generation lives in the registry (module 7, P2); this module only
//! decomposes composite identifiers and dispatches each piece to the right
//! registry category. That registry surface is abstracted behind [`RegistryOps`]
//! so the structural logic is testable now (the concrete `Registry`
//! implements the trait in P2).
//!
//! Regex audit (§R2): three shape matchers (`GUID_SHAPE`, `DOMAIN_SID_SHAPE`,
//! `PREFIXED_SID_SHAPE`). None use lookaround or backreferences, so all work with
//! the `regex` crate — no `fancy-regex` needed. Known nuance: Rust `regex` `$`
//! anchors at end-of-haystack and does not also match just
//! before a single trailing `\n`; SharpHound identifier values contain no
//! newlines, so this does not affect the corpus.

use std::sync::OnceLock;

use regex::Regex;

use crate::casefold::casefold;

/// Registry category names (mirror `shanon.registry` constants).
pub const DOMAINS: &str = "domains";
pub const SIDS: &str = "sids";
pub const ACCOUNTS: &str = "accounts";
pub const HOSTS: &str = "hosts";
pub const GUIDS: &str = "guids";
pub const CERT_TEMPLATES: &str = "cert_templates";
pub const OIDS: &str = "oids";
pub const OPAQUE: &str = "opaque";

/// The registry operations `components` (and `fields`) invoke. Implemented by
/// the concrete `Registry` in P2; driven by a stub in unit tests.
pub trait RegistryOps {
    fn map(&mut self, category: &str, real: &str) -> String;
    fn bind(
        &mut self,
        category: &str,
        real: &str,
        pseudonym: &str,
        preserve_terminal: Option<bool>,
    ) -> String;
    fn sid_subauthority(&mut self, real: &str) -> String;
}

/// Callback deciding whether a CN/OU RDN value is preserved (its uppercased key
/// and raw value are passed), matching the `preserve_rdn` contract.
pub type PreserveRdn<'a> = &'a dyn Fn(&str, &str) -> bool;

const SAFE_DOMAIN_SUFFIXES: &[&str] = &["local", "com", "net", "org"];

const STANDARD_SPN_SERVICE_CLASSES: &[&str] = &[
    "cifs",
    "dns",
    "gc",
    "host",
    "http",
    "ldap",
    "mssqlsvc",
    "restrictedkrbhost",
    "rpcss",
    "termsrv",
    "wsman",
];

fn guid_shape() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
        )
        .unwrap()
    })
}

fn domain_sid_shape() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^S-1-5-21-\d+-\d+-\d+(?:-\d+)?$").unwrap())
}

fn prefixed_sid_shape() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // re.IGNORECASE
    RE.get_or_init(|| Regex::new(r"(?i)^(.+)-(S-1-.+)$").unwrap())
}

/// Remap a SID, retaining a domain RID only with explicit evidence.
pub fn transform_sid(reg: &mut dyn RegistryOps, sid: &str, preserve: bool) -> String {
    if let Some(caps) = prefixed_sid_shape().captures(sid) {
        let domain = caps.get(1).unwrap().as_str().to_string();
        let inner_sid = caps.get(2).unwrap().as_str().to_string();
        let mapped_sid = transform_sid(reg, &inner_sid, preserve);
        return format!("{}-{}", transform_domain(reg, &domain), mapped_sid);
    }

    let parts: Vec<String> = sid.to_uppercase().split('-').map(String::from).collect();
    if parts.len() >= 7 && parts[..4] == ["S", "1", "5", "21"] {
        let mut source_parent = parts[..7].join("-");
        let mut mapped_parent = reg.map(SIDS, &source_parent);
        let descendants = &parts[7..];
        for (index, subauthority) in descendants.iter().enumerate() {
            source_parent = format!("{source_parent}-{subauthority}");
            let preserve_terminal = preserve && index == descendants.len() - 1;
            let mapped_subauthority = if preserve_terminal {
                subauthority.clone()
            } else {
                reg.sid_subauthority(&source_parent)
            };
            mapped_parent = reg.bind(
                SIDS,
                &source_parent,
                &format!("{mapped_parent}-{mapped_subauthority}"),
                Some(preserve_terminal),
            );
        }
        return mapped_parent;
    }

    if preserve {
        return sid.to_string();
    }
    reg.map(SIDS, &sid.to_uppercase())
}

/// Remap organization-specific labels in a dotted domain name.
pub fn transform_domain(reg: &mut dyn RegistryOps, domain: &str) -> String {
    let labels: Vec<&str> = domain.split('.').collect();
    let count = labels.len();
    let mut out: Vec<String> = Vec::with_capacity(count);
    for (index, label) in labels.iter().enumerate() {
        let keep = label.is_empty()
            || (count > 1
                && index == count - 1
                && SAFE_DOMAIN_SUFFIXES.contains(&casefold(label).as_str()));
        if keep {
            out.push((*label).to_string());
        } else {
            out.push(reg.map(DOMAINS, &label.to_lowercase()));
        }
    }
    out.join(".")
}

/// Remap a bare account or group name unless explicitly preserved.
pub fn transform_name_token(reg: &mut dyn RegistryOps, token: &str, preserve: bool) -> String {
    if preserve {
        return token.to_string();
    }
    if guid_shape().is_match(token) {
        return transform_guid(reg, token, false);
    }
    if domain_sid_shape().is_match(token) {
        return transform_sid(reg, token, false);
    }
    reg.map(ACCOUNTS, token)
}

/// Remap a GUID unless the caller supplies preservation evidence.
pub fn transform_guid(reg: &mut dyn RegistryOps, guid: &str, preserve: bool) -> String {
    if preserve {
        return guid.to_string();
    }
    let core = guid.trim();
    let wrapped = core.starts_with('{') && core.ends_with('}') && core.len() >= 2;
    let core = if wrapped {
        &core[1..core.len() - 1]
    } else {
        core
    };
    let core = core.to_lowercase();
    let mapped = reg.map(GUIDS, &core);
    if wrapped {
        format!("{{{mapped}}}")
    } else {
        mapped
    }
}

/// Remap an account name while preserving a machine-account suffix.
pub fn transform_samaccountname(reg: &mut dyn RegistryOps, value: &str) -> String {
    if let Some(stripped) = value.strip_suffix('$') {
        format!("{}$", transform_name_token(reg, stripped, false))
    } else {
        transform_name_token(reg, value, false)
    }
}

/// Remap the name and domain components of a user principal name.
pub fn transform_upn_name(reg: &mut dyn RegistryOps, name: &str) -> String {
    match name.split_once('@') {
        None => transform_name_token(reg, name, false),
        Some((prefix, domain)) => format!(
            "{}@{}",
            transform_name_token(reg, prefix, false),
            transform_domain(reg, domain)
        ),
    }
}

/// Remap the local and domain components of an email address.
pub fn transform_email(reg: &mut dyn RegistryOps, email: &str) -> String {
    match email.split_once('@') {
        None => email.to_string(),
        Some((local, domain)) => format!(
            "{}@{}",
            transform_name_token(reg, local, false),
            transform_domain(reg, domain)
        ),
    }
}

/// Remap a hostname label and its optional domain.
pub fn transform_dnshostname(reg: &mut dyn RegistryOps, host: &str) -> String {
    match host.split_once('.') {
        None => reg.map(HOSTS, &host.to_lowercase()),
        Some((label, domain)) => {
            let mapped_label = reg.map(HOSTS, &label.to_lowercase());
            format!("{}.{}", mapped_label, transform_domain(reg, domain))
        }
    }
}

/// Scrub host/share/name components in Windows-style path values.
pub fn transform_path(reg: &mut dyn RegistryOps, path: &str) -> String {
    if path.starts_with("\\\\") {
        let mut parts: Vec<String> = path.split('\\').map(String::from).collect();
        if parts.len() >= 4 && !parts[2].is_empty() {
            let host = parts[2].clone();
            parts[2] = transform_dnshostname(reg, &host);
            for part in parts.iter_mut().skip(3) {
                if !part.is_empty() {
                    *part = transform_name_token(reg, part.as_str(), false);
                }
            }
            return parts.join("\\");
        }
    }

    let separator = if path.contains('\\') {
        Some('\\')
    } else if path.contains('/') {
        Some('/')
    } else {
        None
    };
    match separator {
        None => transform_name_token(reg, path, false),
        Some(sep) => {
            let mut parts: Vec<String> = path.split(sep).map(String::from).collect();
            for part in parts.iter_mut() {
                if part.is_empty() || part.ends_with(':') {
                    continue;
                }
                *part = transform_name_token(reg, part.as_str(), false);
            }
            parts.join(&sep.to_string())
        }
    }
}

/// Scrub host and path components in URL-like values.
pub fn transform_url(reg: &mut dyn RegistryOps, url: &str) -> String {
    let parsed = urlsplit(url);
    if parsed.scheme.is_empty() || parsed.netloc.is_empty() {
        return transform_path(reg, url);
    }

    let host = match hostname(&parsed.netloc) {
        None => return url.to_string(),
        Some(h) => h,
    };
    let mapped_host = transform_dnshostname(reg, &host);
    let mut netloc = mapped_host;
    if let Some(port) = port_of(&parsed.netloc) {
        netloc = format!("{netloc}:{port}");
    }
    if let Some(username) = username_of(&parsed.netloc) {
        if !username.is_empty() {
            let mut auth = transform_name_token(reg, &username, false);
            if password_present(&parsed.netloc) {
                auth = format!("{auth}:[REDACTED]");
            }
            netloc = format!("{auth}@{netloc}");
        }
    }

    let path = if parsed.path.is_empty() {
        parsed.path.clone()
    } else {
        transform_path(reg, &parsed.path)
    };
    urlunsplit(
        &parsed.scheme,
        &netloc,
        &path,
        &parsed.query,
        &parsed.fragment,
    )
}

fn split_unescaped(value: &str, separator: char) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if character == separator && !escaped {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
        if character == '\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    parts.push(current);
    parts
}

/// Remap name and domain-label values in a distinguished name.
///
/// `preserve_rdn` receives the uppercased attribute key (`"CN"`/`"OU"`) and the
/// raw value, matching the `preserve_rdn` callback contract.
pub fn transform_dn(
    reg: &mut dyn RegistryOps,
    dn: &str,
    preserve_rdn: Option<PreserveRdn<'_>>,
) -> String {
    let rdns = split_unescaped(dn, ',');
    let dc_ava_count = rdns
        .iter()
        .flat_map(|rdn| split_unescaped(rdn, '+'))
        .filter(|ava| {
            ava.contains('=') && ava.split_once('=').unwrap().0.trim().to_uppercase() == "DC"
        })
        .count();

    let mut out_rdns: Vec<String> = Vec::with_capacity(rdns.len());
    for (rdn_index, rdn) in rdns.iter().enumerate() {
        let mut out_avas: Vec<String> = Vec::new();
        for ava in split_unescaped(rdn, '+') {
            let Some((attr, value)) = ava.split_once('=') else {
                out_avas.push(ava);
                continue;
            };
            let key = attr.trim().to_uppercase();
            if key == "DC" {
                let terminal_safe_suffix = dc_ava_count >= 2
                    && rdn_index == rdns.len() - 1
                    && SAFE_DOMAIN_SUFFIXES.contains(&casefold(value).as_str());
                let mapped = if terminal_safe_suffix {
                    value.to_string()
                } else {
                    transform_domain(reg, value)
                };
                out_avas.push(format!("{attr}={mapped}"));
            } else if key == "CN" || key == "OU" {
                let preserve = preserve_rdn.map(|f| f(&key, value)).unwrap_or(false);
                let mapped = transform_name_token(reg, value, preserve);
                out_avas.push(format!("{attr}={mapped}"));
            } else {
                let mapped = reg.map(OPAQUE, value);
                out_avas.push(format!("{attr}={mapped}"));
            }
        }
        out_rdns.push(out_avas.join("+"));
    }
    out_rdns.join(",")
}

/// Map an enterprise OID unless explicitly preserved.
pub fn transform_oid(reg: &mut dyn RegistryOps, oid: &str, preserve: bool) -> String {
    if preserve {
        return oid.to_string();
    }
    reg.map(OIDS, oid)
}

/// Map a certificate-template name in its dedicated namespace.
pub fn transform_template_name(reg: &mut dyn RegistryOps, name: &str, preserve: bool) -> String {
    if preserve {
        return name.to_string();
    }
    reg.map(CERT_TEMPLATES, name)
}

/// Map a BloodHound local-group/computer composite identity.
pub fn transform_ad_local_group_name(
    reg: &mut dyn RegistryOps,
    value: &str,
    preserve_group: bool,
) -> String {
    match value.rsplit_once('@') {
        None => transform_name_token(reg, value, preserve_group),
        Some((group, computer)) => {
            let mapped_group = transform_name_token(reg, group, preserve_group);
            format!("{}@{}", mapped_group, transform_dnshostname(reg, computer))
        }
    }
}

struct Spn<'a> {
    service: &'a str,
    host: &'a str,
    port: Option<&'a str>,
    instance: Option<&'a str>,
}

fn parse_spn(spn: &str) -> Option<Spn<'_>> {
    let components: Vec<&str> = spn.split('/').collect();
    if !(components.len() == 2 || components.len() == 3)
        || components.iter().any(|part| part.is_empty())
    {
        return None;
    }
    let service = components[0];
    let host_port = components[1];
    let instance = if components.len() == 3 {
        Some(components[2])
    } else {
        None
    };
    let host_and_port: Vec<&str> = host_port.split(':').collect();
    let (host, port) = if host_and_port.len() == 1 {
        (host_and_port[0], None)
    } else if host_and_port.len() == 2 && host_and_port.iter().all(|s| !s.is_empty()) {
        (host_and_port[0], Some(host_and_port[1]))
    } else {
        return None;
    };
    if service.is_empty() || host.is_empty() {
        return None;
    }
    Some(Spn {
        service,
        host,
        port,
        instance,
    })
}

/// Remap sensitive service, host, and optional instance identities in an SPN.
pub fn transform_spn(reg: &mut dyn RegistryOps, spn: &str) -> String {
    let Some(parsed) = parse_spn(spn) else {
        return spn.to_string();
    };
    let mapped_service =
        if STANDARD_SPN_SERVICE_CLASSES.contains(&casefold(parsed.service).as_str()) {
            parsed.service.to_string()
        } else {
            transform_name_token(reg, parsed.service, false)
        };
    let port_suffix = parsed.port.map(|p| format!(":{p}")).unwrap_or_default();
    let instance_suffix = parsed
        .instance
        .map(|i| format!("/{}", transform_dnshostname(reg, i)))
        .unwrap_or_default();
    let mapped_host = transform_dnshostname(reg, parsed.host);
    format!("{mapped_service}/{mapped_host}{port_suffix}{instance_suffix}")
}

// ---------------------------------------------------------------------------
// Minimal URL split/unsplit for the
// standard `scheme://[user[:pass]@]host[:port]/path[?query][#fragment]` grammar
// that transform_url exercises.
// ---------------------------------------------------------------------------

struct SplitUrl {
    scheme: String,
    netloc: String,
    path: String,
    query: String,
    fragment: String,
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'
}

fn urlsplit(input: &str) -> SplitUrl {
    let mut url = input;
    let mut scheme = String::new();

    if let Some(i) = url.find(':') {
        if i > 0 && url[..i].chars().all(is_scheme_char) {
            scheme = url[..i].to_lowercase();
            url = &url[i + 1..];
        }
    }

    let mut netloc = String::new();
    if let Some(rest) = url.strip_prefix("//") {
        let delim = rest
            .find(['/', '?', '#'])
            .map(|p| p + 2)
            .unwrap_or(url.len());
        netloc = url[2..delim].to_string();
        url = &url[delim..];
    }

    let mut fragment = String::new();
    if let Some(p) = url.find('#') {
        fragment = url[p + 1..].to_string();
        url = &url[..p];
    }
    let mut query = String::new();
    if let Some(p) = url.find('?') {
        query = url[p + 1..].to_string();
        url = &url[..p];
    }

    SplitUrl {
        scheme,
        netloc,
        path: url.to_string(),
        query,
        fragment,
    }
}

fn hostinfo(netloc: &str) -> &str {
    match netloc.rfind('@') {
        Some(i) => &netloc[i + 1..],
        None => netloc,
    }
}

fn hostname(netloc: &str) -> Option<String> {
    let hi = hostinfo(netloc);
    let host = if let Some(rest) = hi.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hi.split(':').next().unwrap_or(hi)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

fn port_of(netloc: &str) -> Option<u32> {
    let hi = hostinfo(netloc);
    let port_str = if let Some(rest) = hi.strip_prefix('[') {
        match rest.split_once(']') {
            Some((_, after)) => after.strip_prefix(':').unwrap_or(""),
            None => "",
        }
    } else {
        match hi.split_once(':') {
            Some((_, p)) => p,
            None => "",
        }
    };
    if port_str.is_empty() {
        None
    } else {
        port_str.parse::<u32>().ok()
    }
}

fn userinfo(netloc: &str) -> Option<&str> {
    netloc.rfind('@').map(|i| &netloc[..i])
}

fn username_of(netloc: &str) -> Option<String> {
    userinfo(netloc).map(|u| u.split(':').next().unwrap_or("").to_string())
}

fn password_present(netloc: &str) -> bool {
    userinfo(netloc).is_some_and(|u| u.contains(':'))
}

fn urlunsplit(scheme: &str, netloc: &str, path: &str, query: &str, fragment: &str) -> String {
    // transform_url only reaches here with a non-empty netloc.
    let mut url = path.to_string();
    if !netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url = format!("/{url}");
        }
        url = format!("//{netloc}{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !fragment.is_empty() {
        url = format!("{url}#{fragment}");
    }
    url
}
