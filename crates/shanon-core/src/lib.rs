//! shanon-core.
//!
//! Core primitives from the S1 spike ([`canonical_json`], [`seed_int`]) plus the
//! P0 leaf modules (bottom-up per plan §2):
//!
//! * [`wellknown`] — deprecated catalog predicates (catalog abstracted; P1).
//! * [`patterns`] — ordered trie regex source (`factor_literals`).
//! * [`fields`] — ignore-case signatures + v1 token matcher (registry abstracted).
//! * [`components`] — structure-aware composite-identifier transforms (registry
//!   abstracted).
//!
//! Support: [`casefold`] (Unicode full case folding), [`ignorecase`]
//! (case-insensitive single-char equivalence), [`textutil`] (regex metacharacter escaping).

pub mod casefold;
pub mod catalog;
pub mod components;
pub mod engine;
pub mod fields;
pub mod ignorecase;
pub mod patterns;
pub mod pipeline;
pub mod platform;
pub mod policy;
pub mod progress;
pub mod registry;
pub mod restore;
pub mod textutil;
pub mod verify;
pub mod wellknown;

use blake2::digest::consts::U16;
use blake2::{Blake2b, Digest};
use serde_json::Value;

/// BLAKE2b with a 16-byte (128-bit) output — matches
/// `hashlib.blake2b(..., digest_size=16)`.
type Blake2b128 = Blake2b<U16>;

// ---------------------------------------------------------------------------
// Secret material.
// ---------------------------------------------------------------------------

/// Leaf key names whose value is credential material, casefolded.
///
/// A value under one of these is replaced with a constant rather than
/// pseudonymized, because pseudonymizing it would record the cleartext secret
/// as a key in the mapping file. The list is shared by [`engine`] and
/// [`verify`]: the verifier re-derives every leaf independently, so two copies
/// of this list would let a run abort on a field only one side redacts.
///
/// LAPS and gMSA spellings are here because a collector that reads them emits
/// them as ordinary `Properties` strings that no rule declares, which lands
/// them in the fallback path and therefore in the map. The same reasoning adds
/// three more families, each a real directory attribute rather than a guess:
///
/// * **Trust keys.** `trustAuthIncoming` / `trustAuthOutgoing` hold the
///   inter-domain trust key, and `initialAuthIncoming` / `initialAuthOutgoing`
///   the legacy trust password. A trust key forges tickets across a forest
///   edge, which is exactly the edge an attack-path question is about.
/// * **BitLocker.** `msFVE-RecoveryPassword` and `msFVE-KeyPackage` are
///   recovery material stored on the computer object.
/// * **Legacy hashes and GPP.** `dBCSPwd` is where the LM hash lives, and
///   `cpassword` is the Group Policy Preferences field whose AES key Microsoft
///   published, making it cleartext in practice.
///
/// The bare `password` and `pwd` spellings are here for a collector that names
/// a custom attribute the obvious way. Matching is exact on the whole leaf, not
/// a prefix, so they cannot swallow `pwdlastset`, `passwordlastset` or
/// `passwordnotreqd`.
///
/// Attributes that carry a timestamp or an interval rather than a secret
/// (`ms-mcs-admpwdexpirationtime`, `msds-managedpasswordinterval`) are
/// deliberately absent, and so is `msds-keycredentiallink`, which holds a
/// public key.
///
/// This is name-based recognition, and that is a known gap rather than a
/// complete defense: a credential under an attribute this list does not know is
/// still pseudonymized like any other string. See CHANGELOG's known gaps.
pub(crate) const SECRET_MATERIAL_KEYS: [&str; 28] = [
    "cleartextpassword",
    "cpassword",
    "dbcspwd",
    "initialauthincoming",
    "initialauthoutgoing",
    "lmhash",
    "lmpwdhistory",
    "ms-mcs-admpwd",
    "msds-managedpassword",
    "msfve-keypackage",
    "msfve-recoverypassword",
    "mslaps-encrypteddsrmpassword",
    "mslaps-encrypteddsrmpasswordhistory",
    "mslaps-encryptedpassword",
    "mslaps-encryptedpasswordhistory",
    "mslaps-password",
    "nthash",
    "ntpwdhistory",
    "password",
    "pwd",
    "sfupassword",
    "supplementalcredentials",
    "trustauthincoming",
    "trustauthoutgoing",
    "unicodepassword",
    "unicodepwd",
    "unixpassword",
    "userpassword",
];

/// The constant a secret-material leaf is replaced with.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// Whether the last segment of `path` names secret material.
///
/// Applied ahead of the operation the policy resolved, not inside one arm of
/// it: a secret whose value happens to look like a SID, GUID or OID is routed
/// to a structured identifier transform, and pseudonymizing it would put the
/// cleartext in the mapping file just the same.
pub(crate) fn is_secret_material_path(path: &str) -> bool {
    let leaf = path.rsplit('.').next().unwrap_or(path);
    let leaf = match leaf.rfind('[') {
        Some(open) if leaf.ends_with(']') => {
            let inner = &leaf[open + 1..leaf.len() - 1];
            if !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit()) {
                &leaf[..open]
            } else {
                leaf
            }
        }
        _ => leaf,
    };
    SECRET_MATERIAL_KEYS.contains(&casefold::casefold(leaf).as_str())
}

// ---------------------------------------------------------------------------
// Contract 1: canonical JSON serialization, compact-mode defaults.
//
//   canonical_json(output)
//
// Compact-mode defaults (`indent` unset):
//   * item separator  = ", "   (comma + space)
//   * key separator   = ": "   (colon + space)
//   * ensure_ascii    = true   (every codepoint >= 0x7f escaped to \uXXXX,
//                               astral planes as UTF-16 surrogate pairs)
//   * sort_keys       = false  (insertion order preserved -> needs preserve_order)
//   * numbers         = verbatim int text / float repr (-> arbitrary_precision
//                       keeps the input token; see spike report for the caveat)
// ---------------------------------------------------------------------------

/// Canonical JSON serialization of a [`serde_json::Value`]: compact `, `/`: `
/// separators, `ensure_ascii`, lowercase `\uXXXX` escapes. Requires the value
/// to have been parsed with the
/// `preserve_order` + `arbitrary_precision` features enabled.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // With `arbitrary_precision`, Number's Display yields the original
        // numeric token verbatim (no ryu reformatting).
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_py_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_string(k, out);
                out.push_str(": ");
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

/// Escape a string per the canonical JSON ASCII-safe string encoding
/// (`ensure_ascii=true`).
///
/// The literal range is 0x20..=0x7e minus `"` and `\`. Everything else escapes;
/// 0x7f (DEL) and all non-ASCII escape to `\uXXXX`, astral to surrogate pairs.
fn write_py_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (0x20..=0x7e).contains(&(c as u32)) => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    push_u_escape(cp, out);
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    push_u_escape(hi, out);
                    push_u_escape(lo, out);
                }
            }
        }
    }
    out.push('"');
}

/// Canonical JSON serialization with `indent=2, sort_keys=true` (the
/// `Registry.save` payload
/// format, §3.3). Object keys are emitted in sorted (Unicode scalar) order,
/// nested containers indented by two spaces per level, empty containers stay on
/// one line, and every codepoint is escaped (`ensure_ascii=true`).
pub fn canonical_json_sorted(value: &Value) -> String {
    let mut out = String::new();
    write_value_indent(value, 0, &mut out);
    out
}

fn write_value_indent(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(level + 1, out);
                write_value_indent(item, level + 1, out);
            }
            out.push('\n');
            push_indent(level, out);
            out.push(']');
        }
        Value::Object(map) if !map.is_empty() => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(level + 1, out);
                write_py_string(key, out);
                out.push_str(": ");
                write_value_indent(&map[*key], level + 1, out);
            }
            out.push('\n');
            push_indent(level, out);
            out.push('}');
        }
        // Empty containers and scalars reuse the compact writer verbatim.
        _ => write_value(value, out),
    }
}

fn push_indent(level: usize, out: &mut String) {
    for _ in 0..level * 2 {
        out.push(' ');
    }
}

fn push_u_escape(code: u32, out: &mut String) {
    // Lowercase 4-hex digits.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(HEX[((code >> 12) & 0xf) as usize] as char);
    out.push(HEX[((code >> 8) & 0xf) as usize] as char);
    out.push(HEX[((code >> 4) & 0xf) as usize] as char);
    out.push(HEX[(code & 0xf) as usize] as char);
}

// ---------------------------------------------------------------------------
// Contract 2: pseudonym seed layout matching `Registry._seed_int`.
//
//   digest = hashlib.blake2b(
//       f"{self.salt}|{category}|{semantic_real}".encode(), digest_size=16
//   )
//   return int.from_bytes(digest.digest(), "big")
//
// `semantic_real = _normalize_mapping_identity(category, real)` (casefold for
// most categories) is applied by the CALLER; this function takes the already
// normalized value, exactly as the hashed string is built.
// ---------------------------------------------------------------------------

/// Return the raw 16-byte BLAKE2b-128 digest of the seed layout string
/// `"{salt}|{category}|{semantic_real}"` (UTF-8).
pub fn pseudonym_digest(salt: &str, category: &str, semantic_real: &str) -> [u8; 16] {
    let mut hasher = Blake2b128::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"|");
    hasher.update(category.as_bytes());
    hasher.update(b"|");
    hasher.update(semantic_real.as_bytes());
    hasher.finalize().into()
}

/// Lowercase hex of [`pseudonym_digest`] — matches `.hexdigest()` output.
pub fn pseudonym_digest_hex(salt: &str, category: &str, semantic_real: &str) -> String {
    let d = pseudonym_digest(salt, category, semantic_real);
    let mut s = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in d {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// The pseudonym seed as a 128-bit integer, matching
/// `int.from_bytes(digest.digest(), "big")`.
pub fn seed_int(salt: &str, category: &str, semantic_real: &str) -> u128 {
    u128::from_be_bytes(pseudonym_digest(salt, category, semantic_real))
}

/// Reproduce the OIDS pseudonym: `f"2.25.{seed}"`
/// (`Registry._generate` for the `oids` category). Chosen for the spike
/// because it derives purely from the seed integer with no wordlist/base32.
pub fn oid_pseudonym(salt: &str, semantic_real: &str) -> String {
    format!("2.25.{}", seed_int(salt, "oids", semantic_real))
}
