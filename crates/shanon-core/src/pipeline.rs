//! Bounded two-pass transform orchestration and the error/exit-code contract
//! (§3.4).
//!
//! This module houses the pipeline pieces — size bounds, member parsing,
//! latest-duplicate selection, manifest-name validation — and the single
//! [`ShanonError`] enum that the CLI turns into stderr text and exit codes. The
//! error rendering (`stderr`) is the CLI's stable, byte-identical contract.
//!
//! [`anonymize_collection`] is the full two-pass orchestration: discover +
//! finalize + transform + independently verify every accepted member, then
//! atomically publish the collection and (optionally) the mapping file. Output
//! JSON is byte-identical to the canonical serialization (§3.1a); ZIP output is
//! byte-identical on write (a hand-rolled writer +
//! `flate2` zlib backend) modulo the wall-clock DOS timestamp, which — like the
//! mapping's `created` field — the parity replay normalizes on both sides.
//! Anchored reads and no-replace publication come from [`crate::platform`].

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::engine::{AbortLocator, AnonymizationEngine, EngineError, VerificationContext};
use crate::platform;
use crate::policy::{PolicyAudit, PolicyConfig};
use crate::progress::{self, Phase, ProgressEvent, ProgressSink};
use crate::registry::Registry;
use crate::verify::{verify_document_with_progress, VerificationFinding};

/// `_MAX_JSON_MEMBERS`.
pub const MAX_JSON_MEMBERS: usize = 10_000;
/// `_MAX_MEMBER_UNCOMPRESSED`.
pub const MAX_MEMBER_UNCOMPRESSED: u64 = 512 * 1024 * 1024;
/// `_MAX_TOTAL_UNCOMPRESSED`.
pub const MAX_TOTAL_UNCOMPRESSED: u64 = 2 * 1024 * 1024 * 1024;

/// Ordered digest for every safe JSON input member, incl. skipped ones
/// (`_ManifestMember`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestMember {
    pub name: String,
    pub discovery_digest: [u8; 32],
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Error / exit-code contract (§3.4).
// ---------------------------------------------------------------------------

/// A post-commit resource-close failure after both artifacts were valid
/// (`PublicationCleanupWarning`). Non-fatal: it is warned, never aborts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationCleanupWarning {
    pub details: String,
}

/// The unified pipeline error surface. Maps every error case the CLI
/// distinguishes (`VerificationError`, `VerboseVerificationError`,
/// `PseudonymCollisionError`, `UnsafeMappingError`, `PublicationIdentityError`,
/// plus the generic `ValueError`/`OSError`/`FileExistsError` bucket and the
/// non-fatal `PublicationCleanupWarning`).
#[derive(Debug, Clone, thiserror::Error)]
pub enum ShanonError {
    /// `VerificationError`: contextual verification rejected a member.
    #[error("{}", verification_message(.0.as_ref()))]
    Verification(Option<VerificationFinding>),
    /// `VerboseVerificationError`: one or more sanitized findings.
    #[error("{}", verbose_message(.0))]
    VerboseVerification(Vec<VerificationFinding>),
    /// `PseudonymCollisionError`.
    #[error("{0}")]
    PseudonymCollision(String),
    /// `UnsafeMappingError`.
    #[error("{0}")]
    UnsafeMapping(String),
    /// `PublicationIdentityError` (a `RuntimeError` subclass).
    #[error("{0}")]
    PublicationIdentity(String),
    /// Any other `RuntimeError`.
    #[error("{0}")]
    Runtime(String),
    /// `ValueError`.
    #[error("{0}")]
    Value(String),
    /// `OSError` / `UnicodeDecodeError` / `zipfile.BadZipFile`.
    #[error("{0}")]
    Io(String),
    /// `FileExistsError`.
    #[error("{0}")]
    FileExists(String),
    /// Non-fatal post-commit cleanup warning (exit 0, stderr note only).
    #[error("{0}")]
    CleanupWarning(String),
    /// Any of the above with a sanitized abort locator attached. Renders
    /// byte-identically to the error it wraps under [`ShanonError::stderr`];
    /// only [`ShanonError::stderr_verbose`] expands it.
    #[error("{0}")]
    Located(Box<ShanonError>, AbortLocator),
}

impl ShanonError {
    /// The wrapped error, with any locator peeled off.
    pub fn unlocated(&self) -> &ShanonError {
        match self {
            ShanonError::Located(inner, _) => inner.unlocated(),
            other => other,
        }
    }

    /// The attached abort locator, if the failure was raised at a known leaf.
    pub fn locator(&self) -> Option<&AbortLocator> {
        match self {
            ShanonError::Located(_, locator) => Some(locator),
            _ => None,
        }
    }
}

fn verification_message(finding: Option<&VerificationFinding>) -> String {
    let mut message = String::from("contextual verification failed");
    if let Some(f) = finding {
        message.push_str(&format!(
            ": {} {} {} {}",
            f.member, f.path, f.policy_code, f.offender
        ));
    }
    message
}

fn verbose_message(findings: &[VerificationFinding]) -> String {
    match findings.first() {
        None => format!("{} verification finding(s)", findings.len()),
        Some(f) => format!(
            "{} verification finding(s); first: {} {} {} {}",
            findings.len(),
            f.member,
            f.path,
            f.policy_code,
            f.offender
        ),
    }
}

/// Format grouped verbose findings exactly as the verbose-findings formatter.
pub fn format_verbose_findings(findings: &[VerificationFinding]) -> String {
    // Group by gate, preserving first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut grouped: std::collections::HashMap<String, Vec<&VerificationFinding>> =
        std::collections::HashMap::new();
    for f in findings {
        if !grouped.contains_key(&f.gate) {
            order.push(f.gate.clone());
        }
        grouped.entry(f.gate.clone()).or_default().push(f);
    }

    let mut lines: Vec<String> = vec![
        "ABORTED - leak check failed, no output written".to_string(),
        String::new(),
    ];
    for gate in &order {
        lines.push(format!("{gate}:"));
        for f in &grouped[gate] {
            lines.push(format!(
                "- {} {}: {} {}",
                f.member, f.path, f.policy_code, f.offender
            ));
        }
        lines.push(String::new());
    }
    lines.join("\n").trim_end().to_string()
}

impl ShanonError {
    /// The process exit code the CLI raises for this error. All abort paths use
    /// `1`; the non-fatal cleanup warning does not abort (`0`).
    pub fn exit_code(&self) -> i32 {
        match self {
            ShanonError::Located(inner, _) => inner.exit_code(),
            ShanonError::CleanupWarning(_) => 0,
            _ => 1,
        }
    }

    /// The abort class shown in verbose diagnostics. Stable, kebab-case, and
    /// never derived from input.
    fn class(&self) -> &'static str {
        match self.unlocated() {
            ShanonError::Verification(_) | ShanonError::VerboseVerification(_) => "leak-gate",
            ShanonError::PseudonymCollision(_) => "pseudonym-collision",
            ShanonError::UnsafeMapping(_) => "unsafe-mapping",
            ShanonError::PublicationIdentity(_) => "publication-identity",
            ShanonError::Runtime(_) => "runtime",
            ShanonError::Value(_) => "value",
            ShanonError::Io(_) => "io",
            ShanonError::FileExists(_) => "file-exists",
            ShanonError::CleanupWarning(_) => "cleanup-warning",
            ShanonError::Located(_, _) => unreachable!("unlocated() peels every locator"),
        }
    }

    /// The exact stderr text the CLI prints for this error.
    ///
    /// Frozen interop surface (invariant 2). A locator never reaches it.
    pub fn stderr(&self) -> String {
        match self {
            ShanonError::Located(inner, _) => inner.stderr(),
            ShanonError::VerboseVerification(findings) => format_verbose_findings(findings),
            ShanonError::Verification(finding) => format!(
                "ABORTED - leak check failed, no output written: {}",
                verification_message(finding.as_ref())
            ),
            ShanonError::PseudonymCollision(_)
            | ShanonError::UnsafeMapping(_)
            | ShanonError::PublicationIdentity(_)
            | ShanonError::Runtime(_) => {
                "ABORTED - invalid or conflicting mapping data; no output written".to_string()
            }
            ShanonError::Value(m) | ShanonError::Io(m) | ShanonError::FileExists(m) => {
                format!("ABORTED - no output written: {m}")
            }
            ShanonError::CleanupWarning(details) => {
                format!("post-commit publication cleanup warning: {details}")
            }
        }
    }

    /// The stderr text for a run started with `--verbose-failures`.
    ///
    /// Identical to [`ShanonError::stderr`] except for the mapping-abort
    /// classes, which collapse to one fixed line there and so carried no
    /// diagnostic at all. Everything added is sanitized: a stable class slug,
    /// the engine's own value-free reason, the synthetic member name, the
    /// record path, the classified node type, and a BLAKE2b-6 fingerprint of
    /// the offender (invariant 7).
    pub fn stderr_verbose(&self) -> String {
        let headline = self.stderr();
        if !matches!(
            self.unlocated(),
            ShanonError::PseudonymCollision(_)
                | ShanonError::UnsafeMapping(_)
                | ShanonError::PublicationIdentity(_)
                | ShanonError::Runtime(_)
        ) {
            return headline;
        }

        let mut lines = vec![headline, String::new(), "mapping-abort:".to_string()];
        match self.locator() {
            Some(locator) => {
                let member = locator.member.as_deref().unwrap_or("<unknown-member>");
                lines.push(format!(
                    "- {member} {} {} {}",
                    locator.path,
                    self.class(),
                    locator.offender
                ));
                lines.push(format!("  node-type: {}", locator.node_type));
            }
            None => lines.push(format!("- {}", self.class())),
        }
        lines.push(format!("  reason: {}", self.unlocated()));
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Reuse gate.
// ---------------------------------------------------------------------------

/// Refuse a reuse mapping whose catalog version is not this build's.
///
/// A registry reused across collections carries pseudonyms that were minted
/// under the catalog the mapping file records. When that catalog differs from
/// [`CATALOG_VERSION`](crate::catalog::CATALOG_VERSION), the two collections
/// disagree about which values the catalog preserves, so the reused mapping
/// says one thing and the new collection says another.
///
/// Fail-closed (invariant 1): a mapping that does not state its catalog version
/// is refused as well, because an unknown version is a disagreement that cannot
/// be ruled out. `shanon restore` does not run this gate; reversal reads the
/// mapping's own entries and does not depend on catalog agreement.
pub fn ensure_reuse_map_compatible(registry: &Registry) -> Result<(), ShanonError> {
    match registry.source_catalog_version() {
        Some(v) if v == crate::catalog::CATALOG_VERSION => Ok(()),
        Some(_) => Err(ShanonError::UnsafeMapping(
            "mapping file was written under a different catalog version".into(),
        )),
        None => Err(ShanonError::UnsafeMapping(
            "mapping file does not record a catalog version".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Platform-independent helpers.
// ---------------------------------------------------------------------------

/// Parse and shape-check one collection member (`_parse_collection_member`).
/// Returns `None` (skip) when the bytes are not a JSON object with a `data`
/// array — a non-SharpHound member, excluded from output.
pub fn parse_collection_member(raw: &[u8]) -> Option<Map<String, Value>> {
    let text = std::str::from_utf8(raw).ok()?;
    let parsed: Value = serde_json::from_str(text).ok()?;
    let obj = parsed.as_object()?;
    if !obj.get("data").map(|d| d.is_array()).unwrap_or(false) {
        return None;
    }
    Some(obj.clone())
}

/// Retain the last duplicate while preserving its first-name position
/// (`_latest_zip_members`), generalized over any keyed item.
pub fn latest_by_name<T: Clone>(items: &[T], name_of: impl Fn(&T) -> String) -> Vec<T> {
    let mut positions: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut latest: Vec<T> = Vec::new();
    for info in items {
        let name = name_of(info);
        match positions.get(&name) {
            None => {
                positions.insert(name, latest.len());
                latest.push(info.clone());
            }
            Some(&position) => {
                latest[position] = info.clone();
            }
        }
    }
    latest
}

/// Reject a manifest whose ordered names no longer match the current snapshot
/// (`_validate_manifest_names`).
pub fn validate_manifest_names(
    manifest: &[ManifestMember],
    current_names: &[String],
) -> Result<(), ShanonError> {
    let manifest_names: Vec<&String> = manifest.iter().map(|m| &m.name).collect();
    let current: Vec<&String> = current_names.iter().collect();
    if manifest_names != current {
        return Err(ShanonError::Value(
            "input manifest changed after discovery".to_string(),
        ));
    }
    Ok(())
}

/// SHA-256 of a single input file, streamed in bounded chunks (`sha256_of` for
/// the non-directory branch). The directory branch's anchored hashing lives with
/// the orchestration wired in P4.
pub fn sha256_of_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    Ok(s)
}

impl From<EngineError> for ShanonError {
    fn from(e: EngineError) -> Self {
        use crate::registry::RegistryError as R;
        // Classify the wrapped error, then re-attach the locator so the class
        // and the leaf travel together to the CLI.
        if let EngineError::Located(inner, locator) = e {
            return ShanonError::Located(Box::new(ShanonError::from(*inner)), locator);
        }
        match e {
            EngineError::PseudonymCollision(_) => ShanonError::PseudonymCollision(e.to_string()),
            EngineError::Registry(R::PseudonymCollision(_)) => {
                ShanonError::PseudonymCollision(e.to_string())
            }
            EngineError::Registry(R::UnsafeMapping(_)) => ShanonError::UnsafeMapping(e.to_string()),
            EngineError::Registry(R::Value(_)) | EngineError::Value(_) => {
                ShanonError::Value(e.to_string())
            }
            EngineError::Registry(R::Frozen(_))
            | EngineError::Registry(R::Type(_))
            | EngineError::Runtime(_) => ShanonError::Runtime(e.to_string()),
            EngineError::Located(_, _) => unreachable!("peeled above"),
        }
    }
}

// ---------------------------------------------------------------------------
// Path resolution (`Path.resolve()`-equivalent): canonicalize the longest existing
// ancestor (so a `/tmp` symlink expands) and append the rest.
// ---------------------------------------------------------------------------

/// Resolve `p` to an absolute path with symlinks in existing prefixes expanded,
/// tolerating non-existent trailing components (matching `Path.resolve()`).
pub fn resolve(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|c| c.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let mut existing = abs.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(name) => {
                rest.push(name.to_os_string());
                match existing.parent() {
                    Some(parent) => existing = parent.to_path_buf(),
                    None => break,
                }
            }
            None => break,
        }
    }
    let mut base = std::fs::canonicalize(&existing).unwrap_or(existing);
    for name in rest.iter().rev() {
        base.push(name);
    }
    base
}

fn token_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS entropy");
    let mut s = String::with_capacity(bytes * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in buf {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// UTC clock helpers (mapping `created` + zip DOS timestamp). Both are volatile
// fields the freeze tooling normalizes, so only their format must be plausible.
// ---------------------------------------------------------------------------

/// Civil (year, month, day, hour, min, sec) in UTC, now.
fn now_utc() -> (i64, u32, u32, u32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32, h as u32, mi as u32, s as u32)
}

fn created_now() -> String {
    let (y, mo, d, h, mi, s) = now_utc();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
}

/// Current time as (DOS time, DOS date) words (as used by `writestr`;
/// approximated in UTC — the replay normalizes this field).
fn dos_now() -> (u16, u16) {
    let (y, mo, d, h, mi, s) = now_utc();
    if y < 1980 {
        return (0, 0x21);
    }
    let date = (((y - 1980) as u16) << 9) | ((mo as u16) << 5) | d as u16;
    let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2);
    (time, date)
}

// ---------------------------------------------------------------------------
// Minimal ZIP reader/writer, byte-identical to the standard `zipfile` format on write.
// ---------------------------------------------------------------------------

fn bad_zip() -> ShanonError {
    ShanonError::Io("File is not a zip file".to_string())
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// One central-directory record of an input archive.
struct ZipEntry {
    name: String,
    method: u16,
    csize: u64,
    usize_: u64,
    local_offset: u64,
    is_dir: bool,
}

/// Parse the central directory (`ZipFile.infolist()` order).
fn parse_zip_central(raw: &[u8]) -> Result<Vec<ZipEntry>, ShanonError> {
    if raw.len() < 22 {
        return Err(bad_zip());
    }
    let sig = b"PK\x05\x06";
    let scan_start = raw.len() - 22;
    let scan_min = raw.len().saturating_sub(22 + 0xFFFF);
    let mut eocd = None;
    let mut i = scan_start;
    loop {
        if &raw[i..i + 4] == sig {
            eocd = Some(i);
            break;
        }
        if i <= scan_min {
            break;
        }
        i -= 1;
    }
    let e = eocd.ok_or_else(bad_zip)?;
    let total = le16(raw, e + 10) as usize;
    let cd_off = le32(raw, e + 16) as usize;
    let mut entries = Vec::with_capacity(total);
    let mut off = cd_off;
    for _ in 0..total {
        if off + 46 > raw.len() || &raw[off..off + 4] != b"PK\x01\x02" {
            return Err(bad_zip());
        }
        let method = le16(raw, off + 10);
        let csize = le32(raw, off + 20) as u64;
        let usize_ = le32(raw, off + 24) as u64;
        let nlen = le16(raw, off + 28) as usize;
        let elen = le16(raw, off + 30) as usize;
        let clen = le16(raw, off + 32) as usize;
        let lho = le32(raw, off + 42) as u64;
        if off + 46 + nlen > raw.len() {
            return Err(bad_zip());
        }
        let name = String::from_utf8_lossy(&raw[off + 46..off + 46 + nlen]).into_owned();
        let is_dir = name.ends_with('/');
        entries.push(ZipEntry {
            name,
            method,
            csize,
            usize_,
            local_offset: lho,
            is_dir,
        });
        off += 46 + nlen + elen + clen;
    }
    Ok(entries)
}

/// Decompress one archive member from its local header (`archive.open(info)`).
fn read_zip_entry(raw: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, ShanonError> {
    let lo = entry.local_offset as usize;
    if lo + 30 > raw.len() || &raw[lo..lo + 4] != b"PK\x03\x04" {
        return Err(bad_zip());
    }
    let nlen = le16(raw, lo + 26) as usize;
    let elen = le16(raw, lo + 28) as usize;
    let dstart = lo + 30 + nlen + elen;
    let dend = dstart + entry.csize as usize;
    if dend > raw.len() {
        return Err(bad_zip());
    }
    let comp = &raw[dstart..dend];
    // The declared uncompressed size is already bounded by `safe_zip_members`
    // (<= MAX_MEMBER_UNCOMPRESSED). Cap the *actual* output at that declaration so
    // a deflate stream cannot expand past it — the directory-input path enforces
    // the same ceiling during the read (see `platform::read_bounded`).
    let limit = entry.usize_;
    match entry.method {
        0 => {
            if comp.len() as u64 > limit {
                return Err(oversized_member());
            }
            Ok(comp.to_vec())
        }
        8 => decompress_bounded(comp, limit),
        _ => Err(bad_zip()),
    }
}

/// Inflate a deflate stream, aborting as soon as the output exceeds `limit`
/// bytes. Guards against a decompression bomb whose expanded size dwarfs its
/// declared central-directory size.
fn decompress_bounded(comp: &[u8], limit: u64) -> Result<Vec<u8>, ShanonError> {
    use std::io::Read as _;
    let mut out = Vec::new();
    // Read one byte past the ceiling: if the decoder yields it, the stream lied.
    let mut taken = flate2::read::DeflateDecoder::new(comp).take(limit.saturating_add(1));
    taken.read_to_end(&mut out).map_err(|_| bad_zip())?;
    if out.len() as u64 > limit {
        return Err(oversized_member());
    }
    Ok(out)
}

fn oversized_member() -> ShanonError {
    ShanonError::Value("archive contains an oversized JSON member".to_string())
}

/// `_safe_members`: regular `.json` members, path- and size-bounded.
fn safe_zip_members(entries: Vec<ZipEntry>) -> Result<Vec<ZipEntry>, ShanonError> {
    let members: Vec<ZipEntry> = entries
        .into_iter()
        .filter(|e| !e.is_dir && e.name.to_lowercase().ends_with(".json"))
        .collect();
    if members.len() > MAX_JSON_MEMBERS {
        return Err(ShanonError::Value(format!(
            "archive has {} JSON members; max {MAX_JSON_MEMBERS}",
            members.len()
        )));
    }
    let mut total: u64 = 0;
    for info in &members {
        let name = &info.name;
        let unsafe_path = name.starts_with('/')
            || name.starts_with('\\')
            || name.split(['/', '\\']).any(|p| p == "..")
            || (name.len() >= 2 && name.as_bytes()[1] == b':');
        if unsafe_path {
            return Err(ShanonError::Value("unsafe archive member path".to_string()));
        }
        if info.usize_ > MAX_MEMBER_UNCOMPRESSED {
            return Err(ShanonError::Value(
                "archive contains an oversized JSON member".to_string(),
            ));
        }
        total += info.usize_;
    }
    if total > MAX_TOTAL_UNCOMPRESSED {
        return Err(ShanonError::Value(
            "archive uncompressed size exceeds maximum".to_string(),
        ));
    }
    Ok(members)
}

/// Build a ZIP byte-for-byte identical to `zipfile.ZipFile(..., ZIP_DEFLATED)`
/// over `writestr(name, data)` (modulo the wall-clock DOS timestamp, which the
/// parity replay normalizes).
fn build_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let (dtime, ddate) = dos_now();
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, data) in entries {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc = crc.sum();
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(data).expect("in-memory deflate");
        let comp = enc.finish().expect("in-memory deflate");
        let local_offset = out.len() as u32;
        let nb = name.as_bytes();
        // Local file header.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&8u16.to_le_bytes()); // method = deflate
        out.extend_from_slice(&dtime.to_le_bytes());
        out.extend_from_slice(&ddate.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(nb);
        out.extend_from_slice(&comp);
        // Central directory record.
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&0x0314u16.to_le_bytes()); // version made by (unix, 2.0)
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&8u16.to_le_bytes()); // method
        central.extend_from_slice(&dtime.to_le_bytes());
        central.extend_from_slice(&ddate.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0x0180_0000u32.to_le_bytes()); // external attrs 0o600<<16
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(nb);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    let count = entries.len() as u16;
    out.extend_from_slice(&central);
    // End of central directory.
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

// ---------------------------------------------------------------------------
// Directory input enumeration (`_safe_directory_members`).
// ---------------------------------------------------------------------------

fn collect_json_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ShanonError> {
    let entries = std::fs::read_dir(dir).map_err(|_| {
        ShanonError::Value("unable to safely enumerate directory input".to_string())
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            ShanonError::Value("unable to safely enumerate directory input".to_string())
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|_| {
            ShanonError::Value("unable to safely inspect directory member".to_string())
        })?;
        if file_type.is_dir() {
            collect_json_recursive(&path, out)?;
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".json"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(())
}

fn safe_directory_members(input_path: &Path) -> Result<Vec<PathBuf>, ShanonError> {
    let mut paths: Vec<PathBuf> = Vec::new();
    collect_json_recursive(input_path, &mut paths)?;
    paths.sort();
    if paths.len() > MAX_JSON_MEMBERS {
        return Err(ShanonError::Value(
            "directory contains too many JSON members".to_string(),
        ));
    }
    let mut total: u64 = 0;
    for path in &paths {
        let meta = std::fs::symlink_metadata(path).map_err(|_| {
            ShanonError::Value("unable to safely inspect directory member".to_string())
        })?;
        if !meta.file_type().is_file() {
            return Err(ShanonError::Value(
                "directory contains a non-regular JSON member".to_string(),
            ));
        }
        if meta.len() > MAX_MEMBER_UNCOMPRESSED {
            return Err(ShanonError::Value(
                "directory contains an oversized JSON member".to_string(),
            ));
        }
        total += meta.len();
        if total > MAX_TOTAL_UNCOMPRESSED {
            return Err(ShanonError::Value(
                "directory JSON size exceeds maximum".to_string(),
            ));
        }
    }
    Ok(paths)
}

fn dir_input_hash(
    input_path: &Path,
    paths: &[PathBuf],
    root_fd: std::os::fd::BorrowedFd<'_>,
) -> Result<String, ShanonError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    for path in paths {
        let raw = platform::read_directory_member_anchored(input_path, path, root_fd)
            .map_err(|e| ShanonError::Value(e.0))?;
        total += raw.len() as u64;
        if total > MAX_TOTAL_UNCOMPRESSED {
            return Err(ShanonError::Value(
                "directory JSON size exceeds maximum".to_string(),
            ));
        }
        hasher.update(&raw);
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Orchestration (`anonymize_collection` / `_anonymize_collection_impl`).
// ---------------------------------------------------------------------------

/// The result of a successful anonymization: where the collection landed and the
/// policy audit the CLI summarizes.
pub struct AnonymizeOutcome {
    pub dest: PathBuf,
    pub audit: PolicyAudit,
}

struct Accepted {
    name: String,
    doc: Map<String, Value>,
}

/// Read every member of a collection into `(synthetic label, raw bytes)` pairs.
///
/// Shared by [`anonymize_collection`] and [`inspect_collection`] so a dry run
/// sees exactly the members a real run would: the same size bounds, the same
/// openat-anchored traversal, the same latest-duplicate-wins rule, and the same
/// `member-00001.json` labels — real filenames never leave this function
/// (invariant 7). Also returns the raw archive bytes for a zip input, which the
/// mapping's input hash needs.
#[allow(clippy::type_complexity)]
fn read_collection_input(
    input_path: &Path,
    is_dir: bool,
    root_fd: Option<&std::os::fd::OwnedFd>,
) -> Result<(Vec<(String, Vec<u8>)>, Option<Vec<u8>>), ShanonError> {
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();

    if is_dir {
        let root = root_fd.expect("dir root fd");
        let paths = safe_directory_members(input_path)?;
        if paths.is_empty() {
            return Err(ShanonError::Value(
                "input contains no SharpHound JSON members".to_string(),
            ));
        }
        for (index, path) in paths.iter().enumerate() {
            let raw = platform::read_directory_member_anchored(
                input_path,
                path,
                std::os::fd::AsFd::as_fd(root),
            )
            .map_err(|e| ShanonError::Value(e.0))?;
            members.push((format!("member-{:05}.json", index + 1), raw));
        }
        return Ok((members, None));
    }

    // Reject an archive whose on-disk size already exceeds the total
    // uncompressed ceiling before reading it into memory (compressed input can
    // never legitimately be larger than its uncompressed contents).
    if let Ok(meta) = std::fs::metadata(input_path) {
        if meta.len() > MAX_TOTAL_UNCOMPRESSED {
            return Err(ShanonError::Value(
                "archive size exceeds maximum".to_string(),
            ));
        }
    }
    let raw =
        std::fs::read(input_path).map_err(|_| ShanonError::Io("File is not a zip file".into()))?;
    let entries = parse_zip_central(&raw)?;
    let entries = safe_zip_members(entries)?;
    if entries.is_empty() {
        return Err(ShanonError::Value(
            "input contains no SharpHound JSON members".to_string(),
        ));
    }
    // Retain the last duplicate at its first-seen position.
    let mut positions: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut latest: Vec<&ZipEntry> = Vec::new();
    for info in &entries {
        match positions.get(&info.name) {
            None => {
                positions.insert(info.name.clone(), latest.len());
                latest.push(info);
            }
            Some(&p) => latest[p] = info,
        }
    }
    for (index, info) in latest.iter().enumerate() {
        let raw_member = read_zip_entry(&raw, info)?;
        members.push((format!("member-{:05}.json", index + 1), raw_member));
    }
    Ok((members, Some(raw)))
}

/// What a dry run found in one collection, in sanitized form.
///
/// Every field is either a count, a synthetic member label, a canonical policy
/// path, or a value-free classification — the same discipline the leak-gate
/// findings follow, so a report can be pasted into a bug report against a
/// collection that must not leave the operator's machine (invariant 7).
#[derive(Clone, Debug)]
pub struct InspectReport {
    /// Members read from the input, before parsing.
    pub members_read: usize,
    /// Members that parsed as SharpHound documents *and* survived discovery.
    pub members_accepted: usize,
    /// Synthetic labels of members that did not, and would be excluded.
    pub members_skipped: Vec<String>,
    /// Total top-level `data` objects across accepted members.
    pub objects: u64,
    /// One row per `(meta.type, resolved node type, meta.version)`, with the
    /// object count. A node type of `Unknown` is an unrecognized collection.
    pub collection_types: Vec<CollectionTypeRow>,
    /// [`PolicyAudit::summary`] over the transform pass.
    pub audit: Value,
    /// Leak-gate findings, sanitized. Non-empty means the run would abort.
    pub findings: Vec<VerificationFinding>,
    /// A mapping-class abort, rendered as `stderr_verbose` would render it.
    pub abort: Option<String>,
}

/// One `(meta.type, node type, meta.version)` row of an [`InspectReport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionTypeRow {
    pub meta_type: String,
    pub node_type: String,
    pub version: String,
    pub objects: u64,
}

impl InspectReport {
    /// Whether a real run over this input would publish.
    pub fn would_publish(&self) -> bool {
        self.findings.is_empty() && self.abort.is_none()
    }
}

/// Dry-run a collection and report what a real run would do, writing nothing.
///
/// This is the diagnostic path for a collection that will not anonymize: it
/// runs the same discovery, transform and independent verification as
/// [`anonymize_collection`] and then stops, so the answer is the real answer
/// rather than an approximation — but no output collection, no mapping file and
/// no staging directory is ever created.
pub fn inspect_collection(
    input_path: &Path,
    reg: Registry,
    policy: PolicyConfig,
    audit: PolicyAudit,
    progress: Option<ProgressSink>,
) -> Result<InspectReport, ShanonError> {
    let progress = progress.as_ref();
    let is_dir = input_path.is_dir();
    let root_fd = if is_dir {
        Some(platform::open_directory_root(input_path).map_err(|e| ShanonError::Value(e.0))?)
    } else {
        None
    };

    let (raw_members, _) = read_collection_input(input_path, is_dir, root_fd.as_ref())?;

    let mut engine = AnonymizationEngine::new(reg, Some(policy), Some(audit));
    if let Some(sink) = progress {
        engine.set_progress_sink(sink.clone());
    }

    progress::emit(
        progress,
        ProgressEvent::PhaseStarted {
            phase: Phase::Discovery,
            total: None,
        },
    );
    let mut accepted: Vec<Accepted> = Vec::new();
    let mut members_skipped: Vec<String> = Vec::new();
    let mut objects: u64 = 0;
    // Keyed on the row identity so counts aggregate across members.
    let mut types: indexmap::IndexMap<(String, String, String), u64> = indexmap::IndexMap::new();

    for (label, raw) in &raw_members {
        let doc = match parse_collection_member(raw) {
            Some(doc) => doc,
            None => {
                members_skipped.push(label.clone());
                continue;
            }
        };
        let meta = doc.get("meta").and_then(|v| v.as_object());
        let meta_type = meta
            .and_then(|m| m.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>")
            .to_string();
        let version = meta
            .and_then(|m| m.get("version"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<missing>".to_string());
        let node_type = crate::engine::normalize_node_type(meta.and_then(|m| m.get("type")));
        let count = data_len(&doc);
        objects += count;
        *types.entry((meta_type, node_type, version)).or_insert(0) += count;

        // A discovery failure is itself the finding; report it rather than
        // aborting the inspection.
        if let Err(e) = engine.discover_document(label, &doc) {
            let e = ShanonError::from(e);
            return Ok(InspectReport {
                members_read: raw_members.len(),
                members_accepted: accepted.len(),
                members_skipped,
                objects,
                collection_types: rows(types),
                audit: engine.audit.summary(),
                findings: Vec::new(),
                abort: Some(e.stderr_verbose()),
            });
        }
        accepted.push(Accepted {
            name: label.clone(),
            doc,
        });
    }
    progress::emit(progress, ProgressEvent::PhaseFinished);

    if accepted.is_empty() {
        return Err(ShanonError::Value(
            "input contains no SharpHound collection documents".to_string(),
        ));
    }

    let members_accepted = accepted.len();
    let context = match engine.finalize_discovery() {
        Ok(c) => c,
        Err(e) => {
            let e = ShanonError::from(e);
            return Ok(InspectReport {
                members_read: raw_members.len(),
                members_accepted,
                members_skipped,
                objects,
                collection_types: rows(types),
                audit: engine.audit.summary(),
                findings: Vec::new(),
                abort: Some(e.stderr_verbose()),
            });
        }
    };

    progress::emit(
        progress,
        ProgressEvent::PhaseStarted {
            phase: Phase::TransformVerify,
            total: Some(objects * 2),
        },
    );
    let mut findings: Vec<VerificationFinding> = Vec::new();
    let mut abort: Option<String> = None;
    for member in &accepted {
        match engine.transform_document(&member.name, &member.doc) {
            Ok((output, records)) => findings.extend(verify_document_with_progress(
                &member.name,
                &member.doc,
                &output,
                &records,
                &mut engine.registry,
                &context,
                progress,
            )),
            Err(e) => {
                // The first mapping abort is terminal for a real run, so report
                // it and stop rather than compounding a poisoned registry.
                abort = Some(ShanonError::from(e).stderr_verbose());
                break;
            }
        }
    }
    progress::emit(progress, ProgressEvent::PhaseFinished);

    Ok(InspectReport {
        members_read: raw_members.len(),
        members_accepted,
        members_skipped,
        objects,
        collection_types: rows(types),
        audit: engine.audit.summary(),
        findings,
        abort,
    })
}

fn rows(types: indexmap::IndexMap<(String, String, String), u64>) -> Vec<CollectionTypeRow> {
    let mut rows: Vec<CollectionTypeRow> = types
        .into_iter()
        .map(
            |((meta_type, node_type, version), objects)| CollectionTypeRow {
                meta_type,
                node_type,
                version,
                objects,
            },
        )
        .collect();
    rows.sort_by(|a, b| (&a.meta_type, &a.version).cmp(&(&b.meta_type, &b.version)));
    rows
}

/// Anonymize a directory or ZIP through the bounded two-pass pipeline, then
/// atomically publish the collection and (optionally) the mapping file.
#[allow(clippy::too_many_arguments)]
pub fn anonymize_collection(
    input_path: &Path,
    out_dir: &Path,
    reg: Registry,
    verbose_failures: bool,
    policy: PolicyConfig,
    audit: PolicyAudit,
    map_path: Option<&Path>,
    map_policy: Option<Value>,
    progress: Option<ProgressSink>,
) -> Result<AnonymizeOutcome, ShanonError> {
    let progress = progress.as_ref();
    let is_dir = input_path.is_dir();
    let root_fd = if is_dir {
        Some(platform::open_directory_root(input_path).map_err(|e| ShanonError::Value(e.0))?)
    } else {
        None
    };

    let resolved_input = resolve(input_path);
    let resolved_out = resolve(out_dir);
    if is_dir && (resolved_out == resolved_input || resolved_out.starts_with(&resolved_input)) {
        return Err(ShanonError::Value(
            "output directory must not be inside the input directory".to_string(),
        ));
    }

    let dest = out_dir.join(if is_dir {
        "collection_anon"
    } else {
        "collection_anon.zip"
    });
    if dest.exists() {
        return Err(ShanonError::FileExists(format!(
            "output destination already exists: {}",
            dest.display()
        )));
    }

    if let Some(map_path) = map_path {
        if map_path.file_name().is_none() {
            return Err(ShanonError::Value(
                "mapping path must name a file".to_string(),
            ));
        }
        let resolved_map = resolve(map_path);
        let resolved_dest = resolve(&dest);
        if resolved_map == resolved_input || (is_dir && resolved_map.starts_with(&resolved_input)) {
            return Err(ShanonError::Value(
                "mapping path must not modify the input collection".to_string(),
            ));
        }
        if resolved_map == resolved_dest || (is_dir && resolved_map.starts_with(&resolved_dest)) {
            return Err(ShanonError::Value(
                "mapping path must not be inside the output collection".to_string(),
            ));
        }
        if map_path.exists() {
            return Err(ShanonError::FileExists(format!(
                "mapping destination already exists: {}",
                map_path.display()
            )));
        }
    }

    let mut engine = AnonymizationEngine::new(reg, Some(policy), Some(audit));
    if let Some(sink) = progress {
        engine.set_progress_sink(sink.clone());
    }
    let mut accepted: Vec<Accepted> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    // Work units for the transform+verify phase: each accepted object is walked
    // once by the engine and once, independently, by the verifier.
    let mut total_objects: u64 = 0;

    let (raw_members, zip_raw) = read_collection_input(input_path, is_dir, root_fd.as_ref())?;

    let input_hash: Option<String> = if map_path.is_some() {
        Some(if let Some(raw) = &zip_raw {
            sha256_hex(raw)
        } else {
            let root = root_fd.as_ref().expect("dir root fd");
            let paths = safe_directory_members(input_path)?;
            dir_input_hash(input_path, &paths, std::os::fd::AsFd::as_fd(root))?
        })
    } else {
        None
    };

    // ---- Discovery pass -----------------------------------------------------
    // The size of this phase is only known once every member has been parsed,
    // so it reports as indeterminate.
    progress::emit(
        progress,
        ProgressEvent::PhaseStarted {
            phase: Phase::Discovery,
            total: None,
        },
    );
    for (label, raw) in &raw_members {
        match parse_collection_member(raw) {
            Some(doc) => {
                engine.discover_document(label, &doc)?;
                total_objects += data_len(&doc);
                accepted.push(Accepted {
                    name: label.clone(),
                    doc,
                });
            }
            None => skipped.push(label.clone()),
        }
    }
    // Close the bar before any diagnostic below writes to stderr.
    progress::emit(progress, ProgressEvent::PhaseFinished);

    if accepted.is_empty() {
        return Err(ShanonError::Value(
            "input contains no SharpHound collection documents".to_string(),
        ));
    }
    if !skipped.is_empty() {
        let mut sorted = skipped.clone();
        sorted.sort();
        eprintln!(
            "skipped non-SharpHound member(s), excluded from output: {}",
            sorted.join(", ")
        );
    }

    // ---- Transform + verify pass -------------------------------------------
    let context: VerificationContext = engine.finalize_discovery()?;
    // Two units per object: one for the transform walk, one for the independent
    // re-derivation in `verify_document`.
    progress::emit(
        progress,
        ProgressEvent::PhaseStarted {
            phase: Phase::TransformVerify,
            total: Some(total_objects * 2),
        },
    );
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::with_capacity(accepted.len());
    let mut all_findings: Vec<VerificationFinding> = Vec::new();
    for member in &accepted {
        let (output, records) = engine.transform_document(&member.name, &member.doc)?;
        let findings = verify_document_with_progress(
            &member.name,
            &member.doc,
            &output,
            &records,
            &mut engine.registry,
            &context,
            progress,
        );
        if !findings.is_empty() {
            if verbose_failures {
                all_findings.extend(findings);
                continue;
            }
            return Err(ShanonError::Verification(Some(
                findings.into_iter().next().unwrap(),
            )));
        }
        let blob = crate::canonical_json(&Value::Object(output));
        blobs.push((member.name.clone(), blob.into_bytes()));
    }
    if !all_findings.is_empty() {
        return Err(ShanonError::VerboseVerification(all_findings));
    }
    progress::emit(progress, ProgressEvent::PhaseFinished);

    // ---- Publication --------------------------------------------------------
    // A single indivisible step (build, stage, atomic rename), so it reports as
    // indeterminate and only marks its start and end.
    progress::emit(
        progress,
        ProgressEvent::PhaseStarted {
            phase: Phase::Publish,
            total: None,
        },
    );
    let out_dir_existed = out_dir.exists();
    std::fs::create_dir_all(out_dir)
        .map_err(|e| ShanonError::Io(format!("cannot create output directory: {e}")))?;

    let stage = out_dir.join(format!(
        ".{}.{}.tmp",
        dest.file_name().unwrap().to_string_lossy(),
        token_hex(8)
    ));

    let result = if is_dir {
        stage_directory(&stage, &blobs).and_then(|_| {
            publish_with_optional_mapping(
                &stage,
                &dest,
                &engine.registry,
                map_path,
                input_hash.as_deref(),
                map_policy.clone(),
            )
        })
    } else {
        let zip_bytes = build_zip(&blobs);
        write_private_file(&stage, &zip_bytes).and_then(|_| {
            publish_with_optional_mapping(
                &stage,
                &dest,
                &engine.registry,
                map_path,
                input_hash.as_deref(),
                map_policy.clone(),
            )
        })
    };

    if let Err(err) = result {
        cleanup_stage(&stage, is_dir);
        if !out_dir_existed {
            let _ = std::fs::remove_dir(out_dir);
        }
        return Err(err);
    }
    progress::emit(progress, ProgressEvent::PhaseFinished);

    Ok(AnonymizeOutcome {
        dest,
        audit: engine.audit,
    })
}

/// Number of top-level `data` objects in a parsed collection member.
fn data_len(doc: &Map<String, Value>) -> u64 {
    doc.get("data")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<(), ShanonError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| ShanonError::Io(format!("cannot create private file: {e}")))?;
    file.write_all(data)
        .map_err(|e| ShanonError::Io(format!("cannot write private file: {e}")))?;
    Ok(())
}

fn stage_directory(stage: &Path, blobs: &[(String, Vec<u8>)]) -> Result<(), ShanonError> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(stage)
        .map_err(|e| ShanonError::Io(format!("cannot create staging directory: {e}")))?;
    for (name, blob) in blobs {
        write_private_file(&stage.join(name), blob)?;
    }
    Ok(())
}

fn cleanup_stage(stage: &Path, is_dir: bool) {
    if is_dir {
        let _ = std::fs::remove_dir_all(stage);
    } else {
        let _ = std::fs::remove_file(stage);
    }
}

/// Atomic paired publication of the collection and (optionally) the mapping
/// file (`_publish_collection_with_optional_mapping`). Both land or neither
/// does: a failure after the mapping is written rolls the mapping back.
fn publish_with_optional_mapping(
    stage: &Path,
    dest: &Path,
    reg: &Registry,
    map_path: Option<&Path>,
    input_hash: Option<&str>,
    map_policy: Option<Value>,
) -> Result<(), ShanonError> {
    let mut published_map: Option<PathBuf> = None;
    if let Some(map_path) = map_path {
        let input_hash = input_hash.expect("input hash present when mapping requested");
        let payload = reg.save_to_string(input_hash, &created_now(), map_policy);
        let map_tmp = map_path.with_file_name(format!(
            ".{}.{}.tmp",
            map_path.file_name().unwrap().to_string_lossy(),
            token_hex(8)
        ));
        write_private_file(&map_tmp, payload.as_bytes())?;
        if let Err(err) = platform::rename_no_replace(&map_tmp, map_path) {
            let _ = std::fs::remove_file(&map_tmp);
            return Err(rename_error(err, map_path));
        }
        published_map = Some(map_path.to_path_buf());
    }

    if let Err(err) = platform::rename_no_replace(stage, dest) {
        if let Some(map) = &published_map {
            let _ = std::fs::remove_file(map);
        }
        return Err(rename_error(err, dest));
    }
    Ok(())
}

fn rename_error(err: platform::RenameError, dest: &Path) -> ShanonError {
    match err {
        platform::RenameError::Exists => {
            ShanonError::FileExists(format!("destination already exists: {}", dest.display()))
        }
        platform::RenameError::Unsupported => {
            ShanonError::Io("atomic no-replace rename is unavailable".to_string())
        }
        platform::RenameError::Other(n) => ShanonError::Io(format!("rename failed (errno {n})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        gate: &str,
        member: &str,
        path: &str,
        code: &str,
        offender: &str,
    ) -> VerificationFinding {
        VerificationFinding {
            gate: gate.to_string(),
            member: member.to_string(),
            path: path.to_string(),
            policy_code: code.to_string(),
            offender: offender.to_string(),
        }
    }

    #[test]
    fn verbose_stderr_matches_cli_format() {
        let findings = vec![
            finding(
                "contextual-verification",
                "m.json",
                "data[0].x",
                "record-missing",
                "abcd",
            ),
            finding(
                "contextual-verification",
                "m.json",
                "",
                "record-extra",
                "ef01",
            ),
        ];
        let err = ShanonError::VerboseVerification(findings);
        let expected = "ABORTED - leak check failed, no output written\n\n\
contextual-verification:\n\
- m.json data[0].x: record-missing abcd\n\
- m.json : record-extra ef01";
        assert_eq!(err.stderr(), expected);
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn single_verification_stderr() {
        let f = finding(
            "contextual-verification",
            "m.json",
            "data[0].x",
            "identity-not-transformed",
            "abcd",
        );
        let err = ShanonError::Verification(Some(f));
        assert_eq!(
            err.stderr(),
            "ABORTED - leak check failed, no output written: \
contextual verification failed: m.json data[0].x identity-not-transformed abcd"
        );
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn mapping_and_generic_buckets() {
        assert_eq!(
            ShanonError::PseudonymCollision("x".into()).stderr(),
            "ABORTED - invalid or conflicting mapping data; no output written"
        );
        assert_eq!(
            ShanonError::PublicationIdentity("x".into()).stderr(),
            "ABORTED - invalid or conflicting mapping data; no output written"
        );
        assert_eq!(
            ShanonError::Value("bad thing".into()).stderr(),
            "ABORTED - no output written: bad thing"
        );
        assert_eq!(
            ShanonError::FileExists("output destination already exists: /o".into()).stderr(),
            "ABORTED - no output written: output destination already exists: /o"
        );
    }

    #[test]
    fn cleanup_warning_is_non_fatal() {
        let w = ShanonError::CleanupWarning("mapping close (OSError)".into());
        assert_eq!(w.exit_code(), 0);
        assert_eq!(
            w.stderr(),
            "post-commit publication cleanup warning: mapping close (OSError)"
        );
    }

    #[test]
    fn parse_member_skips_non_sharphound() {
        assert!(parse_collection_member(b"{\"data\": []}").is_some());
        assert!(parse_collection_member(b"{\"data\": 7}").is_none());
        assert!(parse_collection_member(b"[]").is_none());
        assert!(parse_collection_member(b"not json").is_none());
    }

    #[test]
    fn latest_retains_last_duplicate_at_first_position() {
        let items = vec![("a", 1), ("b", 2), ("a", 3), ("c", 4)];
        let latest = latest_by_name(&items, |(n, _)| n.to_string());
        assert_eq!(latest, vec![("a", 3), ("b", 2), ("c", 4)]);
    }

    #[test]
    fn manifest_name_drift_is_rejected() {
        let manifest = vec![ManifestMember {
            name: "a.json".into(),
            discovery_digest: [0u8; 32],
            size: 1,
        }];
        assert!(validate_manifest_names(&manifest, &["a.json".to_string()]).is_ok());
        assert!(validate_manifest_names(&manifest, &["b.json".to_string()]).is_err());
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn decompress_bounded_accepts_within_limit() {
        let data = b"the quick brown fox".repeat(64);
        let comp = deflate(&data);
        let out = decompress_bounded(&comp, data.len() as u64).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decompress_bounded_rejects_deflate_bomb() {
        // Highly compressible payload whose expansion dwarfs a tiny declared size.
        let data = vec![0u8; 4 * 1024 * 1024];
        let comp = deflate(&data);
        // Attacker declared 64 bytes; the stream expands to 4 MiB → must abort
        // without materializing the full output.
        let err = decompress_bounded(&comp, 64).unwrap_err();
        assert!(matches!(err, ShanonError::Value(_)));
    }
}
