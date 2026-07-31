//! The ZIP path: archive input and archive output.
//!
//! `shanon anonymize --input engagement.zip` is the headline invocation in the
//! README, and the archive it writes is a frozen interop surface under
//! invariant 2 — but every other pipeline test drives a *directory*, so the
//! whole zip half had no coverage at all. Reading the central directory,
//! rejecting a hostile member path, honouring the size ceilings, and building a
//! loadable archive were all unasserted.
//!
//! Input archives here are built by hand with STORED members, which
//! `read_zip_entry` accepts alongside DEFLATE. That keeps the fixtures readable
//! and, more usefully, lets a test declare a member size that disagrees with
//! the bytes actually present — which is exactly what a malicious archive does
//! and what the ceilings exist to catch.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use shanon_core::pipeline::{anonymize_collection, ShanonError};
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::Registry;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

// ---------------------------------------------------------------------------
// Scratch
// ---------------------------------------------------------------------------

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("shanon-zip-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write_zip(&self, name: &str, members: &[(&str, Vec<u8>)]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, stored_zip(members)).expect("write archive");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// A minimal STORED zip writer, and a reader for the archive shanon publishes.
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Build a STORED archive. `declared_size` defaults to the real length; a
/// caller that wants to lie about it uses [`stored_zip_declaring`].
fn stored_zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let declared: Vec<(&str, Vec<u8>, u32)> = members
        .iter()
        .map(|(n, d)| (*n, d.clone(), d.len() as u32))
        .collect();
    stored_zip_declaring(&declared)
}

/// Build a STORED archive where each member's central-directory uncompressed
/// size is stated explicitly, so it can disagree with the bytes present.
fn stored_zip_declaring(members: &[(&str, Vec<u8>, u32)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for (name, data, declared_usize) in members {
        let local_offset = out.len() as u32;
        let crc = crc32(data);
        let csize = data.len() as u32;
        let nlen = name.len() as u16;

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: STORED
        out.extend_from_slice(&0u16.to_le_bytes()); // dos time
        out.extend_from_slice(&0x21u16.to_le_bytes()); // dos date (1980-01-01)
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&csize.to_le_bytes());
        out.extend_from_slice(&declared_usize.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: STORED
        central.extend_from_slice(&0u16.to_le_bytes()); // dos time
        central.extend_from_slice(&0x21u16.to_le_bytes()); // dos date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&csize.to_le_bytes());
        central.extend_from_slice(&declared_usize.to_le_bytes());
        central.extend_from_slice(&nlen.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    let count = members.len() as u16;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// Read every member of a published archive, which shanon writes DEFLATED.
fn read_zip(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let le16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]) as usize;
    let le32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]) as usize;

    let eocd = (0..=raw.len() - 22)
        .rev()
        .find(|&i| &raw[i..i + 4] == b"PK\x05\x06")
        .expect("end of central directory");
    let count = le16(eocd + 10);
    let mut off = le32(eocd + 16);

    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        assert_eq!(
            &raw[off..off + 4],
            b"PK\x01\x02",
            "central directory record"
        );
        let method = le16(off + 10);
        let csize = le32(off + 20);
        let nlen = le16(off + 28);
        let elen = le16(off + 30);
        let clen = le16(off + 32);
        let lho = le32(off + 42);
        let name = String::from_utf8(raw[off + 46..off + 46 + nlen].to_vec()).expect("utf-8 name");

        assert_eq!(&raw[lho..lho + 4], b"PK\x03\x04", "local header");
        let start = lho + 30 + le16(lho + 26) + le16(lho + 28);
        let comp = &raw[start..start + csize];
        let data = match method {
            0 => comp.to_vec(),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(comp)
                    .read_to_end(&mut out)
                    .expect("inflate published member");
                out
            }
            other => panic!("unexpected compression method {other}"),
        };
        members.push((name, data));
        off += 46 + nlen + elen + clen;
    }
    members
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn users() -> Vec<u8> {
    let doc = json!({
        "data": [{
            "Properties": {
                "domain": DOMAIN,
                "name": format!("JDOE@{DOMAIN}"),
                "distinguishedname": "CN=jdoe,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                "domainsid": DOMAIN_SID,
                "samaccountname": "jdoe"
            },
            "ObjectIdentifier": format!("{DOMAIN_SID}-1104"),
            "Aces": [],
            "IsDeleted": false,
            "IsACLProtected": false,
            "ContainedBy": null
        }],
        "meta": {"methods": 0, "type": "users", "count": 1, "version": 6}
    });
    serde_json::to_vec(&doc).unwrap()
}

fn run(input: &Path, out: &Path, map: Option<&Path>) -> Result<(), ShanonError> {
    anonymize_collection(
        input,
        out,
        Registry::new("test-salt"),
        true,
        PolicyConfig::default(),
        PolicyAudit::new(),
        map,
        None,
        None,
    )
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

/// An archive in, a loadable archive out, with the real identifiers gone.
#[test]
fn an_archive_round_trips_and_carries_no_source_identifier() {
    let scratch = Scratch::new("roundtrip");
    let input = scratch.write_zip("collection.zip", &[("users.json", users())]);
    let out = scratch.path("out");

    run(&input, &out, None).expect("archive input should anonymize");

    let dest = out.join("collection_anon.zip");
    assert!(dest.is_file(), "a zip input must publish a zip");

    let members = read_zip(&fs::read(&dest).unwrap());
    assert_eq!(members.len(), 1, "member count preserved");
    // The member is renamed to a synthetic label. A collector names its files
    // after the collection, so the source filename is organization-bound like
    // anything else in the archive (invariant 7).
    assert_eq!(members[0].0, "member-00001.json", "member label");

    // It is still a SharpHound document.
    let doc: Value = serde_json::from_slice(&members[0].1).expect("published member is JSON");
    assert_eq!(doc["meta"]["type"], "users");
    assert_eq!(doc["data"].as_array().unwrap().len(), 1);

    // And none of the source identifiers survived it.
    let published = String::from_utf8(members[0].1.clone()).unwrap();
    for secret in ["SOUTHRIDGE", "JDOE", "jdoe", DOMAIN_SID] {
        assert!(
            !published.contains(secret),
            "published archive still contains {secret}"
        );
    }
}

/// Non-JSON members and directory entries are not collection members.
#[test]
fn non_json_and_directory_entries_are_ignored() {
    let scratch = Scratch::new("filter");
    let input = scratch.write_zip(
        "collection.zip",
        &[
            ("logs/", Vec::new()),
            ("SharpHound.log", b"not a collection".to_vec()),
            ("users.json", users()),
        ],
    );
    let out = scratch.path("out");

    run(&input, &out, None).expect("extra members should not stop a run");

    let members = read_zip(&fs::read(out.join("collection_anon.zip")).unwrap());
    let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["member-00001.json"],
        "only the JSON member is published"
    );
    // The log's own name must not survive either, in a member name or anywhere
    // else in the archive.
    let raw = fs::read(out.join("collection_anon.zip")).unwrap();
    assert!(
        !String::from_utf8_lossy(&raw).contains("SharpHound.log"),
        "a skipped member's filename reached the published archive"
    );
}

/// `.JSON` is a JSON member. The directory reader used to disagree with this
/// one, silently dropping such a file without even counting it as skipped.
#[test]
fn a_json_extension_is_matched_case_insensitively() {
    let scratch = Scratch::new("case");
    let input = scratch.write_zip("collection.zip", &[("Users.JSON", users())]);
    let out = scratch.path("out");

    run(&input, &out, None).expect("an uppercase extension is still JSON");

    let members = read_zip(&fs::read(out.join("collection_anon.zip")).unwrap());
    assert_eq!(members.len(), 1, "uppercase .JSON member was dropped");
}

// ---------------------------------------------------------------------------
// Hostile archives
// ---------------------------------------------------------------------------

/// Path traversal in a member name is refused before anything is written.
///
/// shanon never extracts to disk, so these cannot escape by themselves — but
/// the member name reaches the output archive, and an archive that writes
/// outside its own root when *the recipient* unpacks it is not one to publish.
#[test]
fn a_traversing_member_path_is_refused() {
    for hostile in [
        "../escape.json",
        "..\\escape.json",
        "nested/../../escape.json",
        "/absolute.json",
        "\\absolute.json",
        "C:evil.json",
    ] {
        let scratch = Scratch::new("traversal");
        let input = scratch.write_zip("collection.zip", &[(hostile, users())]);
        let out = scratch.path("out");

        let result = run(&input, &out, None);
        assert!(result.is_err(), "member path {hostile:?} was accepted");
        assert!(
            !out.join("collection_anon.zip").exists(),
            "member path {hostile:?} produced output"
        );
    }
}

/// A member that declares more than the per-member ceiling is refused on the
/// declaration alone, before its bytes are read.
#[test]
fn an_oversized_declared_member_is_refused() {
    let scratch = Scratch::new("oversized");
    let over = (shanon_core::pipeline::MAX_MEMBER_UNCOMPRESSED + 1) as u32;
    let path = scratch.path("collection.zip");
    fs::write(
        &path,
        stored_zip_declaring(&[("users.json", users(), over)]),
    )
    .unwrap();
    let out = scratch.path("out");

    let result = run(&path, &out, None);
    assert!(result.is_err(), "an oversized declaration was accepted");
    assert!(!out.join("collection_anon.zip").exists());
}

/// Truncated, empty, and non-archive inputs are rejected rather than panicking.
#[test]
fn malformed_archives_are_rejected_without_panicking() {
    let scratch = Scratch::new("malformed");
    let good = stored_zip(&[("users.json", users())]);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("short", b"PK".to_vec()),
        ("not-an-archive", vec![b'x'; 512]),
        // Central directory promised but absent.
        ("truncated", good[..good.len() / 2].to_vec()),
        // Valid trailer, central directory offset past the end.
        ("bad-offset", {
            let mut raw = good.clone();
            let n = raw.len();
            raw[n - 6..n - 2].copy_from_slice(&u32::MAX.to_le_bytes());
            raw
        }),
    ];

    for (name, bytes) in cases {
        let path = scratch.path(&format!("{name}.zip"));
        fs::write(&path, &bytes).unwrap();
        let out = scratch.path(&format!("out-{name}"));
        assert!(
            run(&path, &out, None).is_err(),
            "malformed archive {name:?} was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Bare JSON input
// ---------------------------------------------------------------------------

/// A collector's single `users.json`, handed over without being zipped first.
/// It reads as a one-member collection and publishes the same archive shape a
/// zip input does.
#[test]
fn a_single_json_file_is_read_as_a_one_member_collection() {
    let scratch = Scratch::new("bare-json");
    let input = scratch.path("users.json");
    fs::write(&input, users()).unwrap();
    let out = scratch.path("out");
    let map = scratch.path("run.map.json");

    run(&input, &out, Some(&map)).expect("a bare JSON collection should anonymize");

    let dest = out.join("collection_anon.zip");
    assert!(dest.is_file(), "a non-directory input publishes a zip");

    let members = read_zip(&fs::read(&dest).unwrap());
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, "member-00001.json", "member label");
    let doc: Value = serde_json::from_slice(&members[0].1).expect("published member is JSON");
    assert_eq!(doc["meta"]["type"], "users");
    let published = String::from_utf8(members[0].1.clone()).unwrap();
    for secret in ["SOUTHRIDGE", "JDOE", "jdoe", DOMAIN_SID] {
        assert!(
            !published.contains(secret),
            "published archive still contains {secret}"
        );
    }

    // The mapping still records an input hash, taken over the file's bytes the
    // way a zip input's is taken over the archive's.
    let saved: Value = serde_json::from_slice(&fs::read(&map).unwrap()).unwrap();
    let hash = saved["input_hash"].as_str().expect("input hash recorded");
    assert_eq!(hash.len(), 64, "input hash is a sha-256 hex digest");
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

/// The sniff only diverts input that parses whole as a SharpHound document.
/// Everything else keeps the archive path's frozen error text.
#[test]
fn a_file_that_is_neither_an_archive_nor_a_document_keeps_the_zip_error() {
    let scratch = Scratch::new("bare-other");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // Valid JSON, but not a collection document.
        ("not-a-collection", br#"{"hello": "world"}"#.to_vec()),
        // A JSON array, which `parse_collection_member` refuses.
        ("array", b"[]".to_vec()),
        ("prose", b"not a collection at all".to_vec()),
    ];

    for (name, bytes) in cases {
        let path = scratch.path(&format!("{name}.json"));
        fs::write(&path, &bytes).unwrap();
        let out = scratch.path(&format!("out-{name}"));
        match run(&path, &out, None) {
            Err(ShanonError::Io(message)) => {
                assert_eq!(message, "File is not a zip file", "case {name:?}");
            }
            other => panic!("case {name:?} expected the frozen zip error, got {other:?}"),
        }
        assert!(!out.join("collection_anon.zip").exists());
    }
}
