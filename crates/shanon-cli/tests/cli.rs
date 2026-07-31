//! Integration tests driving the built `shanon` binary. These cover
//! corpus-independent CLI surface behavior (verb wiring, flag handling).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shanon")
}

/// The committed synthetic collection. Small, real-shaped, and safe to print.
fn demo_collection() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../demo/collection")
}

/// A scratch directory unique to the calling test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "shanon-cli-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn help_lists_every_verb() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("anonymize"), "{text}");
    assert!(text.contains("inspect"), "{text}");
    assert!(text.contains("restore"), "{text}");
}

/// `inspect` takes an input and nothing that could name an output — the verb is
/// read-only by construction, not by convention.
#[test]
fn inspect_help_offers_no_output_destination() {
    let out = Command::new(bin())
        .args(["inspect", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--input"), "{text}");
    assert!(!text.contains("--out"), "{text}");
    assert!(!text.contains("--map"), "{text}");
}

/// A downloaded binary must be able to identify itself, and the reported
/// version must track the crate rather than a hand-maintained string.
#[test]
fn version_reports_the_crate_version() {
    for flag in ["--version", "-V"] {
        let out = Command::new(bin()).arg(flag).output().unwrap();
        assert!(out.status.success(), "{flag} exited non-zero");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(env!("CARGO_PKG_VERSION")),
            "{flag} did not report the crate version: {text}"
        );
    }
}

#[test]
fn anonymize_help_documents_the_progress_flags() {
    let out = Command::new(bin())
        .args(["anonymize", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--progress"), "{text}");
    assert!(text.contains("--no-progress"), "{text}");
}

/// Asking to both draw and not draw a bar is a pre-flight refusal, not a
/// silently-picked default.
#[test]
fn anonymize_conflicting_progress_flags_rejected() {
    let out = Command::new(bin())
        .args([
            "anonymize",
            "--input",
            "/nonexistent",
            "--out",
            "/nonexistent",
        ])
        .args(["--progress", "--no-progress"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// A mapping minted under a different catalog version is refused before the
/// pipeline runs, and the refusal publishes nothing: no collection, and no new
/// mapping file that would imply the run got as far as minting pseudonyms.
#[test]
fn anonymize_refuses_a_reuse_map_from_another_catalog_version() {
    let scratch = std::env::temp_dir().join(format!(
        "shanon-cli-reuse-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(scratch.join("collection")).unwrap();
    fs::write(
        scratch.join("collection").join("users.json"),
        br#"{"data":[],"meta":{"methods":0,"type":"users","count":0,"version":6}}"#,
    )
    .unwrap();
    let stale = scratch.join("stale.map.json");
    fs::write(
        &stale,
        br#"{"salt":"0123456789abcdef0123456789abcdef","format_version":2,
             "categories":{},"policy":{"catalog_version":1}}"#,
    )
    .unwrap();

    let run = |verbose: bool| {
        let mut cmd = Command::new(bin());
        cmd.args(["anonymize", "--input"])
            .arg(scratch.join("collection"))
            .arg("--out")
            .arg(scratch.join("out"))
            .arg("--map")
            .arg(scratch.join("fresh.map.json"))
            .arg("--reuse-map")
            .arg(&stale);
        if verbose {
            cmd.arg("--verbose-failures");
        }
        cmd.output().unwrap()
    };

    let out = run(false);
    assert_eq!(out.status.code(), Some(1));
    // The frozen surface says only that the mapping is unusable.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid or conflicting mapping data"),
        "{stderr}"
    );
    // `--verbose-failures` is where the reason is allowed to appear.
    let verbose = run(true);
    assert_eq!(verbose.status.code(), Some(1));
    let verbose_stderr = String::from_utf8_lossy(&verbose.stderr);
    assert!(
        verbose_stderr.contains("catalog version"),
        "{verbose_stderr}"
    );
    assert!(
        !scratch.join("fresh.map.json").exists(),
        "the refused run wrote a mapping file"
    );
    assert!(
        !scratch.join("out").join("collection_anon").exists(),
        "the refused run wrote a collection"
    );
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn anonymize_help_documents_the_summary_flags() {
    let out = Command::new(bin())
        .args(["anonymize", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--summary"), "{text}");
    assert!(text.contains("--no-summary"), "{text}");
}

/// The opt-out is on both subcommands that resolve a policy, because `inspect`
/// is only a dry run of `anonymize` if the two are configured identically.
#[test]
fn both_subcommands_document_the_os_opt_out() {
    for subcommand in ["anonymize", "inspect"] {
        let out = Command::new(bin())
            .args([subcommand, "--help"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--redact-os-strings"), "{subcommand}: {text}");
    }
}

#[test]
fn anonymize_conflicting_summary_flags_rejected() {
    let out = Command::new(bin())
        .args([
            "anonymize",
            "--input",
            "/nonexistent",
            "--out",
            "/nonexistent",
        ])
        .args(["--summary", "--no-summary"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// `--format json` prints one parseable document with the documented keys, and
/// agrees with the text rendering about the verdict.
#[test]
fn inspect_json_format_reports_the_documented_keys() {
    let text = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .output()
        .unwrap();
    let json_run = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(
        json_run.status.code(),
        text.status.code(),
        "json and text disagreed on the exit code"
    );
    assert_eq!(json_run.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&json_run.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is not one JSON document");
    let obj = doc.as_object().expect("top level is not an object");
    for key in [
        "abort",
        "audit",
        "collection_types",
        "duplicate_collection_types",
        "findings",
        "members_accepted",
        "members_read",
        "members_skipped",
        "meta_count_mismatches",
        "missing_core_types",
        "objects",
        "schema_version",
        "would_publish",
    ] {
        assert!(obj.contains_key(key), "missing key {key}: {stdout}");
    }
    assert_eq!(obj["schema_version"], serde_json::json!(1));
    assert_eq!(obj["would_publish"], serde_json::json!(true));
    assert_eq!(obj["abort"], serde_json::Value::Null);
    assert_eq!(obj["members_read"], serde_json::json!(4));
    let row = obj["collection_types"][0].as_object().unwrap();
    for key in ["meta_type", "node_type", "objects", "version"] {
        assert!(
            row.contains_key(key),
            "collection row missing {key}: {stdout}"
        );
    }
    // Sorted-canonical output, not `serde_json`'s pretty printer.
    assert!(stdout.starts_with("{\n  \"abort\""), "{stdout}");
}

/// The text rendering is the default and is what it always was, so nothing that
/// scrapes it needs to learn about `--format`.
#[test]
fn inspect_defaults_to_text() {
    let default = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .output()
        .unwrap();
    let explicit = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .args(["--format", "text"])
        .output()
        .unwrap();
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(default.stdout, explicit.stdout);
    let text = String::from_utf8_lossy(&default.stdout);
    assert!(
        text.starts_with("members: 4 read, 4 accepted, 0 skipped\n"),
        "{text}"
    );
    assert!(
        text.contains("verdict: this collection would anonymize cleanly"),
        "{text}"
    );
}

#[test]
fn inspect_rejects_an_unknown_format() {
    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .args(["--format", "yaml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid value 'yaml'"), "{stderr}");
}

/// A collection with none of the three advisory signals prints no `preflight:`
/// block at all, in either format.
#[test]
fn inspect_omits_preflight_for_a_clean_collection() {
    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("preflight:"), "{text}");

    let json_run = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .args(["--format", "json"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&json_run.stdout).unwrap();
    assert_eq!(doc["meta_count_mismatches"], serde_json::json!([]));
    assert_eq!(doc["missing_core_types"], serde_json::json!([]));
    assert_eq!(doc["duplicate_collection_types"], serde_json::json!([]));
}

/// ...and a collection that trips all three reports them, without any of the
/// three deciding the verdict on its own.
#[test]
fn inspect_reports_the_preflight_signals() {
    let dir = scratch("preflight");
    fs::write(
        dir.join("a.json"),
        br#"{"data":[],"meta":{"methods":0,"type":"users","count":4,"version":6}}"#,
    )
    .unwrap();
    fs::write(
        dir.join("b.json"),
        br#"{"data":[],"meta":{"methods":0,"type":"users","count":0,"version":6}}"#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(&dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\npreflight:\n"), "{text}");
    assert!(
        text.contains("  missing core collection types: computers, domains, groups\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  meta.count disagrees with data length: member-00001.json declared 4, actual 0\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  collection type declared by more than one member: users\n"),
        "{text}"
    );

    let json_run = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(&dir)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(json_run.status.code(), out.status.code());
    let doc: serde_json::Value = serde_json::from_slice(&json_run.stdout).unwrap();
    assert_eq!(
        doc["missing_core_types"],
        serde_json::json!(["computers", "domains", "groups"])
    );
    assert_eq!(
        doc["duplicate_collection_types"],
        serde_json::json!(["users"])
    );
    let mismatch = &doc["meta_count_mismatches"][0];
    assert_eq!(mismatch["member"], serde_json::json!("member-00001.json"));
    assert_eq!(mismatch["declared"], serde_json::json!(4));
    assert_eq!(mismatch["actual"], serde_json::json!(0));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn restore_mutually_exclusive_flags_rejected() {
    let out = Command::new(bin())
        .args(["restore", "--map", "/nonexistent.map.json"])
        .args(["--lookup", "a", "--forward", "b"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
