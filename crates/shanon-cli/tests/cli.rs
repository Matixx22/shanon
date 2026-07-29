//! Integration tests driving the built `shanon` binary. These cover
//! corpus-independent CLI surface behavior (verb wiring, flag handling).

use std::fs;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shanon")
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
fn restore_mutually_exclusive_flags_rejected() {
    let out = Command::new(bin())
        .args(["restore", "--map", "/nonexistent.map.json"])
        .args(["--lookup", "a", "--forward", "b"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
