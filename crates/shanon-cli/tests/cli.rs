//! Integration tests driving the built `shanon` binary. These cover
//! corpus-independent CLI surface behavior (verb wiring, flag handling).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shanon")
}

#[test]
fn help_lists_both_verbs() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("anonymize"), "{text}");
    assert!(text.contains("restore"), "{text}");
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

#[test]
fn restore_mutually_exclusive_flags_rejected() {
    let out = Command::new(bin())
        .args(["restore", "--map", "/nonexistent.map.json"])
        .args(["--lookup", "a", "--forward", "b"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
