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

#[test]
fn restore_mutually_exclusive_flags_rejected() {
    let out = Command::new(bin())
        .args(["restore", "--map", "/nonexistent.map.json"])
        .args(["--lookup", "a", "--forward", "b"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
}
