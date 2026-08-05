//! Integration tests driving the built `shanon` binary. These cover
//! corpus-independent CLI surface behavior (verb wiring, flag handling).

use std::fs;
use std::io::Write;
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
    assert!(text.contains("scrub"), "{text}");
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

/// Run `anonymize` over the demo collection into a fresh scratch directory.
fn anonymize_demo(tag: &str, extra: &[&str]) -> std::process::Output {
    let dir = scratch(tag);
    Command::new(bin())
        .args(["anonymize", "--input"])
        .arg(demo_collection())
        .arg("--out")
        .arg(dir.join("out"))
        .args(extra)
        .output()
        .unwrap()
}

/// The default report answers "what did this do to my collection?" in the
/// operator's terms: how much was replaced, how the objects were classified,
/// what was left alone, and where the two artifacts landed.
#[test]
fn anonymize_report_says_what_happened_to_the_input() {
    let out = anonymize_demo("report", &[]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("8 objects anonymized across 4 files"),
        "{text}"
    );
    assert!(text.contains("each with a stable pseudonym"), "{text}");
    // Registry categories are reported in the reader's spelling, not the map's.
    for label in ["domains", "SIDs", "accounts", "hostnames"] {
        assert!(text.contains(label), "missing category {label}: {text}");
    }
    // Privacy classes likewise: no `core_global_default` reaches the operator.
    assert!(
        text.contains("built-in Active Directory defaults"),
        "{text}"
    );
    assert!(text.contains("specific to your organization"), "{text}");
    assert!(!text.contains("core_global_default"), "{text}");

    // The half of the report that carries risk, printed even when both are zero.
    assert!(text.contains("field paths shanon does not model"), "{text}");
    assert!(text.contains("numeric values passed through"), "{text}");

    // The mapping file is the one artifact that must not be shared, and the
    // report has to say so wherever it names it.
    assert!(text.contains("KEEP LOCAL"), "{text}");
    assert!(text.contains("safe to share"), "{text}");
}

/// Invariant 7 applies to the friendly rendering exactly as it does to every
/// other diagnostic: a report is only shareable if it is made of counts. No
/// identifier the demo collection contains may appear in it.
#[test]
fn anonymize_report_leaks_no_source_value() {
    let out = anonymize_demo("report-leak", &[]);
    let text = String::from_utf8_lossy(&out.stdout);
    let lower = text.to_lowercase();
    for secret in [
        "contoso",
        "svc_sql",
        "sql01",
        "sql server service account",
        "s-1-5-21-1111111111",
        "helpdesk",
    ] {
        assert!(!lower.contains(secret), "leaked {secret}: {text}");
    }
}

/// The report is the run's own output, so it must not depend on whether a
/// terminal is attached or whether the default was named explicitly. Captured
/// stdout is what both tests here see, and `--summary` must not change it.
#[test]
fn anonymize_report_is_the_default_and_does_not_vary() {
    let default = anonymize_demo("report-default", &[]);
    let explicit = anonymize_demo("report-explicit", &["--summary"]);
    let normalize = |out: &std::process::Output| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.contains("shanon-cli-report-"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(normalize(&default), normalize(&explicit));
}

/// The compatibility promise for the stdout break: `--no-summary` still prints
/// the five previous lines, in order, and prints nothing else. A script that
/// matched them keeps working by adding one flag, so this pins the escape hatch
/// rather than the report.
#[test]
fn anonymize_no_summary_prints_the_previous_lines_verbatim() {
    let out = anonymize_demo("terse", &["--no-summary"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines.len(), 5, "{text}");
    assert!(lines[0].starts_with("anonymized -> "), "{text}");
    assert!(
        lines[1].starts_with("mapping (client-sensitive, keep local) -> "),
        "{text}"
    );
    assert_eq!(lines[2], "policy: core-global-defaults");
    assert_eq!(
        lines[3],
        "classified: core=2 feature=0 third_party=0 custom=6 unknown=0"
    );
    assert_eq!(lines[4], "unknown string paths: 0");
}

/// `inspect` is a dry run of `anonymize`, so its report answers the same
/// questions in the same vocabulary, and says up front that it wrote nothing.
#[test]
fn inspect_report_reads_like_the_anonymize_report() {
    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);

    // The one claim a skimmed dry run must not get wrong.
    assert!(text.starts_with("Dry run. Nothing was written."), "{text}");

    assert!(text.contains("Read 4 files, all usable."), "{text}");
    assert!(text.contains("Found 8 objects."), "{text}");
    // Same blocks as the anonymize report, in the conditional tense.
    assert!(
        text.contains("Would replace 37 identifiers, each with a stable pseudonym:"),
        "{text}"
    );
    assert!(
        text.contains("built-in Active Directory defaults"),
        "{text}"
    );
    assert!(text.contains("Would not anonymize:"), "{text}");
    assert!(text.contains("Verdict:"), "{text}");
    // No catalog or registry enum name reaches the operator.
    assert!(!text.contains("core_global_default"), "{text}");
    assert!(!text.contains("type=Computer"), "{text}");
}

/// The dry run mints pseudonyms against a throwaway salt, so its counts must
/// match a real run's even though the values it invents do not.
#[test]
fn inspect_would_replace_count_matches_a_real_run() {
    let inspected = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(demo_collection())
        .args(["--format", "json"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    let dry: u64 = doc["mapped_per_category"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["count"].as_u64().unwrap())
        .sum();

    let real = anonymize_demo("inspect-parity", &[]);
    let text = String::from_utf8_lossy(&real.stdout);
    assert!(
        text.contains(&format!("Replaced {dry} identifiers")),
        "dry run counted {dry}, real run said: {text}"
    );
}

/// A dry run over a collection that would abort has to say so unambiguously,
/// and has to lead with the reason rather than the verdict.
#[test]
fn inspect_report_names_the_reason_it_would_abort() {
    let dir = scratch("abort-report");
    fs::write(
        dir.join("a.json"),
        br#"{"data":[],"meta":{"methods":0,"type":"users","count":4,"version":6}}"#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("each one enough to abort the run"), "{text}");
    assert!(
        text.contains("Verdict: this collection would abort. No output would be written."),
        "{text}"
    );
    // A run that would abort must not also offer the next step.
    assert!(!text.contains("Next: `shanon anonymize"), "{text}");
    let _ = fs::remove_dir_all(&dir);
}

/// A clean verdict covers the leak gate and nothing else. When the dry run
/// found advisory signals, the verdict line must not be the last word.
#[test]
fn inspect_clean_verdict_still_points_at_the_advisory_counts() {
    let dir = scratch("advisory");
    // A field no rule models, and a number at an undeclared path.
    fs::write(
        dir.join("users.json"),
        br#"{"data":[{"Properties":{"name":"A@B.LOCAL","vendorfield":"x","vendorscore":7}}],
             "meta":{"methods":0,"type":"users","count":1,"version":6}}"#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["inspect", "--input"])
        .arg(&dir)
        .arg("--keep-undeclared-numbers")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Verdict: this collection would anonymize cleanly."),
        "{text}"
    );
    assert!(
        text.contains("the verdict does not cover it"),
        "advisory caveat missing: {text}"
    );

    // Invariant 7 reaches the drift listing too. An unmodeled field is named
    // only by fingerprint: the path says where the drift is, never what the
    // collector called it, and never the value underneath.
    let lower = text.to_lowercase();
    for secret in ["vendorfield", "vendorscore", "a@b.local"] {
        assert!(!lower.contains(secret), "leaked {secret}: {text}");
    }
    let _ = fs::remove_dir_all(&dir);
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
        text.starts_with("Dry run. Nothing was written.\n"),
        "{text}"
    );
    assert!(text.contains("Read 4 files, all usable."), "{text}");
    assert!(
        text.contains("Verdict: this collection would anonymize cleanly."),
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
    assert!(
        !text.contains("Worth checking before you run this:"),
        "{text}"
    );

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
    assert!(
        text.contains("\nWorth checking before you run this:\n"),
        "{text}"
    );
    assert!(
        text.contains("  Missing core collection types: computers, domains, groups.\n"),
        "{text}"
    );
    assert!(
        text.contains("  member-00001.json says it holds 4 objects but carries 0.\n"),
        "{text}"
    );
    assert!(
        text.contains("  Declared by more than one file: users.\n"),
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

/// Feed `text` to `shanon scrub` on stdin and return the finished process.
fn scrub_stdin(map: &std::path::Path, text: &str, extra: &[&str]) -> std::process::Output {
    let mut child = Command::new(bin())
        .args(["scrub", "--map"])
        .arg(map)
        .args(extra)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // A run that refuses its map exits before it reads stdin, so this write can
    // lose the race and hit EPIPE. That is the child answering, not a failure:
    // what the caller asserts on is the exit code and the output. Unwrapping
    // here made the outcome depend on scheduling, which is how it passed on
    // x86_64 and failed on arm64.
    let mut stdin = child.stdin.take().unwrap();
    match stdin.write_all(text.as_bytes()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("writing to scrub stdin: {e}"),
    }
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// The point of the verb: the pseudonym it puts in your prompt has to be the one
/// the model was actually given, so the assertion is against the published
/// collection rather than against the scrubber's own idea of the mapping.
#[test]
fn scrub_rewrites_a_real_value_into_the_published_pseudonym() {
    let dir = scratch("scrub-roundtrip");
    let out_dir = dir.join("out");
    let map = dir.join("collection.map.json");
    let anonymize = Command::new(bin())
        .args(["anonymize", "--input"])
        .arg(demo_collection())
        .arg("--out")
        .arg(&out_dir)
        .arg("--map")
        .arg(&map)
        .output()
        .unwrap();
    assert_eq!(anonymize.status.code(), Some(0));

    // Mixed spellings on purpose: an operator types the domain however they
    // remember it, and the collection stores exactly one of those spellings.
    let scrub = scrub_stdin(&map, "can SVC_SQL in CONTOSO.LOCAL reach anything?", &[]);
    assert_eq!(scrub.status.code(), Some(0));
    let scrubbed = String::from_utf8_lossy(&scrub.stdout).into_owned();
    let minted: Vec<&str> = scrubbed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .filter(|token| token.len() > 12)
        .collect();
    assert!(!minted.is_empty(), "nothing was replaced: {scrubbed}");

    // Asserted against what is left once the minted tokens are removed, not
    // against the whole line. A pseudonym is not required to be disjoint from
    // its source: the registry forbids only a mapping that leaves the value
    // unchanged, so a domain label can draw a company word equal to its own and
    // `contoso` legitimately becomes `contoso-<fingerprint>` (see the
    // `pseudonym_spans` note in `core::scrub`). The wordlist holds 20 names and
    // this collection is CONTOSO, so about one run in twenty produced that, and
    // a blanket search for the stem failed on those runs while nothing was
    // wrong. What must hold on every run is this: no real value survives
    // outside a token the scrub minted.
    let residue = minted
        .iter()
        .fold(scrubbed.clone(), |text, token| text.replace(token, ""))
        .to_lowercase();
    assert!(!residue.contains("svc_sql"), "{scrubbed}");
    assert!(!residue.contains("contoso"), "{scrubbed}");

    // Every token the scrub produced must appear in the collection the model
    // would receive; a pseudonym that is merely internally consistent is worth
    // nothing to the person pasting it into a chat window.
    let published = fs::read_to_string(out_dir.join("collection_anon").join("member-00004.json"))
        .or_else(|_| {
            let mut joined = String::new();
            for entry in fs::read_dir(out_dir.join("collection_anon")).unwrap() {
                joined.push_str(&fs::read_to_string(entry.unwrap().path()).unwrap());
            }
            Ok::<String, std::io::Error>(joined)
        })
        .unwrap();
    for token in minted {
        assert!(
            published.contains(token),
            "scrub minted '{token}', absent from the published collection"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

/// The report follows the `anonymize` summary rule: stderr that is not a
/// terminal stays byte-identical to a run without it (invariant 2).
#[test]
fn scrub_reports_nothing_to_a_captured_stderr() {
    let dir = scratch("scrub-quiet");
    let map = dir.join("collection.map.json");
    let anonymize = Command::new(bin())
        .args(["anonymize", "--input"])
        .arg(demo_collection())
        .arg("--out")
        .arg(dir.join("out"))
        .arg("--map")
        .arg(&map)
        .output()
        .unwrap();
    assert_eq!(anonymize.status.code(), Some(0));

    let quiet = scrub_stdin(&map, "svc_sql", &[]);
    assert!(quiet.stderr.is_empty(), "{:?}", quiet.stderr);
    // ...and `--summary` is how you ask for it anyway.
    let forced = scrub_stdin(&map, "svc_sql", &["--summary"]);
    let stderr = String::from_utf8_lossy(&forced.stderr);
    assert!(stderr.contains("scrubbed: 1 replacements"), "{stderr}");
    assert!(stderr.contains("categories: accounts 1"), "{stderr}");
    // The limit is stated every time, not only when little was replaced.
    assert!(stderr.contains("only what the map knows"), "{stderr}");

    let _ = fs::remove_dir_all(&dir);
}

/// An unreadable map aborts on the same frozen line `restore` uses, and prints
/// no scrubbed text: a partial scrub is worse than none.
#[test]
fn scrub_refuses_an_unusable_map() {
    let out = scrub_stdin(
        std::path::Path::new("/nonexistent.map.json"),
        "svc_sql",
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid or conflicting mapping data"),
        "{stderr}"
    );
}

#[test]
fn scrub_conflicting_summary_flags_rejected() {
    let out = Command::new(bin())
        .args([
            "scrub",
            "--map",
            "/nonexistent.map.json",
            "--summary",
            "--no-summary",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
