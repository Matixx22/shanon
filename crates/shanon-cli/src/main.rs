//! shanon CLI (module 12): the `clap`-derived command surface.
//!
//! Subcommands, help text, stdout/stderr and exit codes are stable byte-for-byte
//! (§3.4), with these deliberate additions:
//!
//! * `-V/--version` reports the crate version so a downloaded binary can be
//!   identified. That adds a line to the top-level help and re-pads the adjacent
//!   `-h` line as clap widens the column.
//! * `--progress/--no-progress` on `anonymize`, adding two lines to that
//!   subcommand's help. A run takes minutes on a real collection, and used to
//!   give no sign it was alive.
//! * `--summary/--no-summary` on `anonymize`, on the same terms.
//! * `--format text|json` on `inspect`. `text` is the byte-identical default;
//!   `json` prints one canonical document and nothing else.
//! * the `scrub` verb, which adds a line to the top-level subcommand list. Its
//!   arrival is also the one *reworded* line here: `anonymize` used to describe
//!   itself as scrubbing a collection, which now names a different verb.
//!
//! The progress bar itself changes no captured bytes: it draws only when stderr
//! is a terminal (see [`progress::should_render`]), so redirected stderr — every
//! parity fixture and every CLI test — is unchanged. The run summary is drawn on
//! the same condition, for the same reason. All other stderr, and every exit
//! code, are as before.

mod progress;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

use shanon_core::catalog::CATALOG_VERSION;
use shanon_core::pipeline::{
    anonymize_collection, ensure_reuse_map_compatible, resolve, ShanonError,
};
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::Registry;
use shanon_core::restore::{bulk_restore, forward as forward_lookup, lookup};
use shanon_core::scrub::bulk_scrub;

#[derive(Parser)]
#[command(
    name = "shanon",
    version,
    about = "Deterministic anonymizer for SharpHound collections.",
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Anonymize a SharpHound collection; write output + mapping file.
    Anonymize {
        /// SharpHound zip or dir
        #[arg(long)]
        input: PathBuf,
        /// output directory
        #[arg(long)]
        out: PathBuf,
        /// mapping file path
        #[arg(long)]
        map: Option<PathBuf>,
        /// reuse salt+mappings from a prior run
        #[arg(long = "reuse-map")]
        reuse_map: Option<PathBuf>,
        /// print every verification-gate finding before aborting
        #[arg(long = "verbose-failures")]
        verbose_failures: bool,
        /// publish numbers at undeclared paths verbatim instead of redacting
        #[arg(long = "keep-undeclared-numbers")]
        keep_undeclared_numbers: bool,
        /// redact known Windows product strings instead of preserving them
        #[arg(long = "redact-os-strings")]
        redact_os_strings: bool,
        /// draw a progress bar even when stderr is not a terminal
        #[arg(long, conflicts_with = "no_progress")]
        progress: bool,
        /// never draw a progress bar
        #[arg(long = "no-progress")]
        no_progress: bool,
        /// print a run summary even when stderr is not a terminal
        #[arg(long, conflicts_with = "no_summary")]
        summary: bool,
        /// never print a run summary
        #[arg(long = "no-summary")]
        no_summary: bool,
    },
    /// Dry-run a collection and report what a real run would do. Writes nothing.
    Inspect {
        /// SharpHound zip or dir
        #[arg(long)]
        input: PathBuf,
        /// publish numbers at undeclared paths verbatim instead of redacting
        #[arg(long = "keep-undeclared-numbers")]
        keep_undeclared_numbers: bool,
        /// redact known Windows product strings instead of preserving them
        #[arg(long = "redact-os-strings")]
        redact_os_strings: bool,
        /// report format
        #[arg(long, value_enum, default_value_t = InspectFormat::Text)]
        format: InspectFormat,
        /// draw a progress bar even when stderr is not a terminal
        #[arg(long, conflicts_with = "no_progress")]
        progress: bool,
        /// never draw a progress bar
        #[arg(long = "no-progress")]
        no_progress: bool,
    },
    /// Resolve pseudonyms against a mapping file (lookup / forward / bulk).
    Restore {
        /// mapping file
        #[arg(long)]
        map: PathBuf,
        /// pseudonym -> real
        #[arg(long = "lookup")]
        lookup_value: Option<String>,
        /// real -> pseudonym
        #[arg(long = "forward")]
        forward_value: Option<String>,
        /// bulk file
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Rewrite real identifiers in your own text to the pseudonyms a map minted.
    Scrub {
        /// mapping file
        #[arg(long)]
        map: PathBuf,
        /// text to scrub (omit to read stdin)
        #[arg(long)]
        input: Option<PathBuf>,
        /// print the scrub report even when stderr is not a terminal
        #[arg(long, conflicts_with = "no_summary")]
        summary: bool,
        /// never print the scrub report
        #[arg(long = "no-summary")]
        no_summary: bool,
    },
}

/// How `inspect` renders its report.
///
/// `Text` is the operator-facing rendering and is frozen byte-for-byte; `Json`
/// is the machine-readable one, serialized by the crate's own canonical sorted
/// writer so the same input always produces the same bytes (invariants 2, 5).
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum InspectFormat {
    Text,
    Json,
}

/// Version of the `inspect --format json` document. Bumped when a key changes
/// meaning or disappears; adding a key does not bump it.
const INSPECT_SCHEMA_VERSION: u64 = 1;

/// What a run draws on stderr for a human watching it.
///
/// Both are off whenever stderr is not a terminal, so neither can move a
/// captured byte (invariant 2).
#[derive(Copy, Clone)]
struct Rendering {
    progress: bool,
    summary: bool,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Anonymize {
            input,
            out,
            map,
            reuse_map,
            verbose_failures,
            keep_undeclared_numbers,
            redact_os_strings,
            progress,
            no_progress,
            summary,
            no_summary,
        } => anonymize(
            input,
            out,
            map,
            reuse_map,
            verbose_failures,
            policy_config(keep_undeclared_numbers, redact_os_strings),
            Rendering {
                progress: progress::should_render(progress, no_progress),
                summary: progress::should_render(summary, no_summary),
            },
        ),
        Command::Inspect {
            input,
            keep_undeclared_numbers,
            redact_os_strings,
            format,
            progress,
            no_progress,
        } => inspect(
            input,
            policy_config(keep_undeclared_numbers, redact_os_strings),
            progress::should_render(progress, no_progress),
            format,
        ),
        Command::Restore {
            map,
            lookup_value,
            forward_value,
            input,
        } => restore(map, lookup_value, forward_value, input),
        Command::Scrub {
            map,
            input,
            summary,
            no_summary,
        } => scrub(map, input, progress::should_render(summary, no_summary)),
    }
}

/// The run's policy, which differs from the default only where a flag says so.
///
/// Both flags are spelled as opt-outs rather than modes, for opposite reasons.
/// `--keep-undeclared-numbers` widens what leaves the machine, so the safe value
/// is what you get by saying nothing. `--redact-os-strings` narrows it: a
/// catalog-listed Windows product string is a global constant rather than
/// anything about the client, and preserving it is what lets the model reason
/// about an unsupported OS at all, so the useful value is the default and the
/// flag is there for an operator who wants the field gone regardless.
fn policy_config(keep_undeclared_numbers: bool, redact_os_strings: bool) -> PolicyConfig {
    PolicyConfig {
        redact_undeclared_numbers: !keep_undeclared_numbers,
        preserve_os_strings: !redact_os_strings,
        ..PolicyConfig::default()
    }
}

/// Dry-run a collection: same discovery, transform and verification as a real
/// run, then stop. Nothing is written, and every line printed is a count, a
/// synthetic member label, a canonical path or a fingerprint — so a report can
/// be shared for a collection that cannot be.
fn inspect(input: PathBuf, policy: PolicyConfig, render_progress: bool, format: InspectFormat) {
    let reporter = render_progress.then(progress::Reporter::new);
    let sink = reporter.as_ref().map(|(_, sink)| sink.clone());

    let report = shanon_core::pipeline::inspect_collection(
        &input,
        Registry::new_random(),
        policy,
        PolicyAudit::new(),
        sink,
    );
    if let Some((reporter, _)) = &reporter {
        reporter.finish();
    }
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e.stderr_verbose());
            exit(e.exit_code());
        }
    };

    match format {
        InspectFormat::Text => inspect_text(&report),
        InspectFormat::Json => inspect_json(&report),
    }

    // The verdict is the exit code in both formats: the report decides, the
    // rendering only describes it.
    if !report.would_publish() {
        exit(1);
    }
}

/// The operator-facing rendering. Frozen byte-for-byte for a given report, with
/// the sole addition of the `preflight:` block, which is drawn only when the
/// dry run actually has an advisory signal to report.
fn inspect_text(report: &shanon_core::pipeline::InspectReport) {
    println!(
        "members: {} read, {} accepted, {} skipped",
        report.members_read,
        report.members_accepted,
        report.members_skipped.len()
    );
    println!("objects: {}", report.objects);

    println!("\ncollections:");
    for row in &report.collection_types {
        let flag = if row.node_type == "Unknown" {
            "  <- unrecognized, contents anonymized opaquely"
        } else {
            ""
        };
        println!(
            "  {:<24} type={:<14} version={:<10} objects={}{}",
            row.meta_type, row.node_type, row.version, row.objects, flag
        );
    }

    for (label, section) in [
        ("object classifications", "object_classifications"),
        ("audit codes", "audit_codes"),
    ] {
        if let Some(map) = report.audit.get(section).and_then(|v| v.as_object()) {
            if !map.is_empty() {
                println!("\n{label}:");
                for (key, value) in map {
                    println!("  {key}: {value}");
                }
            }
        }
    }

    // Unknown paths are the ingestor-drift signal: fields no rule covers. They
    // are anonymized, not leaked, but each one is a field shanon does not model.
    if let Some(map) = report
        .audit
        .get("unknown_paths")
        .and_then(|v| v.as_object())
    {
        if !map.is_empty() {
            let mut paths: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            paths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            println!("\nunknown field paths ({} distinct):", paths.len());
            for (path, count) in paths.iter().take(20) {
                println!("  {count:>8}  {path}");
            }
            if paths.len() > 20 {
                println!("  ... {} more", paths.len() - 20);
            }
        }
    }

    // Numeric leaves never reach the policy, so one at an undeclared path is
    // passed through unchanged rather than anonymized. Unlike the unknown paths
    // above, these are not modelled imperfectly — they are not modelled at all,
    // and the value went out exactly as it came in. See SECURITY.md.
    if let Some(map) = report
        .audit
        .get("numeric_passthrough_paths")
        .and_then(|v| v.as_object())
    {
        if !map.is_empty() {
            let mut paths: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            paths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            println!(
                "\nnumeric values passed through unchanged ({} distinct path(s)):",
                paths.len()
            );
            for (path, count) in paths.iter().take(20) {
                println!("  {count:>8}  {path}");
            }
            if paths.len() > 20 {
                println!("  ... {} more", paths.len() - 20);
            }
        }
    }

    // Advisory shape checks. None of these change the verdict; a mismatched
    // `meta.count` is already a leak-gate finding of its own, and this line
    // only says in operator terms what the abort below says in gate terms.
    if !report.missing_core_types.is_empty()
        || !report.meta_count_mismatches.is_empty()
        || !report.duplicate_collection_types.is_empty()
    {
        println!("\npreflight:");
        if !report.missing_core_types.is_empty() {
            println!(
                "  missing core collection types: {}",
                report.missing_core_types.join(", ")
            );
        }
        for m in &report.meta_count_mismatches {
            println!(
                "  meta.count disagrees with data length: {} declared {}, actual {}",
                m.member, m.declared, m.actual
            );
        }
        if !report.duplicate_collection_types.is_empty() {
            println!(
                "  collection type declared by more than one member: {}",
                report.duplicate_collection_types.join(", ")
            );
        }
    }

    if let Some(abort) = &report.abort {
        println!("\nwould abort:");
        for line in abort.lines() {
            println!("  {line}");
        }
    }
    if !report.findings.is_empty() {
        println!(
            "\nwould abort - {} leak-gate finding(s):",
            report.findings.len()
        );
        for f in report.findings.iter().take(50) {
            println!(
                "  {} {}: {} {}",
                f.member, f.path, f.policy_code, f.offender
            );
        }
        if report.findings.len() > 50 {
            println!("  ... {} more", report.findings.len() - 50);
        }
    }

    if report.would_publish() {
        println!("\nverdict: this collection would anonymize cleanly");
    } else {
        println!("\nverdict: this collection would abort with no output written");
    }
}

/// The machine-readable rendering: one document on stdout and nothing else.
///
/// Every value here is a count, a synthetic member label, a canonical field
/// path or a keyed fingerprint — the same sanitized material the text rendering
/// prints (invariant 7). Serialization goes through the crate's own sorted
/// canonical writer rather than `serde_json`'s pretty printer, so key order,
/// escaping and number tokens are the ones the rest of shanon emits
/// (invariants 3, 5).
fn inspect_json(report: &shanon_core::pipeline::InspectReport) {
    let doc = json!({
        "schema_version": INSPECT_SCHEMA_VERSION,
        "members_read": report.members_read,
        "members_accepted": report.members_accepted,
        "members_skipped": report.members_skipped,
        "objects": report.objects,
        "collection_types": report
            .collection_types
            .iter()
            .map(|row| json!({
                "meta_type": row.meta_type,
                "node_type": row.node_type,
                "version": row.version,
                "objects": row.objects,
            }))
            .collect::<Vec<Value>>(),
        "audit": report.audit,
        "findings": report
            .findings
            .iter()
            .map(|f| json!({
                "member": f.member,
                "path": f.path,
                "policy_code": f.policy_code,
                "offender": f.offender,
            }))
            .collect::<Vec<Value>>(),
        "abort": report.abort,
        "meta_count_mismatches": report
            .meta_count_mismatches
            .iter()
            .map(|m| json!({
                "member": m.member,
                "declared": m.declared,
                "actual": m.actual,
            }))
            .collect::<Vec<Value>>(),
        "missing_core_types": report.missing_core_types,
        "duplicate_collection_types": report.duplicate_collection_types,
        "would_publish": report.would_publish(),
    });
    println!("{}", shanon_core::canonical_json_sorted(&doc));
}

/// Load an untrusted restoration map without propagating sensitive details,
/// and refuse one minted under a different catalog version.
fn load_reuse_registry(path: &Path) -> Result<Registry, ShanonError> {
    let registry = Registry::load(path)
        .map_err(|_| ShanonError::UnsafeMapping("mapping file is invalid".into()))?;
    ensure_reuse_map_compatible(&registry)?;
    Ok(registry)
}

fn anonymize(
    input: PathBuf,
    out: PathBuf,
    map: Option<PathBuf>,
    reuse_map: Option<PathBuf>,
    verbose_failures: bool,
    policy: PolicyConfig,
    rendering: Rendering,
) {
    let out = resolve(&out);
    let map_path = resolve(&map.unwrap_or_else(|| out.join("collection.map.json")));

    let collection_path = resolve(&out.join(if input.is_dir() {
        "collection_anon"
    } else {
        "collection_anon.zip"
    }));

    // A map beside the collection in --out is valid. A map equal to the output
    // zip or nested inside the output collection directory is not.
    let map_inside_collection =
        map_path == collection_path || (input.is_dir() && map_path.starts_with(&collection_path));
    let resolved_input = resolve(&input);
    let map_mutates_input =
        map_path == resolved_input || (input.is_dir() && map_path.starts_with(&resolved_input));
    if map_inside_collection || map_mutates_input {
        eprintln!("refusing mapping path inside the input or output collection");
        exit(2);
    }
    if map_path.exists() {
        eprintln!("refusing to overwrite existing mapping file");
        exit(2);
    }

    let audit = PolicyAudit::new();
    // Deliberately not recorded in the map: the sentinel writes no registry
    // entry, so `--keep-undeclared-numbers` changes the collection and nothing
    // about the reversal keys. Adding a field here would change the frozen map
    // format for a setting the map does not need.
    let map_policy = json!({
        "profile": "core-global-defaults",
        "catalog_version": CATALOG_VERSION,
        "preserve_microsoft_feature_defaults": policy.preserve_microsoft_feature_defaults,
        "preserve_third_party_defaults": policy.preserve_third_party_defaults,
    });

    let reg = match &reuse_map {
        Some(p) => load_reuse_registry(p),
        None => Ok(Registry::new_random()),
    };
    let reg = match reg {
        Ok(r) => r,
        Err(e) => {
            // Same split as the pipeline's own aborts below: the frozen line
            // by default, the sanitized reason under `--verbose-failures`.
            if verbose_failures {
                eprintln!("{}", e.stderr_verbose());
            } else {
                eprintln!("{}", e.stderr());
            }
            exit(e.exit_code());
        }
    };

    // Held across the call so the bar can be torn down before anything else
    // writes to stderr — an aborted run never emits a closing phase event.
    let reporter = rendering.progress.then(progress::Reporter::new);
    let sink = reporter.as_ref().map(|(_, sink)| sink.clone());

    let result = anonymize_collection(
        &input,
        &out,
        reg,
        verbose_failures,
        policy,
        audit,
        Some(&map_path),
        Some(map_policy),
        sink,
    );
    if let Some((reporter, _)) = &reporter {
        reporter.finish();
    }

    let outcome = match result {
        Ok(o) => o,
        Err(e) => {
            // Without the flag this is byte-identical to `e.stderr()`; with it,
            // the mapping-abort classes gain their sanitized detail.
            if verbose_failures {
                eprintln!("{}", e.stderr_verbose());
            } else {
                eprintln!("{}", e.stderr());
            }
            exit(e.exit_code());
        }
    };

    let summary = outcome.audit.summary();
    let classified = &summary["object_classifications"];
    let get = |k: &str| classified.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let unknown_total: u64 = summary["unknown_paths"]
        .as_object()
        .map(|m| m.values().filter_map(|v| v.as_u64()).sum())
        .unwrap_or(0);

    println!("anonymized -> {}", outcome.dest.display());
    println!(
        "mapping (client-sensitive, keep local) -> {}",
        map_path.display()
    );
    println!("policy: core-global-defaults");
    println!(
        "classified: core={} feature={} third_party={} custom={} unknown={}",
        get("core_global_default"),
        get("microsoft_feature_default"),
        get("third_party_default"),
        get("custom"),
        get("unknown"),
    );
    println!("unknown string paths: {unknown_total}");

    if rendering.summary {
        run_summary(&summary, &outcome.dest, &map_path);
    }
}

/// Draw a compact run summary on stderr.
///
/// Same rule as the progress bar: this is written to stderr and only when
/// stderr is a terminal, so a redirected or captured stderr — every parity
/// fixture, every CLI test — is byte-identical to before (invariant 2). Every
/// figure comes from the audit the run actually kept; nothing here is derived
/// from a source value, and the two paths are the destinations the caller named.
fn run_summary(summary: &Value, dest: &Path, map_path: &Path) {
    /// `key`'s `{name: count}` map as pairs, in the audit's own sorted order.
    fn counts<'a>(summary: &'a Value, key: &str) -> Vec<(&'a String, u64)> {
        summary
            .get(key)
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn joined(pairs: &[(&String, u64)]) -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    let classifications = counts(summary, "object_classifications");
    let objects: u64 = classifications.iter().map(|(_, v)| *v).sum();
    let audit_codes = counts(summary, "audit_codes");

    let mut err = std::io::stderr();
    let _ = writeln!(err, "summary: {objects} objects");
    if !classifications.is_empty() {
        let _ = writeln!(err, "  classifications: {}", joined(&classifications));
    }
    if !audit_codes.is_empty() {
        let _ = writeln!(err, "  audit codes: {}", joined(&audit_codes));
    }
    let _ = writeln!(
        err,
        "  unknown field paths: {} distinct",
        counts(summary, "unknown_paths").len()
    );
    // Always printed, including the zero: a numeric leaf at an undeclared path
    // leaves the machine unchanged, so "none happened" is the load-bearing case.
    let _ = writeln!(
        err,
        "  numeric values passed through: {} distinct path(s)",
        counts(summary, "numeric_passthrough_paths").len()
    );
    let _ = writeln!(err, "  collection: {}", dest.display());
    let _ = writeln!(err, "  map: {}", map_path.display());
    let _ = err.flush();
}

/// Load a mapping file, or abort on the frozen stderr line for bad map data.
///
/// Shared by `restore` and `scrub`: both take an untrusted map from the
/// operator, and neither may say anything about why it failed to parse, since
/// the reason would describe its contents (invariant 7).
fn load_map_or_exit(map: &Path) -> Registry {
    match Registry::load(map) {
        Ok(registry) => registry,
        Err(_) => {
            eprintln!("ABORTED - invalid or conflicting mapping data; no output written");
            exit(1);
        }
    }
}

/// Read the bulk-text argument, from a file or from stdin when absent.
fn read_text_or_exit(input: &Option<PathBuf>) -> String {
    match input {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot read --input file '{}': {e}", p.display());
                exit(1);
            }
        },
        None => {
            let mut s = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut s) {
                eprintln!("cannot read from stdin: {e}");
                exit(1);
            }
            s
        }
    }
}

fn restore(
    map: PathBuf,
    lookup_value: Option<String>,
    forward_value: Option<String>,
    input: Option<PathBuf>,
) {
    let chosen = [
        lookup_value.is_some(),
        forward_value.is_some(),
        input.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if chosen > 1 {
        eprintln!("use only one of --lookup / --forward / --input");
        exit(2);
    }

    let reg = load_map_or_exit(&map);

    if let Some(value) = lookup_value {
        let matches = lookup(&reg, &value);
        if matches.is_empty() {
            eprintln!("no match for pseudonym '{value}'");
            exit(1);
        }
        for (category, real) in matches {
            println!("{category}: {real}");
        }
        return;
    }

    if let Some(value) = forward_value {
        let matches = forward_lookup(&reg, &value);
        if matches.is_empty() {
            eprintln!("no match for real value '{value}'");
            exit(1);
        }
        for (category, fake) in matches {
            println!("{category}: {fake}");
        }
        return;
    }

    let text = read_text_or_exit(&input);
    print!("{}", bulk_restore(&reg, &text));
}

/// Rewrite the operator's own text into the pseudonyms a prior run minted.
///
/// The scrubbed text goes to stdout and the report to stderr, so the useful
/// output pipes cleanly into a file or a clipboard command while the counts stay
/// on the terminal. The report is drawn under the same rule as the `anonymize`
/// summary, which keeps redirected stderr byte-identical to a run without it
/// (invariant 2).
fn scrub(map: PathBuf, input: Option<PathBuf>, render_summary: bool) {
    let reg = load_map_or_exit(&map);
    let text = read_text_or_exit(&input);
    let (scrubbed, report) = bulk_scrub(&reg, &text);
    print!("{scrubbed}");

    if !render_summary {
        return;
    }
    let mut err = std::io::stderr();
    let _ = writeln!(err, "scrubbed: {} replacements", report.replacements);
    if !report.per_category.is_empty() {
        let joined = report
            .per_category
            .iter()
            .map(|(category, count)| format!("{category} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(err, "  categories: {joined}");
    }
    if report.unresolved > 0 {
        let _ = writeln!(
            err,
            "  matched but unmapped, left in the clear: {}",
            report.unresolved
        );
    }
    // Always printed, including after a full-looking scrub: the number shows
    // what was replaced and can say nothing about what was not in the map.
    let _ = writeln!(
        err,
        "  this replaces only what the map knows; check the rest by hand"
    );
    let _ = err.flush();
}
