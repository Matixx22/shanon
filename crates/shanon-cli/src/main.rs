//! shanon CLI (module 12): the `clap`-derived command surface.
//!
//! Subcommands, flags, help text, stdout/stderr and exit codes are stable
//! byte-for-byte (§3.4).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use serde_json::json;

use shanon_core::catalog::CATALOG_VERSION;
use shanon_core::pipeline::{anonymize_collection, resolve, ShanonError};
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::Registry;
use shanon_core::restore::{bulk_restore, forward as forward_lookup, lookup};

#[derive(Parser)]
#[command(
    name = "shanon",
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
    /// Scrub a SharpHound collection; write anonymized output + mapping file.
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
        } => anonymize(input, out, map, reuse_map, verbose_failures),
        Command::Restore {
            map,
            lookup_value,
            forward_value,
            input,
        } => restore(map, lookup_value, forward_value, input),
    }
}

/// Load an untrusted restoration map without propagating sensitive details.
fn load_reuse_registry(path: &Path) -> Result<Registry, ShanonError> {
    Registry::load(path).map_err(|_| ShanonError::UnsafeMapping("mapping file is invalid".into()))
}

fn anonymize(
    input: PathBuf,
    out: PathBuf,
    map: Option<PathBuf>,
    reuse_map: Option<PathBuf>,
    verbose_failures: bool,
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

    let policy = PolicyConfig::default();
    let audit = PolicyAudit::new();
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
            eprintln!("{}", e.stderr());
            exit(e.exit_code());
        }
    };

    let outcome = match anonymize_collection(
        &input,
        &out,
        reg,
        verbose_failures,
        policy,
        audit,
        Some(&map_path),
        Some(map_policy),
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e.stderr());
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

    let reg = match Registry::load(&map) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("ABORTED - invalid or conflicting mapping data; no output written");
            exit(1);
        }
    };

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

    let text = match &input {
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
    };
    print!("{}", bulk_restore(&reg, &text));
}
