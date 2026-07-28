//! A progress sink observes work; it must never change it.
//!
//! The bar exists for the operator's benefit, so the load-bearing property is
//! negative: installing a sink changes no published byte (invariants 1 and 3).
//! The event stream is asserted alongside it so a miscounted phase — a bar that
//! stalls at 80% or overruns its own total — fails here rather than on a real
//! collection.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use shanon_core::pipeline::anonymize_collection;
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::progress::{Phase, ProgressEvent, ProgressSink};
use shanon_core::registry::Registry;

/// A scratch directory that removes itself, so the suite needs no temp-file
/// dependency.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("shanon-progress-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Three users and two computers: five top-level objects in total.
const USERS: usize = 3;
const COMPUTERS: usize = 2;
const OBJECTS: u64 = (USERS + COMPUTERS) as u64;

fn write_collection(dir: &Path) {
    let users: Vec<Value> = (0..USERS)
        .map(|i| {
            json!({
                "ObjectIdentifier": format!("S-1-5-21-71234567-72345678-73456789-{}", 1100 + i),
                "Properties": {
                    "name": format!("ZQUSER{i}@ZQCORP.LOCAL"),
                    "samaccountname": format!("zquser{i}"),
                    "distinguishedname": format!("CN=zquser{i},OU=Staff,DC=zqcorp,DC=local"),
                    "domain": "ZQCORP.LOCAL",
                },
            })
        })
        .collect();
    let computers: Vec<Value> = (0..COMPUTERS)
        .map(|i| {
            json!({
                "ObjectIdentifier": format!("S-1-5-21-71234567-72345678-73456789-{}", 1200 + i),
                "Properties": {
                    "name": format!("ZQHOST{i}.ZQCORP.LOCAL"),
                    "dnshostname": format!("zqhost{i}.zqcorp.local"),
                    "domain": "ZQCORP.LOCAL",
                },
            })
        })
        .collect();

    let users_doc = json!({
        "meta": {"type": "users", "count": users.len(), "version": 6},
        "data": users,
    });
    let computers_doc = json!({
        "meta": {"type": "computers", "count": computers.len(), "version": 6},
        "data": computers,
    });
    std::fs::write(dir.join("users.json"), users_doc.to_string()).expect("write users");
    std::fs::write(dir.join("computers.json"), computers_doc.to_string()).expect("write computers");
}

/// Every published member, sorted by name, as raw bytes.
fn published_bytes(collection: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(collection)
        .expect("read published collection")
        .map(|entry| {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            (name, std::fs::read(entry.path()).expect("read member"))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn run(input: &Path, out: &Path, sink: Option<ProgressSink>) {
    anonymize_collection(
        input,
        out,
        // A fixed salt makes the two runs comparable byte for byte.
        Registry::new("00"),
        false,
        PolicyConfig::default(),
        PolicyAudit::new(),
        None,
        None,
        sink,
    )
    .expect("anonymize");
}

#[test]
fn a_progress_sink_changes_no_published_byte() {
    let scratch = Scratch::new("parity");
    let input = scratch.path().join("input");
    std::fs::create_dir_all(&input).expect("input dir");
    write_collection(&input);

    let silent_out = scratch.path().join("silent");
    let observed_out = scratch.path().join("observed");

    run(&input, &silent_out, None);

    let events: Arc<Mutex<Vec<ProgressEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&events);
    let sink: ProgressSink = Arc::new(move |event| recorder.lock().unwrap().push(event));
    run(&input, &observed_out, Some(sink));

    assert_eq!(
        published_bytes(&silent_out.join("collection_anon")),
        published_bytes(&observed_out.join("collection_anon")),
        "installing a progress sink altered the published collection"
    );

    assert!(
        !events.lock().unwrap().is_empty(),
        "the sink was installed but never called"
    );
}

#[test]
fn the_event_stream_matches_the_work_actually_done() {
    let scratch = Scratch::new("events");
    let input = scratch.path().join("input");
    std::fs::create_dir_all(&input).expect("input dir");
    write_collection(&input);

    let events: Arc<Mutex<Vec<ProgressEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&events);
    let sink: ProgressSink = Arc::new(move |event| recorder.lock().unwrap().push(event));
    run(&input, &scratch.path().join("out"), Some(sink));

    let events = events.lock().unwrap().clone();

    // Phases arrive in order, each opened and closed exactly once.
    let phases: Vec<Phase> = events
        .iter()
        .filter_map(|e| match e {
            ProgressEvent::PhaseStarted { phase, .. } => Some(*phase),
            _ => None,
        })
        .collect();
    assert_eq!(
        phases,
        vec![Phase::Discovery, Phase::TransformVerify, Phase::Publish]
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ProgressEvent::PhaseFinished))
            .count(),
        3,
        "every phase must close, or the bar is left hanging"
    );

    // Discovery cannot know its size up front; transform+verify must, since the
    // bar it drives is determinate.
    let totals: Vec<Option<u64>> = events
        .iter()
        .filter_map(|e| match e {
            ProgressEvent::PhaseStarted { total, .. } => Some(*total),
            _ => None,
        })
        .collect();
    assert_eq!(totals, vec![None, Some(OBJECTS * 2), None]);

    // Units advanced inside each phase, split at the phase boundaries.
    let mut per_phase: Vec<u64> = Vec::new();
    let mut current = 0u64;
    for event in &events {
        match event {
            ProgressEvent::Advanced(units) => current += units,
            ProgressEvent::PhaseFinished => {
                per_phase.push(current);
                current = 0;
            }
            ProgressEvent::PhaseStarted { .. } => current = 0,
        }
    }

    // Discovery walks every object once. Transform+verify walks each object
    // twice — once transforming, once re-deriving it independently — and must
    // land exactly on its declared total, never short and never over.
    assert_eq!(per_phase[0], OBJECTS, "discovery undercounted objects");
    assert_eq!(
        per_phase[1],
        OBJECTS * 2,
        "transform+verify did not finish on its declared total"
    );
    assert_eq!(per_phase[2], 0, "publish is indivisible and ticks no units");
}
