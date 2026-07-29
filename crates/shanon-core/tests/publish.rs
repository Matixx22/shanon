//! The publish path: what a failed run must leave behind, which is nothing.
//!
//! Invariant 1 says a run that cannot verify does not publish. That was only
//! ever asserted at the primitive level — `platform`'s no-replace rename has
//! its own test — and never through `anonymize_collection`, which is where the
//! guarantee actually has to hold: a failure has to leave no output collection,
//! no mapping file, and no staging directory. The mapping file matters most.
//! It carries the real↔fake table in the clear, it is written *before* the
//! collection, and a run that says "no output written" while leaving one behind
//! is worse than one that never started.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use shanon_core::pipeline::{anonymize_collection, ShanonError};
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::{Registry, RegistryError};

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("shanon-publish-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// A one-member collection directory.
    fn collection(&self, name: &str) -> PathBuf {
        let dir = self.path(name);
        fs::create_dir_all(&dir).expect("collection dir");
        let doc = json!({
            "data": [{
                "Properties": {
                    "domain": DOMAIN,
                    "name": format!("JDOE@{DOMAIN}"),
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
        fs::write(dir.join("users.json"), serde_json::to_vec(&doc).unwrap()).expect("member");
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(input: &Path, out: &Path, map: Option<&Path>, reuse: Registry) -> Result<(), ShanonError> {
    anonymize_collection(
        input,
        out,
        reuse,
        true,
        PolicyConfig::default(),
        PolicyAudit::new(),
        map,
        None,
        None,
    )
    .map(|_| ())
}

/// Assert the complete "nothing was written" property for one failed run.
fn assert_nothing_published(out: &Path, map: &Path) {
    assert!(
        !map.exists(),
        "the mapping file survived a failed run — it holds the real↔fake table \
         in the clear, and stderr claimed no output was written"
    );
    assert!(
        !out.join("collection_anon").exists(),
        "an output collection survived a failed run"
    );
    assert!(
        !out.join("collection_anon.zip").exists(),
        "an output archive survived a failed run"
    );
    if out.exists() {
        let leftovers: Vec<String> = fs::read_dir(out)
            .expect("read output dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed run left {leftovers:?} in the output directory — staging is \
             `.<dest>.<hex>.tmp` inside it and must not outlive the failure"
        );
    }
}

/// A reuse map whose stored pseudonym for a value *is* that value is refused
/// by the loader, before a pipeline that would have published it can start.
///
/// This is the earliest of the fail-closed gates and the cheapest to get wrong:
/// such a map is structurally valid JSON in the right format, and only a
/// semantic check catches it.
#[test]
fn a_map_that_maps_a_value_to_itself_is_refused_at_load() {
    let poisoned: Value = json!({
        "salt": "0123456789abcdef0123456789abcdef",
        "format_version": 2,
        "categories": {"accounts": {"jdoe": "jdoe"}}
    });
    let err = Registry::from_value(&poisoned)
        .expect_err("a mapping that leaves its source unchanged must be refused");
    assert!(
        matches!(err, RegistryError::UnsafeMapping(_)),
        "expected an unsafe-mapping refusal, got {err:?}"
    );
}

/// The headline guarantee: a run that aborts publishes nothing at all.
///
/// The abort is driven by a member that parses as a collection document but
/// carries no `meta`, which the engine refuses. That is a real abort inside
/// `anonymize_collection` rather than a pre-flight refusal, and it takes the
/// valid sibling member down with it — see the note in
/// `an_unparseable_member_aborts_the_whole_collection`.
#[test]
fn an_aborted_run_writes_no_output_no_map_and_no_staging() {
    let scratch = Scratch::new("abort");
    let input = scratch.collection("collection");
    // Parses, has a `data` array, has no `meta`.
    fs::write(input.join("stray.json"), br#"{"data":[]}"#).expect("stray member");
    let out = scratch.path("out");
    let map = scratch.path("collection.map.json");

    let result = run(&input, &out, Some(&map), Registry::new("test-salt"));

    assert!(
        result.is_err(),
        "a member with no `meta` must abort the run"
    );
    assert_nothing_published(&out, &map);
}

/// A dangling symlink at the destination is refused like any other occupant.
///
/// This is the one destination check that could plausibly go wrong: the target
/// does not exist, so a plain `exists()` answers false and the run would
/// proceed to write a mapping file for a collection whose publish is going to
/// fail anyway.
///
/// Unix-only: creating a symlink on Windows needs either developer mode or
/// `SeCreateSymbolicLinkPrivilege`, so the test would report a privilege failure
/// rather than a publish failure. The behaviour it pins is covered on Windows by
/// `MoveFileExW` refusing an occupied destination, which does not resolve
/// reparse points either.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_at_the_destination_is_refused_before_the_map_is_written() {
    let scratch = Scratch::new("dangling");
    let input = scratch.collection("collection");
    let out = scratch.path("out");
    let map = scratch.path("collection.map.json");

    fs::create_dir_all(&out).expect("output dir");
    std::os::unix::fs::symlink(scratch.path("does-not-exist"), out.join("collection_anon"))
        .expect("dangling symlink");

    let result = run(&input, &out, Some(&map), Registry::new("test-salt"));

    assert!(result.is_err(), "a dangling destination must be refused");
    assert!(
        !map.exists(),
        "a mapping file was written for a publish that could never succeed"
    );
    assert!(
        out.join("collection_anon").is_symlink(),
        "the symlink was followed or replaced instead of refused"
    );
}

/// A member that is not a SharpHound document aborts the entire collection
/// rather than being skipped, taking every valid member with it.
///
/// This pins current behavior, and current behavior is arguably wrong: the
/// accept predicate (`parse_collection_member`, which asks only for a `data`
/// array) and the skip path disagree with the engine, which additionally
/// requires `meta`. A stray file in a collection directory therefore fails the
/// whole run, and the message does not name the member. Fixing that means
/// making the two predicates agree — at which point this test should be
/// rewritten to assert a skip.
#[test]
fn an_unparseable_member_aborts_the_whole_collection() {
    let scratch = Scratch::new("stray");
    let input = scratch.collection("collection");
    fs::write(input.join("stray.json"), br#"{"data":[]}"#).expect("stray member");
    let out = scratch.path("out");

    let err = run(&input, &out, None, Registry::new("test-salt"))
        .expect_err("a member with no `meta` currently aborts");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("meta"),
        "the abort should at least say what was missing: {rendered}"
    );
}

/// An existing destination is refused, and refusing it does not disturb what is
/// already there — nor leave a mapping file for a collection never written.
#[test]
fn an_existing_destination_is_refused_and_left_intact() {
    let scratch = Scratch::new("exists");
    let input = scratch.collection("collection");
    let out = scratch.path("out");
    let map = scratch.path("collection.map.json");

    // Something is already at the destination.
    let dest = out.join("collection_anon");
    fs::create_dir_all(&dest).expect("pre-existing destination");
    fs::write(dest.join("keep.json"), b"{\"keep\":true}").expect("pre-existing file");

    let result = run(&input, &out, Some(&map), Registry::new("test-salt"));

    assert!(
        result.is_err(),
        "an existing destination must be refused, never replaced"
    );
    assert_eq!(
        fs::read(dest.join("keep.json")).unwrap(),
        b"{\"keep\":true}",
        "the pre-existing destination was modified"
    );
    assert!(
        !map.exists(),
        "a mapping file was written for a collection that was never published"
    );
    let leftovers: Vec<String> = fs::read_dir(&out)
        .expect("read output dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        leftovers,
        ["collection_anon"],
        "the refusal left something behind besides the destination itself"
    );
}

/// A successful run is the control: it writes exactly the two things it says it
/// does, and no staging directory outlives it.
#[test]
fn a_successful_run_leaves_only_the_collection_and_the_map() {
    let scratch = Scratch::new("success");
    let input = scratch.collection("collection");
    let out = scratch.path("out");
    let map = scratch.path("collection.map.json");

    run(&input, &out, Some(&map), Registry::new("test-salt")).expect("clean run");

    assert!(map.is_file(), "the mapping file is the run's other output");
    let leftovers: Vec<String> = fs::read_dir(&out)
        .expect("read output dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        leftovers,
        ["collection_anon"],
        "a staging directory outlived a successful run"
    );
}
