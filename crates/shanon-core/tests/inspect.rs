//! `inspect_collection`: the read-only dry run.
//!
//! Two properties matter and are pinned here. It must write nothing — the whole
//! point is that an operator can run it against a collection that cannot leave
//! their machine. And it must agree with a real run about whether that
//! collection would publish, since a dry run that disagrees is worse than none.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use shanon_core::pipeline::{anonymize_collection, inspect_collection};
use shanon_core::policy::{PolicyAudit, PolicyConfig};
use shanon_core::registry::Registry;

const DOMAIN: &str = "SOUTHRIDGE.LOCAL";
const DOMAIN_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333";

/// A scratch directory that removes itself, so a failing assertion cannot leave
/// state behind for the next run to trip over.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("shanon-inspect-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn write(&self, name: &str, doc: &Value) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).expect("parent");
        fs::write(&path, serde_json::to_vec(doc).unwrap()).expect("write fixture");
        path
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A BloodHound CE shaped users collection: `meta.version` 6, lowercase
/// property keys, a domain-qualified principal, a GUID principal, an empty
/// attribute, and CE-only blocks the rule table does not model.
fn ce_users() -> Value {
    json!({
        "data": [{
            "Properties": {
                "domain": DOMAIN,
                "name": format!("JDOE@{DOMAIN}"),
                "distinguishedname": "CN=jdoe,CN=Users,DC=SOUTHRIDGE,DC=LOCAL",
                "domainsid": DOMAIN_SID,
                "samaccountname": "jdoe",
                "email": "",
                "whencreated": 1600000000,
            },
            "ObjectIdentifier": format!("{DOMAIN_SID}-1104"),
            "PrimaryGroupSID": format!("{DOMAIN_SID}-513"),
            "ContainedBy": {
                "ObjectIdentifier": "ABCD1234-1111-2222-3333-444455556666",
                "ObjectType": "Container",
            },
            "Aces": [
                {"PrincipalSID": format!("{DOMAIN}-S-1-5-32-544"), "PrincipalType": "Group",
                 "RightName": "GenericAll", "IsInherited": false},
                {"PrincipalSID": format!("{DOMAIN_SID}-513"), "PrincipalType": "Group",
                 "RightName": "Owns", "IsInherited": false},
                {"PrincipalSID": "ABCD1234-1111-2222-3333-444455556666",
                 "PrincipalType": "Container", "RightName": "Owns", "IsInherited": false},
            ],
            "SPNTargets": [],
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "IsDeleted": false,
            "IsACLProtected": false,
        }],
        "meta": {"methods": 46067, "type": "users", "count": 1, "version": 6},
    })
}

fn report(input: &Path) -> shanon_core::pipeline::InspectReport {
    inspect_collection(
        input,
        Registry::new("test-salt"),
        PolicyConfig::default(),
        PolicyAudit::new(),
        None,
    )
    .expect("inspect")
}

/// The headline guarantee: a dry run leaves the filesystem exactly as it found
/// it. No output collection, no mapping, no staging directory.
#[test]
fn inspect_writes_nothing() {
    let scratch = Scratch::new("writes-nothing");
    scratch.write("collection/users.json", &ce_users());
    let input = scratch.path("collection");

    let before: Vec<_> = fs::read_dir(&scratch.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let report = report(&input);
    let after: Vec<_> = fs::read_dir(&scratch.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();

    assert!(report.would_publish());
    assert_eq!(before, after, "inspect created or removed an entry");
    assert_eq!(
        fs::read_dir(&input).unwrap().count(),
        1,
        "inspect touched the input directory"
    );
}

/// A dry run that disagrees with the real thing is worse than no dry run.
#[test]
fn inspect_agrees_with_a_real_run() {
    let scratch = Scratch::new("agrees");
    scratch.write("collection/users.json", &ce_users());
    let input = scratch.path("collection");

    assert!(report(&input).would_publish());

    let out = scratch.path("out");
    let result = anonymize_collection(
        &input,
        &out,
        Registry::new("test-salt"),
        true,
        PolicyConfig::default(),
        PolicyAudit::new(),
        None,
        None,
        None,
    );
    assert!(result.is_ok(), "real run disagreed: {:?}", result.err());
}

/// A CE collection exercises the shapes each of the mapping fixes covers at
/// once: a well-known RID at a declared and an undeclared path, a
/// domain-qualified well-known SID, a GUID principal, and an empty attribute.
#[test]
fn a_ce_shaped_collection_is_accounted_for() {
    let scratch = Scratch::new("ce-shape");
    scratch.write("collection/users.json", &ce_users());
    let report = report(&scratch.path("collection"));

    assert_eq!(report.members_read, 1);
    assert_eq!(report.members_accepted, 1);
    assert!(report.members_skipped.is_empty());
    assert_eq!(report.objects, 1);

    let row = &report.collection_types[0];
    assert_eq!(row.meta_type, "users");
    assert_eq!(row.node_type, "User");
    assert_eq!(row.version, "6");
    assert_eq!(row.objects, 1);

    // CE-only blocks are fields the rule table does not model. They are
    // anonymized, but an operator needs to see that they exist.
    let unknown = report.audit["unknown_paths"]
        .as_object()
        .expect("unknown_paths");
    assert!(!unknown.is_empty(), "ContainedBy should surface as unknown");
}

/// A collection type no ingestor version taught shanon about must be reported,
/// not silently folded into the totals.
#[test]
fn an_unrecognized_collection_type_is_flagged() {
    let scratch = Scratch::new("unknown-type");
    scratch.write(
        "collection/azbase.json",
        &json!({
            "data": [{"Properties": {"name": "thing"},
                      "ObjectIdentifier": "3D0D0F4F-1111-2222-3333-444455556666"}],
            "meta": {"methods": 0, "type": "azbase", "count": 1, "version": 6},
        }),
    );
    let report = report(&scratch.path("collection"));
    let row = &report.collection_types[0];
    assert_eq!(row.meta_type, "azbase");
    assert_eq!(row.node_type, "Unknown");
}

/// A member that is not a SharpHound document is excluded from output by a real
/// run, so the dry run must account for it separately rather than silently.
#[test]
fn a_non_sharphound_member_is_counted_as_skipped() {
    let scratch = Scratch::new("skipped");
    scratch.write("collection/users.json", &ce_users());
    scratch.write("collection/notes.json", &json!({"unrelated": true}));
    let report = report(&scratch.path("collection"));

    assert_eq!(report.members_read, 2);
    assert_eq!(report.members_accepted, 1);
    assert_eq!(report.members_skipped.len(), 1);
    // Synthetic labels only — a real filename must never reach a report.
    assert!(
        report.members_skipped[0].starts_with("member-"),
        "got {}",
        report.members_skipped[0]
    );
}

/// When a collection would abort, the dry run says so and carries the sanitized
/// reason rather than raising it.
#[test]
fn a_collection_that_would_abort_reports_instead_of_failing() {
    let scratch = Scratch::new("would-abort");
    scratch.write(
        "collection/users.json",
        &json!({
            "data": [{"Properties": {"name": "x"}, "ObjectIdentifier": "S-1-5-21-1-2-3-1104"}],
            "meta": {"methods": 0, "type": "", "count": 1, "version": 6},
        }),
    );
    let report = report(&scratch.path("collection"));
    assert!(!report.would_publish());
    let abort = report.abort.expect("abort reason");
    assert!(abort.contains("ABORTED"), "got {abort}");
    // Sanitized: the reason names the document shape, never a value.
    assert!(!abort.contains("S-1-5-21-1-2-3-1104"), "got {abort}");
}
