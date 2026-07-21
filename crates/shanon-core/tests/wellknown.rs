//! `wellknown` predicates against the committed ground-truth fixtures, using a
//! fake catalog built from the same catalog-derived facts (the catalog itself is P1).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::wellknown::{
    is_builtin_name, is_builtin_rid, is_wellknown_guid, is_wellknown_sid, WellKnownCatalog,
};

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

struct FakeCatalog {
    canonical_names: BTreeSet<String>,
    core_sids: BTreeSet<String>,
    core_rids: BTreeSet<String>,
    wellknown_guids: BTreeSet<String>,
}

impl WellKnownCatalog for FakeCatalog {
    fn sid_is_core_global_default(&self, sid: &str) -> bool {
        self.core_sids.contains(sid)
    }
    fn is_core_canonical_name(&self, folded_name: &str) -> bool {
        self.canonical_names.contains(folded_name)
    }
    fn is_core_rid(&self, rid: &str) -> bool {
        self.core_rids.contains(rid)
    }
    fn is_wellknown_guid(&self, normalized_guid: &str) -> bool {
        self.wellknown_guids.contains(normalized_guid)
    }
}

#[test]
fn wellknown_predicates_match_reference() {
    let t = truth("wellknown.json");

    let canonical_names: BTreeSet<String> = t["core_canonical_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // Build the fake catalog's positive sets directly from the true answers, so
    // this exercises the wrapper's normalization (strip/casefold/lower/str(rid)).
    let core_sids: BTreeSet<String> = t["sids"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p[1].as_bool().unwrap())
        .map(|p| p[0].as_str().unwrap().to_string())
        .collect();
    let core_rids: BTreeSet<String> = t["rids"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p[1].as_bool().unwrap())
        .map(|p| p[0].as_i64().unwrap().to_string())
        .collect();
    let wellknown_guids: BTreeSet<String> = t["guids"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p[1].as_bool().unwrap())
        // store the normalized (trim+lower) form the catalog would hold
        .map(|p| p[0].as_str().unwrap().trim().to_lowercase())
        .collect();

    let catalog = FakeCatalog {
        canonical_names,
        core_sids,
        core_rids,
        wellknown_guids,
    };

    for p in t["sids"].as_array().unwrap() {
        let sid = p[0].as_str().unwrap();
        assert_eq!(
            is_wellknown_sid(&catalog, sid),
            p[1].as_bool().unwrap(),
            "sid {sid}"
        );
    }
    for p in t["names"].as_array().unwrap() {
        let name = p[0].as_str().unwrap();
        assert_eq!(
            is_builtin_name(&catalog, name),
            p[1].as_bool().unwrap(),
            "name {name:?}"
        );
    }
    for p in t["rids"].as_array().unwrap() {
        let rid = p[0].as_i64().unwrap();
        assert_eq!(
            is_builtin_rid(&catalog, rid),
            p[1].as_bool().unwrap(),
            "rid {rid}"
        );
    }
    for p in t["guids"].as_array().unwrap() {
        let guid = p[0].as_str().unwrap();
        assert_eq!(
            is_wellknown_guid(&catalog, guid),
            p[1].as_bool().unwrap(),
            "guid {guid:?}"
        );
    }
}
