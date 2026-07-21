//! `components` structural transforms byte-exact against the ground-truth
//! fixtures, driven by a stub registry whose string contract matches exactly.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use shanon_core::components::*;

fn truth(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/truth")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Byte-identical to the `ComponentsStub` reference fixture contract.
struct Stub;
impl RegistryOps for Stub {
    fn map(&mut self, category: &str, real: &str) -> String {
        format!("M<{category}|{real}>")
    }
    fn bind(
        &mut self,
        _category: &str,
        _real: &str,
        pseudonym: &str,
        _preserve_terminal: Option<bool>,
    ) -> String {
        pseudonym.to_string()
    }
    fn sid_subauthority(&mut self, real: &str) -> String {
        format!("SA<{real}>")
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}
fn b(v: &Value) -> bool {
    v.as_bool().unwrap()
}

type DnCallback = Box<dyn Fn(&str, &str) -> bool>;

fn dn_callback(name: &str) -> Option<DnCallback> {
    match name {
        "none" => None,
        "preserve_ou" => Some(Box::new(|k: &str, _v: &str| k == "OU")),
        "preserve_cn_set" => Some(Box::new(|k: &str, v: &str| {
            k == "CN" && (v == "Domain Admins" || v == "Users")
        })),
        other => panic!("unknown dn callback {other}"),
    }
}

#[test]
fn components_match_reference() {
    let cases = truth("components.json");
    let arr = cases.as_array().unwrap();
    assert!(arr.len() > 50, "expected a broad components corpus");

    for case in arr {
        let mut reg = Stub;
        let fnname = s(&case["fn"]);
        let args = case["args"].as_array().unwrap();
        let expected = s(&case["output"]);

        let got = match fnname {
            "transform_sid" => transform_sid(&mut reg, s(&args[0]), b(&args[1])),
            "transform_domain" => transform_domain(&mut reg, s(&args[0])),
            "transform_name_token" => transform_name_token(&mut reg, s(&args[0]), b(&args[1])),
            "transform_guid" => transform_guid(&mut reg, s(&args[0]), b(&args[1])),
            "transform_samaccountname" => transform_samaccountname(&mut reg, s(&args[0])),
            "transform_upn_name" => transform_upn_name(&mut reg, s(&args[0])),
            "transform_email" => transform_email(&mut reg, s(&args[0])),
            "transform_dnshostname" => transform_dnshostname(&mut reg, s(&args[0])),
            "transform_path" => transform_path(&mut reg, s(&args[0])),
            "transform_url" => transform_url(&mut reg, s(&args[0])),
            "transform_dn" => {
                let cb = dn_callback(s(&args[1]));
                transform_dn(&mut reg, s(&args[0]), cb.as_deref())
            }
            "transform_oid" => transform_oid(&mut reg, s(&args[0]), b(&args[1])),
            "transform_template_name" => {
                transform_template_name(&mut reg, s(&args[0]), b(&args[1]))
            }
            "transform_ad_local_group_name" => {
                transform_ad_local_group_name(&mut reg, s(&args[0]), b(&args[1]))
            }
            "transform_spn" => transform_spn(&mut reg, s(&args[0])),
            other => panic!("unhandled fn {other}"),
        };

        assert_eq!(got, expected, "{fnname}({args:?}) diverged");
    }
}
