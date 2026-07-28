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

// ---------------------------------------------------------------------------
// Deliberate divergences from the reference implementation.
//
// These are cases the reference gets wrong, so they are asserted here rather
// than added to `tests/truth/components.json` — that file is the record of what
// the reference produces, and it should stay that.
// ---------------------------------------------------------------------------

/// A named SQL instance is not a port, and must not survive as one.
///
/// MS-ADTS permits `MSSQLSvc/<fqdn>:<instancename>` alongside
/// `MSSQLSvc/<fqdn>:<port>`. The reference treats every `:<suffix>` as a port
/// and copies it through, so an organization's instance name reached the output
/// — and cleared the leak gate, because the rest of the SPN did change.
#[test]
fn spn_named_instance_is_remapped_but_a_port_number_is_not() {
    let mut reg = Stub;

    // Numeric suffix: a port identifies nobody and stays verbatim.
    assert_eq!(
        transform_spn(&mut reg, "MSSQLSvc/sql01.contoso.local:1433"),
        "MSSQLSvc/M<hosts|sql01>.M<domains|contoso>.local:1433"
    );

    // Non-numeric suffix: an instance name is a name, and is remapped as one.
    assert_eq!(
        transform_spn(&mut reg, "MSSQLSvc/sql01.contoso.local:SAGE_PROD"),
        "MSSQLSvc/M<hosts|sql01>.M<domains|contoso>.local:M<accounts|SAGE_PROD>"
    );
}

/// A DN carrying a schema-extended RDN attribute type must not be decomposed.
///
/// `transform_dn` emits attribute types verbatim — correct for the standard
/// set, which is schema rather than data. A directory that puts its own
/// attribute in an RDN would have that type published no matter how well the
/// value was redacted, and neither the policy's source gate nor the verifier's
/// output gate could see it, because both only asked whether an `=` was
/// present.
#[test]
fn dn_attribute_type_allowlist_admits_the_standard_set_only() {
    // Everything Active Directory actually builds DNs from.
    assert!(dn_attribute_types_are_standard(
        "CN=Bob,OU=Staff,DC=contoso,DC=local"
    ));
    assert!(dn_attribute_types_are_standard(
        "UID=bob,STREET=1 Main,L=Springfield,ST=IL,C=US,O=Contoso"
    ));
    // Attribute types are case-insensitive.
    assert!(dn_attribute_types_are_standard("cn=Bob,ou=Staff,dc=local"));
    // Multi-valued RDNs are checked component by component.
    assert!(dn_attribute_types_are_standard("CN=Bob+UID=bob,DC=local"));

    // A schema extension is not admitted, whatever else the DN contains.
    assert!(!dn_attribute_types_are_standard(
        "CN=Bob,ACMEPAYROLLID=99,DC=contoso,DC=local"
    ));
    assert!(!dn_attribute_types_are_standard(
        "CN=Bob+ACMEPAYROLLID=99,DC=local"
    ));
    // A malformed AVA is not a well-formed RDN either.
    assert!(!dn_attribute_types_are_standard(
        "CN=Bob,justastring,DC=local"
    ));
}

/// The standard types still decompose exactly as before — the allowlist gates
/// which DNs are decomposed, it does not change how a permitted one is mapped.
#[test]
fn dn_transform_of_standard_types_is_unchanged() {
    let mut reg = Stub;
    assert_eq!(
        transform_dn(&mut reg, "CN=Bob,OU=Staff,DC=contoso,DC=local", None),
        "CN=M<accounts|Bob>,OU=M<accounts|Staff>,DC=M<domains|contoso>,DC=local"
    );
}
