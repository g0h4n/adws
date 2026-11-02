//! Flatten an ADWS directory object into a [`SearchEntry`] that matches ldap3's
//! `attrs` / `bin_attrs` split exactly. This is the impedance match that lets
//! RustHound-CE's parsers (`secdesc.rs`, `acl.rs`, `sid.rs`) work unchanged.
//!
//! Routing rule (mirrors ldap3, which bins non-UTF-8 values):
//! - `base64Binary` / raw bytes  => `bin_attrs`
//! - text                        => `attrs`
//!
//! [`BINARY_ATTRS`] is a safety hint for attributes RustHound reads from
//! `bin_attrs`; a parser that receives one as text (e.g. an unexpected hex/raw
//! form) can consult [`is_known_binary`] to route it correctly.

use std::collections::HashMap;

use base64::Engine;

use crate::error::{AdwsError, Result};
use crate::types::SearchEntry;

/// A single attribute value as it comes off an ADWS response.
#[derive(Debug, Clone)]
pub enum AttrValue {
    /// A text value (`attrs`).
    Text(String),
    /// A `base64Binary`-typed value (decoded into `bin_attrs`).
    Base64(String),
    /// Already-decoded raw bytes (`bin_attrs`).
    Bytes(Vec<u8>),
}

/// AD attributes that are inherently binary and that RustHound-CE reads from
/// `bin_attrs`. Matched case-insensitively. Not exhaustive - a hint.
pub const BINARY_ATTRS: &[&str] = &[
    "objectsid",
    "objectguid",
    "ntsecuritydescriptor",
    "msds-keycredentiallink",
    "msds-allowedtoactonbehalfofotheridentity",
    "sidhistory",
    "cacertificate",
    "usercertificate",
    "schemaidguid",
    "attributesecurityguid",
    "dnsrecord",
    "logonhours",
    "auditingpolicy",
    "pkiexpirationperiod",
    "pkioverlapperiod",
];

/// Whether `name` is a known-binary attribute (case-insensitive).
pub fn is_known_binary(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    BINARY_ATTRS.contains(&lower.as_str())
}

/// Flatten `(dn, attributes)` into a [`SearchEntry`].
pub fn object_to_entry(dn: String, attributes: Vec<(String, Vec<AttrValue>)>) -> Result<SearchEntry> {
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
    let mut bin_attrs: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    for (name, values) in attributes {
        let known_binary = is_known_binary(&name);
        for value in values {
            match value {
                AttrValue::Base64(b64) => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64.trim())
                        .map_err(|e| AdwsError::Xml(format!("base64 in {name}: {e}")))?;
                    bin_attrs.entry(name.clone()).or_default().push(bytes);
                }
                AttrValue::Bytes(bytes) => {
                    bin_attrs.entry(name.clone()).or_default().push(bytes);
                }
                AttrValue::Text(text) if known_binary => {
                    // A known-binary attr arriving as text: keep its bytes so the
                    // downstream binary parser still finds it.
                    bin_attrs.entry(name.clone()).or_default().push(text.into_bytes());
                }
                AttrValue::Text(text) => {
                    attrs.entry(name.clone()).or_default().push(text);
                }
            }
        }
    }

    Ok(SearchEntry { dn, attrs, bin_attrs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_goes_to_attrs() {
        let e = object_to_entry(
            "CN=Jon,DC=essos,DC=local".into(),
            vec![
                ("sAMAccountName".into(), vec![AttrValue::Text("jon".into())]),
                (
                    "memberOf".into(),
                    vec![AttrValue::Text("CN=A".into()), AttrValue::Text("CN=B".into())],
                ),
            ],
        )
        .unwrap();
        assert_eq!(e.attrs["sAMAccountName"], vec!["jon"]);
        assert_eq!(e.attrs["memberOf"].len(), 2);
        assert!(e.bin_attrs.is_empty());
    }

    #[test]
    fn base64_goes_to_bin_attrs_decoded() {
        // base64("ABC") = "QUJD"
        let e = object_to_entry(
            "x".into(),
            vec![("objectSid".into(), vec![AttrValue::Base64("QUJD".into())])],
        )
        .unwrap();
        assert!(e.attrs.is_empty());
        assert_eq!(e.bin_attrs["objectSid"], vec![b"ABC".to_vec()]);
    }

    #[test]
    fn known_binary_text_is_binned() {
        let e = object_to_entry(
            "x".into(),
            vec![("nTSecurityDescriptor".into(), vec![AttrValue::Text("raw".into())])],
        )
        .unwrap();
        assert!(e.attrs.is_empty());
        assert_eq!(e.bin_attrs["nTSecurityDescriptor"], vec![b"raw".to_vec()]);
    }

    #[test]
    fn bad_base64_errors() {
        let r = object_to_entry(
            "x".into(),
            vec![("objectGUID".into(), vec![AttrValue::Base64("!!!!".into())])],
        );
        assert!(r.is_err());
    }
}
