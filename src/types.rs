//! Directory types, field-compatible with the `ldap3` crate.

use std::collections::HashMap;

/// A directory entry, field-for-field compatible with `ldap3::SearchEntry`.
///
/// `attrs` holds UTF-8 string values; `bin_attrs` holds raw bytes for
/// non-UTF-8 attributes such as `objectSid`, `objectGUID`,
/// `nTSecurityDescriptor` and `msDS-KeyCredentialLink`. When parsing an ADWS
/// response (XML, often `base64Binary`), values MUST be routed to the same
/// bucket ldap3 would use, or downstream parsers that read `bin_attrs` break.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// Search scope, mirroring `ldap3::Scope`. Maps onto the ADWS enumeration scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
}

/// A single attribute value in a modification: UTF-8 text or raw bytes.
///
/// `Text` is rendered as `xsi:type="xsd:string"`; `Bytes` is base64-encoded and
/// rendered as `xsi:type="xsd:base64Binary"` (needed for binary attributes such
/// as `nTSecurityDescriptor` or `msDS-KeyCredentialLink`).
#[derive(Debug, Clone)]
pub enum Value {
    Text(String),
    Bytes(Vec<u8>),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}
impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

/// A single modification applied by a WS-Transfer `Put`. Each variant maps onto
/// an IMDA `da:Change` (add / replace / delete).
#[derive(Debug, Clone)]
pub enum Mod {
    Add(String, Vec<Value>),
    Delete(String, Vec<Value>),
    Replace(String, Vec<Value>),
}

impl Mod {
    /// Add values to an attribute.
    pub fn add(attr: impl Into<String>, values: impl IntoIterator<Item = impl Into<Value>>) -> Mod {
        Mod::Add(attr.into(), values.into_iter().map(Into::into).collect())
    }

    /// Replace all values of an attribute. Pass no values to clear it.
    pub fn replace(
        attr: impl Into<String>,
        values: impl IntoIterator<Item = impl Into<Value>>,
    ) -> Mod {
        Mod::Replace(attr.into(), values.into_iter().map(Into::into).collect())
    }

    /// Delete specific values; pass none to remove all values of the attribute.
    pub fn delete(
        attr: impl Into<String>,
        values: impl IntoIterator<Item = impl Into<Value>>,
    ) -> Mod {
        Mod::Delete(attr.into(), values.into_iter().map(Into::into).collect())
    }

    /// Delete all values of an attribute.
    pub fn delete_all(attr: impl Into<String>) -> Mod {
        Mod::Delete(attr.into(), Vec::new())
    }
}

#[cfg(feature = "ldap3")]
mod ldap3_compat {
    use super::{Scope, SearchEntry};

    impl From<ldap3::SearchEntry> for SearchEntry {
        fn from(e: ldap3::SearchEntry) -> Self {
            SearchEntry { dn: e.dn, attrs: e.attrs, bin_attrs: e.bin_attrs }
        }
    }

    impl From<SearchEntry> for ldap3::SearchEntry {
        fn from(e: SearchEntry) -> Self {
            ldap3::SearchEntry { dn: e.dn, attrs: e.attrs, bin_attrs: e.bin_attrs }
        }
    }

    impl From<Scope> for ldap3::Scope {
        fn from(s: Scope) -> Self {
            match s {
                Scope::Base => ldap3::Scope::Base,
                Scope::OneLevel => ldap3::Scope::OneLevel,
                Scope::Subtree => ldap3::Scope::Subtree,
            }
        }
    }
}
