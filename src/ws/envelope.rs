//! Build the WS-Enumeration SOAP requests as text XML, ported from go-adws
//! `soap/build_enumeration.go`. The text is then turned into NBFSE bytes by
//! [`crate::ws::nbfx::encode_nbfse_request`].

use base64::Engine;

use crate::control::{SdFlags, SHOW_DELETED_OID};
use crate::types::Scope;

// WS-* constants (from go-adws soap/*.go).
pub const ACTION_ENUMERATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
pub const ACTION_PULL: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";
pub const ACTION_RELEASE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release";
pub const ADDRESS_ANONYMOUS: &str = "http://www.w3.org/2005/08/addressing/anonymous";
pub const RESOURCE_INSTANCE: &str =
    "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/Instance";
pub const DIALECT_LDAP_QUERY: &str =
    "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery";
pub const DIALECT_XPATH_L1: &str =
    "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1";

pub(crate) fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn message_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

fn scope_str(scope: Scope) -> &'static str {
    match scope {
        Scope::Base => "base",
        Scope::OneLevel => "onelevel",
        Scope::Subtree => "subtree",
    }
}

fn selection_xml(attrs: &[&str]) -> String {
    let props: String = attrs
        .iter()
        .map(|a| {
            let p = if *a == "*" { "ad:all".to_string() } else { format!("addata:{a}") };
            format!("            <ad:SelectionProperty>{}</ad:SelectionProperty>\n", escape_xml(&p))
        })
        .collect();
    format!("            <ad:Selection Dialect=\"{DIALECT_XPATH_L1}\">\n{props}            </ad:Selection>\n")
}

/// Build the `<ad:controls>` header mirroring the LDAP controls RustHound-CE
/// sends (SD flags, show-deleted). Empty string when nothing is requested.
pub fn build_control_header(sd_flags: Option<SdFlags>, show_deleted: bool) -> String {
    let mut controls = String::new();
    if let Some(sd) = sd_flags {
        let value = base64::engine::general_purpose::STANDARD.encode(sd.der_value());
        controls.push_str(&format!(
            "<ad:control type=\"{oid}\" criticality=\"true\"><ad:controlValue xsi:type=\"xsd:base64Binary\">{value}</ad:controlValue></ad:control>",
            oid = SdFlags::OID,
        ));
    }
    if show_deleted {
        controls.push_str(&format!("<ad:control type=\"{SHOW_DELETED_OID}\" criticality=\"false\"></ad:control>"));
    }
    if controls.is_empty() {
        String::new()
    } else {
        format!("            <ad:controls>{controls}</ad:controls>\n")
    }
}

/// Build a WS-Enumeration `Enumerate` request envelope (text XML).
///
/// `to` is the endpoint's net.tcp URL (same as the NMF Via), e.g.
/// `net.tcp://dc:9389/ActiveDirectoryWebServices/Windows/Enumeration`. ADWS
/// matches this against the endpoint's AddressFilter, so it must be the endpoint
/// URL, not the logical `Data/Instance` URI (confirmed against SOAPy).
pub fn build_enumerate_request(
    to: &str,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attrs: &[&str],
    ldap_port: u16,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
        <ad:instance>ldap:{ldap_port}</ad:instance>
        <wsa:MessageID>{msg_id}</wsa:MessageID>
        <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">{to}</wsa:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
        <wsen:Enumerate>
            <wsen:Filter Dialect="{dialect}">
                <adlq:LdapQuery>
                    <adlq:Filter>{filter}</adlq:Filter>
                    <adlq:BaseObject>{base}</adlq:BaseObject>
                    <adlq:Scope>{scope}</adlq:Scope>
                </adlq:LdapQuery>
            </wsen:Filter>
{selection}        </wsen:Enumerate>
    </s:Body>
</s:Envelope>"#,
        action = ACTION_ENUMERATE,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        dialect = DIALECT_LDAP_QUERY,
        filter = escape_xml(filter),
        base = escape_xml(base_dn),
        scope = scope_str(scope),
        selection = selection_xml(attrs),
    )
}

/// Build a WS-Enumeration `Pull` request envelope (text XML), with the SD-flags
/// / show-deleted controls header.
pub fn build_pull_request(
    to: &str,
    enumeration_context: &str,
    max_elements: usize,
    sd_flags: Option<SdFlags>,
    show_deleted: bool,
) -> String {
    let controls = build_control_header(sd_flags, show_deleted);
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
        <wsa:MessageID>{msg_id}</wsa:MessageID>
        <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">{to}</wsa:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Pull>
            <wsen:EnumerationContext>{ctx}</wsen:EnumerationContext>
            <wsen:MaxElements>{max}</wsen:MaxElements>
{controls}        </wsen:Pull>
    </s:Body>
</s:Envelope>"#,
        action = ACTION_PULL,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        ctx = escape_xml(enumeration_context),
        max = max_elements,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TO: &str = "net.tcp://dc:9389/ActiveDirectoryWebServices/Windows/Enumeration";

    #[test]
    fn enumerate_request_has_query() {
        let r = build_enumerate_request(
            TO,
            "DC=essos,DC=local",
            Scope::Subtree,
            "(objectClass=user)",
            &["cn", "objectSid"],
            389,
        );
        assert!(r.contains("wsen:Enumerate"));
        assert!(r.contains("<adlq:Scope>subtree</adlq:Scope>"));
        assert!(r.contains("(objectClass=user)"));
        assert!(r.contains("addata:objectSid"));
        assert!(r.contains(ACTION_ENUMERATE));
        assert!(r.contains("Windows/Enumeration</wsa:To>"));
    }

    #[test]
    fn pull_request_has_controls() {
        let r = build_pull_request(TO, "ctx-1", 256, Some(SdFlags::OWNER_DACL), false);
        assert!(r.contains("wsen:Pull"));
        assert!(r.contains("<wsen:MaxElements>256</wsen:MaxElements>"));
        assert!(r.contains("MAMCAQU=")); // SD-flags value
        assert!(r.contains("ctx-1"));
    }

    #[test]
    fn requests_encode_to_nbfse() {
        // The whole request must survive text -> NBFX -> NBFSE -> decode.
        let xml = build_enumerate_request(TO, "DC=x", Scope::Base, "(cn=*)", &["cn"], 389);
        let payload = crate::ws::nbfx::encode_nbfse_request(&xml).unwrap();
        let mut sess = crate::ws::nbfx::NbfseSession::new();
        let root = crate::ws::nbfx::decode_nbfse(&mut sess, &payload).unwrap();
        assert_eq!(root.name, "Envelope");
    }
}
