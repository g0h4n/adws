//! WS-Transfer write requests (Put / Delete) over ADWS, ported from go-adws
//! `soap/build_transfer.go`. These target the `Windows/Resource` endpoint and
//! identify the object by its DN in `<ad:objectReferenceProperty>`.
//!
//! `Create` (on `Windows/ResourceFactory`) is a planned follow-up; the seam is
//! reserved here. Binary-typed values (`xsi:type="xsd:base64Binary"`, needed for
//! e.g. `nTSecurityDescriptor` or `msDS-KeyCredentialLink`) are the next step;
//! this first cut sends string values (`xsd:string`).

use crate::control::SdFlags;
use crate::types::{Mod, Value};
use crate::ws::envelope::{escape_xml, message_id, ADDRESS_ANONYMOUS, DIALECT_XPATH_L1};

pub const ACTION_PUT: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put";
pub const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
pub const ACTION_CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";

/// The ADWS endpoint path for Get / Put / Delete.
pub const ENDPOINT_RESOURCE: &str = "Windows/Resource";
/// The ADWS endpoint path for Create.
pub const ENDPOINT_RESOURCE_FACTORY: &str = "Windows/ResourceFactory";

const CONTROL_PERMISSIVE_MODIFY: &str = "1.2.840.113556.1.4.1413";

fn op_name(m: &Mod) -> &'static str {
    match m {
        Mod::Add(..) => "add",
        Mod::Replace(..) => "replace",
        Mod::Delete(..) => "delete",
    }
}

fn parts(m: &Mod) -> (&str, &[Value]) {
    match m {
        Mod::Add(a, v) | Mod::Replace(a, v) | Mod::Delete(a, v) => (a.as_str(), v.as_slice()),
    }
}

/// Render one `<ad:value>` with the xsi:type matching the value kind.
fn value_xml(v: &Value) -> String {
    use base64::Engine;
    match v {
        Value::Text(s) => {
            format!("        <ad:value xsi:type=\"xsd:string\">{}</ad:value>\n", escape_xml(s))
        }
        Value::Bytes(b) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(b);
            format!("        <ad:value xsi:type=\"xsd:base64Binary\">{b64}</ad:value>\n")
        }
    }
}

/// Qualify an attribute name: a bare local name becomes `addata:<name>`.
fn attr_type(attr: &str) -> String {
    if attr.contains(':') {
        attr.to_string()
    } else {
        format!("addata:{}", escape_xml(attr))
    }
}

/// Render the `<ad:controls>` block: PermissiveModify, plus SDFlags when writing
/// a security descriptor. Matches go-adws `BuildControlsXML`.
fn controls_block(sd_flags: Option<SdFlags>) -> String {
    use base64::Engine;
    let mut b = String::from("  <ad:controls>\n");
    b.push_str(&format!(
        "    <ad:control type=\"{CONTROL_PERMISSIVE_MODIFY}\" criticality=\"true\" />\n"
    ));
    if let Some(sd) = sd_flags {
        // Write-form BER: SEQUENCE { INTEGER flags } with long-form length (go-adws).
        let value = [0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, sd.0 as u8];
        let b64 = base64::engine::general_purpose::STANDARD.encode(value);
        b.push_str(&format!(
            "    <ad:control type=\"{oid}\" criticality=\"true\">\n\
             \x20     <ad:controlValue xsi:type=\"xsd:base64Binary\">{b64}</ad:controlValue>\n\
             \x20   </ad:control>\n",
            oid = SdFlags::OID,
        ));
    }
    b.push_str("  </ad:controls>\n");
    b
}

/// Build the IMDA `da:ModifyRequest` body carrying one or more changes. This is
/// the payload of a WS-Transfer `Put`.
pub fn build_modify_request(mods: &[Mod], sd_flags: Option<SdFlags>) -> String {
    let mut changes = String::new();
    for m in mods {
        let (attr, values) = parts(m);
        let op = op_name(m);
        let mut values_xml = String::new();
        for v in values {
            values_xml.push_str(&value_xml(v));
        }
        // add requires values; replace/delete without values removes all values.
        let attr_value = if values_xml.is_empty() {
            String::new()
        } else {
            format!("      <da:AttributeValue>\n{values_xml}      </da:AttributeValue>\n")
        };
        changes.push_str(&format!(
            "  <da:Change Operation=\"{op}\">\n\
             \x20   <da:AttributeType>{}</da:AttributeType>\n\
             {attr_value}\
             \x20 </da:Change>\n",
            attr_type(attr),
        ));
    }

    format!(
        "<da:ModifyRequest Dialect=\"{dialect}\" \
         xmlns:da=\"http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess\" \
         xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\" \
         xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
         {changes}{controls}</da:ModifyRequest>",
        dialect = DIALECT_XPATH_L1,
        controls = controls_block(sd_flags),
    )
}

/// Build a WS-Transfer `Put` envelope (modify `dn` with the given ModifyRequest).
pub fn build_put_request(to: &str, dn: &str, modify_request_xml: &str, ldap_port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
        <ad:instance>ldap:{ldap_port}</ad:instance>
        <ad:objectReferenceProperty>{dn}</ad:objectReferenceProperty>
        <da:IdentityManagementOperation s:mustUnderstand="1" />
        <wsa:MessageID>{msg_id}</wsa:MessageID>
        <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">{to}</wsa:To>
    </s:Header>
    <s:Body>
{body}
    </s:Body>
</s:Envelope>"#,
        action = ACTION_PUT,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        dn = escape_xml(dn),
        body = modify_request_xml,
    )
}

/// Build the IMDA `da:AddRequest` body for a WS-Transfer `Create`: a flat list
/// of attribute/value pairs (no operation, unlike `Change`). `objectClass` and
/// the mandatory attributes must be included by the caller.
pub fn build_add_request(attrs: &[(String, Vec<Value>)]) -> String {
    let mut body = String::new();
    for (attr, values) in attrs {
        let mut values_xml = String::new();
        for v in values {
            values_xml.push_str(&value_xml(v));
        }
        body.push_str(&format!(
            "  <da:AttributeTypeAndValue>\n\
             \x20   <da:AttributeType>{}</da:AttributeType>\n\
             \x20   <da:AttributeValue>\n{values_xml}      </da:AttributeValue>\n\
             \x20 </da:AttributeTypeAndValue>\n",
            attr_type(attr),
        ));
    }

    format!(
        "<da:AddRequest Dialect=\"{dialect}\" \
         xmlns:da=\"http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess\" \
         xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\" \
         xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
         {body}</da:AddRequest>",
        dialect = DIALECT_XPATH_L1,
    )
}

/// Build a WS-Transfer `Create` envelope against `Windows/ResourceFactory`.
/// Unlike Put/Delete, Create carries **no** `objectReferenceProperty`: the new
/// object's location is given inside the `AddRequest` body through
/// `ad:relativeDistinguishedName` and `ad:container-hierarchy-parent`
/// (see [`AdwsClient::create`](crate::AdwsClient::create)).
pub fn build_create_request(to: &str, add_request_xml: &str, ldap_port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
        <ad:instance>ldap:{ldap_port}</ad:instance>
        <da:IdentityManagementOperation s:mustUnderstand="1" />
        <wsa:MessageID>{msg_id}</wsa:MessageID>
        <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">{to}</wsa:To>
    </s:Header>
    <s:Body>
{body}
    </s:Body>
</s:Envelope>"#,
        action = ACTION_CREATE,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        body = add_request_xml,
    )
}

/// Build a WS-Transfer `Delete` envelope for `dn`.
pub fn build_delete_request(to: &str, dn: &str, ldap_port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
        <ad:instance>ldap:{ldap_port}</ad:instance>
        <ad:objectReferenceProperty>{dn}</ad:objectReferenceProperty>
        <wsa:MessageID>{msg_id}</wsa:MessageID>
        <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
        <wsa:To s:mustUnderstand="1">{to}</wsa:To>
    </s:Header>
    <s:Body></s:Body>
</s:Envelope>"#,
        action = ACTION_DELETE,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        dn = escape_xml(dn),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TO: &str = "net.tcp://dc:9389/ActiveDirectoryWebServices/Windows/Resource";

    #[test]
    fn modify_request_renders_changes() {
        let mods = vec![
            Mod::replace("description", ["hello"]),
            Mod::add("servicePrincipalName", ["HOST/x"]),
            Mod::delete_all("comment"),
        ];
        let xml = build_modify_request(&mods, None);
        assert!(xml.contains("Operation=\"replace\""));
        assert!(xml.contains("<da:AttributeType>addata:description</da:AttributeType>"));
        assert!(xml.contains("HOST/x"));
        assert!(xml.contains("xsi:type=\"xsd:string\""));
        // delete_all => no AttributeValue (removes all).
        assert!(xml.contains("Operation=\"delete\""));
        assert!(xml.contains("1.2.840.113556.1.4.1413")); // PermissiveModify
    }

    #[test]
    fn binary_value_is_base64_typed() {
        // base64("ABCD") = "QUJDRA=="
        let xml = build_modify_request(
            &[Mod::replace("msDS-KeyCredentialLink", [b"ABCD".to_vec()])],
            None,
        );
        assert!(xml.contains("xsi:type=\"xsd:base64Binary\""));
        assert!(xml.contains("QUJDRA=="));
        assert!(!xml.contains("xsi:type=\"xsd:string\""));
    }

    #[test]
    fn put_envelope_wraps_dn_and_body() {
        let body = build_modify_request(&[Mod::replace("description", ["x"])], None);
        let env = build_put_request(TO, "CN=jon,DC=essos,DC=local", &body, 389);
        assert!(env.contains(ACTION_PUT));
        assert!(env.contains("<ad:objectReferenceProperty>CN=jon,DC=essos,DC=local</ad:objectReferenceProperty>"));
        assert!(env.contains("Windows/Resource</wsa:To>"));
        assert!(env.contains("da:ModifyRequest"));
    }

    #[test]
    fn delete_envelope_has_dn() {
        let env = build_delete_request(TO, "CN=stale,DC=essos,DC=local", 389);
        assert!(env.contains(ACTION_DELETE));
        assert!(env.contains("CN=stale,DC=essos,DC=local"));
    }

    #[test]
    fn sd_flags_control_included_when_requested() {
        // Writing a security descriptor: binary value + SDFlags control.
        let xml = build_modify_request(
            &[Mod::replace("nTSecurityDescriptor", [vec![0x01u8, 0x00]])],
            Some(SdFlags(SdFlags::DACL)),
        );
        assert!(xml.contains(SdFlags::OID));
        assert!(xml.contains("base64Binary"));
    }

    #[test]
    fn put_and_modify_survive_nbfse_roundtrip() {
        let body = build_modify_request(&[Mod::add("description", ["x"])], None);
        let env = build_put_request(TO, "CN=x,DC=y", &body, 389);
        let payload = crate::ws::nbfx::encode_nbfse_request(&env).unwrap();
        let mut sess = crate::ws::nbfx::NbfseSession::new();
        let root = crate::ws::nbfx::decode_nbfse(&mut sess, &payload).unwrap();
        assert_eq!(root.name, "Envelope");
    }
}