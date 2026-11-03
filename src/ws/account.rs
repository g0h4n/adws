//! MS-ADCAP "Account Management" custom actions over ADWS, ported from go-adws
//! `soap/build_adcap.go` + `soap/parse_adcap.go`. These target the
//! `Windows/AccountManagement` endpoint and are the SOAP equivalent of the
//! Active Directory PowerShell cmdlets (`Get-ADGroupMember`, ...).
//!
//! The one implemented here, [`build_get_ad_group_member_request`]
//! (`GetADGroupMember`, MS-ADCAP §3.3.4.2), is the officially sanctioned way to
//! enumerate a group's members: the server resolves the full membership
//! internally, so it is NOT subject to the LDAP `MaxValRange` cap (default
//! 1500) that truncates the `member` attribute on a plain search. It is the
//! ADWS replacement for LDAP ranged retrieval (`member;range=lo-hi`), which the
//! ADWS `Enumerate` selection dialect does not support.

use crate::error::{AdwsError, Result};
use crate::ws::envelope::{escape_xml, message_id, ADDRESS_ANONYMOUS};
use crate::ws::nbfx::NbfxNode;
use crate::ws::response::{child_text, collect_descendants, find_descendant};

/// The ADWS endpoint path for MS-ADCAP Account Management custom actions.
pub const ENDPOINT_ACCOUNT_MANAGEMENT: &str = "Windows/AccountManagement";

/// WS-Addressing action for `GetADGroupMember`.
pub const ACTION_GET_AD_GROUP_MEMBER: &str =
    "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADGroupMember";

/// The MS-ADCAP CustomActions namespace (default xmlns of the request body).
const NS_CUSTOM_ACTIONS: &str = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions";

/// One member returned by `GetADGroupMember` (a decoded MS-ADCAP
/// `ActiveDirectoryPrincipal`). `dn` is always present; the rest are best-effort
/// and may be empty depending on the member type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMember {
    pub dn: String,
    pub name: String,
    pub object_class: String,
    pub object_guid: String,
    /// SID as the server serialized it (SDDL string form, e.g. `S-1-5-21-...`).
    pub sid: String,
    pub sam_account_name: String,
}

/// Build a `GetADGroupMember` request envelope.
///
/// * `to` - the `Windows/AccountManagement` endpoint net.tcp URL (`wsa:To`).
/// * `group_dn` - the group's distinguished name.
/// * `partition_dn` - the naming context the group lives in (usually the domain
///   base DN, e.g. `DC=essos,DC=local`).
/// * `recursive` - expand nested group membership server-side when `true`.
pub fn build_get_ad_group_member_request(
    to: &str,
    group_dn: &str,
    partition_dn: &str,
    recursive: bool,
    ldap_port: u16,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">{action}</wsa:Action>
    <ca:Server xmlns:ca="{ns_ca}" xmlns="{ns_ca}">ldap:{ldap_port}</ca:Server>
    <wsa:MessageID>{msg_id}</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>{anon}</wsa:Address></wsa:ReplyTo>
    <wsa:To s:mustUnderstand="1">{to}</wsa:To>
  </s:Header>
  <s:Body>
    <GetADGroupMemberRequest xmlns="{ns_ca}">
      <GroupDN>{group_dn}</GroupDN>
      <PartitionDN>{partition_dn}</PartitionDN>
      <Recursive>{recursive}</Recursive>
    </GetADGroupMemberRequest>
  </s:Body>
</s:Envelope>"#,
        action = ACTION_GET_AD_GROUP_MEMBER,
        ns_ca = NS_CUSTOM_ACTIONS,
        ldap_port = ldap_port,
        msg_id = message_id(),
        anon = ADDRESS_ANONYMOUS,
        to = escape_xml(to),
        group_dn = escape_xml(group_dn),
        partition_dn = escape_xml(partition_dn),
        recursive = if recursive { "true" } else { "false" },
    )
}

/// Parse a `GetADGroupMemberResponse` envelope tree into its members.
///
/// Gathers every `ActiveDirectoryPrincipal` descendant (robust to the exact
/// `Members` wrapper), reading each one's `DistinguishedName`, `Name`,
/// `ObjectClass`, `ObjectGuid`, `SID` and `SamAccountName`.
pub fn parse_get_ad_group_member_response(root: &NbfxNode) -> Result<Vec<GroupMember>> {
    let resp = find_descendant(root, "GetADGroupMemberResponse")
        .ok_or_else(|| AdwsError::Soap("no GetADGroupMemberResponse in body".into()))?;

    let mut principals: Vec<&NbfxNode> = Vec::new();
    collect_descendants(resp, "ActiveDirectoryPrincipal", &mut principals);

    let mut members = Vec::with_capacity(principals.len());
    for p in principals {
        let dn = child_text(p, "DistinguishedName").unwrap_or_default();
        if dn.is_empty() {
            // A principal with no DN is not useful for membership; skip it.
            continue;
        }
        members.push(GroupMember {
            dn,
            name: child_text(p, "Name").unwrap_or_default(),
            object_class: child_text(p, "ObjectClass").unwrap_or_default(),
            object_guid: child_text(p, "ObjectGuid").unwrap_or_default(),
            sid: child_text(p, "SID").unwrap_or_default(),
            sam_account_name: child_text(p, "SamAccountName").unwrap_or_default(),
        });
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(name: &str) -> NbfxNode {
        NbfxNode { name: name.into(), ..Default::default() }
    }
    fn txt(name: &str, text: &str) -> NbfxNode {
        NbfxNode { name: name.into(), text: text.into(), ..Default::default() }
    }

    #[test]
    fn request_has_action_endpoint_and_fields() {
        let to = "net.tcp://dc:9389/ActiveDirectoryWebServices/Windows/AccountManagement";
        let xml = build_get_ad_group_member_request(
            to, "CN=GS-TEST01,DC=essos,DC=local", "DC=essos,DC=local", false, 389,
        );
        assert!(xml.contains(ACTION_GET_AD_GROUP_MEMBER));
        assert!(xml.contains("<ca:Server"));
        assert!(xml.contains(">ldap:389</ca:Server>"));
        assert!(xml.contains("<GroupDN>CN=GS-TEST01,DC=essos,DC=local</GroupDN>"));
        assert!(xml.contains("<PartitionDN>DC=essos,DC=local</PartitionDN>"));
        assert!(xml.contains("<Recursive>false</Recursive>"));
        assert!(xml.contains("Windows/AccountManagement</wsa:To>"));
    }

    fn principal(dn: &str, sam: &str, class: &str) -> NbfxNode {
        let mut p = el("ActiveDirectoryPrincipal");
        p.children.push(txt("DistinguishedName", dn));
        p.children.push(txt("SamAccountName", sam));
        p.children.push(txt("ObjectClass", class));
        p.children.push(txt("SID", "S-1-5-21-1-2-3-1104"));
        p
    }

    #[test]
    fn parses_members() {
        let mut members_wrap = el("Members");
        members_wrap.children.push(principal("CN=a,DC=x", "a", "user"));
        members_wrap.children.push(principal("CN=b,DC=x", "b", "computer"));
        // a principal with no DN must be skipped
        members_wrap.children.push(el("ActiveDirectoryPrincipal"));

        let mut resp = el("GetADGroupMemberResponse");
        resp.children.push(members_wrap);
        let mut body = el("Body");
        body.children.push(resp);
        let mut env = el("Envelope");
        env.children.push(body);

        let got = parse_get_ad_group_member_response(&env).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].dn, "CN=a,DC=x");
        assert_eq!(got[0].sam_account_name, "a");
        assert_eq!(got[0].object_class, "user");
        assert_eq!(got[1].dn, "CN=b,DC=x");
    }
}