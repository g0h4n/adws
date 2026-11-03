//! Walk a decoded PullResponse tree into [`SearchEntry`] values.
//!
//! Ported from go-adws `soap/parsing.go`. The binary/text decision follows the
//! object's **`LdapSyntax`** (MS-ADDM §2.3.4): the four base64 syntaxes go to
//! `bin_attrs`, everything else to `attrs`.

use crate::error::{AdwsError, Result};
use crate::types::SearchEntry;
use crate::ws::mapping::{object_to_entry, AttrValue};
use crate::ws::nbfx::NbfxNode;

/// One parsed Pull batch.
#[derive(Debug, Default)]
pub struct PullResult {
    pub items: Vec<SearchEntry>,
    pub enumeration_context: Option<String>,
    pub end_of_sequence: bool,
}

/// The LDAP syntaxes ADWS encodes as `xsd:base64Binary` (MS-ADDM §2.3.4).
fn is_base64_binary_syntax(syntax: &str) -> bool {
    matches!(
        syntax,
        "OctetString" | "SidString" | "NTSecurityDescriptor" | "ReplicaLink"
    )
}

fn local_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub(crate) fn find_descendant<'a>(node: &'a NbfxNode, local: &str) -> Option<&'a NbfxNode> {
    if local_eq(&node.name, local) {
        return Some(node);
    }
    node.children.iter().find_map(|c| find_descendant(c, local))
}

pub(crate) fn find_child<'a>(node: &'a NbfxNode, local: &str) -> Option<&'a NbfxNode> {
    node.children.iter().find(|c| local_eq(&c.name, local))
}

/// Collect every descendant (and the node itself) whose local name matches,
/// without descending into a match's own subtree. Used to gather repeated
/// response elements (e.g. MS-ADCAP `ActiveDirectoryPrincipal`) robustly,
/// regardless of the exact wrapper element around them.
pub(crate) fn collect_descendants<'a>(node: &'a NbfxNode, local: &str, out: &mut Vec<&'a NbfxNode>) {
    if local_eq(&node.name, local) {
        out.push(node);
        return;
    }
    for c in &node.children {
        collect_descendants(c, local, out);
    }
}

/// Text of the first direct child with the given local name, trimmed.
pub(crate) fn child_text(node: &NbfxNode, local: &str) -> Option<String> {
    find_child(node, local).map(|n| n.text.trim().to_string()).filter(|s| !s.is_empty())
}

/// Read an attribute by local name (ignoring any `prefix:` on the stored key).
fn attr_value<'a>(node: &'a NbfxNode, local: &str) -> Option<&'a str> {
    node.attrs
        .iter()
        .find(|(k, _)| k.rsplit(':').next().map(|x| local_eq(x, local)).unwrap_or(false))
        .map(|(_, v)| v.as_str())
}

/// Parse a decoded SOAP envelope tree that contains a `PullResponse`.
pub fn parse_pull_response(root: &NbfxNode) -> Result<PullResult> {
    let pr = find_descendant(root, "PullResponse")
        .ok_or_else(|| AdwsError::Soap("no PullResponse in body".into()))?;

    let enumeration_context = find_child(pr, "EnumerationContext")
        .map(|n| n.text.trim().to_string())
        .filter(|s| !s.is_empty());
    let end_of_sequence = find_child(pr, "EndOfSequence").is_some();

    let mut items = Vec::new();
    if let Some(items_node) = find_child(pr, "Items") {
        for obj in &items_node.children {
            items.push(parse_object(obj)?);
        }
    }

    Ok(PullResult { items, enumeration_context, end_of_sequence })
}

fn parse_object(obj: &NbfxNode) -> Result<SearchEntry> {
    let mut dn = String::new();
    let mut attributes: Vec<(String, Vec<AttrValue>)> = Vec::new();

    for field in &obj.children {
        let name = field.name.clone();
        if local_eq(&name, "objectReferenceProperty") {
            continue;
        }

        let binary = attr_value(field, "LdapSyntax")
            .map(is_base64_binary_syntax)
            .unwrap_or(false);

        // Values are <ad:value> children; fall back to the field's own text.
        let raw: Vec<String> = {
            let value_nodes: Vec<&NbfxNode> =
                field.children.iter().filter(|c| local_eq(&c.name, "value")).collect();
            if value_nodes.is_empty() {
                let t = field.text.trim();
                if t.is_empty() { Vec::new() } else { vec![t.to_string()] }
            } else {
                value_nodes
                    .iter()
                    .map(|v| v.text.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
        };
        if raw.is_empty() {
            continue;
        }

        if local_eq(&name, "distinguishedName") && dn.is_empty() {
            dn = raw[0].clone();
        }

        let values = raw
            .into_iter()
            .map(|v| if binary { AttrValue::Base64(v) } else { AttrValue::Text(v) })
            .collect();
        attributes.push((name, values));
    }

    object_to_entry(dn, attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(name: &str) -> NbfxNode {
        NbfxNode { name: name.into(), ..Default::default() }
    }
    fn value_node(text: &str) -> NbfxNode {
        NbfxNode { name: "value".into(), text: text.into(), ..Default::default() }
    }
    fn field(name: &str, syntax: &str, values: &[&str]) -> NbfxNode {
        let mut f = el(name);
        if !syntax.is_empty() {
            f.attrs.push(("LdapSyntax".into(), syntax.into()));
        }
        f.children = values.iter().map(|v| value_node(v)).collect();
        f
    }

    fn sample_tree() -> NbfxNode {
        let mut obj = el("user");
        obj.children.push(field("distinguishedName", "DNString", &["CN=jon,DC=essos,DC=local"]));
        obj.children.push(field("sAMAccountName", "UnicodeString", &["jon"]));
        // base64("ABCD") = "QUJDRA=="
        obj.children.push(field("objectSid", "SidString", &["QUJDRA=="]));

        let mut items = el("Items");
        items.children.push(obj);

        let mut ctx = el("EnumerationContext");
        ctx.text = "ctx-123".into();

        let mut pr = el("PullResponse");
        pr.children.push(ctx);
        pr.children.push(items);

        let mut body = el("Body");
        body.children.push(pr);
        let mut env = el("Envelope");
        env.children.push(body);
        env
    }

    #[test]
    fn parses_items_dn_and_binary_routing() {
        let r = parse_pull_response(&sample_tree()).unwrap();
        assert_eq!(r.enumeration_context.as_deref(), Some("ctx-123"));
        assert!(!r.end_of_sequence);
        assert_eq!(r.items.len(), 1);

        let e = &r.items[0];
        assert_eq!(e.dn, "CN=jon,DC=essos,DC=local");
        assert_eq!(e.attrs["sAMAccountName"], vec!["jon"]);
        // SidString => base64 => bin_attrs, decoded.
        assert_eq!(e.bin_attrs["objectSid"], vec![b"ABCD".to_vec()]);
        assert!(!e.attrs.contains_key("objectSid"));
    }

    #[test]
    fn end_of_sequence_detected() {
        let mut env = sample_tree();
        // Add <EndOfSequence/> under PullResponse.
        let pr = env.children[0].children.iter_mut().find(|n| n.name == "PullResponse").unwrap();
        pr.children.push(el("EndOfSequence"));
        let r = parse_pull_response(&env).unwrap();
        assert!(r.end_of_sequence);
    }

    #[test]
    fn collect_descendants_gathers_repeated_elements() {
        let mut wrap = el("Members");
        wrap.children.push(el("ActiveDirectoryPrincipal"));
        wrap.children.push(el("ActiveDirectoryPrincipal"));
        let mut resp = el("GetADGroupMemberResponse");
        resp.children.push(wrap);

        let mut out = Vec::new();
        collect_descendants(&resp, "ActiveDirectoryPrincipal", &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn child_text_reads_direct_child() {
        let mut p = el("ActiveDirectoryPrincipal");
        p.children.push(value_node("")); // unrelated
        let mut dn = el("DistinguishedName");
        dn.text = "  CN=a,DC=x  ".into();
        p.children.push(dn);
        assert_eq!(child_text(&p, "DistinguishedName").as_deref(), Some("CN=a,DC=x"));
        assert_eq!(child_text(&p, "SID"), None);
    }
}

/// Result of a WS-Enumeration `Enumerate` (opens the context).
#[derive(Debug, Default)]
pub struct EnumerateResult {
    pub enumeration_context: Option<String>,
    pub end_of_sequence: bool,
}

/// Parse an `EnumerateResponse` envelope tree.
pub fn parse_enumerate_response(root: &NbfxNode) -> Result<EnumerateResult> {
    let er = find_descendant(root, "EnumerateResponse")
        .ok_or_else(|| AdwsError::Soap("no EnumerateResponse in body".into()))?;
    let enumeration_context = find_child(er, "EnumerationContext")
        .map(|n| n.text.trim().to_string())
        .filter(|s| !s.is_empty());
    let end_of_sequence = find_child(er, "EndOfSequence").is_some();
    Ok(EnumerateResult { enumeration_context, end_of_sequence })
}

/// Return an error if the envelope carries a SOAP Fault.
pub fn check_fault(root: &NbfxNode) -> Result<()> {
    if let Some(fault) = find_descendant(root, "Fault") {
        let reason = find_descendant(fault, "Text")
            .or_else(|| find_descendant(fault, "Reason"))
            .map(|n| n.text.trim().to_string())
            .unwrap_or_default();
        let code = find_descendant(fault, "Value")
            .map(|n| n.text.trim().to_string())
            .unwrap_or_default();
        return Err(AdwsError::Fault { code, reason });
    }
    Ok(())
}