//! Connect to a Domain Controller over ADWS and run a search.
//!
//! Run against a lab (needs the SSPI auth provider and a reachable DC):
//!
//! ```bash
//! RUST_LOG=trace cargo run --example connect_search --features "ldap3 sspi-auth"
//! ```
//!
//! Without `sspi-auth`, `connect` returns an error telling you to enable it.

use adws::client::Target;
use adws::{AdwsClient, Credentials, Scope, SdFlags};

#[tokio::main]
async fn main() -> adws::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // --- Adjust these to your environment (example: GOAD essos.local) ---
    let target = Target::new("meereen.essos.local", "essos.local");
    let creds = Credentials::Password {
        domain: "essos.local".into(),
        username: "daenerys.targaryen".into(),
        password: "BurnThemAll!".into(),
    };
    // Pass-the-Hash instead:
    // let creds = Credentials::NtHash { domain: "essos.local".into(),
    //     username: "daenerys.targaryen".into(), nt_hash: [/* 16 bytes */ 0u8; 16] };

    println!("[*] Connecting to {} over ADWS (9389)...", target.host);
    let mut client = AdwsClient::connect(target, creds).await?;

    println!("[*] Naming contexts:");
    for nc in client.naming_contexts().await? {
        println!("      {nc}");
    }

    let base = "DC=essos,DC=local";
    println!("[*] Searching {base} for users...");
    let entries = client
        .search(
            base,
            Scope::Subtree,
            "(objectClass=user)",
            &["sAMAccountName", "objectSid"],
            Some(SdFlags::OWNER_DACL), // request the DACL, like RustHound-CE
            false,
        )
        .await?;

    println!("[+] {} entries", entries.len());
    for e in entries.iter().take(20) {
        let sam = e
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or("");
        let has_sid = e.bin_attrs.contains_key("objectSid");
        println!("      {sam:<24} sid:{:<5} {}", has_sid, e.dn);
    }

    Ok(())
}
