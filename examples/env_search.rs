//! Connect + search, configured entirely from environment variables so you can
//! run it against a lab (GOAD) without editing source.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_BASE='DC=essos,DC=local' ADWS_FILTER='(objectClass=user)' \
//! cargo run --example env_search --features "ldap3 sspi-auth"
//! ```
//!
//! `ADWS_BASE` / `ADWS_FILTER` are optional (base defaults to the first domain
//! naming context, filter to all users).

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Scope, SdFlags};

fn req(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing env var {key}"))
}

#[tokio::main]
async fn main() -> adws::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let host = req("ADWS_HOST");
    let domain = req("ADWS_DOMAIN");
    let user = req("ADWS_USER");
    let pass = req("ADWS_PASS");
    let filter = env::var("ADWS_FILTER").unwrap_or_else(|_| "(objectClass=user)".into());

    let target = Target::new(host.clone(), domain.clone());
    let creds = Credentials::Password { domain: domain.clone(), username: user, password: pass };

    eprintln!("[*] connecting to {host}:9389 ...");
    let mut client = AdwsClient::connect(target, creds).await?;
    eprintln!("[+] connected");

    let ncs = client.naming_contexts().await?;
    eprintln!("[*] naming contexts:");
    for nc in &ncs {
        eprintln!("      {nc}");
    }

    let base = match env::var("ADWS_BASE") {
        Ok(b) if !b.is_empty() => b,
        _ => ncs
            .iter()
            .find(|n| n.to_lowercase().starts_with("dc="))
            .cloned()
            .unwrap_or_default(),
    };

    eprintln!("[*] search base={base} filter={filter}");
    let entries = client
        .search(&base, Scope::Subtree, &filter, &[], Some(SdFlags::OWNER_DACL), false)
        .await?;
    eprintln!("[+] {} entries", entries.len());
    for e in entries.iter().take(25) {
        eprintln!("      {}", e.dn);
    }

    // Verify the ldap3-shaped split that RustHound-CE relies on: text in attrs,
    // raw bytes in bin_attrs. Show the first entry that carries a security
    // descriptor (proves the SD-flags control + binary routing both work).
    if let Some(e) = entries.iter().find(|e| e.bin_attrs.contains_key("nTSecurityDescriptor")) {
        let mut text_keys: Vec<&String> = e.attrs.keys().collect();
        let mut bin_keys: Vec<&String> = e.bin_attrs.keys().collect();
        text_keys.sort();
        bin_keys.sort();
        eprintln!("\n[*] sample object: {}", e.dn);
        eprintln!("      attrs ({}):     {:?}", text_keys.len(), text_keys);
        eprintln!("      bin_attrs ({}): {:?}", bin_keys.len(), bin_keys);
        let sid = e.bin_attrs.get("objectSid").map(|v| v[0].len()).unwrap_or(0);
        let sd = e.bin_attrs.get("nTSecurityDescriptor").map(|v| v[0].len()).unwrap_or(0);
        eprintln!("      objectSid: {sid} bytes, nTSecurityDescriptor: {sd} bytes");
    } else {
        eprintln!("\n[!] no nTSecurityDescriptor in any entry - SD-flags control may need checking");
    }
    Ok(())
}
