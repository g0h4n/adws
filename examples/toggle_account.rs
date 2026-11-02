//! Prove the write path: enable/disable an account by toggling the
//! `ACCOUNTDISABLE` (0x2) flag of its `userAccountControl`, over ADWS.
//!
//! It reads the account's current `userAccountControl`, flips the disable bit,
//! and writes it back with a WS-Transfer `Put`. Run it twice to toggle back.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_TARGET=g0h4n \
//! cargo run --example toggle_account --features "sspi-auth"
//! ```

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Mod, Scope, SdFlags};

/// userAccountControl ACCOUNTDISABLE flag.
const UAC_ACCOUNTDISABLE: u32 = 0x0002;

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
    let sam = env::var("ADWS_TARGET").unwrap_or_else(|_| "g0h4n".into());

    // Derive the base DN from the domain (essos.local => DC=essos,DC=local),
    // so the write test does not depend on the RootDSE read.
    let base = domain
        .split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain, username: user, password: pass };
    let mut client = AdwsClient::connect(target, creds).await?;

    let filter = format!("(sAMAccountName={sam})");
    let entries = client
        .search(&base, Scope::Subtree, &filter, &["userAccountControl"], None, false)
        .await?;
    let entry = entries
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("account {sam} not found"));

    let uac: u32 = entry
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|s| s.parse().ok())
        .expect("userAccountControl missing or not an integer");

    let disabled = uac & UAC_ACCOUNTDISABLE != 0;
    let new_uac = uac ^ UAC_ACCOUNTDISABLE; // flip the disable bit
    eprintln!("[*] {}", entry.dn);
    eprintln!(
        "[*] userAccountControl: {uac} ({}) => {new_uac} ({})",
        if disabled { "disabled" } else { "enabled" },
        if disabled { "enabling" } else { "disabling" },
    );

    client
        .modify(
            &entry.dn,
            &[Mod::replace("userAccountControl", [new_uac.to_string()])],
            None::<SdFlags>,
        )
        .await?;

    eprintln!("[+] write OK: account is now {}", if disabled { "ENABLED" } else { "DISABLED" });
    Ok(())
}
