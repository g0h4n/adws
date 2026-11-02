//! Connect with username/password (NTLM) and search everything, yielding
//! `ldap3::SearchEntry` values.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! cargo run --example connect_username_password --features "ldap3 sspi-auth"
//! ```

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

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain, username: user, password: pass };

    let mut client = AdwsClient::connect(target, creds).await?;

    // Search everything under the first domain naming context.
    let base = client
        .naming_contexts()
        .await?
        .into_iter()
        .find(|n| n.to_lowercase().starts_with("dc="))
        .unwrap_or_default();

    let entries = client
        .search(&base, Scope::Subtree, "(objectClass=*)", &[], Some(SdFlags::OWNER_DACL), false)
        .await?;
    eprintln!("[+] {} entries under {base}", entries.len());

    // Yield ldap3::SearchEntry (free conversion under the `ldap3` feature).
    for entry in entries.into_iter().take(10) {
        let e: ldap3::SearchEntry = entry.into();
        eprintln!(
            "      {} | {} attrs, {} bin_attrs",
            e.dn,
            e.attrs.len(),
            e.bin_attrs.len()
        );
    }
    Ok(())
}
