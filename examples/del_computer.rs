//! Delete a machine (computer) account over ADWS with a WS-Transfer `Delete`.
//! Resolves the account's DN by `sAMAccountName`, then removes it. Pair with
//! the `add_computer` example.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_COMPUTER='EVILPC$' \
//! cargo run --example del_computer --features "sspi-auth"
//! ```

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Scope};

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
    let name = env::var("ADWS_COMPUTER").unwrap_or_else(|_| "EVILPC$".into());
    let name = if name.ends_with('$') { name } else { format!("{name}$") };

    let base = domain.split('.').map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain, username: user, password: pass };
    let mut client = AdwsClient::connect(target, creds).await?;

    let filter = format!("(sAMAccountName={name})");
    let entries = client
        .search(&base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
        .await?;
    let entry = entries
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("computer {name} not found"));

    eprintln!("[*] deleting {}", entry.dn);
    client.delete(&entry.dn).await?;
    eprintln!("[+] computer account '{name}' deleted");
    Ok(())
}