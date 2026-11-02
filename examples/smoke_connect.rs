//! Minimal bring-up test: connect + naming contexts only, no search.
//!
//! Run this FIRST when bringing the transport up against a DC - it isolates the
//! NMF upgrade, the NNS handshake, and the first SOAP exchange from the search
//! logic, so a failure points straight at the transport/auth layer.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! cargo run --example smoke_connect --features sspi-auth
//! ```

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials};

#[tokio::main]
async fn main() -> adws::Result<()> {
    // Library logging via `log`; set RUST_LOG=debug or trace for wire detail.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let host = env::var("ADWS_HOST").expect("set ADWS_HOST");
    let domain = env::var("ADWS_DOMAIN").expect("set ADWS_DOMAIN");
    let user = env::var("ADWS_USER").expect("set ADWS_USER");
    let pass = env::var("ADWS_PASS").expect("set ADWS_PASS");

    eprintln!("[*] TCP + NMF upgrade + NNS handshake to {host}:9389 ...");
    let mut client = AdwsClient::connect(
        Target::new(host, domain.clone()),
        Credentials::Password { domain, username: user, password: pass },
    )
    .await?;
    eprintln!("[+] handshake OK - authenticated channel is up");

    eprintln!("[*] first SOAP exchange (RootDSE namingContexts) ...");
    let ncs = client.naming_contexts().await?;
    eprintln!("[+] {} naming contexts:", ncs.len());
    for nc in &ncs {
        eprintln!("      {nc}");
    }
    if !ncs.iter().any(|n| n.contains("Configuration")) {
        eprintln!("[!] no Configuration NC - RootDSE read likely needs adjustment");
    }
    Ok(())
}
