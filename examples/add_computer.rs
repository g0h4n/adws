//! Prove object creation over ADWS: create a machine (computer) account with a
//! WS-Transfer `Create` against `Windows/ResourceFactory`.
//!
//! Sets `objectClass`, `sAMAccountName` (NAME$), `dnsHostName`,
//! `userAccountControl` (WORKSTATION_TRUST_ACCOUNT), the SPNs, and the machine
//! password as a UTF-16 `unicodePwd`. Delete it afterwards with the
//! `del_computer` example.
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_COMPUTER='EVILPC$' ADWS_COMPUTER_PASS='Str0ngP@ss!' \
//! cargo run --example add_computer --features "sspi-auth"
//! ```

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Value};

const UAC_WORKSTATION_TRUST: &str = "4096";

fn req(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing env var {key}"))
}

/// Encode a password as the DC expects for `unicodePwd`: the quoted password in
/// UTF-16LE.
fn pwd_utf16(p: &str) -> Vec<u8> {
    format!("\"{p}\"").encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
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
    let comp_pass = env::var("ADWS_COMPUTER_PASS").unwrap_or_else(|_| "Str0ngP@ssw0rd!".into());

    // essos.local => DC=essos,DC=local
    let base = domain.split('.').map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");
    let hostname = name.trim_end_matches('$');
    let dn = format!("CN={hostname},CN=Computers,{base}");
    let dns = format!("{hostname}.{domain}");

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain, username: user, password: pass };
    let mut client = AdwsClient::connect(target, creds).await?;

    // ADWS/IMDA Create wants only the structural class "computer" (unlike an
    // LDAP add, which lists the full top/person/.../computer chain).
    let t = |s: String| Value::Text(s);
    let attrs: Vec<(String, Vec<Value>)> = vec![
        ("objectClass".into(), vec![t("computer".into())]),
        ("sAMAccountName".into(), vec![t(name.clone())]),
        ("dNSHostName".into(), vec![t(dns.clone())]),
        ("userAccountControl".into(), vec![t(UAC_WORKSTATION_TRUST.into())]),
        ("unicodePwd".into(), vec![Value::Bytes(pwd_utf16(&comp_pass))]),
        (
            "servicePrincipalName".into(),
            vec![t(format!("HOST/{hostname}")), t(format!("HOST/{dns}"))],
        ),
    ];

    eprintln!("[*] creating {dn}");
    client.create(&dn, &attrs).await?;
    eprintln!("[+] computer account '{name}' created with password: {comp_pass}");
    eprintln!("    clean up with: cargo run --example del_computer --features sspi-auth  (ADWS_COMPUTER={name})");
    Ok(())
}