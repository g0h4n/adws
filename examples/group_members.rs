//! Recover the FULL membership of a group over ADWS, past the LDAP
//! `MaxValRange` cap (default 1500), using the MS-ADCAP `GetADGroupMember`
//! custom action (`AdwsClient::group_members`) - the SOAP equivalent of
//! `Get-ADGroupMember`.
//!
//! It prints, side by side:
//!   * Part A - the `member` count returned by a plain search (capped at 1500
//!     for large groups, with no `;range=` signal over ADWS);
//!   * Part B - the count returned by `GetADGroupMember` (the full membership).
//!
//! ```bash
//! RUST_LOG=trace ADWS_HOST=meereen.essos.local ADWS_DOMAIN=essos.local \
//! ADWS_USER=daenerys.targaryen ADWS_PASS='BurnThemAll!' \
//! ADWS_DN='CN=GS-TEST01,OU=<REAL-OU>,DC=essos,DC=local' \
//! cargo run --example group_members --features sspi-auth
//! ```
//!
//! Set ADWS_RECURSIVE=1 to expand nested group membership server-side.

use std::env;

use adws::client::Target;
use adws::{AdwsClient, Credentials, Scope};

fn req(k: &str) -> String {
    env::var(k).unwrap_or_else(|_| panic!("missing env var {k}"))
}

/// Rough check: does this string look like a distinguished name already?
fn looks_like_dn(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains(",dc=") || l.starts_with("cn=") || l.starts_with("ou=")
}

#[tokio::main]
async fn main() -> adws::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let host = req("ADWS_HOST");
    let domain = req("ADWS_DOMAIN");
    let user = req("ADWS_USER");
    let pass = req("ADWS_PASS");
    let dn_or_name = req("ADWS_DN");
    let recursive = matches!(env::var("ADWS_RECURSIVE").as_deref(), Ok("1") | Ok("true"));

    let target = Target::new(host, domain.clone());
    let creds = Credentials::Password { domain: domain.clone(), username: user, password: pass };
    let mut client = AdwsClient::connect(target, creds).await?;

    // Accept either a full DN or a plain group name (CN / sAMAccountName): if it
    // is not already a DN, resolve it to one with a subtree search over the
    // domain base, so you do not have to spell out the OU path.
    let dn = if looks_like_dn(&dn_or_name) {
        dn_or_name.clone()
    } else {
        let base = domain
            .split('.')
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",");
        let filter = format!(
            "(&(objectClass=group)(|(cn={0})(sAMAccountName={0})))",
            dn_or_name.replace(['(', ')', '*', '\\'], "")
        );
        let hits = client
            .search(&base, Scope::Subtree, &filter, &["distinguishedName"], None, false)
            .await?;
        match hits.into_iter().next() {
            Some(e) => {
                eprintln!("[*] resolved '{dn_or_name}' => {}", e.dn);
                e.dn
            }
            None => {
                eprintln!("[!] group '{dn_or_name}' not found under {base}");
                return Ok(());
            }
        }
    };

    // --- Part A: plain `member` via a search (subject to MaxValRange) ---
    let capped = {
        let entries = client
            .search(&dn, Scope::Base, "(objectClass=*)", &["member"], None, false)
            .await?;
        entries
            .into_iter()
            .next()
            .and_then(|e| e.attrs.get("member").map(|v| v.len()))
            .unwrap_or(0)
    };
    eprintln!("[A] plain search  => member = {capped} value(s)");

    // --- Part B: full membership via GetADGroupMember (MS-ADCAP) ---
    let members = client.group_members(&dn, recursive).await?;
    eprintln!("[B] GetADGroupMember (recursive={recursive}) => {} member(s)", members.len());

    // Print every member with ADWS_PRINT_ALL=1, else a short sample.
    let print_all = matches!(env::var("ADWS_PRINT_ALL").as_deref(), Ok("1") | Ok("true"));
    let shown = if print_all { members.len() } else { members.len().min(5) };
    for (i, m) in members.iter().take(shown).enumerate() {
        let class = if m.object_class.is_empty() { "?" } else { &m.object_class };
        eprintln!("      [{:>4}] {}  [{}]", i + 1, m.dn, class);
    }
    if !print_all && members.len() > shown {
        eprintln!("      ... ({} more; set ADWS_PRINT_ALL=1 to list them all)", members.len() - shown);
    }

    if members.len() > capped {
        eprintln!("\n[+] Recovered {} member(s) the capped search missed.", members.len() - capped);
    } else {
        eprintln!("\n[*] No overflow (group at or under the cap).");
    }
    Ok(())
}