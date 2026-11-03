<p align="center">
    <h1 align="center">adws</h1>
    <p align="center">A Rust client for Active Directory Web Services (ADWS), with ldap3-compatible types a drop-in alternate transport for RustHound-CE.</p>
    <p align="center">
    <a href="https://crates.io/crates/adws"><img alt="Crates.io Version" src="https://img.shields.io/crates/v/adws"></a>
    <img alt="Rust edition" src="https://img.shields.io/badge/rust-2021-orange.svg">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
    <img alt="Platforms" src="https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg">
    <a href="https://github.com/g0h4n/RustHound-CE/issues/109"><img alt="RustHound-CE Issue" src="https://img.shields.io/badge/RustHound--CE-%23109-8A2BE2.svg"></a>
    </p>
</p>

<hr />

`adws` is a cross-platform Rust library that speaks to a Domain Controller over **Active Directory Web Services** (the SOAP/WS-* endpoint on TCP `9389`, which the DC proxies to its local LDAP). Because directory reads go over ADWS rather than LDAP (389/636), they stay out of the view of LDAP-centric detections.

This library was built to provide a **read and write ADWS (SOAP) library in Rust**. It is a building block I needed for several Red Team tools, and in particular for [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (as an alternate `--transport soap` collector) and for [adshell-rs](https://github.com/g0h4n/adshell-rs).

The crate is built bottom-up over the real protocol stack MC-NMF framing, MS-NNS (NegotiateStream) security, and the NBFSE binary-XML SOAP layer (MS-ADDM) and exposes results as `SearchEntry` values that convert to and from `ldap3::SearchEntry` for free. It also covers the MS-ADCAP custom actions where a plain search is not enough: `GetADGroupMember` resolves a group's full membership server-side, past the `MaxValRange` (1500) cap that truncates `member` over ADWS (there is no LDAP-style ranged retrieval on the wire). The goal is to give [RustHound-CE](https://github.com/g0h4n/RustHound-CE) and other ldap3-based tools a `--transport (adws,soap)|ldap` option with no change to the code above the transport.

This project is inspired by the existing ADWS tooling ([go-adws](https://github.com/Macmod/go-adws) by [@MacmodSec](https://x.com/MacmodSec), [SOAPy](https://github.com/logangoins/soapy) by [@_logangoins](https://x.com/_logangoins), [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) by [@FalconForceTeam](https://x.com/FalconForceTeam)), which served as protocol and wire references. It was developed with AI assistance (Claude Opus 4.8) to move faster, so there may be rough edges to smooth out or changes to apply. Do not hesitate to open issues or pull requests, I will gladly take care of them.

- [HELP.md](HELP.md) - How to build it? How to test it? How to use it?
- [CHANGELOG.md](CHANGELOG.md) - A record of all significant version changes
- [ROADMAP.md](ROADMAP.md) - Protocol coverage and planned evolutions
- [INTEGRATION.md](INTEGRATION.md) - How to use `adws` as a library (and wire it into RustHound-CE)
- [examples/](examples/) - Runnable examples: connect, search, group membership, and the write path (toggle, RBCD, add/del computer)

# Quick usage

## Compilation

```bash
# Build the library
cargo build --release

# With ldap3-compatible types (From/Into ldap3::SearchEntry)
cargo build --release --features ldap3

# With the SSPI auth provider (NTLM / Kerberos) required for a live connection
cargo build --release --features sspi-auth

# Run the test suite
cargo test
cd examples; ./test.sh
```

## Installation

<a href="https://crates.io/crates/adws"><img alt="Crates.io Version" src="https://img.shields.io/crates/v/adws"></a>

```bash
cargo add adws --features ldap3 --features sspi-auth
```

## Usage

```rust
use adws::{AdwsClient, Credentials, Scope, SdFlags, client::Target};

#[tokio::main]
async fn main() -> adws::Result<()> {

    let target = Target::new("dc01.essos.local", "essos.local");

    let creds = Credentials::Password {
        domain: "essos.local".into(),
        username: "daenerys.targaryen".into(),
        password: "BurnThemAll!".into(),
    };

    let mut client = AdwsClient::connect(target, creds).await?;

    let entries = client.search(
        "DC=essos,DC=local",
        Scope::Subtree,
        "(objectClass=user)",
        &["sAMAccountName", "objectSid", "nTSecurityDescriptor"],
        Some(SdFlags::OWNER_DACL), // read the DACL, like RustHound-CE
        false,
    ).await?;

    for e in entries {
        println!("{}", e.dn); // e.attrs / e.bin_attrs, ldap3-shaped
    }

    // Full membership of a large group (past the 1500 member cap over ADWS)
    let members = client.group_members("CN=GS-TEST01,OU=TEST01,DC=essos,DC=local", false).await?;
    println!("{} members", members.len());

    Ok(())
}
```

More build options and examples are in [HELP.md](HELP.md); library embedding is covered in [INTEGRATION.md](INTEGRATION.md).

# Special thanks to

[![](https://github.com/Macmod.png?size=50)](https://github.com/Macmod)
[![](https://github.com/logangoins.png?size=50)](https://github.com/logangoins)
[![](https://github.com/FalconForceTeam.png?size=50)](https://github.com/FalconForceTeam)