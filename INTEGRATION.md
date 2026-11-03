# Using adws as a Rust library

`adws` is a library first. It gives you an authenticated ADWS session and
yields directory objects as `SearchEntry` values that are field-compatible with
the [`ldap3`](https://crates.io/crates/ldap3) crate, so it can replace an LDAP
transport without touching the code above it.

```rust
let mut client = adws::AdwsClient::connect(target, creds).await?; // 1. connect + auth
let entries = client.search(base, scope, filter, attrs, sd_flags, false).await?; // 2. read
```

- [Add the dependency](#add-the-dependency)
- [Quick start](#quick-start)
- [ldap3 compatibility](#ldap3-compatibility)
- [Large groups (past MaxValRange)](#large-groups-past-maxvalrange)
- [Wiring it into RustHound-CE](#wiring-it-into-rusthound-ce)
- [Feature flags](#feature-flags)
- [API surface](#api-surface)

## Add the dependency

```toml
[dependencies]
adws = { version = "0.1", features = ["ldap3", "sspi-auth"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net"] }
```

## Quick start

```rust
use adws::{AdwsClient, Credentials, Scope, SdFlags, client::Target};

#[tokio::main]
async fn main() -> adws::Result<()> {
    let target = Target::new("meereen.essos.local", "essos.local");
    let creds = Credentials::Password {
        domain: "essos.local".into(),
        username: "daenerys.targaryen".into(),
        password: "BurnThemAll!".into(),
    };

    let mut client = AdwsClient::connect(target, creds).await?;
    for nc in client.naming_contexts().await? {
        let entries = client
            .search(&nc, Scope::Subtree, "(objectClass=*)", &[], Some(SdFlags::OWNER_DACL), false)
            .await?;
        println!("{nc}: {} objects", entries.len());
    }
    Ok(())
}
```

## ldap3 compatibility

With the `ldap3` feature, the currency types convert for free:

```rust
let e: adws::SearchEntry = /* from adws */;
let as_ldap3: ldap3::SearchEntry = e.into();          // and From<ldap3::SearchEntry> too
let scope: ldap3::Scope = adws::Scope::Subtree.into();
```

The split matches ldap3 exactly: UTF-8 values in `attrs`, raw bytes in
`bin_attrs` (for `objectSid`, `objectGUID`, `nTSecurityDescriptor`,
`msDS-KeyCredentialLink`, …). The binary/text decision follows the object's
`LdapSyntax` as sent by ADWS.

## Large groups (past MaxValRange)

A search returns at most `MaxValRange` (default 1500) values of a multivalued
attribute, and ADWS does not support the LDAP ranged-retrieval option
(`member;range=lo-hi`) in a selection, so a big group's `member` list comes back
silently truncated at 1500. Use the MS-ADCAP `GetADGroupMember` custom action to
get the complete membership (resolved server-side, no cap):

```rust
// direct members; pass `true` to expand nested groups server-side
let members = client.group_members("CN=GS-TEST01,OU=TEST01,DC=essos,DC=local", false).await?;
for m in &members {
    println!("{}  {}  {}", m.dn, m.sam_account_name, m.object_class);
}
// group_members_in(group_dn, partition_dn, recursive) sets the partition explicitly
```

## Wiring it into RustHound-CE

RustHound-CE funnels every directory read through three functions in
`src/transport/ldap.rs` and feeds everything downstream as `LdapSearchEntry`
(the same `{ dn, attrs, bin_attrs }` shape). A `src/transport/adws.rs` that
adapts this crate behind a `DirectoryTransport` trait gives a `--transport
soap|ldap` switch with **no change** to `objects/*` or the JSON maker:

| RustHound-CE (LDAP)        | adws equivalent                        |
| -------------------------- | ----------------------------------------- |
| `ldap_auth`                | `AdwsClient::connect`                     |
| `get_all_naming_contexts`  | `AdwsClient::naming_contexts`             |
| `collect_from_ldap_into`   | `AdwsClient::search_streaming` => `.into()` => `LdapSearchEntry` |
| ranged retrieval (`member;range=`) | `AdwsClient::group_members` (`GetADGroupMember`) |
| `LDAP_SERVER_SD_FLAGS`      | `SdFlags::OWNER_DACL` (same OID + value)  |

Only the LDAP-queried slice moves to ADWS; the RPC/SMB modules (sessions, SAMR
local groups, SYSVOL/GPO) keep their own protocols.

Groups larger than `MaxValRange` (1500) are completed with `GetADGroupMember`
over `Windows/AccountManagement`, so the `member` list matches what the LDAP
collector reconstructs with ranged retrieval. The `adws` transport does this
automatically for any group whose `member` reaches the cap.

## Feature flags

See [HELP.md](HELP.md#feature-flags). Enable `ldap3` for the RustHound-CE
integration, `sspi-auth` for a live connection.

## API surface

- `AdwsClient::connect`, `naming_contexts`, `search`, `search_streaming`
- `AdwsClient::group_members` / `group_members_in` => `Vec<GroupMember>` (MS-ADCAP `GetADGroupMember`)
- `AdwsClient::create`, `modify`, `delete` - the WS-Transfer write path
- `types::{SearchEntry, Scope, Mod, Value}`
- `GroupMember`
- `control::SdFlags`
- `auth::{Credentials, SspiProvider}`
- `transport::{nmf, nns}`, `ws::{nbfx, nbfs_dict, mapping, response, envelope, transfer, account}`