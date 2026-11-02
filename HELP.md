# How to build it?

`adws` is a pure-Rust library with no system dependencies in its default
build. Optional features pull extra crates (see [Feature flags](#feature-flags)).

## Using Cargo

```bash
# Default build (native types, no SSPI)
cargo build --release

# ldap3-compatible types (From/Into ldap3::SearchEntry, ldap3::Scope)
cargo build --release --features ldap3

# SSPI auth provider (NTLM / Kerberos) - needed to actually connect
cargo build --release --features sspi-auth

# Everything
cargo build --release --features "ldap3 sspi-auth"
```

### Required dependencies

The default build needs only a stable Rust toolchain (`rust-version = 1.75`).
The `sspi-auth` feature builds on [`sspi`](https://github.com/Devolutions/sspi-rs);
on Linux its Kerberos path may need the usual GSSAPI headers (`clang`,
`libclang-dev`, `libkrb5-dev`) depending on how it is configured.

## Run the tests

```bash
cargo test
# a specific module
cargo test ws::nbfx
```

The test suite covers the deterministic layers (framing, NBFSE codec, the static
dictionary, `SearchEntry` mapping, and PullResponse extraction). It does **not**
yet include an integration test against a live Domain Controller.

## How to build the documentation?

```bash
cargo doc --no-deps --features "ldap3 sspi-auth" --open
```

## Logging

`adws` emits records through the [`log`](https://crates.io/crates/log)
facade (like RustHound-CE and PassTheCert-rs); the application chooses a logger.
Levels used:

- `error!` - an unrecoverable condition about to be returned (e.g. an auth
  mechanism that is not wired).
- `warn!`  - a recoverable oddity (a SOAP fault, a missing Configuration NC).
- `info!`  - milestones: connect, handshake complete, search start/end + counts.
- `debug!` - per-exchange and per-Pull-batch progress, naming contexts.
- `trace!` - wire detail: NMF preamble/upgrade, NNS handshake and data frame
  sizes, the full request XML, sized-envelope reassembly.

The examples initialise `env_logger`, so pick a level with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run --example smoke_connect --features sspi-auth
RUST_LOG=adws=trace cargo run --example env_search --features "ldap3 sspi-auth"
```

# Feature flags

| Feature      | Default | What it adds |
| ------------ | ------- | ------------ |
| `ldap3`      | off     | `From`/`Into` between `adws::SearchEntry` and `ldap3::SearchEntry`, and `Scope` => `ldap3::Scope`. Pulls `ldap3`. |
| `sspi-auth`  | off     | The concrete SSPI provider (NTLM / Kerberos) that drives the NNS handshake. Pulls `sspi`. |

# Usage

`adws` is a library. The high-level entry point is
[`AdwsClient`](https://docs.rs/adws):

```rust
use adws::{AdwsClient, Credentials, Scope, SdFlags, client::Target};

let target = Target::new("dc01.essos.local", "essos.local");
let mut client = AdwsClient::connect(target, creds).await?;

// Enumerate naming contexts (Schema / Domain / Configuration)
let ncs = client.naming_contexts().await?;

// Search a context, requesting the DACL via the SD-flags control
let entries = client.search(
    "DC=essos,DC=local",
    Scope::Subtree,
    "(objectClass=user)",
    &["sAMAccountName", "objectSid"],
    Some(SdFlags::OWNER_DACL),
    false,
).await?;
```

## Authentication modes

`Credentials` mirrors what RustHound-CE accepts:

```rust
// Username + password
Credentials::Password { domain, username, password }
// Pass-the-Hash
Credentials::NtHash { domain, username, nt_hash }
// Kerberos from a ccache
Credentials::KerberosCcache { ccache_path }
// Kerberos from an AES key
Credentials::KerberosAesKey { domain, username, aes_key }
// Pass-the-Certificate (PKINIT -> TGT -> Kerberos over NNS)
Credentials::Certificate { domain, username, cert_der, key_der }
```

> Authentication requires the `sspi-auth` feature. Without it, `connect`
> returns an error telling you to enable it.

# Examples

Runnable, commented examples live in [`examples/`](examples/); each reads its
target and credentials from `ADWS_*` environment variables.

| Example | Features | What it shows |
| ------- | -------- | ------------- |
| `smoke_connect` | `sspi-auth` | Bare connect + handshake. |
| `connect_username_password` | `ldap3 sspi-auth` | Password auth + a `SearchEntry` dump. |
| `connect_pth` | `ldap3 sspi-auth` | Pass-the-hash (NT hash) auth. |
| `connect_search` | `ldap3 sspi-auth` | Naming contexts + a user search (constants in the file). |
| `env_search` | `ldap3 sspi-auth` | Env-driven search (`ADWS_BASE` / `ADWS_FILTER`). |
| `toggle_account` | `sspi-auth` | **Write**: toggle `userAccountControl` (string write). |
| `rbcd` | `sspi-auth` | **Write**: RBCD security descriptor (binary write). |
| `add_computer` | `sspi-auth` | **Create**: new machine account via WS-Transfer `Create`. |
| `del_computer` | `sspi-auth` | **Delete**: remove a machine account. |