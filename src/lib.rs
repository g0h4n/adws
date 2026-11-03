// Scaffold stage: wire-level bodies are `todo!()`. Remove this allow once filled.
#![allow(dead_code, unused_variables, unused_imports)]

//! # adws
//!
//! A Rust client for **Active Directory Web Services (ADWS)** - the SOAP/WS-*
//! endpoint a Domain Controller exposes on TCP **9389**, which it proxies to its
//! *local* LDAP. Talking to a DC over ADWS instead of LDAP (389/636) is a known
//! way to stay out of the view of LDAP-centric detections.
//!
//! The crate is built bottom-up over the real protocol stack:
//! - [`transport::nmf`] - **MC-NMF**, the .NET Message Framing over TCP.
//! - [`transport::nns`] - **MS-NNS**, the .NET NegotiateStream handshake and the
//!   signed/sealed framing of application data.
//! - [`ws`] - the SOAP layer: **MS-ADDM** data model over **WS-Transfer** and
//!   **WS-Enumeration**, carrying the directory operations.
//!
//! ## Design goals
//! - **Read first.** [`client::AdwsClient`] implements enumeration/search now.
//!   Write operations (RBCD, Shadow Credentials, DACL, altSecurityIdentities…)
//!   are a planned second phase and have their seams reserved in [`ws`].
//! - **ldap3-compatible currency.** With the `ldap3` feature, [`types::SearchEntry`]
//!   converts to and from [`ldap3::SearchEntry`] for free, so this crate drops
//!   into ldap3-based tools (e.g. RustHound-CE) as an alternate transport.
//!
//! ## Integration with RustHound-CE
//! RustHound-CE already funnels its directory reads through three functions in
//! `src/transport/ldap.rs` (`ldap_auth`, `get_all_naming_contexts`,
//! `collect_from_ldap_into`) and feeds everything downstream as `LdapSearchEntry`
//! (= `ldap3::SearchEntry` fields). A thin `src/transport/adws.rs` adapts this
//! crate's [`AdwsClient`] to those three functions; nothing in `objects/*` changes.
//!
//! ## References
//! - \[MS-NNS\], \[MC-NMF\], \[MS-ADDM\] (Microsoft Open Specifications)
//! - SOAPy (Python) and go-adws / sopa (Go) as wire references to port from.

pub mod auth;
pub mod client;
pub mod control;
pub mod error;
pub mod transport;
pub mod types;
pub mod ws;

pub use auth::Credentials;
pub use client::{AdwsClient, DEFAULT_PULL_BATCH};
pub use control::SdFlags;
pub use error::{AdwsError, Result};
pub use types::{Mod, Scope, SearchEntry, Value};
pub use ws::account::GroupMember;