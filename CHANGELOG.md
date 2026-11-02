# Changelog

## 0.1.0 - 2026-11-02

First release. A pure-Rust client for **Active Directory Web Services** (ADWS,
the SOAP/WS-* endpoint on TCP 9389), with `ldap3`-compatible types so it can act
as a drop-in `--transport soap` for [RustHound-CE](https://github.com/g0h4n/RustHound-CE), [adshell-rs](https://github.com/g0h4n/adshell-rs) and other tooling.

### Added

- Full protocol stack: MC-NMF framing, MS-NNS (NegotiateStream) security layer,
  NBFX/NBFSE binary-XML codec with the MC-NBFS static dictionary.
- `AdwsClient`: `connect`, `naming_contexts`, `search` / `search_streaming`.
- Full CRUD over WS-Enumeration + WS-Transfer: **read** (Enumerate/Pull),
  **create** (`ResourceFactory`), **update** (`Put`, from `types::Mod`) and
  **delete**, with string and binary (`base64Binary`) attribute values.
- `ldap3`-compatible `SearchEntry` / `Scope` / `Mod` types, with `From`/`Into`
  conversions behind the `ldap3` feature.
- `SdFlags` control (`OWNER_DACL`, OID `1.2.840.113556.1.4.801`) for reading and
  writing `nTSecurityDescriptor`.
- Authentication via `sspi` (feature `sspi-auth`): NTLM password and
  pass-the-hash. Kerberos and pass-the-certificate (PKINIT) are not wired yet.
- Logging through the `log` facade; examples for connect, search, and the write
  path (toggle account, RBCD, add/del computer).
- Docs: README, HELP, ROADMAP, INTEGRATION.

### Validated

- Live against a lab DC (GOAD): connect + handshake, paged searches, NTLM
  password and pass-the-hash, string and binary writes (UAC toggle, RBCD), and
  machine-account create/delete.