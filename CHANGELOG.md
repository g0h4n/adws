# Changelog

## 0.1.1 - 2026-11-03

### Added

- `AdwsClient::group_members` / `group_members_in`: enumerate a group's **full**
  membership through the MS-ADCAP `GetADGroupMember` custom action over the
  `Windows/AccountManagement` endpoint (the SOAP equivalent of the
  `Get-ADGroupMember` cmdlet), with an optional `recursive` flag to expand
  nested groups server-side.
- `GroupMember` type (`dn`, `name`, `object_class`, `object_guid`, `sid`,
  `sam_account_name`), re-exported at the crate root.
- `group_members` example: resolves a group by name or DN, then prints the
  capped `member` count from a plain search next to the complete membership from
  `GetADGroupMember` (set `ADWS_PRINT_ALL=1` to list every member).

### Fixed

- **Large groups over ADWS.** Active Directory caps a multivalued attribute at
  `MaxValRange` (default 1500) per search, and ADWS does **not** accept the LDAP
  ranged-retrieval option (`member;range=lo-hi`) in a selection property (it
  faults with `The specified AttributeType is not valid`). A group's `member`
  list was therefore silently truncated at 1500 with no `;range=` signal to act
  on. It is now completed with `GetADGroupMember`, which resolves the whole
  membership server-side. The RustHound-CE `--transport soap` collector applies
  this automatically for any group whose `member` reaches the cap.

### Validated

- Live against GOAD: a 2000-member group returned 1500 via a plain search and
  the full 2000 via `GetADGroupMember` (500 recovered), DNs matching the LDAP
  collector.

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