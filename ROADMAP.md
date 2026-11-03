# Roadmap

- [Protocol stack](#protocol-stack)
- [Read path](#read-path)
- [Write path (phase 2)](#write-path-phase-2)
- [Custom actions (MS-ADCAP)](#custom-actions-ms-adcap)
- [Authentication](#authentication)
- [Dependencies](#dependencies)

Status legend: :white_check_mark: done & tested · :red_circle: planned.

## Protocol stack

| Layer | Spec | Status |
| ----- | ---- | ------ |
| MC-NMF framing (records, size varint, preamble, upgrade, sized envelopes) | \[MC-NMF\] | :white_check_mark: |
| MS-NNS message framing (handshake header, data length, sign/seal) | \[MS-NNS\] | :white_check_mark: |
| NNS SSPI token exchange + message wrap/unwrap | \[MS-NNS\] | :white_check_mark: |
| NBFSE codec, encode (`0x00` + inline), decode (StringTable + dictionary) | \[MC-NBFX\]/\[MC-NBFSE\] | :white_check_mark: |
| NBFS static dictionary (486 entries) | \[MC-NBFS\] | :white_check_mark: |
| WS-Enumeration response => `SearchEntry` (items, `LdapSyntax` routing) | \[MS-ADDM\] | :white_check_mark: |
| WS-Enumeration request build (`Enumerate`/`Pull`) in NBFX | \[MS-ADDM\] | :white_check_mark: |
| MS-ADCAP custom actions (`GetADGroupMember`) over `Windows/AccountManagement` | \[MS-ADCAP\] | :white_check_mark: |
| End-to-end send/recv over the NNS channel (multi-frame reassembly) | - | :white_check_mark: |

## Read path

- :white_check_mark: `SearchEntry` type, ldap3-compatible, `bin_attrs` routing.
- :white_check_mark: SD-flags control (`OWNER_DACL`, OID `1.2.840.113556.1.4.801`).
- :white_check_mark: Naming-context enumeration with RustHound-CE's ordering.
- :white_check_mark: PullResponse parsing (DN, attributes, base64 binary syntaxes).
- :white_check_mark: Request NBFX builders + channel I/O running a real `search`.
- :white_check_mark: Large multivalued attributes (groups past the 1500 `MaxValRange` cap) completed via `GetADGroupMember` (see [Custom actions](#custom-actions-ms-adcap)), since ADWS has no ranged retrieval.
- :white_check_mark: Validated against a live DC (GOAD): 2259 objects, paged and reassembled, `objectSid` / `nTSecurityDescriptor` in `bin_attrs`.

## Write path (phase 2)

`adws` provides the **generic** ADWS write primitives only. The named attack
techniques (RBCD, Shadow Credentials, DACL abuse, password reset, SPN/UAC) are
built on top of these in `ldapshell-rs`, not in this library, since they are just
specific attribute writes plus some payload construction (an ACE, a
KeyCredential blob, a UTF-16 password). Reserved seams are in place
(`types::Mod`, the `ws::transfer` slot). Planned here:

- :white_check_mark: WS-Transfer `Put` (modify: add / replace / delete attribute values), taking `types::Mod`. Validated live (toggled `userAccountControl` to enable/disable an account over `Windows/Resource`).
- :white_check_mark: WS-Transfer `Delete` (remove an object).
- :white_check_mark: WS-Transfer `Create` (add an object, `Windows/ResourceFactory`), via `AdwsClient::create`. See the `add_computer` / `del_computer` examples. Validated: build + unit tests; live object creation to confirm on a DC.
- :white_check_mark: Binary-typed values (`Value::Bytes` => `xsi:type="xsd:base64Binary"`). Validated live: wrote an RBCD security descriptor to `msDS-AllowedToActOnBehalfOfOtherIdentity` (see the `rbcd` example). So `msDS-KeyCredentialLink`, `nTSecurityDescriptor`, etc. are all reachable as generic binary writes.

## Custom actions (MS-ADCAP)

The Account Management / Topology custom actions (\[MS-ADCAP\]) that the Active
Directory PowerShell cmdlets drive. Carried over the `Windows/AccountManagement`
endpoint (its own net.tcp connection, same NMF/NNS handshake).

- :white_check_mark: `GetADGroupMember` (`AdwsClient::group_members` / `group_members_in`): a group's full membership resolved server-side, past the `MaxValRange` (1500) cap that truncates `member` on a plain search. This is the ADWS replacement for LDAP ranged retrieval (`member;range=lo-hi`), which the ADWS selection dialect rejects. Optional `recursive` expansion of nested groups. Validated live (GOAD): recovered 2000 members where the capped search returned 1500.
- :red_circle: other MS-ADCAP actions as needed (`GetADPrincipalGroupMembership`, `TranslateName`, password reset, ...).

## Authentication

| Mode | Status |
| ---- | ------ |
| Username + password | :white_check_mark: wired (sspi-rs NTLM), validated live |
| Pass-the-Hash (NT hash) | :white_check_mark: wired (sspi-rs NTLM), validated live |
| Kerberos (ccache) | :red_circle: |
| Kerberos (AES key) | :red_circle: |
| Pass-the-Certificate (PKINIT => Kerberos) | :red_circle: |

Gated behind `sspi-auth`. NTLM (password / pass-the-hash) is implemented via
`sspi` 0.16.x (see [Dependencies](#dependencies) for why this version) and
validated against a live DC. Kerberos (AES key) can reuse the same
`SspiProvider` seam via sspi's `Keytab`, but ccache and PKINIT need a dedicated
Kerberos stack (sspi has no ccache loader and its only certificate path is
PKCS#11 smart card, not a PFX).

## Dependencies

- :red_circle: **Update `sspi` to the latest version.** `sspi` is pinned to
  **0.16.1** on purpose, not because adws needs an old API but because
  RustHound-CE's `ldap3` (0.12.1, `ntlm` feature) pulls `sspi` 0.16.1; a second,
  semver-incompatible `sspi` in the same binary would force conflicting `picky`
  versions and break the build. adws therefore stays on 0.16.x so a single
  `sspi` (and `picky`) resolves across the whole tree. Bump to the latest `sspi`
  once `ldap3` itself is ported to the latest `sspi` **and** its pass-the-hash PR
  ([inejge/ldap3#154](https://github.com/inejge/ldap3/pull/154)) is merged. The
  NTLM provider (`auth.rs`) will then need its ISC / `encrypt_message` /
  `decrypt_message` calls realigned to the newer API (the reverse of the
  0.23 => 0.16.1 port), and the `picky` / `picky-krb` pins dropped.