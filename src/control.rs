//! Directory controls that must be reproduced over ADWS for parity with LDAP.

/// `SECURITY_INFORMATION` flags for reading `nTSecurityDescriptor`.
///
/// Over LDAP, RustHound-CE sends these via `LDAP_SERVER_SD_FLAGS`
/// (OID `1.2.840.113556.1.4.801`) with the DER value `SEQUENCE { INTEGER 5 }`,
/// i.e. `OWNER | DACL` - no SACL, so no `SeSecurityPrivilege` is required.
///
/// Over ADWS the same request is carried as an ADCAP `LdapServerControl`
/// (a `controls` entry in the SOAP header). Reproducing it is mandatory: without
/// it, `nTSecurityDescriptor` comes back empty and BloodHound gets no ACEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdFlags(pub u32);

impl SdFlags {
    pub const OWNER: u32 = 0x1;
    pub const GROUP: u32 = 0x2;
    pub const DACL: u32 = 0x4;
    pub const SACL: u32 = 0x8;

    /// Owner + DACL - the exact set RustHound-CE requests over LDAP.
    pub const OWNER_DACL: SdFlags = SdFlags(Self::OWNER | Self::DACL);

    /// DER encoding of `SEQUENCE { INTEGER <flags> }`, as sent in the LDAP
    /// control value. Kept here so the ADWS mapping and the LDAP path stay
    /// provably identical. For flags = 5 this yields `[48, 3, 2, 1, 5]`.
    pub fn der_value(self) -> Vec<u8> {
        vec![0x30, 0x03, 0x02, 0x01, self.0 as u8]
    }

    pub const OID: &'static str = "1.2.840.113556.1.4.801";
}

/// `LDAP_SERVER_SHOW_DELETED` (OID `1.2.840.113556.1.4.417`), non-critical.
pub const SHOW_DELETED_OID: &str = "1.2.840.113556.1.4.417";
