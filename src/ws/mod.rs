//! SOAP / WS-* layer over the NNS channel (MS-ADDM data model).
//!
//! - [`envelope`] / [`response`] - build `Enumerate`/`Pull` requests and parse responses (the read path).
//! - [`mapping`] - flatten an ADWS object into an ldap3-compatible `SearchEntry`.
//! - [`transfer`] - WS-Transfer (`Put`/`Delete`): the generic **write** path.
//!
//! NOTE: on the wire these envelopes are carried as **.NET Binary XML** (NBFS,
//! implied by KnownEncoding 0x08), not text. The builders here produce the
//! logical SOAP; the NBFSE codec sits between them and the NNS channel bytes.

pub mod envelope;
pub mod mapping;
pub mod nbfs_dict;
pub mod nbfx;
pub mod response;
pub mod transfer;
