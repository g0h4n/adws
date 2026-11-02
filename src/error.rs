//! Crate error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AdwsError>;

#[derive(Debug, Error)]
pub enum AdwsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// MC-NMF framing error (bad record type, size, or upgrade handshake).
    #[error("NMF framing error: {0}")]
    Nmf(String),

    /// MS-NNS handshake or message-protection error.
    #[error("NNS error: {0}")]
    Nns(String),

    /// Authentication failure (token exchange, SSPI/GSS, PKINIT…).
    #[error("authentication failed: {0}")]
    Auth(String),

    /// SOAP/WS layer error (envelope, WS-Enumeration/Transfer fault).
    #[error("SOAP error: {0}")]
    Soap(String),

    /// A SOAP Fault returned by the server.
    #[error("server fault: {code}: {reason}")]
    Fault { code: String, reason: String },

    /// XML parse/serialize error.
    #[error("XML error: {0}")]
    Xml(String),

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
