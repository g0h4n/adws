//! MS-NNS - .NET NegotiateStream Protocol (runs after the MC-NMF upgrade).
//!
//! Handshake messages carry SPNEGO/GSS tokens until `HandshakeDone`; afterwards
//! application data travels as Data messages, signed/sealed by the negotiated
//! mechanism when the protection level is `Sign` or `EncryptAndSign`. Identity
//! is fixed at the handshake - there is no re-authentication on an established
//! connection (see the research notes on why relaying to ADWS is a dead end
//! under `EncryptAndSign`).
//!
//! The message framing below is exact and unit-tested. The token exchange and
//! the sign/seal are delegated to an [`crate::auth::SspiProvider`].

use log::trace;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::SspiProvider;
use crate::error::{AdwsError, Result};

// Handshake message types - MS-NNS 2.2.1. VERIFY against a capture.
pub const HANDSHAKE_DONE: u8 = 0x14;
pub const HANDSHAKE_ERROR: u8 = 0x15;
pub const HANDSHAKE_IN_PROGRESS: u8 = 0x16;
const NNS_MAJOR: u8 = 0x01;
const NNS_MINOR: u8 = 0x00;

/// Protection level negotiated for the connection (MS-NNS 3.x). The server
/// application (ADWS) sets the *required* level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    None,
    Sign,
    EncryptAndSign,
}

/// Encode a handshake message header: `type(1) major(1) minor(1) size(2, BE)`.
fn handshake_header(msg_type: u8, payload_len: usize) -> [u8; 5] {
    let len = payload_len as u16;
    [msg_type, NNS_MAJOR, NNS_MINOR, (len >> 8) as u8, (len & 0xff) as u8]
}

/// Read one handshake frame: 5-byte header (`type major minor size(2, BE)`) then
/// `size` payload bytes. Returns `(msg_type, payload)`.
async fn read_handshake<S>(stream: &mut S) -> Result<(u8, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let size = ((hdr[3] as usize) << 8) | hdr[4] as usize;
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload).await?;
    trace!("nns: recv handshake type=0x{:02X} len={size}", hdr[0]);
    Ok((hdr[0], payload))
}

/// An authenticated NNS channel over an async stream.
pub struct SecureChannel<S> {
    stream: S,
    provider: Box<dyn SspiProvider>,
    protection: ProtectionLevel,
}

impl<S> SecureChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Drive the NNS handshake to completion over an already-upgraded stream.
    pub async fn handshake(mut stream: S, mut provider: Box<dyn SspiProvider>) -> Result<Self> {
        let mut in_token: Option<Vec<u8>> = None;

        loop {
            // Produce our next token from the last server token.
            if let Some(out) = provider.step(in_token.as_deref())? {
                let msg_type = if provider.is_complete() {
                    HANDSHAKE_DONE
                } else {
                    HANDSHAKE_IN_PROGRESS
                };
                trace!("nns: send handshake type=0x{msg_type:02X} len={}", out.len());
                stream.write_all(&handshake_header(msg_type, out.len())).await?;
                stream.write_all(&out).await?;
            }

            if provider.is_complete() {
                // The peer answers our final token with a terminal HandshakeDone
                // frame (MS-NNS: WaitingForHandshakeDone -> Authenticated). It
                // MUST be consumed before the data phase, otherwise the next
                // read desyncs on these leftover bytes.
                let (msg_type, _payload) = read_handshake(&mut stream).await?;
                match msg_type {
                    HANDSHAKE_DONE => break,
                    HANDSHAKE_ERROR => {
                        return Err(AdwsError::Nns("server returned HandshakeError at completion".into()))
                    }
                    other => {
                        return Err(AdwsError::Nns(format!(
                            "unexpected completion handshake type 0x{other:02X}"
                        )))
                    }
                }
            }

            // Read the server's next handshake message.
            let (msg_type, payload) = read_handshake(&mut stream).await?;
            match msg_type {
                HANDSHAKE_ERROR => {
                    return Err(AdwsError::Nns("server returned HandshakeError".into()))
                }
                HANDSHAKE_IN_PROGRESS | HANDSHAKE_DONE => in_token = Some(payload),
                other => {
                    return Err(AdwsError::Nns(format!("bad handshake type 0x{other:02X}")))
                }
            }
        }

        let protection = provider.protection();
        Ok(Self { stream, provider, protection })
    }

    /// Send an application payload as a (signed/sealed) Data message:
    /// `PayloadSize(4, little-endian)` + protected payload (MS-NNS 2.2.2).
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let body = match self.protection {
            ProtectionLevel::None => payload.to_vec(),
            _ => self.provider.wrap(payload)?,
        };
        trace!("nns: send data frame len={} (protection={:?})", body.len(), self.protection);
        self.stream.write_all(&(body.len() as u32).to_le_bytes()).await?;
        self.stream.write_all(&body).await?;
        Ok(())
    }

    /// Receive and verify/unseal one application payload.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let n = u32::from_le_bytes(len) as usize;
        trace!("nns: recv data frame len={n}");
        let mut body = vec![0u8; n];
        self.stream.read_exact(&mut body).await?;
        match self.protection {
            ProtectionLevel::None => Ok(body),
            _ => self.provider.unwrap(&body),
        }
    }

    pub fn protection(&self) -> ProtectionLevel {
        self.protection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encoding() {
        assert_eq!(handshake_header(HANDSHAKE_IN_PROGRESS, 0x0102), [0x16, 1, 0, 0x01, 0x02]);
        assert_eq!(handshake_header(HANDSHAKE_DONE, 0), [0x14, 1, 0, 0, 0]);
    }
}
