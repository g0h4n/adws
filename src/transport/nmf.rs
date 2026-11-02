//! MC-NMF - .NET Message Framing Protocol (TCP 9389).
//!
//! Implemented here: the record types, the variable-length "record size"
//! encoding, the duplex-session preamble, the security upgrade handshake, and
//! sized-envelope read/write. The size encoding and record framing are exact
//! and unit-tested; the two preamble *constants* (mode + known-encoding) and
//! the end-to-end ordering are marked VERIFY and should be confirmed against
//! go-adws / SOAPy or a live DC capture.
//!
//! Wire references: \[MC-NMF\], SOAPy (Python), go-adws `transport` (Go),
//! ernw/silentsignal `net.tcp-proxy`.

use log::trace;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AdwsError, Result};

// Record types - MC-NMF 2.2.3.
pub const REC_VERSION: u8 = 0x00;
pub const REC_MODE: u8 = 0x01;
pub const REC_VIA: u8 = 0x02;
pub const REC_KNOWN_ENCODING: u8 = 0x03;
pub const REC_UPGRADE_REQUEST: u8 = 0x09;
pub const REC_UPGRADE_RESPONSE: u8 = 0x0A;
pub const REC_PREAMBLE_ACK: u8 = 0x0B;
pub const REC_PREAMBLE_END: u8 = 0x0C;
pub const REC_SIZED_ENVELOPE: u8 = 0x06;
pub const REC_END: u8 = 0x07;
pub const REC_FAULT: u8 = 0x08;

// Mode (MC-NMF 2.2.3.2): SingletonUnsized=1, Duplex=2, Simplex=3, SingletonSized=4.
pub const MODE_DUPLEX: u8 = 0x02; // VERIFY: WCF net.tcp session mode.
// KnownEncoding (2.2.3.4): 0x08 = .NET Binary with in-band dictionary (session).
pub const ENC_BINARY_SESSION: u8 = 0x08; // VERIFY against go-adws/SOAPy.
// Security upgrade content type for the NegotiateStream upgrade.
pub const UPGRADE_NEGOTIATE: &str = "application/negotiate";

/// Encode a length with MC-NMF's 7-bit "record size" encoding (little-endian,
/// high bit = continuation).
pub fn encode_size(mut n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// Decode a 7-bit record size from the front of `buf`, returning
/// `(value, bytes_consumed)`.
pub fn decode_size(buf: &[u8]) -> Result<(usize, usize)> {
    let mut value: usize = 0usize;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        value |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift > 35 {
            return Err(AdwsError::Nmf("record size too large".into()));
        }
    }
    Err(AdwsError::Nmf("truncated record size".into()))
}

/// A framed MC-NMF connection over an async byte stream.
pub struct NmfConnection<S> {
    stream: S,
}

impl<S> NmfConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    async fn read_encoded_size(&mut self) -> Result<usize> {
        let mut value: usize = 0;
        let mut shift = 0u32;
        loop {
            let b = self.stream.read_u8().await?;
            value |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 35 {
                return Err(AdwsError::Nmf("record size too large".into()));
            }
        }
    }

    async fn write_sized_record(&mut self, rec: u8, data: &[u8]) -> Result<()> {
        self.stream.write_u8(rec).await?;
        self.stream.write_all(&encode_size(data.len())).await?;
        self.stream.write_all(data).await?;
        Ok(())
    }

    /// Send the duplex-session preamble (Version, Mode, Via, KnownEncoding) then
    /// the UpgradeRequest, and await the UpgradeResponse. After this returns the
    /// raw stream is ready for the MS-NNS handshake.
    pub async fn negotiate_and_upgrade(&mut self, via: &str) -> Result<()> {
        trace!("nmf: sending preamble, via={via}");
        // Version 1.0
        self.stream.write_all(&[REC_VERSION, 0x01, 0x00]).await?;
        // Mode
        self.stream.write_all(&[REC_MODE, MODE_DUPLEX]).await?;
        // Via (target URL)
        self.write_sized_record(REC_VIA, via.as_bytes()).await?;
        // Known encoding
        self.stream.write_all(&[REC_KNOWN_ENCODING, ENC_BINARY_SESSION]).await?;
        // Request the security upgrade to NegotiateStream.
        self.write_sized_record(REC_UPGRADE_REQUEST, UPGRADE_NEGOTIATE.as_bytes())
            .await?;

        let resp = self.stream.read_u8().await?;
        if resp != REC_UPGRADE_RESPONSE {
            return Err(AdwsError::Nmf(format!(
                "expected UpgradeResponse (0x0A), got 0x{resp:02X}"
            )));
        }
        trace!("nmf: upgrade response received");
        Ok(())
    }

    /// Send PreambleEnd and await PreambleAck. Runs after the NNS handshake.
    /// VERIFY: ordering relative to the secured channel against a capture.
    pub async fn finish_preamble(&mut self) -> Result<()> {
        self.stream.write_u8(REC_PREAMBLE_END).await?;
        let ack = self.stream.read_u8().await?;
        if ack != REC_PREAMBLE_ACK {
            return Err(AdwsError::Nmf(format!(
                "expected PreambleAck (0x0B), got 0x{ack:02X}"
            )));
        }
        Ok(())
    }

    /// Write one sized-envelope record (an application payload).
    pub async fn write_sized_envelope(&mut self, payload: &[u8]) -> Result<()> {
        self.write_sized_record(REC_SIZED_ENVELOPE, payload).await
    }

    /// Read one sized-envelope record.
    pub async fn read_sized_envelope(&mut self) -> Result<Vec<u8>> {
        let rec = self.stream.read_u8().await?;
        match rec {
            REC_SIZED_ENVELOPE => {
                let len = self.read_encoded_size().await?;
                let mut buf = vec![0u8; len];
                self.stream.read_exact(&mut buf).await?;
                Ok(buf)
            }
            REC_END => Err(AdwsError::Nmf("connection End record".into())),
            REC_FAULT => Err(AdwsError::Nmf("server Fault record".into())),
            other => Err(AdwsError::Nmf(format!("unexpected record 0x{other:02X}"))),
        }
    }

    /// Borrow the underlying stream (the NNS layer frames its handshake on it).
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_roundtrip() {
        for n in [0usize, 1, 5, 127, 128, 300, 16_383, 16_384, 2_097_151, 2_097_152] {
            let enc = encode_size(n);
            let (dec, used) = decode_size(&enc).unwrap();
            assert_eq!(dec, n, "value {n}");
            assert_eq!(used, enc.len(), "consumed for {n}");
        }
    }

    #[test]
    fn size_known_vectors() {
        assert_eq!(encode_size(5), vec![0x05]);
        assert_eq!(encode_size(127), vec![0x7f]);
        assert_eq!(encode_size(128), vec![0x80, 0x01]);
        assert_eq!(encode_size(16_384), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn decode_truncated_errors() {
        assert!(decode_size(&[0x80]).is_err());
    }
}
