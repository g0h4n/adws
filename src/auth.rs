//! Authentication for the NNS (NegotiateStream) handshake.
//!
//! ADWS authenticates through SSPI/Negotiate (NTLM or Kerberos) carried in the
//! NNS handshake - NOT Schannel. "Pass-the-certificate" therefore means
//! **PKINIT => TGT => Kerberos over NNS**, not direct certificate auth.
//!
//! [`SspiProvider`] abstracts the chosen mechanism: it yields handshake tokens
//! and, once established, signs/seals ([`wrap`](SspiProvider::wrap)) and
//! verifies/unseals ([`unwrap`](SspiProvider::unwrap)) Data messages. A concrete
//! provider over Devolutions `sspi-rs` lives behind the `sspi-auth` feature.

use crate::error::{AdwsError, Result};
use crate::transport::nns::ProtectionLevel;

/// The ways to authenticate to ADWS.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Username + plaintext password (NTLM or Kerberos).
    Password { domain: String, username: String, password: String },
    /// Pass-the-Hash: NTLM with the NT hash, no plaintext.
    NtHash { domain: String, username: String, nt_hash: [u8; 16] },
    /// Kerberos from an existing credential cache.
    KerberosCcache { ccache_path: String },
    /// Kerberos from an AES (128/256) key.
    KerberosAesKey { domain: String, username: String, aes_key: Vec<u8> },
    /// Pass-the-Certificate via PKINIT (reuses the PassTheCert-rs brick).
    Certificate { domain: String, username: String, cert_der: Vec<u8>, key_der: Vec<u8> },
}

/// Drives one authentication mechanism for the NNS layer.
pub trait SspiProvider: Send {
    /// Advance the handshake: given the last server token (if any), return the
    /// next token to send, or `None` when there is nothing more to send.
    fn step(&mut self, in_token: Option<&[u8]>) -> Result<Option<Vec<u8>>>;

    /// True once the security context is fully established.
    fn is_complete(&self) -> bool;

    /// Protection level negotiated for Data messages.
    fn protection(&self) -> ProtectionLevel;

    /// Sign and/or seal an outgoing Data message payload.
    fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify and/or unseal an incoming Data message payload.
    fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

impl Credentials {
    /// Build the [`SspiProvider`] for the NNS handshake against `target_spn`
    /// (e.g. `HOST/dc01.domain.local`).
    pub fn provider(&self, target_spn: &str) -> Result<Box<dyn SspiProvider>> {
        #[cfg(feature = "sspi-auth")]
        {
            sspi_provider::build(self, target_spn)
        }
        #[cfg(not(feature = "sspi-auth"))]
        {
            let _ = target_spn;
            Err(AdwsError::Auth(
                "no SSPI provider: build with --features sspi-auth".into(),
            ))
        }
    }
}

#[cfg(feature = "sspi-auth")]
mod sspi_provider {
    use super::*;

    use sspi::builders::{AcquireCredentialsHandle, WithoutCredentialUse};
    use sspi::credssp::SspiContext;
    use sspi::ntlm::NtlmConfig;
    use sspi::{
        AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, Credentials as SspiCredentials,
        CredentialsBuffers, DataRepresentation, EncryptionFlags, Ntlm, Secret,
        SecurityBuffer, SecurityBufferRef, SecurityStatus, Sspi, SspiImpl, Username,
    };

    /// Encode an NT hash as the "password" sspi-rs reads for pass-the-hash: the
    /// 32 upper-hex ASCII chars of the hash followed by >=512 bytes of padding
    /// once UTF-16LE encoded (sspi's `SSPI_CREDENTIALS_HASH_LENGTH_OFFSET`).
    /// This is the same encoding RustHound-CE feeds `sasl_ntlm_bind`.
    fn nt_hash_pth_password(nt: &[u8; 16]) -> String {
        let hex: String = nt.iter().map(|b| format!("{b:02X}")).collect();
        let bytes = hex.as_bytes();
        let mut password = String::new();
        for pair in bytes.chunks(2) {
            let low = pair[0] as u32;
            let high = if pair.len() > 1 { pair[1] as u32 } else { 0 };
            password.push(char::from_u32((high << 8) | low).unwrap_or('\0'));
        }
        for _ in 0..256 {
            password.push('\0');
        }
        password
    }

    fn logon_name(domain: &str, username: &str) -> String {
        if domain.is_empty() {
            username.to_string()
        } else {
            format!("{domain}\\{username}")
        }
    }

    /// Provider backed by Devolutions `sspi-rs` (NTLM for now).
    pub(super) fn build(creds: &Credentials, target_spn: &str) -> Result<Box<dyn SspiProvider>> {
        let (user, secret) = match creds {
            Credentials::Password { domain, username, password } => {
                log::debug!("auth: NTLM with password for {}", logon_name(domain, username));
                (logon_name(domain, username), password.clone())
            }
            Credentials::NtHash { domain, username, nt_hash } => {
                log::debug!("auth: NTLM pass-the-hash for {}", logon_name(domain, username));
                (logon_name(domain, username), nt_hash_pth_password(nt_hash))
            }
            _ => {
                log::error!("auth: requested mechanism not yet wired (only NTLM password / NT-hash)");
                return Err(AdwsError::Auth(
                    "only password and NT-hash (NTLM) are wired so far".into(),
                ))
            }
        };
        log::trace!("auth: target SPN = {target_spn}");

        let identity = AuthIdentity {
            username: Username::parse(&user).map_err(|e| AdwsError::Auth(format!("username: {e}")))?,
            password: Secret::from(secret),
        };
        let credentials = SspiCredentials::AuthIdentity(identity);

        let mut ctx = SspiContext::Ntlm(Ntlm::with_config(NtlmConfig { client_computer_name: None }));
        let acq = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new()
            .with_auth_data(&credentials)
            .with_credential_use(CredentialUse::Outbound)
            .execute(&mut ctx)
            .map_err(|e| AdwsError::Auth(format!("acquire credentials: {e}")))?;

        Ok(Box::new(SspiRsProvider {
            ctx,
            cred: acq.credentials_handle,
            target: target_spn.to_string(),
            complete: false,
            send_seq: 0,
            recv_seq: 0,
        }))
    }

    struct SspiRsProvider {
        ctx: SspiContext,
        cred: Option<CredentialsBuffers>,
        target: String,
        complete: bool,
        // MS-NNS data messages are signed/sealed with a per-direction sequence
        // number (sspi 0.16 takes it explicitly; NTLM folds it into the MAC).
        send_seq: u32,
        recv_seq: u32,
    }

    impl SspiProvider for SspiRsProvider {
        fn step(&mut self, in_token: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
            if self.complete {
                return Ok(None);
            }
            let mut input =
                [SecurityBuffer::new(in_token.map(|t| t.to_vec()).unwrap_or_default(), BufferType::Token)];
            let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

            let target = self.target.clone();
            let mut cred = self.cred.take();
            let mut builder = self
                .ctx
                .initialize_security_context()
                .with_credentials_handle(&mut cred)
                .with_context_requirements(
                    ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::INTEGRITY
                        | ClientRequestFlags::CONFIDENTIALITY
                        | ClientRequestFlags::SEQUENCE_DETECT
                        | ClientRequestFlags::REPLAY_DETECT,
                )
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            builder.target_name = Some(&target);

            let result = self
                .ctx
                .initialize_security_context_impl(&mut builder)
                .map_err(|e| AdwsError::Auth(format!("initialize_security_context: {e}")))
                .and_then(|mut generator| {
                    generator
                        .resolve_to_result()
                        .map_err(|e| AdwsError::Auth(format!("initialize_security_context: {e}")))
                });
            self.cred = cred;
            let result = result?;

            if result.status == SecurityStatus::Ok {
                self.complete = true;
            }
            let token = std::mem::take(&mut output[0].buffer);
            Ok(if token.is_empty() { None } else { Some(token) })
        }

        fn is_complete(&self) -> bool {
            self.complete
        }

        fn protection(&self) -> ProtectionLevel {
            // We request INTEGRITY | CONFIDENTIALITY, so NNS seals data messages.
            ProtectionLevel::EncryptAndSign
        }

        fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
            // Stream pattern: [token][data] on the wire (NNS / SSPI-GSS interop).
            let mut token = vec![0u8; 1024];
            let mut payload = data.to_vec();
            let mut message =
                [SecurityBufferRef::token_buf(&mut token), SecurityBufferRef::data_buf(&mut payload)];
            let seq = self.send_seq;
            self.ctx
                .encrypt_message(EncryptionFlags::empty(), &mut message, seq)
                .map_err(|e| AdwsError::Nns(format!("encrypt_message: {e}")))?;
            self.send_seq = self.send_seq.wrapping_add(1);
            let mut out = message[0].data().to_vec();
            out.extend_from_slice(message[1].data());
            Ok(out)
        }

        fn unwrap(&mut self, data: &[u8]) -> Result<Vec<u8>> {
            let mut buffer = data.to_vec();
            let mut message =
                [SecurityBufferRef::stream_buf(&mut buffer), SecurityBufferRef::data_buf(&mut [])];
            let seq = self.recv_seq;
            self.ctx
                .decrypt_message(&mut message, seq)
                .map_err(|e| AdwsError::Nns(format!("decrypt_message: {e}")))?;
            self.recv_seq = self.recv_seq.wrapping_add(1);
            Ok(message[1].data().to_vec())
        }
    }
}
