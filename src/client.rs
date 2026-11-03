//! High-level ADWS client - the public read API.
//!
//! This is the surface RustHound-CE's `transport/adws.rs` adapts to its three
//! transport functions. Everything yields [`SearchEntry`], which converts to
//! `ldap3::SearchEntry` for free under the `ldap3` feature.
//!
//! NOTE: the send/recv framing here (one NMF sized-envelope per NNS data
//! message, PreambleEnd/Ack over the secured channel) is marked VERIFY and
//! should be confirmed against a live capture.

use log::{debug, trace, warn};
use tokio::net::TcpStream;

use crate::auth::Credentials;
use crate::control::SdFlags;
use crate::error::{AdwsError, Result};
use crate::transport::{nmf, NmfConnection, SecureChannel};
use crate::types::{Mod, Scope, SearchEntry, Value};
use crate::ws::account::{self, GroupMember};
use crate::ws::envelope::{build_enumerate_request, build_pull_request};
use crate::ws::nbfx::{decode_nbfse, encode_nbfse_request, NbfseSession, NbfxNode};
use crate::ws::{response, transfer};

/// Default number of objects requested per WS-Enumeration `Pull`
/// (`MaxElements`) when a caller does not specify one. Larger batches mean
/// fewer round-trips on big naming contexts, at a higher per-response memory
/// cost. Override per call with the `batch` argument of
/// [`AdwsClient::search_streaming`].
pub const DEFAULT_PULL_BATCH: usize = 512;

/// Where to reach the DC's ADWS endpoint.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    /// ADWS always listens on 9389; kept configurable for labs/forwarders.
    pub port: u16,
    /// The LDAP port the `ad:instance` header refers to (default 389).
    pub ldap_port: u16,
    pub domain: String,
}

impl Target {
    pub fn new(host: impl Into<String>, domain: impl Into<String>) -> Self {
        Self { host: host.into(), port: 9389, ldap_port: 389, domain: domain.into() }
    }
}

/// One authenticated endpoint connection: a secure channel, its NBFSE session,
/// and the endpoint net.tcp URL used as the SOAP `wsa:To`.
struct Endpoint {
    channel: SecureChannel<TcpStream>,
    session: NbfseSession,
    url: String,
}

/// A connected, authenticated ADWS session.
///
/// Reads go over the `Windows/Enumeration` endpoint. Writes use a separate
/// connection to `Windows/Resource`, opened lazily on the first write (each ADWS
/// endpoint is a distinct net.tcp address, so it needs its own NMF/NNS channel).
pub struct AdwsClient {
    enumeration: Endpoint,
    resource: Option<Endpoint>,
    resource_factory: Option<Endpoint>,
    account_management: Option<Endpoint>,
    target: Target,
    creds: Credentials,
}

impl AdwsClient {
    /// Connect to the DC on 9389, run MC-NMF upgrade + MS-NNS handshake with the
    /// given credentials. Analogue of RustHound-CE's `ldap_auth`.
    pub async fn connect(target: Target, creds: Credentials) -> Result<Self> {
        let enumeration = connect_endpoint(&target, &creds, "Windows/Enumeration").await?;
        Ok(Self {
            enumeration,
            resource: None,
            resource_factory: None,
            account_management: None,
            target,
            creds,
        })
    }

    /// Enumerate RootDSE `namingContexts` (Schema / Domain / Configuration),
    /// ordered the way RustHound-CE relies on. VERIFY: RootDSE read over ADWS.
    pub async fn naming_contexts(&mut self) -> Result<Vec<String>> {
        debug!("enumerating RootDSE namingContexts");
        let roots = self
            .search("", Scope::Base, "(objectClass=*)", &["namingContexts"], None, false)
            .await?;
        let mut ncs: Vec<String> = roots
            .into_iter()
            .flat_map(|e| e.attrs.get("namingContexts").cloned().unwrap_or_default())
            .collect();
        ncs.sort_by_key(|cn| {
            if cn.contains("CN=Schema") { 0 }
            else if cn.to_lowercase().starts_with("dc=") { 1 }
            else if cn.contains("CN=Configuration") { 2 }
            else { 3 }
        });
        if !ncs.iter().any(|n| n.contains("Configuration")) {
            warn!("no Configuration namingContext found (is the target a DC?)");
        }
        debug!("found {} namingContexts", ncs.len());
        Ok(ncs)
    }

    /// Run a search, collecting every entry.
    pub async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        ldap_filter: &str,
        attrs: &[&str],
        sd_flags: Option<SdFlags>,
        show_deleted: bool,
    ) -> Result<Vec<SearchEntry>> {
        let mut out = Vec::new();
        self.search_streaming(base, scope, ldap_filter, attrs, sd_flags, show_deleted, None, |e| {
            out.push(e)
        })
        .await?;
        Ok(out)
    }

    /// Run a search, invoking `sink` per entry (for streaming into storage, like
    /// RustHound-CE's `collect_from_ldap_into`).
    pub async fn search_streaming<F>(
        &mut self,
        base: &str,
        scope: Scope,
        ldap_filter: &str,
        attrs: &[&str],
        sd_flags: Option<SdFlags>,
        show_deleted: bool,
        batch: Option<usize>,
        mut sink: F,
    ) -> Result<usize>
    where
        F: FnMut(SearchEntry),
    {
        // Objects requested per Pull: caller's value, else the default. Guard
        // against 0 (which would make the server return nothing and never
        // terminate on the short-read check).
        let batch = batch.unwrap_or(DEFAULT_PULL_BATCH).max(1);
        debug!("search base='{base}' scope={scope:?} filter='{ldap_filter}' batch={batch}");
        // Always request distinguishedName when a specific attribute set is
        // selected, so every entry carries its DN (needed for writes and for
        // RustHound-CE). An empty selection already returns all attributes.
        let mut selection: Vec<&str> = attrs.to_vec();
        // RootDSE (empty base) is a pseudo-object with no distinguishedName;
        // requesting it there makes ADWS fault with "bad parameter". Only append
        // it for a real base object.
        if !selection.is_empty()
            && !base.is_empty()
            && !selection.iter().any(|a| a.eq_ignore_ascii_case("distinguishedName"))
        {
            selection.push("distinguishedName");
        }

        // 1) Enumerate opens the context.
        let enum_xml = build_enumerate_request(
            &self.enumeration.url, base, scope, ldap_filter, &selection, self.target.ldap_port,
        );
        let tree = self.enumeration.exchange(&enum_xml).await?;
        let enumerate = response::parse_enumerate_response(&tree)?;
        if enumerate.end_of_sequence {
            debug!("enumerate returned EndOfSequence (empty result)");
            return Ok(0);
        }
        let mut context = enumerate
            .enumeration_context
            .ok_or_else(|| AdwsError::Soap("Enumerate returned no EnumerationContext".into()))?;

        // 2) Pull batches until EndOfSequence.
        let mut total = 0usize;
        let mut batch_no = 0usize;
        loop {
            let pull_xml =
                build_pull_request(&self.enumeration.url, &context, batch, sd_flags, show_deleted);
            let tree = self.enumeration.exchange(&pull_xml).await?;
            let pull = response::parse_pull_response(&tree)?;

            let n = pull.items.len();
            batch_no += 1;
            for entry in pull.items {
                total += 1;
                sink(entry);
            }
            debug!("pull batch {batch_no}: {n} items (total {total})");
            if pull.end_of_sequence {
                break;
            }
            if let Some(c) = pull.enumeration_context {
                context = c;
            }
            // A short read without EndOfSequence also terminates (some DCs omit it).
            if n < batch {
                trace!("short pull batch without EndOfSequence, terminating");
                break;
            }
        }
        debug!("search complete: {total} entries in {batch_no} batches");
        Ok(total)
    }

    /// Ensure the `Windows/Resource` write endpoint is connected, opening it on
    /// first use (a separate net.tcp connection with its own handshake).
    async fn resource(&mut self) -> Result<&mut Endpoint> {
        if self.resource.is_none() {
            debug!("opening Windows/Resource endpoint for writes");
            let ep = connect_endpoint(&self.target, &self.creds, transfer::ENDPOINT_RESOURCE).await?;
            self.resource = Some(ep);
        }
        Ok(self.resource.as_mut().unwrap())
    }

    /// Modify an object: apply a set of attribute changes (add / replace /
    /// delete) in a single WS-Transfer `Put`. `sd_flags` is required only when a
    /// change touches `nTSecurityDescriptor` (e.g. `Some(SdFlags(SdFlags::DACL))`).
    pub async fn modify(&mut self, dn: &str, mods: &[Mod], sd_flags: Option<SdFlags>) -> Result<()> {
        debug!("modify {dn} ({} change(s))", mods.len());
        let ldap_port = self.target.ldap_port;
        let ep = self.resource().await?;
        let body = transfer::build_modify_request(mods, sd_flags);
        let xml = transfer::build_put_request(&ep.url, dn, &body, ldap_port);
        ep.exchange(&xml).await?;
        Ok(())
    }

    /// Delete an object by DN (WS-Transfer `Delete`).
    pub async fn delete(&mut self, dn: &str) -> Result<()> {
        debug!("delete {dn}");
        let ldap_port = self.target.ldap_port;
        let ep = self.resource().await?;
        let xml = transfer::build_delete_request(&ep.url, dn, ldap_port);
        ep.exchange(&xml).await?;
        Ok(())
    }

    /// Ensure the `Windows/ResourceFactory` endpoint is connected (for Create).
    async fn resource_factory(&mut self) -> Result<&mut Endpoint> {
        if self.resource_factory.is_none() {
            debug!("opening Windows/ResourceFactory endpoint for create");
            let ep = connect_endpoint(&self.target, &self.creds, transfer::ENDPOINT_RESOURCE_FACTORY).await?;
            self.resource_factory = Some(ep);
        }
        Ok(self.resource_factory.as_mut().unwrap())
    }

    /// Create an object at `dn` with the given attributes (WS-Transfer `Create`
    /// against `Windows/ResourceFactory`). The caller supplies `objectClass` and
    /// every mandatory attribute; values may be `Text` or `Bytes` (e.g. a
    /// UTF-16 `unicodePwd`). The object's location is NOT passed as a DN header:
    /// ADWS wants it as `ad:relativeDistinguishedName` (the leading RDN) and
    /// `ad:container-hierarchy-parent` (the parent container), which this method
    /// derives from `dn` and injects into the `AddRequest`.
    pub async fn create(&mut self, dn: &str, attrs: &[(String, Vec<Value>)]) -> Result<()> {
        debug!("create {dn} ({} attribute(s))", attrs.len());
        let (rdn, parent) = dn
            .split_once(',')
            .ok_or_else(|| AdwsError::Soap(format!("invalid DN (no parent container): {dn}")))?;

        let mut full: Vec<(String, Vec<Value>)> = Vec::with_capacity(attrs.len() + 2);
        full.push(("ad:relativeDistinguishedName".into(), vec![Value::Text(rdn.to_string())]));
        full.push(("ad:container-hierarchy-parent".into(), vec![Value::Text(parent.to_string())]));
        full.extend(attrs.iter().cloned());

        let ldap_port = self.target.ldap_port;
        let ep = self.resource_factory().await?;
        let body = transfer::build_add_request(&full);
        let xml = transfer::build_create_request(&ep.url, &body, ldap_port);
        ep.exchange(&xml).await?;
        Ok(())
    }

    /// Ensure the `Windows/AccountManagement` endpoint is connected (for the
    /// MS-ADCAP custom actions, e.g. `GetADGroupMember`).
    async fn account_management(&mut self) -> Result<&mut Endpoint> {
        if self.account_management.is_none() {
            debug!("opening Windows/AccountManagement endpoint for custom actions");
            let ep =
                connect_endpoint(&self.target, &self.creds, account::ENDPOINT_ACCOUNT_MANAGEMENT)
                    .await?;
            self.account_management = Some(ep);
        }
        Ok(self.account_management.as_mut().unwrap())
    }

    /// Enumerate a group's members via the MS-ADCAP `GetADGroupMember` custom
    /// action (the SOAP equivalent of `Get-ADGroupMember`).
    ///
    /// Unlike reading the `member` attribute with a search, this is NOT capped
    /// at `MaxValRange` (default 1500): the DC resolves the full membership
    /// server-side. It is the ADWS replacement for LDAP ranged retrieval, which
    /// the ADWS selection dialect does not support.
    ///
    /// `recursive` expands nested-group membership server-side. The group's
    /// partition (naming context) defaults to the `DC=` components of
    /// `group_dn`; override it with [`AdwsClient::group_members_in`] when the
    /// group lives outside the default domain partition.
    pub async fn group_members(&mut self, group_dn: &str, recursive: bool) -> Result<Vec<GroupMember>> {
        let partition = base_from_dn(group_dn);
        self.group_members_in(group_dn, &partition, recursive).await
    }

    /// Like [`AdwsClient::group_members`] but with an explicit partition DN.
    pub async fn group_members_in(
        &mut self,
        group_dn: &str,
        partition_dn: &str,
        recursive: bool,
    ) -> Result<Vec<GroupMember>> {
        debug!("GetADGroupMember {group_dn} (recursive={recursive})");
        let ldap_port = self.target.ldap_port;
        let ep = self.account_management().await?;
        let xml = account::build_get_ad_group_member_request(
            &ep.url, group_dn, partition_dn, recursive, ldap_port,
        );
        let tree = ep.exchange(&xml).await?;
        let members = account::parse_get_ad_group_member_response(&tree)?;
        debug!("GetADGroupMember returned {} member(s)", members.len());
        Ok(members)
    }
}

/// Extract the domain base DN (the `DC=` components) from a full DN.
fn base_from_dn(dn: &str) -> String {
    dn.split(',')
        .map(str::trim)
        .filter(|s| s.len() >= 3 && s[..3].eq_ignore_ascii_case("dc="))
        .collect::<Vec<_>>()
        .join(",")
}

impl Endpoint {
    /// Send one SOAP request on this endpoint and decode the response tree.
    async fn exchange(&mut self, xml: &str) -> Result<NbfxNode> {
        trace!("exchange request:\n{xml}");
        let payload = encode_nbfse_request(xml)?;

        // Wrap as one NMF sized-envelope record, sealed by the NNS channel.
        let mut framed = Vec::with_capacity(payload.len() + 6);
        framed.push(nmf::REC_SIZED_ENVELOPE);
        framed.extend_from_slice(&nmf::encode_size(payload.len()));
        framed.extend_from_slice(&payload);
        self.channel.send(&framed).await?;

        let body = self.recv_envelope().await?;
        let tree = decode_nbfse(&mut self.session, &body)?;
        if let Err(e) = response::check_fault(&tree) {
            warn!("server returned a SOAP fault: {e}");
            return Err(e);
        }
        Ok(tree)
    }

    /// Receive one SOAP response: a sized-envelope record whose payload may span
    /// several NNS data frames. The first frame carries the record header
    /// (`0x06` + size) and the start of the payload; subsequent frames are raw
    /// payload continuations, read until `size` bytes are collected (per go-adws).
    async fn recv_envelope(&mut self) -> Result<Vec<u8>> {
        let first = self.channel.recv().await?;
        if first.first() != Some(&nmf::REC_SIZED_ENVELOPE) {
            // Not re-framed inside the secure channel: take it as a raw payload.
            return Ok(first);
        }
        let (size, used) = nmf::decode_size(&first[1..])?;
        let header = 1 + used;

        let mut payload = first[header..].to_vec();
        let mut frames = 1usize;
        while payload.len() < size {
            let more = self.channel.recv().await?;
            if more.is_empty() {
                return Err(AdwsError::Nmf("unexpected empty continuation frame".into()));
            }
            payload.extend_from_slice(&more);
            frames += 1;
        }
        payload.truncate(size);
        trace!("received sized-envelope: {size} bytes across {frames} frame(s)");
        Ok(payload)
    }
}

/// Open and authenticate one ADWS endpoint connection (`endpoint_path` e.g.
/// `Windows/Enumeration` or `Windows/Resource`).
async fn connect_endpoint(
    target: &Target,
    creds: &Credentials,
    endpoint_path: &str,
) -> Result<Endpoint> {
    let addr = format!("{}:{}", target.host, target.port);
    debug!("connecting endpoint {endpoint_path} at {addr}");
    let tcp = TcpStream::connect(&addr).await?;

    let url = format!(
        "net.tcp://{}:{}/ActiveDirectoryWebServices/{endpoint_path}",
        target.host, target.port
    );
    let mut nmf = NmfConnection::new(tcp);
    nmf.negotiate_and_upgrade(&url).await?;

    let spn = format!("HOST/{}", target.host);
    let provider = creds.provider(&spn)?;
    let mut channel = SecureChannel::handshake(nmf.into_inner(), provider).await?;
    debug!("{endpoint_path}: NNS handshake complete (protection={:?})", channel.protection());

    // PreambleEnd / Ack over the secured channel.
    channel.send(&[nmf::REC_PREAMBLE_END]).await?;
    let _ack = channel.recv().await.ok();

    Ok(Endpoint { channel, session: NbfseSession::new(), url })
}