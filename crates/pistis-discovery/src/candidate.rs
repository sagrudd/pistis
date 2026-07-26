use crate::{EndpointId, ProtocolVersion, ServiceType};
use pistis_domain::{ChallengeId, InstallationId};
use pistis_protocol::UnixTimeMillis;

/// Opaque platform adapter identifier for a network interface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceId([u8; 16]);

impl InterfaceId {
    /// Constructs an adapter-scoped identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Constructs an adapter identifier from an operating-system interface index.
    ///
    /// Index zero is reserved for "unknown" and is rejected by discovery
    /// adapters before this constructor is used.
    #[must_use]
    pub const fn from_platform_index(index: u32) -> Self {
        let index = index.to_be_bytes();
        Self([
            b'p', b'i', b's', b't', b'i', b's', b'-', b'i', b'f', b'-', b'1', 0, index[0],
            index[1], index[2], index[3],
        ])
    }

    /// Returns the encoded operating-system interface index, when present.
    #[must_use]
    pub const fn platform_index(&self) -> Option<u32> {
        if self.0[0] == b'p'
            && self.0[1] == b'i'
            && self.0[2] == b's'
            && self.0[3] == b't'
            && self.0[4] == b'i'
            && self.0[5] == b's'
            && self.0[6] == b'-'
            && self.0[7] == b'i'
            && self.0[8] == b'f'
            && self.0[9] == b'-'
            && self.0[10] == b'1'
            && self.0[11] == 0
        {
            Some(u32::from_be_bytes([
                self.0[12], self.0[13], self.0[14], self.0[15],
            ]))
        } else {
            None
        }
    }
}

/// Adapter-classified address scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressScope {
    /// Unicast address valid on the producing local network.
    LocalUnicast,
    /// Globally scoped unicast address observed on the producing interface.
    GlobalUnicast,
    /// Loopback address, ineligible for a remote phone.
    Loopback,
    /// Unspecified address.
    Unspecified,
    /// Multicast address, never a direct endpoint.
    Multicast,
}

/// Digest of the installation-controlled TLS public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsPublicKeyDigest([u8; 32]);

impl TlsPublicKeyDigest {
    /// Constructs a digest supplied by an authenticated binding.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Exact authenticated context in which an endpoint may be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingContext {
    /// Endpoint is valid only for one challenge.
    Challenge(ChallengeId),
    /// Endpoint came from a previously authenticated pairing.
    Pairing([u8; 16]),
}

/// Installation-signed endpoint binding obtained outside discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointBinding {
    /// Signed discovery protocol version.
    pub version: ProtocolVersion,
    /// Installation whose identity authenticated this binding.
    pub installation_id: InstallationId,
    /// Exact opaque endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Exact service type.
    pub service_type: ServiceType,
    /// Exact permitted HTTPS port.
    pub https_port: u16,
    /// Exact installation TLS public-key digest.
    pub tls_public_key_digest: TlsPublicKeyDigest,
    /// Earliest valid time.
    pub issued_at: UnixTimeMillis,
    /// Exclusive expiry.
    pub expires_at: UnixTimeMillis,
    /// Exact challenge or pairing context.
    pub context: BindingContext,
}

/// One untrusted endpoint candidate returned by a platform adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Advertised protocol version.
    pub version: ProtocolVersion,
    /// Advertised service type.
    pub service_type: ServiceType,
    /// Advertised opaque endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Resolved HTTPS port.
    pub port: u16,
    /// Interface that produced the answer.
    pub answer_interface: InterfaceId,
    /// Interface on which the connection would be opened.
    pub connection_interface: InterfaceId,
    /// Adapter-classified resolved address scope.
    pub address_scope: AddressScope,
    /// Exclusive DNS record expiry.
    pub record_expires_at: UnixTimeMillis,
}

impl Candidate {
    /// Validates this untrusted candidate against an authenticated binding.
    ///
    /// # Errors
    ///
    /// Every mismatch, stale time, unsupported scope, or interface
    /// substitution fails closed.
    pub fn authorize(
        self,
        binding: EndpointBinding,
        expected_installation: InstallationId,
        expected_context: BindingContext,
        now: UnixTimeMillis,
    ) -> Result<DirectRequest, CandidateFailure> {
        if binding.installation_id != expected_installation {
            return Err(CandidateFailure::WrongInstallation);
        }
        if binding.context != expected_context {
            return Err(CandidateFailure::WrongContext);
        }
        if now < binding.issued_at || now >= binding.expires_at {
            return Err(CandidateFailure::StaleBinding);
        }
        if now >= self.record_expires_at {
            return Err(CandidateFailure::StaleRecord);
        }
        if self.version != binding.version {
            return Err(CandidateFailure::WrongVersion);
        }
        if self.service_type != binding.service_type {
            return Err(CandidateFailure::WrongService);
        }
        if self.endpoint_id != binding.endpoint_id {
            return Err(CandidateFailure::WrongEndpoint);
        }
        if self.port != binding.https_port {
            return Err(CandidateFailure::WrongPort);
        }
        if self.answer_interface != self.connection_interface {
            return Err(CandidateFailure::WrongInterface);
        }
        if !matches!(
            self.address_scope,
            AddressScope::LocalUnicast | AddressScope::GlobalUnicast
        ) {
            return Err(CandidateFailure::UnsupportedAddressScope);
        }
        Ok(DirectRequest {
            installation_id: binding.installation_id,
            endpoint_id: self.endpoint_id,
            port: self.port,
            interface_id: self.connection_interface,
            tls_public_key_digest: binding.tls_public_key_digest,
            context: binding.context,
        })
    }
}

/// Narrow request passed to a direct HTTPS adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectRequest {
    /// Exact installation authenticated by the signed binding.
    pub installation_id: InstallationId,
    /// Exact opaque endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Exact authenticated port.
    pub port: u16,
    /// Network interface to retain for the connection.
    pub interface_id: InterfaceId,
    /// Exact TLS public-key pin.
    pub tls_public_key_digest: TlsPublicKeyDigest,
    /// Exact authenticated challenge or pairing context.
    pub context: BindingContext,
}

/// Typed candidate rejection safe for deterministic QR fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateFailure {
    /// Signed binding names a different installation.
    WrongInstallation,
    /// Signed binding names a different challenge or pairing.
    WrongContext,
    /// Signed binding is not currently valid.
    StaleBinding,
    /// DNS record expired.
    StaleRecord,
    /// Candidate advertises a different protocol version.
    WrongVersion,
    /// Candidate advertises a different service type.
    WrongService,
    /// Candidate advertises a different endpoint identifier.
    WrongEndpoint,
    /// Resolved port differs from the authenticated port.
    WrongPort,
    /// Connection interface differs from the answer interface.
    WrongInterface,
    /// Resolved address is not eligible unicast.
    UnsupportedAddressScope,
}
