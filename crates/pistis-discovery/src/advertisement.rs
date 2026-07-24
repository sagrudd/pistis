use pistis_protocol::UnixTimeMillis;

/// Supported discovery protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    /// Initial contract version.
    V1,
    /// Version not supported by this contract.
    Unsupported(u16),
}

/// Approved DNS-SD service type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceType {
    /// The `_pistis._tcp.local.` service.
    PistisTcpLocal,
    /// Any other adapter-classified service type.
    Other,
}

/// Closed, privacy-preserving advertised capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Pinned direct HTTPS exchange is available.
    DirectHttps,
}

/// Fresh non-semantic DNS-SD instance name bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceName([u8; 16]);

impl InstanceName {
    /// Constructs a name from independently generated random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Opaque short-lived endpoint identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointId([u8; 16]);

impl EndpointId {
    /// Constructs an endpoint identifier from independent random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Minimal non-authoritative discovery advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertisement {
    /// Fresh non-semantic instance name.
    pub instance_name: InstanceName,
    /// Closed service type.
    pub service_type: ServiceType,
    /// Discovery contract version.
    pub version: ProtocolVersion,
    /// Opaque endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Non-sensitive transport capability.
    pub capability: Capability,
    /// Exclusive advertisement expiry.
    pub expires_at: UnixTimeMillis,
}

impl Advertisement {
    /// Creates an advertisement bounded by an active ceremony.
    ///
    /// # Errors
    ///
    /// Rejects an already-expired advertisement or one extending beyond the
    /// ceremony window.
    pub fn new(
        instance_name: InstanceName,
        endpoint_id: EndpointId,
        capability: Capability,
        now: UnixTimeMillis,
        expires_at: UnixTimeMillis,
        ceremony_expires_at: UnixTimeMillis,
    ) -> Result<Self, AdvertisementError> {
        if now >= expires_at {
            return Err(AdvertisementError::Expired);
        }
        if expires_at > ceremony_expires_at {
            return Err(AdvertisementError::BeyondCeremony);
        }
        Ok(Self {
            instance_name,
            service_type: ServiceType::PistisTcpLocal,
            version: ProtocolVersion::V1,
            endpoint_id,
            capability,
            expires_at,
        })
    }
}

/// Typed advertisement construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvertisementError {
    /// Advertisement expiry is not in the future.
    Expired,
    /// Advertisement outlives its eligible ceremony.
    BeyondCeremony,
}
