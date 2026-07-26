use crate::{Advertisement, Capability, ProtocolVersion, ServiceType};
use pistis_protocol::UnixTimeMillis;

/// Exact approved DNS-SD service type.
pub const SERVICE_TYPE_FQDN: &str = "_pistis._tcp.local.";
const MAX_TTL_SECONDS: u32 = 30;

/// Minimal adapter-ready DNS-SD advertisement fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireAdvertisement {
    /// Random lowercase hexadecimal instance name.
    pub instance_name: String,
    /// Exact approved fully-qualified service type.
    pub service_type: &'static str,
    /// Closed ordered TXT entries.
    pub txt: [String; 3],
    /// Bounded record lifetime in seconds.
    pub ttl_seconds: u32,
}

impl WireAdvertisement {
    /// Encodes the reviewed minimal advertisement at `now`.
    ///
    /// # Errors
    ///
    /// Rejects unsupported enum variants, expired records, and lifetimes too
    /// short to encode without advertising beyond their expiry.
    pub fn encode(
        advertisement: Advertisement,
        now: UnixTimeMillis,
    ) -> Result<Self, WireAdvertisementError> {
        if advertisement.service_type != ServiceType::PistisTcpLocal
            || advertisement.version != ProtocolVersion::V1
            || advertisement.capability != Capability::DirectHttps
        {
            return Err(WireAdvertisementError::Unsupported);
        }
        if now >= advertisement.expires_at {
            return Err(WireAdvertisementError::Expired);
        }
        let lifetime = advertisement
            .expires_at
            .get()
            .checked_sub(now.get())
            .ok_or(WireAdvertisementError::Expired)?;
        let ttl_seconds =
            u32::try_from(lifetime / 1_000).map_err(|_| WireAdvertisementError::Unsupported)?;
        if ttl_seconds == 0 {
            return Err(WireAdvertisementError::LifetimeTooShort);
        }
        Ok(Self {
            instance_name: hexadecimal(advertisement.instance_name.as_bytes()),
            service_type: SERVICE_TYPE_FQDN,
            txt: [
                "v=1".into(),
                format!("id={}", hexadecimal(advertisement.endpoint_id.as_bytes())),
                "cap=https".into(),
            ],
            ttl_seconds: ttl_seconds.min(MAX_TTL_SECONDS),
        })
    }
}

/// Advertisement wire-encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireAdvertisementError {
    /// Advertisement is already expired.
    Expired,
    /// Less than one complete second remains.
    LifetimeTooShort,
    /// A service, version, capability, or lifetime is unsupported.
    Unsupported,
}

fn hexadecimal<const N: usize>(bytes: &[u8; N]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(N * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EndpointId, InstanceName};

    fn advertisement(expires_at: u64) -> Advertisement {
        Advertisement::new(
            InstanceName::from_bytes([0xab; 16]),
            EndpointId::from_bytes([0xcd; 16]),
            Capability::DirectHttps,
            UnixTimeMillis::new(1_000),
            UnixTimeMillis::new(expires_at),
            UnixTimeMillis::new(expires_at),
        )
        .unwrap()
    }

    #[test]
    fn encoding_is_closed_minimal_and_deterministic() {
        let wire =
            WireAdvertisement::encode(advertisement(45_000), UnixTimeMillis::new(5_000)).unwrap();
        assert_eq!(wire.service_type, "_pistis._tcp.local.");
        assert_eq!(wire.instance_name, "abababababababababababababababab");
        assert_eq!(
            wire.txt,
            ["v=1", "id=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "cap=https"]
        );
        assert_eq!(wire.ttl_seconds, 30);
        assert!(
            wire.instance_name
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn expired_and_subsecond_records_are_never_advertised() {
        assert_eq!(
            WireAdvertisement::encode(advertisement(5_000), UnixTimeMillis::new(5_000)),
            Err(WireAdvertisementError::Expired)
        );
        assert_eq!(
            WireAdvertisement::encode(advertisement(5_500), UnixTimeMillis::new(5_000)),
            Err(WireAdvertisementError::LifetimeTooShort)
        );
        assert_eq!(
            WireAdvertisement::encode(advertisement(4_000), UnixTimeMillis::new(5_000)),
            Err(WireAdvertisementError::Expired)
        );
    }
}
