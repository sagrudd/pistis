use crate::{
    AddressScope, Candidate, EndpointId, InterfaceId, ProtocolVersion, SERVICE_TYPE_FQDN,
    ServiceType,
};
use mdns_sd::{DaemonEvent, ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent};
use pistis_protocol::UnixTimeMillis;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{mpsc, mpsc::Receiver},
    thread,
    time::{Duration, Instant},
};

const MAX_BROWSE_SECONDS: u32 = 30;

/// Settings for one foreground-only browse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowseConfiguration {
    /// Bounded browse duration in complete seconds.
    pub duration_seconds: u32,
}

impl BrowseConfiguration {
    fn validate(self) -> Result<(), BrowseFailure> {
        if self.duration_seconds == 0 || self.duration_seconds > MAX_BROWSE_SECONDS {
            return Err(BrowseFailure::InvalidDuration);
        }
        Ok(())
    }
}

/// A resolved address and its untrusted candidate metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedCandidate {
    /// Untrusted candidate requiring an authenticated endpoint binding.
    pub candidate: Candidate,
    /// Resolved local address on `candidate.answer_interface`.
    pub address: IpAddr,
}

/// Events emitted by a bounded browse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrowseEvent {
    /// A strictly parsed local candidate was resolved.
    Candidate(ResolvedCandidate),
    /// An opaque instance disappeared from mDNS.
    Removed(String),
    /// The browse reached one terminal state.
    Finished(BrowseState),
}

/// Terminal browse state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowseState {
    /// The configured foreground deadline elapsed.
    Expired,
    /// The browse owner cancelled the operation.
    Stopped,
    /// The mDNS daemon failed or disconnected.
    BackendFailure,
}

/// Browse startup or record rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowseFailure {
    /// Duration must be between one and thirty seconds.
    InvalidDuration,
    /// The wall-clock expiry overflowed.
    TimeOverflow,
    /// The mDNS daemon could not be started or subscribed.
    Backend,
    /// The lifecycle worker could not be started.
    Worker,
    /// Service type, names, TXT data, port, or address scope was invalid.
    InvalidRecord,
    /// The record carried no usable interface identifier.
    MissingInterface,
}

/// RAII owner for one foreground-only DNS-SD browse.
pub struct DiscoveryBrowser {
    events: Option<Receiver<BrowseEvent>>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl DiscoveryBrowser {
    /// Starts a bounded browse for the exact Pistis service type.
    ///
    /// # Errors
    ///
    /// Fails before browsing when configuration, time arithmetic, daemon
    /// startup, or worker creation fails.
    pub fn browse(
        configuration: BrowseConfiguration,
        now: UnixTimeMillis,
    ) -> Result<Self, BrowseFailure> {
        configuration.validate()?;
        let lifetime_millis = u64::from(configuration.duration_seconds) * 1_000;
        let record_expires_at = UnixTimeMillis::new(
            now.get()
                .checked_add(lifetime_millis)
                .ok_or(BrowseFailure::TimeOverflow)?,
        );
        let daemon = ServiceDaemon::new().map_err(|_| BrowseFailure::Backend)?;
        let daemon_events = daemon.monitor().map_err(|_| BrowseFailure::Backend)?;
        let service_events = daemon
            .browse(SERVICE_TYPE_FQDN)
            .map_err(|_| BrowseFailure::Backend)?;
        let (event_tx, events) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let deadline =
            Instant::now() + Duration::from_secs(u64::from(configuration.duration_seconds));
        let worker = thread::Builder::new()
            .name("pistis-mdns-browse".into())
            .spawn(move || {
                run_browse(
                    &daemon,
                    &service_events,
                    &daemon_events,
                    record_expires_at,
                    deadline,
                    &stop_rx,
                    &event_tx,
                );
            })
            .map_err(|_| BrowseFailure::Worker)?;
        Ok(Self {
            events: Some(events),
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    /// Takes the single event receiver owned by this browse.
    #[must_use]
    pub fn take_events(&mut self) -> Option<Receiver<BrowseEvent>> {
        self.events.take()
    }
}

impl Drop for DiscoveryBrowser {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_browse(
    daemon: &ServiceDaemon,
    service_events: &mdns_sd::Receiver<ServiceEvent>,
    daemon_events: &mdns_sd::Receiver<DaemonEvent>,
    record_expires_at: UnixTimeMillis,
    deadline: Instant,
    stop: &mpsc::Receiver<()>,
    output: &mpsc::Sender<BrowseEvent>,
) {
    let terminal = 'browse: loop {
        if stop.try_recv().is_ok() {
            break BrowseState::Stopped;
        }
        if daemon_events
            .try_recv()
            .is_ok_and(|event| matches!(event, DaemonEvent::Error(_)))
            || daemon_events.is_disconnected()
            || service_events.is_disconnected()
        {
            break BrowseState::BackendFailure;
        }
        let now = Instant::now();
        if now >= deadline {
            break BrowseState::Expired;
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        match service_events.recv_timeout(wait) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                if let Ok(candidates) = parse_service(&service, record_expires_at) {
                    for candidate in candidates {
                        if output.send(BrowseEvent::Candidate(candidate)).is_err() {
                            break 'browse BrowseState::Stopped;
                        }
                    }
                }
            }
            Ok(ServiceEvent::ServiceRemoved(service_type, fullname))
                if service_type == SERVICE_TYPE_FQDN =>
            {
                if let Ok(instance) = parse_instance(&fullname) {
                    let _ = output.send(BrowseEvent::Removed(instance));
                }
            }
            Ok(_) | Err(_) => {}
        }
    };
    let _ = daemon.stop_browse(SERVICE_TYPE_FQDN);
    let _ = daemon.shutdown();
    let _ = output.send(BrowseEvent::Finished(terminal));
}

fn parse_service(
    service: &ResolvedService,
    record_expires_at: UnixTimeMillis,
) -> Result<Vec<ResolvedCandidate>, BrowseFailure> {
    if service.ty_domain != SERVICE_TYPE_FQDN
        || service.sub_ty_domain.is_some()
        || service.port == 0
        || service.txt_properties.len() != 3
    {
        return Err(BrowseFailure::InvalidRecord);
    }
    let instance = parse_instance(&service.fullname)?;
    if service.host != format!("pistis-{instance}.local.")
        || service.get_property_val_str("v") != Some("1")
        || service.get_property_val_str("cap") != Some("https")
    {
        return Err(BrowseFailure::InvalidRecord);
    }
    let endpoint_id = decode_identifier(
        service
            .get_property_val_str("id")
            .ok_or(BrowseFailure::InvalidRecord)?,
    )?;
    let mut candidates = Vec::new();
    for address in &service.addresses {
        append_candidates(
            &mut candidates,
            address,
            endpoint_id,
            service.port,
            record_expires_at,
        )?;
    }
    if candidates.is_empty() {
        return Err(BrowseFailure::InvalidRecord);
    }
    candidates.sort_by_key(|candidate| {
        (
            candidate.candidate.answer_interface.platform_index(),
            candidate.address,
        )
    });
    candidates.dedup();
    Ok(candidates)
}

fn append_candidates(
    output: &mut Vec<ResolvedCandidate>,
    scoped: &ScopedIp,
    endpoint_id: EndpointId,
    port: u16,
    record_expires_at: UnixTimeMillis,
) -> Result<(), BrowseFailure> {
    let address = scoped.to_ip_addr();
    if !is_local(address) {
        return Err(BrowseFailure::InvalidRecord);
    }
    match scoped {
        ScopedIp::V4(scoped) => {
            if scoped.interface_ids().is_empty() {
                return Err(BrowseFailure::MissingInterface);
            }
            for interface in scoped.interface_ids() {
                push_candidate(
                    output,
                    address,
                    interface.index,
                    endpoint_id,
                    port,
                    record_expires_at,
                )?;
            }
        }
        ScopedIp::V6(scoped) => push_candidate(
            output,
            address,
            scoped.scope_id().index,
            endpoint_id,
            port,
            record_expires_at,
        )?,
        _ => return Err(BrowseFailure::InvalidRecord),
    }
    Ok(())
}

fn push_candidate(
    output: &mut Vec<ResolvedCandidate>,
    address: IpAddr,
    interface_index: u32,
    endpoint_id: EndpointId,
    port: u16,
    record_expires_at: UnixTimeMillis,
) -> Result<(), BrowseFailure> {
    if interface_index == 0 {
        return Err(BrowseFailure::MissingInterface);
    }
    let interface = InterfaceId::from_platform_index(interface_index);
    output.push(ResolvedCandidate {
        candidate: Candidate {
            version: ProtocolVersion::V1,
            service_type: ServiceType::PistisTcpLocal,
            endpoint_id,
            port,
            answer_interface: interface,
            connection_interface: interface,
            address_scope: AddressScope::LocalUnicast,
            record_expires_at,
        },
        address,
    });
    Ok(())
}

fn parse_instance(fullname: &str) -> Result<String, BrowseFailure> {
    let instance = fullname
        .strip_suffix(SERVICE_TYPE_FQDN)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .ok_or(BrowseFailure::InvalidRecord)?;
    if instance.len() != 32 || !is_lower_hex(instance) {
        return Err(BrowseFailure::InvalidRecord);
    }
    Ok(instance.to_owned())
}

fn decode_identifier(value: &str) -> Result<EndpointId, BrowseFailure> {
    if value.len() != 32 || !is_lower_hex(value) {
        return Err(BrowseFailure::InvalidRecord);
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| BrowseFailure::InvalidRecord)?;
    }
    Ok(EndpointId::from_bytes(bytes))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_local_v4(address),
        IpAddr::V6(address) => is_local_v6(address),
    }
}

fn is_local_v4(address: Ipv4Addr) -> bool {
    address.is_private() || address.is_link_local()
}

fn is_local_v6(address: Ipv6Addr) -> bool {
    address.is_unicast_link_local() || (address.segments()[0] & 0xfe00 == 0xfc00)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdns_sd::{InterfaceId as MdnsInterfaceId, ScopedIpV4, ServiceInfo, TxtProperties};
    use std::collections::HashSet;

    fn service() -> ResolvedService {
        let mut service = ServiceInfo::new(
            SERVICE_TYPE_FQDN,
            "abababababababababababababababab",
            "pistis-abababababababababababababababab.local.",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            8443,
            &[
                ("v", "1"),
                ("id", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
                ("cap", "https"),
            ][..],
        )
        .unwrap()
        .as_resolved_service();
        service.addresses = HashSet::from([ScopedIp::V4(ScopedIpV4::new(
            Ipv4Addr::new(192, 168, 1, 8),
            MdnsInterfaceId {
                name: "en-test".into(),
                index: 7,
            },
        ))]);
        service
    }

    fn properties(values: &[(&str, &str)]) -> TxtProperties {
        ServiceInfo::new(
            SERVICE_TYPE_FQDN,
            "abababababababababababababababab",
            "pistis-abababababababababababababababab.local.",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            8443,
            values,
        )
        .unwrap()
        .as_resolved_service()
        .txt_properties
    }

    #[test]
    fn strict_projection_preserves_address_port_endpoint_and_interface() {
        let candidates = parse_service(&service(), UnixTimeMillis::new(31_000)).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8))
        );
        assert_eq!(candidates[0].candidate.port, 8443);
        assert_eq!(
            candidates[0].candidate.answer_interface.platform_index(),
            Some(7)
        );
        assert_eq!(
            candidates[0].candidate.connection_interface,
            candidates[0].candidate.answer_interface
        );
        assert_eq!(
            candidates[0].candidate.record_expires_at,
            UnixTimeMillis::new(31_000)
        );
    }

    #[test]
    fn malformed_privacy_expanding_and_public_records_fail_closed() {
        let mut cases = Vec::new();
        let mut wrong_version = service();
        wrong_version.txt_properties = properties(&[
            ("v", "2"),
            ("id", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            ("cap", "https"),
        ]);
        cases.push(wrong_version);
        let mut extra_txt = service();
        extra_txt.txt_properties = properties(&[
            ("v", "1"),
            ("id", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            ("cap", "https"),
            ("user", "alice"),
        ]);
        cases.push(extra_txt);
        let mut public_address = service();
        public_address.addresses = HashSet::from([ScopedIp::V4(ScopedIpV4::new(
            Ipv4Addr::new(203, 0, 113, 8),
            MdnsInterfaceId {
                name: "en-test".into(),
                index: 7,
            },
        ))]);
        cases.push(public_address);
        let mut wrong_host = service();
        wrong_host.host = "stephens-mac.local.".into();
        cases.push(wrong_host);
        let mut uppercase_id = service();
        uppercase_id.txt_properties = properties(&[
            ("v", "1"),
            ("id", "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"),
            ("cap", "https"),
        ]);
        cases.push(uppercase_id);

        for invalid in cases {
            assert_eq!(
                parse_service(&invalid, UnixTimeMillis::new(31_000)),
                Err(BrowseFailure::InvalidRecord)
            );
        }
    }

    #[test]
    fn missing_interface_and_invalid_duration_are_rejected() {
        let mut missing_interface = service();
        missing_interface.addresses =
            HashSet::from([ScopedIp::from(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))]);
        assert_eq!(
            parse_service(&missing_interface, UnixTimeMillis::new(31_000)),
            Err(BrowseFailure::MissingInterface)
        );
        assert_eq!(
            BrowseConfiguration {
                duration_seconds: 0
            }
            .validate(),
            Err(BrowseFailure::InvalidDuration)
        );
        assert_eq!(
            BrowseConfiguration {
                duration_seconds: 31
            }
            .validate(),
            Err(BrowseFailure::InvalidDuration)
        );
    }

    #[test]
    fn platform_interface_encoding_is_typed_and_round_trips() {
        let interface = InterfaceId::from_platform_index(4_294_967_294);
        assert_eq!(interface.platform_index(), Some(4_294_967_294));
        assert_eq!(InterfaceId::from_bytes([0; 16]).platform_index(), None);
    }
}
