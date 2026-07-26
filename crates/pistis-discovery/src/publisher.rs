use crate::WireAdvertisement;
use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceInfo};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

/// Explicit host-network settings for one short-lived publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherConfiguration {
    /// HTTPS listener port.
    pub port: u16,
    /// Reviewed local addresses to publish. Automatic host discovery is forbidden.
    pub addresses: Vec<IpAddr>,
}

impl PublisherConfiguration {
    fn validate(&self) -> Result<(), PublicationError> {
        if self.port == 0 {
            return Err(PublicationError::InvalidPort);
        }
        if self.addresses.is_empty() {
            return Err(PublicationError::NoAddresses);
        }
        if self.addresses.iter().any(|address| !is_local(address)) {
            return Err(PublicationError::NonLocalAddress);
        }
        Ok(())
    }
}

/// Observable state of a bounded publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    /// Registered and awaiting expiry or an adapter event.
    Active,
    /// The bounded publication lifetime elapsed.
    Expired,
    /// The adapter changed a probed name after a collision; publication failed closed.
    NameConflict,
    /// The mDNS daemon reported an operational failure.
    BackendFailure,
    /// The owner explicitly stopped the publication.
    Stopped,
}

/// Host publication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationError {
    /// Port zero cannot identify the HTTPS listener.
    InvalidPort,
    /// At least one explicitly selected address is required.
    NoAddresses,
    /// A selected address is not private, link-local, or unique-local.
    NonLocalAddress,
    /// The mDNS daemon could not be created, monitored, or registered.
    Backend,
    /// The lifecycle worker could not be started.
    Worker,
}

/// RAII owner for exactly one bounded DNS-SD publication.
///
/// Dropping the owner unregisters the record, emits mDNS goodbye records, and
/// shuts down its private daemon. Name conflicts and daemon errors also stop
/// publication rather than silently changing the advertised identity.
pub struct AdvertisementPublisher {
    state: Arc<Mutex<PublicationState>>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl AdvertisementPublisher {
    /// Publishes a previously validated wire advertisement.
    ///
    /// # Errors
    ///
    /// Fails before registration for invalid network scope or adapter startup
    /// failures. Runtime failures are exposed through [`Self::state`].
    pub fn publish(
        wire: &WireAdvertisement,
        configuration: &PublisherConfiguration,
    ) -> Result<Self, PublicationError> {
        configuration.validate()?;
        let daemon = ServiceDaemon::new().map_err(|_| PublicationError::Backend)?;
        let events = daemon.monitor().map_err(|_| PublicationError::Backend)?;
        let service = build_service(wire, configuration)?;
        let fullname = service.get_fullname().to_owned();
        daemon
            .register(service)
            .map_err(|_| PublicationError::Backend)?;

        let state = Arc::new(Mutex::new(PublicationState::Active));
        let worker_state = Arc::clone(&state);
        let (stop, stop_rx) = mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(u64::from(wire.ttl_seconds));
        let worker = thread::Builder::new()
            .name("pistis-mdns-publication".into())
            .spawn(move || {
                run_lifecycle(
                    &daemon,
                    &events,
                    &fullname,
                    deadline,
                    &stop_rx,
                    &worker_state,
                );
            })
            .map_err(|_| PublicationError::Worker)?;
        Ok(Self {
            state,
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    /// Returns the current fail-closed lifecycle state.
    #[must_use]
    pub fn state(&self) -> PublicationState {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for AdvertisementPublisher {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_lifecycle(
    daemon: &ServiceDaemon,
    events: &mdns_sd::Receiver<DaemonEvent>,
    fullname: &str,
    deadline: Instant,
    stop: &mpsc::Receiver<()>,
    state: &Mutex<PublicationState>,
) {
    let terminal = loop {
        if stop.try_recv().is_ok() {
            break terminal_state(LifecycleSignal::Stop);
        }
        let now = Instant::now();
        if now >= deadline {
            break terminal_state(LifecycleSignal::Expiry);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        match events.recv_timeout(wait) {
            Ok(DaemonEvent::NameChange(_)) => {
                break terminal_state(LifecycleSignal::NameConflict);
            }
            Ok(DaemonEvent::Error(_)) => {
                break terminal_state(LifecycleSignal::BackendFailure);
            }
            Err(_) if events.is_disconnected() => {
                break terminal_state(LifecycleSignal::BackendFailure);
            }
            Ok(_) | Err(_) => {}
        }
    };
    let _ = daemon.unregister(fullname);
    let _ = daemon.shutdown();
    *state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = terminal;
}

fn build_service(
    wire: &WireAdvertisement,
    configuration: &PublisherConfiguration,
) -> Result<ServiceInfo, PublicationError> {
    let hostname = format!("pistis-{}.local.", wire.instance_name);
    let properties = wire
        .txt
        .iter()
        .map(|entry| entry.split_once('=').ok_or(PublicationError::Backend))
        .collect::<Result<Vec<_>, _>>()?;
    let mut service = ServiceInfo::new(
        wire.service_type,
        &wire.instance_name,
        &hostname,
        configuration.addresses.as_slice(),
        configuration.port,
        properties.as_slice(),
    )
    .map_err(|_| PublicationError::Backend)?;
    service.set_interfaces(
        configuration
            .addresses
            .iter()
            .copied()
            .map(mdns_sd::IfKind::Addr)
            .collect(),
    );
    Ok(service)
}

#[derive(Clone, Copy)]
enum LifecycleSignal {
    Stop,
    Expiry,
    NameConflict,
    BackendFailure,
}

const fn terminal_state(signal: LifecycleSignal) -> PublicationState {
    match signal {
        LifecycleSignal::Stop => PublicationState::Stopped,
        LifecycleSignal::Expiry => PublicationState::Expired,
        LifecycleSignal::NameConflict => PublicationState::NameConflict,
        LifecycleSignal::BackendFailure => PublicationState::BackendFailure,
    }
}

fn is_local(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_local_v4(*address),
        IpAddr::V6(address) => is_local_v6(*address),
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
    use crate::SERVICE_TYPE_FQDN;

    #[test]
    fn configuration_rejects_implicit_and_non_local_publication() {
        assert_eq!(
            PublisherConfiguration {
                port: 0,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))]
            }
            .validate(),
            Err(PublicationError::InvalidPort)
        );
        assert_eq!(
            PublisherConfiguration {
                port: 443,
                addresses: vec![]
            }
            .validate(),
            Err(PublicationError::NoAddresses)
        );
        assert_eq!(
            PublisherConfiguration {
                port: 443,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]
            }
            .validate(),
            Err(PublicationError::NonLocalAddress)
        );
    }

    #[test]
    fn configuration_accepts_private_link_local_and_unique_local_addresses() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 4, 5)),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("fd00::1".parse().unwrap()),
        ] {
            assert!(
                PublisherConfiguration {
                    port: 8443,
                    addresses: vec![address]
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn service_projection_has_only_random_names_explicit_addresses_and_closed_txt() {
        let wire = WireAdvertisement {
            instance_name: "abababababababababababababababab".into(),
            service_type: SERVICE_TYPE_FQDN,
            txt: [
                "v=1".into(),
                "id=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".into(),
                "cap=https".into(),
            ],
            ttl_seconds: 30,
        };
        let address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12));
        let service = build_service(
            &wire,
            &PublisherConfiguration {
                port: 8443,
                addresses: vec![address],
            },
        )
        .unwrap();

        assert_eq!(service.get_type(), SERVICE_TYPE_FQDN);
        assert_eq!(
            service.get_fullname(),
            "abababababababababababababababab._pistis._tcp.local."
        );
        assert_eq!(
            service.get_hostname(),
            "pistis-abababababababababababababababab.local."
        );
        assert_eq!(service.get_port(), 8443);
        assert_eq!(
            service.get_addresses().iter().copied().collect::<Vec<_>>(),
            [address]
        );
        assert_eq!(service.get_properties().len(), 3);
        assert_eq!(
            service.get_properties().get_property_val_str("v"),
            Some("1")
        );
        assert_eq!(
            service.get_properties().get_property_val_str("id"),
            Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
        assert_eq!(
            service.get_properties().get_property_val_str("cap"),
            Some("https")
        );
    }

    #[test]
    fn every_terminal_lifecycle_signal_fails_closed() {
        assert_eq!(
            terminal_state(LifecycleSignal::Stop),
            PublicationState::Stopped
        );
        assert_eq!(
            terminal_state(LifecycleSignal::Expiry),
            PublicationState::Expired
        );
        assert_eq!(
            terminal_state(LifecycleSignal::NameConflict),
            PublicationState::NameConflict
        );
        assert_eq!(
            terminal_state(LifecycleSignal::BackendFailure),
            PublicationState::BackendFailure
        );
    }
}
