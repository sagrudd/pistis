use crate::{
    DeviceRecord, DeviceRepository, DeviceRepositoryError, DeviceRevision, DeviceStatus,
    DeviceTransition, LifecycleEvent, LifecycleEventKind, NewDevice,
};
use pistis_domain::{DeviceId, InstallationId, KeyId};
use pistis_protocol::UnixTimeMillis;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Debug, Default)]
struct State {
    devices: BTreeMap<DeviceId, DeviceRecord>,
    lifecycle: BTreeMap<DeviceId, Vec<LifecycleEvent>>,
}

/// Thread-safe in-memory device repository for deterministic tests.
///
/// Clones share state. Every operation holds one lock for validation and the
/// complete mutation, matching the atomicity required of durable adapters.
#[derive(Clone, Debug, Default)]
pub struct InMemoryDeviceRepository {
    state: Arc<Mutex<State>>,
}

impl DeviceRepository for InMemoryDeviceRepository {
    fn insert(&self, device: NewDevice) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        if !is_storable_time(device.enrolled_at) {
            return Err(DeviceRepositoryError::InvalidTimestamp);
        }
        if state.devices.contains_key(&device.id) {
            return Err(DeviceRepositoryError::AlreadyExists);
        }
        if state.devices.values().any(|existing| {
            existing.installation_id == device.installation_id
                && existing.public_key.key_id() == device.public_key.key_id()
        }) {
            return Err(DeviceRepositoryError::KeyConflict);
        }
        let record = DeviceRecord::from(device);
        state.devices.insert(record.id, record.clone());
        state.lifecycle.insert(record.id, Vec::new());
        Ok(record)
    }

    fn get(&self, id: DeviceId) -> Result<Option<DeviceRecord>, DeviceRepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        Ok(state.devices.get(&id).cloned())
    }

    fn find_by_key(
        &self,
        installation_id: InstallationId,
        key_id: KeyId,
    ) -> Result<Option<DeviceRecord>, DeviceRepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        Ok(state
            .devices
            .values()
            .find(|record| {
                record.installation_id == installation_id && record.public_key.key_id() == key_id
            })
            .cloned())
    }

    fn transition(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        transition: DeviceTransition,
    ) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        let latest_event_at = state
            .lifecycle
            .get(&id)
            .and_then(|events| events.last())
            .map(|event| event.at);
        let record = state
            .devices
            .get_mut(&id)
            .ok_or(DeviceRepositoryError::NotFound)?;
        if record.revision != expected_revision {
            return Err(DeviceRepositoryError::Conflict);
        }
        let latest_event_at = latest_event_at.unwrap_or(record.enrolled_at);
        if !is_storable_time(transition.at()) || transition.at() < latest_event_at {
            return Err(DeviceRepositoryError::InvalidTimestamp);
        }
        let transition_at = transition.at();
        let next_revision = record
            .revision
            .next()
            .ok_or(DeviceRepositoryError::Corrupt)?;
        let (status, kind) = next_state(&record.status, transition)?;
        record.status = status;
        record.revision = next_revision;
        let updated = record.clone();
        state
            .lifecycle
            .get_mut(&id)
            .ok_or(DeviceRepositoryError::Corrupt)?
            .push(LifecycleEvent {
                device_id: id,
                revision: next_revision,
                at: transition_at,
                kind,
            });
        Ok(updated)
    }

    fn record_use(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        at: UnixTimeMillis,
    ) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        let record = state
            .devices
            .get_mut(&id)
            .ok_or(DeviceRepositoryError::NotFound)?;
        if record.revision != expected_revision {
            return Err(DeviceRepositoryError::Conflict);
        }
        if record.status != DeviceStatus::Active {
            return Err(DeviceRepositoryError::InvalidTransition);
        }
        if !is_storable_time(at)
            || at < record.enrolled_at
            || record.last_used_at.is_some_and(|previous| at <= previous)
        {
            return Err(DeviceRepositoryError::InvalidTimestamp);
        }
        record.revision = record
            .revision
            .next()
            .ok_or(DeviceRepositoryError::Corrupt)?;
        record.last_used_at = Some(at);
        Ok(record.clone())
    }

    fn lifecycle(&self, id: DeviceId) -> Result<Vec<LifecycleEvent>, DeviceRepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)?;
        if !state.devices.contains_key(&id) {
            return Err(DeviceRepositoryError::NotFound);
        }
        state
            .lifecycle
            .get(&id)
            .cloned()
            .ok_or(DeviceRepositoryError::Corrupt)
    }
}

fn next_state(
    current: &DeviceStatus,
    transition: DeviceTransition,
) -> Result<(DeviceStatus, LifecycleEventKind), DeviceRepositoryError> {
    match (current, transition) {
        (DeviceStatus::Active, DeviceTransition::Suspend { at, reason }) => Ok((
            DeviceStatus::Suspended {
                at,
                reason: reason.clone(),
            },
            LifecycleEventKind::Suspended(reason),
        )),
        (DeviceStatus::Suspended { .. }, DeviceTransition::Resume { .. }) => {
            Ok((DeviceStatus::Active, LifecycleEventKind::Resumed))
        }
        (
            DeviceStatus::Active | DeviceStatus::Suspended { .. },
            DeviceTransition::Revoke { at, reason },
        ) => Ok((
            DeviceStatus::Revoked {
                at,
                reason: reason.clone(),
            },
            LifecycleEventKind::Revoked(reason),
        )),
        _ => Err(DeviceRepositoryError::InvalidTransition),
    }
}

fn is_storable_time(time: UnixTimeMillis) -> bool {
    i64::try_from(time.get()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApplicationVersion, AssuranceMetadata, AssuranceState, AttestationState, DevicePlatform,
        DevicePublicKey, LifecycleReason, UserVerification,
    };
    use pistis_domain::{EvidenceId, ExternalIdentityId, UserId};
    use std::sync::{Arc, Barrier};

    const PUBLIC_KEY: [u8; 33] = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];

    fn new_device(device: u8, installation: u8) -> NewDevice {
        let version = ApplicationVersion::new("1.2.3").expect("valid version");
        NewDevice {
            id: DeviceId::from_bytes([device; 16]),
            installation_id: InstallationId::from_bytes([installation; 16]),
            user_id: UserId::from_bytes([3; 16]),
            external_identity_id: ExternalIdentityId::from_bytes([4; 16]),
            public_key: DevicePublicKey::from_sec1_bytes(&PUBLIC_KEY).expect("valid key"),
            platform: DevicePlatform::Ios,
            application_version: version.clone(),
            assurance: AssuranceMetadata {
                application_generated_key: true,
                hardware_backing: AssuranceState::Verified,
                user_verification: UserVerification::Required,
                platform_attestation: AttestationState::Verified,
                device_integrity: AttestationState::Unavailable,
                evidence_version: version.clone(),
                verifier_version: version,
            },
            enrolment_evidence_id: EvidenceId::from_bytes([5; 16]),
            enrolled_at: UnixTimeMillis::new(1_000),
        }
    }

    fn reason(value: &str) -> LifecycleReason {
        LifecycleReason::new(value).expect("valid reason")
    }

    #[test]
    fn insertion_preserves_complete_public_record() {
        let repository = InMemoryDeviceRepository::default();
        let new = new_device(1, 2);
        let record = repository.insert(new.clone()).expect("insert succeeds");

        assert_eq!(record, DeviceRecord::from(new));
        assert_eq!(repository.get(record.id), Ok(Some(record.clone())));
        assert_eq!(
            repository.find_by_key(record.installation_id, record.public_key.key_id()),
            Ok(Some(record))
        );
    }

    #[test]
    fn rejects_duplicate_id_and_installation_scoped_key_without_mutation() {
        let repository = InMemoryDeviceRepository::default();
        let original = repository.insert(new_device(1, 2)).expect("initial insert");

        assert_eq!(
            repository.insert(new_device(1, 9)),
            Err(DeviceRepositoryError::AlreadyExists)
        );
        assert_eq!(
            repository.insert(new_device(9, 2)),
            Err(DeviceRepositoryError::KeyConflict)
        );
        assert_eq!(repository.get(original.id), Ok(Some(original)));
    }

    #[test]
    fn permits_same_key_in_independent_installations() {
        let repository = InMemoryDeviceRepository::default();
        repository
            .insert(new_device(1, 2))
            .expect("first installation");
        assert!(repository.insert(new_device(9, 8)).is_ok());
    }

    #[test]
    fn suspend_resume_and_revoke_append_ordered_events() {
        let repository = InMemoryDeviceRepository::default();
        let active = repository.insert(new_device(1, 2)).expect("insert");
        let suspended = repository
            .transition(
                active.id,
                active.revision,
                DeviceTransition::Suspend {
                    at: UnixTimeMillis::new(2_000),
                    reason: reason("device temporarily lost"),
                },
            )
            .expect("suspend");
        assert!(matches!(suspended.status, DeviceStatus::Suspended { .. }));
        let resumed = repository
            .transition(
                active.id,
                suspended.revision,
                DeviceTransition::Resume {
                    at: UnixTimeMillis::new(3_000),
                },
            )
            .expect("resume");
        assert_eq!(resumed.status, DeviceStatus::Active);
        let revoked = repository
            .transition(
                active.id,
                resumed.revision,
                DeviceTransition::Revoke {
                    at: UnixTimeMillis::new(4_000),
                    reason: reason("device permanently lost"),
                },
            )
            .expect("revoke");

        assert!(matches!(revoked.status, DeviceStatus::Revoked { .. }));
        let events = repository.lifecycle(active.id).expect("events");
        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.revision.get())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.at.get())
                .collect::<Vec<_>>(),
            vec![2_000, 3_000, 4_000]
        );
    }

    #[test]
    fn revocation_is_terminal_and_preserves_record_and_history() {
        let repository = InMemoryDeviceRepository::default();
        let active = repository.insert(new_device(1, 2)).expect("insert");
        let revoked = repository
            .transition(
                active.id,
                active.revision,
                DeviceTransition::Revoke {
                    at: UnixTimeMillis::new(2_000),
                    reason: reason("compromised"),
                },
            )
            .expect("revoke");

        for transition in [
            DeviceTransition::Resume {
                at: UnixTimeMillis::new(3_000),
            },
            DeviceTransition::Suspend {
                at: UnixTimeMillis::new(3_000),
                reason: reason("cannot suspend"),
            },
            DeviceTransition::Revoke {
                at: UnixTimeMillis::new(3_000),
                reason: reason("cannot revoke twice"),
            },
        ] {
            assert_eq!(
                repository.transition(active.id, revoked.revision, transition),
                Err(DeviceRepositoryError::InvalidTransition)
            );
        }
        assert_eq!(repository.get(active.id), Ok(Some(revoked)));
        assert_eq!(repository.lifecycle(active.id).expect("events").len(), 1);
    }

    #[test]
    fn invalid_transitions_and_non_monotonic_times_leave_state_unchanged() {
        let repository = InMemoryDeviceRepository::default();
        let active = repository.insert(new_device(1, 2)).expect("insert");
        assert_eq!(
            repository.transition(
                active.id,
                active.revision,
                DeviceTransition::Resume {
                    at: UnixTimeMillis::new(2_000)
                }
            ),
            Err(DeviceRepositoryError::InvalidTransition)
        );
        assert_eq!(
            repository.transition(
                active.id,
                active.revision,
                DeviceTransition::Suspend {
                    at: UnixTimeMillis::new(999),
                    reason: reason("predates enrolment")
                }
            ),
            Err(DeviceRepositoryError::InvalidTimestamp)
        );
        assert_eq!(repository.get(active.id), Ok(Some(active.clone())));
        assert!(repository.lifecycle(active.id).expect("events").is_empty());
    }

    #[test]
    fn rejects_times_outside_the_durable_storage_domain() {
        let repository = InMemoryDeviceRepository::default();
        let mut invalid = new_device(1, 2);
        invalid.enrolled_at = UnixTimeMillis::new(u64::MAX);
        assert_eq!(
            repository.insert(invalid),
            Err(DeviceRepositoryError::InvalidTimestamp)
        );

        let active = repository.insert(new_device(1, 2)).expect("insert");
        assert_eq!(
            repository.record_use(active.id, active.revision, UnixTimeMillis::new(u64::MAX)),
            Err(DeviceRepositoryError::InvalidTimestamp)
        );
    }

    #[test]
    fn record_use_is_active_only_monotonic_and_revision_guarded() {
        let repository = InMemoryDeviceRepository::default();
        let active = repository.insert(new_device(1, 2)).expect("insert");
        let used = repository
            .record_use(active.id, active.revision, UnixTimeMillis::new(2_000))
            .expect("record use");
        assert_eq!(used.last_used_at, Some(UnixTimeMillis::new(2_000)));
        assert_eq!(
            repository.record_use(active.id, active.revision, UnixTimeMillis::new(3_000)),
            Err(DeviceRepositoryError::Conflict)
        );
        assert_eq!(
            repository.record_use(used.id, used.revision, UnixTimeMillis::new(2_000)),
            Err(DeviceRepositoryError::InvalidTimestamp)
        );

        let suspended = repository
            .transition(
                used.id,
                used.revision,
                DeviceTransition::Suspend {
                    at: UnixTimeMillis::new(3_000),
                    reason: reason("paused"),
                },
            )
            .expect("suspend");
        assert_eq!(
            repository.record_use(suspended.id, suspended.revision, UnixTimeMillis::new(4_000)),
            Err(DeviceRepositoryError::InvalidTransition)
        );
    }

    #[test]
    fn concurrent_transitions_from_one_revision_allow_exactly_one_commit() {
        let repository = InMemoryDeviceRepository::default();
        let active = repository.insert(new_device(1, 2)).expect("insert");
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();

        for index in 0..2 {
            let repository = repository.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                repository.transition(
                    active.id,
                    active.revision,
                    DeviceTransition::Suspend {
                        at: UnixTimeMillis::new(2_000 + index),
                        reason: reason("concurrent"),
                    },
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(DeviceRepositoryError::Conflict))
                .count(),
            1
        );
        assert_eq!(repository.lifecycle(active.id).expect("events").len(), 1);
    }

    #[test]
    fn missing_devices_are_distinguished_from_empty_results() {
        let repository = InMemoryDeviceRepository::default();
        let id = DeviceId::from_bytes([7; 16]);
        assert_eq!(repository.get(id), Ok(None));
        assert_eq!(
            repository.lifecycle(id),
            Err(DeviceRepositoryError::NotFound)
        );
        assert_eq!(
            repository.transition(
                id,
                DeviceRevision::default(),
                DeviceTransition::Revoke {
                    at: UnixTimeMillis::new(1),
                    reason: reason("missing")
                }
            ),
            Err(DeviceRepositoryError::NotFound)
        );
    }
}
