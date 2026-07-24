//! Local, fail-closed device registry domain and persistence ports.
//!
//! The crate contains public verification material only. It deliberately has
//! no private-key representation and exposes lifecycle changes only through
//! constrained repository operations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod memory;
mod migration;
mod model;
mod repository;
mod sqlite;

pub use memory::InMemoryDeviceRepository;
pub use migration::{CURRENT_SCHEMA_VERSION, MigrationError};
pub use model::{
    ApplicationVersion, AssuranceMetadata, AssuranceState, AttestationState, DevicePlatform,
    DevicePublicKey, DeviceRecord, DeviceRevision, DeviceStatus, DeviceTransition,
    InvalidApplicationVersion, InvalidDevicePublicKey, InvalidLifecycleReason, LifecycleEvent,
    LifecycleEventKind, LifecycleReason, NewDevice, UserVerification,
};
pub use repository::{DeviceRepository, DeviceRepositoryError};
pub use sqlite::SqliteDeviceRepository;
