//! Hostile-network discovery and direct-transfer contract.
//!
//! Discovery produces untrusted endpoint candidates, never authentication or
//! installation trust. Only a candidate matching an already authenticated
//! endpoint binding may produce a pinned direct request.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod advertisement;
mod candidate;
mod fallback;
mod wire;

pub use advertisement::{
    Advertisement, AdvertisementError, Capability, EndpointId, InstanceName, ProtocolVersion,
    ServiceType,
};
pub use candidate::{
    AddressScope, BindingContext, Candidate, CandidateFailure, DirectRequest, EndpointBinding,
    InterfaceId, TlsPublicKeyDigest,
};
pub use fallback::{
    AttemptFailure, SelectionState, TransferAttempt, TransferPlan, TransportRejection,
};
pub use wire::{SERVICE_TYPE_FQDN, WireAdvertisement, WireAdvertisementError};
