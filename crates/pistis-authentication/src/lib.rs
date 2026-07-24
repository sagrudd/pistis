//! Framework-neutral QR authentication ceremony.
//!
//! Transport adapters may deliver a signed response directly or decode it from
//! QR framing. Neither transport is trusted: authentication is established only
//! by [`AuthenticationService::complete`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod schema;
mod service;

pub use model::{
    AuditEvent, AuthenticatedSessionId, ChallengeContext, ChallengeDocument, Completion, Decision,
    DeviceCredential, DeviceDirectory, LoginHandle, LoginStatus, PreAuthSessionId, PublicFailure,
    RandomSource, ResponseEnvelope, ServiceError, TransferMode, UnixTimeMillis,
};
pub use schema::{decode_challenge, encode_challenge, encode_response};
pub use service::AuthenticationService;
