//! Framework-neutral QR authentication ceremony.
//!
//! Transport adapters may deliver a signed response directly or decode it from
//! QR framing. Neither transport is trusted: authentication is established only
//! by [`AuthenticationService::complete`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod action;
mod model;
mod production_response;
mod schema;
mod service;

pub use action::{
    ActionApprovalChallenge, ActionApprovalResponse, ActionDescriptor, ActionEnvironment,
    ActionResource, ActionResourceKind, MAX_ACTION_ARGUMENTS, MAX_ACTION_ENVIRONMENT,
    MAX_ACTION_RESOURCES, action_descriptor_digest, decode_action_challenge,
    decode_action_descriptor, decode_action_response, encode_action_challenge,
    encode_action_descriptor, encode_action_response,
};
pub use model::{
    AuditEvent, AuthenticatedSessionId, ChallengeContext, ChallengeDocument, Completion, Decision,
    DeviceCredential, DeviceDirectory, LoginHandle, LoginStatus, PreAuthSessionId, PublicFailure,
    RandomSource, ResponseEnvelope, ServiceError, TransferMode, UnixTimeMillis,
};
pub use production_response::{
    AuthenticationResponseCredential, AuthenticationResponseExpectation,
    AuthenticationResponseVerificationError, VerifiedAuthenticationResponse,
    verify_authentication_response,
};
pub use schema::{decode_challenge, encode_challenge, encode_response};
pub use service::AuthenticationService;
