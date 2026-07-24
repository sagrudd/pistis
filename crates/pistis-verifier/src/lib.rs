//! Structured, fail-closed verification of Pistis signed messages.
//!
//! The pipeline deliberately returns a detailed [`VerificationOutcome`] rather
//! than collapsing security decisions into a boolean. Cryptographic
//! implementations, key storage, policy, and atomic challenge consumption are
//! supplied through narrow traits. This crate never handles private keys.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod pipeline;
mod ports;
mod signature;

pub use model::{
    Algorithm, ExpectedBindings, KeyRecord, KeyStatus, ParsedMessage, PublicKey, VerificationInput,
    VerificationOutcome,
};
pub use pipeline::Verifier;
pub use ports::{
    ChallengeConsumer, ChallengeError, Clock, KeyResolver, ParseError, Policy, PolicyError,
    SignatureError, SignatureVerifier, SignedMessageParser,
};
pub use signature::Es256SignatureVerifier;
