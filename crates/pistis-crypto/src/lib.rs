//! Fail-closed cryptographic verification primitives for Pistis.
//!
//! The crate intentionally exposes no private-key or signing API. Protocol v1
//! accepts only ES256, canonicalizes public keys to compressed SEC1 form, and
//! requires fixed-width, low-S COSE signatures.

#![forbid(unsafe_code)]

mod digest;
mod key;
mod signature;
mod suite;

pub use digest::{Sha256Digest, sha256};
pub use key::{PublicKey, PublicKeyError, derive_key_id};
pub use signature::{SignatureError, verify};
pub use suite::{AlgorithmError, SignatureSuite};
