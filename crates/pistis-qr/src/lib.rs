//! Bounded QR transport framing and module rendering.
//!
//! This crate detects transfer corruption and renders visual transport. It
//! makes no authentication, signature, trust, or authorization decision.

#![forbid(unsafe_code)]

mod frame;
mod matrix;

pub use frame::{
    MAX_PAYLOAD_BYTES, MAX_TRANSFER_TEXT_BYTES, QrError, SIGNATURE_BYTES, TransferKind,
    TransferRef, decode, encode,
};
pub use matrix::{Module, ModuleMatrix, render};
