//! Bounded QR transport framing and module rendering.
//!
//! This crate detects transfer corruption and renders visual transport. It
//! makes no authentication, signature, trust, or authorization decision.

#![forbid(unsafe_code)]

mod frame;
mod matrix;
mod response_input;
mod terminal_render;

pub use frame::{
    MAX_PAYLOAD_BYTES, MAX_TRANSFER_TEXT_BYTES, QrError, SIGNATURE_BYTES, TransferKind,
    TransferRef, decode, encode,
};
pub use matrix::{Module, ModuleMatrix, render};
pub use response_input::{ResponseInputError, read_response_input, read_response_transfer};
pub use terminal_render::{
    GlyphSet, ModulePolarity, TerminalProfile, TerminalQr, TerminalRenderError, render_for_terminal,
};
