//! Bounded QR transport framing and module rendering.
//!
//! This crate detects transfer corruption and renders visual transport. It
//! makes no authentication, signature, trust, or authorization decision.

#![forbid(unsafe_code)]

mod enrolment_frame;
mod frame;
mod matrix;
mod production_frame;
mod response_input;
mod terminal_render;

pub use enrolment_frame::{
    EnrolmentTransfer, EnrolmentTransferRef, decode_enrolment, encode_enrolment,
    encode_enrolment_frame,
};
pub use frame::{
    MAX_PAYLOAD_BYTES, MAX_TRANSFER_TEXT_BYTES, QrError, SIGNATURE_BYTES, TransferKind,
    TransferRef, decode, encode,
};
pub use matrix::{Module, ModuleMatrix, render};
pub use production_frame::{
    MAX_COSE_ENVELOPE_BYTES, ProductionTransferRef, decode_production, encode_production,
};
pub use response_input::{ResponseInputError, read_response_input, read_response_transfer};
pub use terminal_render::{
    GlyphSet, ModulePolarity, TerminalProfile, TerminalQr, TerminalRenderError, render_for_terminal,
};
