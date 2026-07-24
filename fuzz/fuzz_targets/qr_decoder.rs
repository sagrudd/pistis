#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_qr::{MAX_TRANSFER_TEXT_BYTES, TransferKind, decode};

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_TRANSFER_TEXT_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let _ = decode(text, TransferKind::Challenge);
    let _ = decode(text, TransferKind::Response);
});
