#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_canonical::{MAX_MESSAGE_SIZE, from_slice, to_vec};

fuzz_target!(|input: &[u8]| {
    // Keep each execution within the protocol's documented input bound. Larger
    // inputs are rejected by the ordinary unit and integration test suites.
    if input.len() > MAX_MESSAGE_SIZE {
        return;
    }

    if let Ok(value) = from_slice(input)
        && let Ok(encoded) = to_vec(&value)
    {
        let _ = from_slice(&encoded);
    }
});
