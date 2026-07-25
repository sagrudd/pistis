#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_authentication::decode_challenge;
use pistis_canonical::MAX_MESSAGE_SIZE;

fuzz_target!(|input: &[u8]| {
    if input.len() <= MAX_MESSAGE_SIZE {
        let _ = decode_challenge(input);
    }
});
