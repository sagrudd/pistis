#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_canonical::MAX_MESSAGE_SIZE;
use pistis_crypto::{PublicKey, SignatureSuite, verify};

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_MESSAGE_SIZE {
        return;
    }

    let mut algorithm_bytes = [0_u8; 8];
    let algorithm_prefix = input.get(..8).unwrap_or(input);
    algorithm_bytes[..algorithm_prefix.len()].copy_from_slice(algorithm_prefix);
    let algorithm = i64::from_le_bytes(algorithm_bytes);

    let key_length = input.get(8).copied().unwrap_or_default() as usize % 66;
    let key_start = input.len().min(9);
    let key_end = input.len().min(key_start.saturating_add(key_length));
    let signature_length = input.get(key_end).copied().unwrap_or_default() as usize % 81;
    let signature_start = input.len().min(key_end.saturating_add(1));
    let signature_end = input
        .len()
        .min(signature_start.saturating_add(signature_length));

    let (Ok(suite), Ok(key)) = (
        SignatureSuite::try_from(algorithm),
        PublicKey::from_sec1_bytes(&input[key_start..key_end]),
    ) else {
        return;
    };
    let signature = &input[signature_start..signature_end];
    let message = &input[signature_end..];
    let _ = verify(suite, &key, message, signature);
});
