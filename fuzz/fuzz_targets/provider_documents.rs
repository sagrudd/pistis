#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_google::{DiscoveryDocument, JwkSet, MAX_PROVIDER_DOCUMENT_BYTES};

fuzz_target!(|input: &[u8]| {
    if input.len() <= MAX_PROVIDER_DOCUMENT_BYTES {
        let _ = DiscoveryDocument::parse(input);
        let _ = JwkSet::parse(input);
    }
});
