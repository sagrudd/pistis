use pistis_authentication::decode_challenge;
use pistis_canonical::MAX_MESSAGE_SIZE;

#[test]
fn deterministic_malformed_corpus_never_produces_a_challenge() {
    let mut cases = vec![
        Vec::new(),
        vec![0xff; 1024],
        vec![0x9f; 64],
        vec![0xbf; 64],
        vec![0; MAX_MESSAGE_SIZE + 1],
    ];
    for byte in u8::MIN..=u8::MAX {
        cases.push(vec![byte]);
    }

    for input in cases {
        assert!(decode_challenge(&input).is_err());
    }
}
