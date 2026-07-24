use pistis_google::{
    DiscoveryDocument, DiscoveryError, JwkSet, JwksError, MAX_PROVIDER_DOCUMENT_BYTES,
};

#[test]
fn provider_documents_reject_oversize_before_json_parsing() {
    let oversized = vec![b' '; MAX_PROVIDER_DOCUMENT_BYTES + 1];
    assert_eq!(
        DiscoveryDocument::parse(&oversized),
        Err(DiscoveryError::InvalidDocument)
    );
    assert!(matches!(
        JwkSet::parse(&oversized),
        Err(JwksError::InvalidDocument)
    ));
}

#[test]
fn deterministic_malformed_corpus_never_produces_a_document() {
    let mut cases = vec![
        Vec::new(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        vec![b'['; 256],
        vec![0xff; 1024],
    ];
    for byte in u8::MIN..=u8::MAX {
        cases.push(vec![byte]);
    }

    for input in cases {
        assert!(DiscoveryDocument::parse(&input).is_err());
        assert!(JwkSet::parse(&input).is_err());
    }
}
