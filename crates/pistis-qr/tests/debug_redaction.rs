//! QR transfer diagnostics must never format scanned binary material.

use pistis_qr::{
    EnrolmentTransfer, EnrolmentTransferRef, ProductionTransferRef, TransferKind, TransferRef,
};

#[test]
fn debug_output_contains_only_kind_and_lengths() {
    let payload = b"private-qr-payload-marker";
    let signature = b"private-qr-signature-marker";
    let cose = b"private-qr-cose-marker";
    let authority_bundle = b"private-qr-authority-marker";

    let outputs = [
        format!(
            "{:?}",
            TransferRef {
                kind: TransferKind::Response,
                payload,
                signature,
            }
        ),
        format!(
            "{:?}",
            ProductionTransferRef {
                kind: TransferKind::Challenge,
                cose,
            }
        ),
        format!(
            "{:?}",
            EnrolmentTransferRef {
                presentation_cose: cose,
                authority_bundle,
            }
        ),
        format!(
            "{:?}",
            EnrolmentTransfer {
                presentation_cose: cose.to_vec(),
                authority_bundle: authority_bundle.to_vec(),
            }
        ),
    ];

    let markers: [&[u8]; 4] = [payload, signature, cose, authority_bundle];
    for output in outputs {
        for marker in markers {
            assert!(
                !output.contains(std::str::from_utf8(marker).expect("ASCII marker")),
                "QR binary material leaked through Debug: {output}"
            );
        }
        assert!(
            output.contains("length"),
            "Debug must retain safe diagnostics"
        );
    }
}
