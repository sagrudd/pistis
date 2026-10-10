extern crate proxenos;
use proxenos::site_root_convergence_wire_v1::{
    SiteRootAcknowledgementPresentationV2, encode_site_root_acknowledgement_presentation_v2,
};
fn main() {
    let bytes =
        encode_site_root_acknowledgement_presentation_v2(SiteRootAcknowledgementPresentationV2 {
            site_uuid: [1; 16],
            target_id: [2; 32],
            transaction_id: [3; 16],
            root_generation: 1,
            trust_state_revision: 1,
            root_fingerprint: [4; 32],
            issued_at_millis: 1_900_000_000_000,
            expires_at_millis: 1_900_000_300_000,
            nonce: [5; 32],
            ack_key_generation: 1,
        })
        .unwrap();
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
