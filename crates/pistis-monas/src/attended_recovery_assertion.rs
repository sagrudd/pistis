//! Purpose-specific attended-recovery assertion boundary.
//!
//! Inputs must be reconstructed from protected host state. This module does not
//! authenticate a broker, establish user presence, or consume the counter.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use sha2::{Digest as _, Sha256};

use crate::{
    MonotonicAppAttestCounterV1, SiteTrustAppAttestAssertionIngressErrorV1,
    site_trust_assertion_ingress::verify_purpose_bound_app_attest_assertion_v2,
};

/// Exact server-owned values for one attended recovery transcript.
#[derive(Clone)]
pub struct AttendedRecoveryBindingV1 {
    /// Fresh mailbox nonce.
    pub nonce: [u8; 32],
    /// Original operation identifier.
    pub operation: [u8; 16],
    /// Domain-separated original correlation digest.
    pub correlation_digest: [u8; 32],
    /// Hash of the protected reference.
    pub reference_digest: [u8; 32],
    /// Hash of the canonical protected site.
    pub site_digest: [u8; 32],
    /// Original installation identifier.
    pub installation: [u8; 16],
    /// Apple-registered B key identifier.
    pub app_attest_key_id: [u8; 32],
    /// Compressed public key of the already registered Site Root.
    pub site_root_public_key: [u8; 33],
    /// Accepted owner transaction.
    pub owner_transaction: [u8; 16],
    /// Digest of the accepted owner result.
    pub owner_result_digest: [u8; 32],
    /// Digest of the fixed endpoint set.
    pub endpoint_digest: [u8; 32],
    /// Digest of the exact host-owned intent.
    pub intent_digest: [u8; 32],
    /// The intent's deadline in Unix seconds.
    pub expires_at: u64,
}

impl AttendedRecoveryBindingV1 {
    pub(crate) fn client_data_hash(
        &self,
        signature: &[u8; 64],
        now: u64,
    ) -> Result<[u8; 32], SiteTrustAppAttestAssertionIngressErrorV1> {
        let deny = || SiteTrustAppAttestAssertionIngressErrorV1::Denied;
        if self.nonce == [0; 32]
            || self.operation == [0; 16]
            || self.correlation_digest == [0; 32]
            || self.reference_digest == [0; 32]
            || self.site_digest == [0; 32]
            || self.installation == [0; 16]
            || self.app_attest_key_id == [0; 32]
            || self.owner_transaction == [0; 16]
            || self.owner_result_digest == [0; 32]
            || self.endpoint_digest == [0; 32]
            || self.intent_digest == [0; 32]
            || self.expires_at <= now
            || self.expires_at.checked_sub(now).ok_or_else(deny)? > 120
        {
            return Err(deny());
        }
        let mut transcript = b"mnemosyne.monas.attended-recovery.v1\0".to_vec();
        transcript.extend_from_slice(&self.nonce);
        transcript.extend_from_slice(&self.operation);
        transcript.extend_from_slice(&self.correlation_digest);
        transcript.extend_from_slice(&self.reference_digest);
        transcript.extend_from_slice(&self.site_digest);
        transcript.extend_from_slice(&self.installation);
        transcript.extend_from_slice(&self.app_attest_key_id);
        transcript.extend_from_slice(&Sha256::digest(self.site_root_public_key));
        transcript.extend_from_slice(&self.owner_transaction);
        transcript.extend_from_slice(&self.owner_result_digest);
        transcript.extend_from_slice(&self.endpoint_digest);
        transcript.extend_from_slice(&self.intent_digest);
        transcript.extend_from_slice(&self.expires_at.to_be_bytes());
        let transcript_hash = Sha256::digest(&transcript);
        let sig = Signature::from_slice(signature).map_err(|_| deny())?;
        if sig.normalize_s() != sig {
            return Err(deny());
        }
        let key = VerifyingKey::from_sec1_bytes(&self.site_root_public_key).map_err(|_| deny())?;
        let mut message = b"mnemosyne.monas.attended-recovery.site-root.v1\0".to_vec();
        message.extend_from_slice(&transcript_hash);
        key.verify(&message, &sig).map_err(|_| deny())?;
        let mut hash = Sha256::new();
        hash.update(b"mnemosyne.monas.attended-recovery.app-attest.v1\0");
        hash.update(transcript_hash);
        hash.update(signature);
        Ok(hash.finalize().into())
    }
}

/// Opaque acceptance made only by the pinned registration factory.
pub struct AttendedRecoveryAppAttestAcceptanceV1 {
    pub(crate) expected_client_data_hash: [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) registered_key_id: [u8; 32],
    pub(crate) registered_public_key_sec1: [u8; 65],
    pub(crate) previous_counter: u32,
    pub(crate) bundle_version: String,
}

/// Verified evidence; the host must atomically consume the counter and nonce.
pub struct AttendedRecoveryAppAttestOutcomeV1 {
    counter: MonotonicAppAttestCounterV1,
    assertion_sha256: [u8; 32],
}
impl AttendedRecoveryAppAttestOutcomeV1 {
    /// Strictly advanced Apple counter.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }
    /// Digest of the verified assertion.
    #[must_use]
    pub const fn assertion_sha256(&self) -> [u8; 32] {
        self.assertion_sha256
    }
}

/// Verify the exact purpose-bound assertion; no state or authority is changed.
///
/// # Errors
/// Denies malformed, mismatched or stale Apple evidence.
pub fn verify_attended_recovery_app_attest_assertion_v1(
    acceptance: &AttendedRecoveryAppAttestAcceptanceV1,
    assertion: &[u8],
    now: u64,
) -> Result<AttendedRecoveryAppAttestOutcomeV1, SiteTrustAppAttestAssertionIngressErrorV1> {
    if now >= acceptance.expires_at {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let (counter, assertion_sha256) = verify_purpose_bound_app_attest_assertion_v2(
        assertion,
        acceptance.expected_client_data_hash,
        acceptance.registered_key_id,
        acceptance.registered_public_key_sec1,
        acceptance.previous_counter,
        &acceptance.bundle_version,
    )?;
    Ok(AttendedRecoveryAppAttestOutcomeV1 {
        counter,
        assertion_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn take<const N: usize>(t: &[u8], pos: &mut usize) -> [u8; N] {
        let x = t[*pos..*pos + N].try_into().unwrap();
        *pos += N;
        x
    }
    fn fixture() -> (AttendedRecoveryBindingV1, [u8; 64], [u8; 32]) {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/attended-recovery-phone-vector.json"
        ))
        .unwrap();
        let t = hex(v["transcript_hex"].as_str().unwrap());
        let qr: serde_json::Value = serde_json::from_str(v["qr_json"].as_str().unwrap()).unwrap();
        let root: [u8; 33] = URL_SAFE_NO_PAD
            .decode(qr["site_root_public_key_b64url"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut pos = b"mnemosyne.monas.attended-recovery.v1\0".len();
        let binding = AttendedRecoveryBindingV1 {
            nonce: take(&t, &mut pos),
            operation: take(&t, &mut pos),
            correlation_digest: take(&t, &mut pos),
            reference_digest: take(&t, &mut pos),
            site_digest: take(&t, &mut pos),
            installation: take(&t, &mut pos),
            app_attest_key_id: take(&t, &mut pos),
            site_root_public_key: root,
            owner_transaction: {
                let _: [u8; 32] = take(&t, &mut pos);
                take(&t, &mut pos)
            },
            owner_result_digest: take(&t, &mut pos),
            endpoint_digest: take(&t, &mut pos),
            intent_digest: take(&t, &mut pos),
            expires_at: u64::from_be_bytes(take(&t, &mut pos)),
        };
        assert_eq!(pos, t.len());
        (
            binding,
            hex(v["site_root_signature_raw_low_s_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            hex(v["app_attest_client_data_hash_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
    }
    #[test]
    fn shared_vector_and_binding_negatives() {
        let (mut b, sig, expected) = fixture();
        assert_eq!(
            b.client_data_hash(&sig, b.expires_at - 1).unwrap(),
            expected
        );
        assert!(b.client_data_hash(&sig, b.expires_at).is_err());
        b.operation[0] ^= 1;
        assert!(b.client_data_hash(&sig, b.expires_at - 1).is_err());
    }
    fn cbor_bytes(out: &mut Vec<u8>, v: &[u8]) {
        out.extend_from_slice(&[
            0x58,
            u8::try_from(v.len()).expect("fixture byte string length"),
        ]);
        out.extend_from_slice(v);
    }
    #[test]
    fn real_p256_apple_assertion_is_bound_to_transcript_and_counter() {
        let (binding, root_sig, client_hash) = fixture();
        let key = SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let public: [u8; 65] = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut auth =
            Sha256::digest(crate::MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes())
                .to_vec();
        auth.push(0);
        auth.extend_from_slice(&9u32.to_be_bytes());
        let nonce = Sha256::digest([auth.as_slice(), client_hash.as_slice()].concat());
        let signature: Signature = key.sign(&nonce);
        let mut assertion = vec![0xa2, 0x69];
        assertion.extend_from_slice(b"signature");
        cbor_bytes(&mut assertion, signature.to_der().as_bytes());
        assertion.push(0x71);
        assertion.extend_from_slice(b"authenticatorData");
        cbor_bytes(&mut assertion, &auth);
        let mut acceptance = AttendedRecoveryAppAttestAcceptanceV1 {
            expected_client_data_hash: binding
                .client_data_hash(&root_sig, binding.expires_at - 1)
                .unwrap(),
            expires_at: binding.expires_at,
            registered_key_id: Sha256::digest(public).into(),
            registered_public_key_sec1: public,
            previous_counter: 8,
            bundle_version: "1.0.0".into(),
        };
        assert_eq!(
            verify_attended_recovery_app_attest_assertion_v1(
                &acceptance,
                &assertion,
                binding.expires_at - 1
            )
            .unwrap()
            .counter()
            .get(),
            9
        );
        assert!(
            verify_attended_recovery_app_attest_assertion_v1(
                &acceptance,
                &assertion,
                binding.expires_at
            )
            .is_err()
        );
        acceptance.previous_counter = 9;
        assert!(
            verify_attended_recovery_app_attest_assertion_v1(
                &acceptance,
                &assertion,
                binding.expires_at - 1
            )
            .is_err()
        );
        acceptance.previous_counter = 8;
        acceptance.expected_client_data_hash[0] ^= 1;
        assert!(
            verify_attended_recovery_app_attest_assertion_v1(
                &acceptance,
                &assertion,
                binding.expires_at - 1
            )
            .is_err()
        );
    }
    #[test]
    fn factory_enforces_exact_registered_b_identity() {
        let (mut binding, _, _) = fixture();
        let apple = SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let public: [u8; 65] = apple
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        binding.app_attest_key_id = Sha256::digest(public).into();
        let root = SigningKey::from_bytes((&[0x32; 32]).into()).unwrap();
        binding.site_root_public_key = root
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut t = b"mnemosyne.monas.attended-recovery.v1\0".to_vec();
        for field in [
            &binding.nonce[..],
            &binding.operation,
            &binding.correlation_digest,
            &binding.reference_digest,
            &binding.site_digest,
            &binding.installation,
            &binding.app_attest_key_id,
            &Sha256::digest(binding.site_root_public_key),
            &binding.owner_transaction,
            &binding.owner_result_digest,
            &binding.endpoint_digest,
            &binding.intent_digest,
            &binding.expires_at.to_be_bytes(),
        ] {
            t.extend_from_slice(field);
        }
        let mut message = b"mnemosyne.monas.attended-recovery.site-root.v1\0".to_vec();
        message.extend_from_slice(&Sha256::digest(&t));
        let signature: Signature = root.sign(&message);
        let signature: [u8; 64] = signature.normalize_s().to_bytes().into();
        let factory = crate::ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
        let key_id = URL_SAFE_NO_PAD.encode(binding.app_attest_key_id);
        let manifest: [u8; 32] = URL_SAFE_NO_PAD
            .decode("68Muj_qAmNAUNJYYV3Vv8gfWb708-mdjUNiYUYGOwaI")
            .unwrap()
            .try_into()
            .unwrap();
        let call = |id: &str, app: &str, counter: u32| {
            factory.resume_durable_registration_for_attended_recovery_v1(
                &binding,
                &signature,
                binding.expires_at - 1,
                app,
                id,
                public,
                manifest,
                "1.0.0",
                counter,
            )
        };
        assert!(
            call(
                &key_id,
                crate::MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
                8
            )
            .is_ok()
        );
        assert!(
            call(
                &URL_SAFE_NO_PAD.encode([1; 32]),
                crate::MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
                8
            )
            .is_err()
        );
        assert!(call(&key_id, "wrong.application", 8).is_err());
        assert!(
            call(
                &key_id,
                crate::MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
                u32::MAX
            )
            .is_err()
        );
    }
}
