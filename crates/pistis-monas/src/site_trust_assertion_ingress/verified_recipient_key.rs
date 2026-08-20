//! Verified public recipient-key projection for Site Trust custody genesis.
//!
//! It extends only the opaque acceptance produced by the pinned Apple-root
//! registration verifier. The projection is public, canonical P-256 SEC1
//! material; it is neither a secret nor a separate authority source.

use p256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint as _};

use super::{ServerHeldMonasAppAttestAcceptanceV1, SiteTrustAppAttestAssertionIngressErrorV1};

impl ServerHeldMonasAppAttestAcceptanceV1 {
    /// Returns the exact verified iPhone recipient key in canonical compressed
    /// SEC1 form for the one-use Site Trust custody-genesis reservation.
    ///
    /// It is available only from the opaque server-held registration acceptance
    /// and is never read from client input, local identity, environment, CLI,
    /// cookie, token, or caller-selected credential. This does not persist,
    /// derive, sign, or establish authority.
    ///
    /// # Errors
    ///
    /// Returns unavailable if the existing opaque acceptance cannot still
    /// validate and yield its exact canonical P-256 public key.
    pub fn verified_recipient_public_key_compressed_sec1(
        &self,
    ) -> Result<[u8; 33], SiteTrustAppAttestAssertionIngressErrorV1> {
        self.validate()?;
        PublicKey::from_sec1_bytes(&self.registered_public_key_sec1)
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Unavailable)?
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::super::tests::acceptance;

    #[test]
    fn server_held_acceptance_exposes_only_canonical_verified_recipient_key() {
        let key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        let acceptance = acceptance(&key, 0);
        let expected: [u8; 33] = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            acceptance
                .verified_recipient_public_key_compressed_sec1()
                .unwrap(),
            expected
        );
    }
}
