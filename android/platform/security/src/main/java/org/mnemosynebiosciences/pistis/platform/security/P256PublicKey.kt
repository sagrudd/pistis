package org.mnemosynebiosciences.pistis.platform.security

import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.math.BigInteger

/** Canonical SEC1 encoding for a validated Android P-256 public key. */
internal object P256PublicKey {
    private const val COORDINATE_BYTES = 32
    private const val P256_FIELD_SIZE = 256
    private val p256Order =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val p256Prime =
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)

    fun compressed(key: ECPublicKey): ByteArray {
        require(key.params.curve.field.fieldSize == P256_FIELD_SIZE) { "public key is not P-256" }
        require(key.params.order == p256Order && key.params.cofactor == 1) {
            "public key has unexpected curve parameters"
        }
        val field = key.params.curve.field as? ECFieldFp
            ?: throw IllegalArgumentException("public key does not use a prime field")
        require(field.p == p256Prime) { "public key has unexpected field parameters" }
        val x = unsignedFixed(key.w.affineX.toByteArray())
        val prefix = if (key.w.affineY.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix.toByte()) + x
    }

    private fun unsignedFixed(signed: ByteArray): ByteArray {
        val unsigned = if (signed.size == COORDINATE_BYTES + 1 && signed[0] == 0.toByte()) {
            signed.copyOfRange(1, signed.size)
        } else {
            signed
        }
        require(unsigned.size <= COORDINATE_BYTES) { "coordinate is wider than P-256" }
        return ByteArray(COORDINATE_BYTES - unsigned.size) + unsigned
    }
}
