package org.mnemosynebiosciences.pistis.platform.security

import java.math.BigInteger

/**
 * Strictly converts ASN.1 DER ECDSA signatures into fixed-width, low-S ES256.
 *
 * This parser accepts exactly `SEQUENCE(INTEGER r, INTEGER s)`. Both integers
 * must be minimally encoded, positive P-256 scalars in `1..<n`, and the input
 * must contain no trailing bytes.
 */
object DerEs256 {
    private const val SEQUENCE_TAG = 0x30
    private const val INTEGER_TAG = 0x02
    private const val SCALAR_BYTES = 32

    private val order =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val halfOrder = order.shiftRight(1)

    fun toFixedLowS(der: ByteArray): ByteArray {
        val cursor = Cursor(der)
        cursor.expect(SEQUENCE_TAG)
        val sequenceLength = cursor.readLength()
        val sequenceEnd = cursor.position + sequenceLength
        require(sequenceEnd == der.size) { "DER sequence length is not exact" }

        val r = cursor.readPositiveScalar()
        var s = cursor.readPositiveScalar()
        require(cursor.position == sequenceEnd) { "DER contains trailing sequence data" }
        if (s > halfOrder) {
            s = order.subtract(s)
        }

        return fixed(r) + fixed(s)
    }

    private fun fixed(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        val unsigned = if (signed.size == SCALAR_BYTES + 1 && signed[0] == 0.toByte()) {
            signed.copyOfRange(1, signed.size)
        } else {
            signed
        }
        require(unsigned.size <= SCALAR_BYTES) { "scalar is wider than P-256" }
        return ByteArray(SCALAR_BYTES - unsigned.size) + unsigned
    }

    private class Cursor(private val input: ByteArray) {
        var position: Int = 0
            private set

        fun expect(expected: Int) {
            require(readByte() == expected) { "unexpected DER tag" }
        }

        fun readLength(): Int {
            val first = readByte()
            if (first < 0x80) return first
            val count = first and 0x7f
            require(count in 1..2) { "unsupported DER length" }
            require(remaining() >= count) { "truncated DER length" }
            require(input[position].toInt() and 0xff != 0) { "non-minimal DER length" }
            var length = 0
            repeat(count) { length = (length shl 8) or readByte() }
            require(length >= 0x80) { "non-minimal long-form DER length" }
            require(length <= remaining()) { "truncated DER value" }
            return length
        }

        fun readPositiveScalar(): BigInteger {
            expect(INTEGER_TAG)
            val length = readLength()
            require(length in 1..33 && length <= remaining()) { "invalid scalar length" }
            val bytes = input.copyOfRange(position, position + length)
            position += length
            require(bytes[0].toInt() and 0x80 == 0) { "negative scalar" }
            if (bytes.size > 1 && bytes[0] == 0.toByte()) {
                require(bytes[1].toInt() and 0x80 != 0) { "redundant scalar padding" }
            }
            val value = BigInteger(1, bytes)
            require(value.signum() > 0 && value < order) { "scalar outside P-256 range" }
            return value
        }

        private fun readByte(): Int {
            require(position < input.size) { "truncated DER" }
            return input[position++].toInt() and 0xff
        }

        private fun remaining(): Int = input.size - position
    }
}
