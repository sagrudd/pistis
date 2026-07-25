package org.mnemosynebiosciences.pistis.platform.security

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DerEs256Test {
    private val order =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    @Test
    fun convertsAndPadsTwoPositiveScalars() {
        val fixed = DerEs256.toFixedLowS(sequence(integer(BigInteger.ONE), integer(BigInteger.TWO)))

        assertEquals(64, fixed.size)
        assertEquals(1, fixed[31].toInt())
        assertEquals(2, fixed[63].toInt())
    }

    @Test
    fun stripsRequiredPositiveIntegerPadding() {
        val scalar = BigInteger("80", 16)

        val fixed = DerEs256.toFixedLowS(sequence(integer(scalar), integer(BigInteger.ONE)))

        assertEquals(0x80.toByte(), fixed[31])
    }

    @Test
    fun normalizesHighSToLowS() {
        val highS = order.subtract(BigInteger.ONE)

        val fixed = DerEs256.toFixedLowS(sequence(integer(BigInteger.TWO), integer(highS)))

        assertArrayEquals(ByteArray(31) + byteArrayOf(1), fixed.copyOfRange(32, 64))
    }

    @Test
    fun acceptsLargestLowSValue() {
        val halfOrder = order.shiftRight(1)

        val fixed = DerEs256.toFixedLowS(sequence(integer(BigInteger.ONE), integer(halfOrder)))

        assertEquals(64, fixed.size)
        assertArrayEquals(unsignedFixed(halfOrder), fixed.copyOfRange(32, 64))
    }

    @Test
    fun rejectsEmptyAndTruncatedInput() {
        rejects(byteArrayOf())
        rejects(byteArrayOf(0x30, 0x01, 0x02))
        rejects(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01))
    }

    @Test
    fun rejectsWrongTagsAndExtraIntegers() {
        rejects(byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))
        rejects(byteArrayOf(0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01))
        rejects(
            byteArrayOf(
                0x30, 0x09,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
            ),
        )
    }

    @Test
    fun rejectsTrailingBytesAndIncorrectSequenceLength() {
        rejects(sequence(integer(BigInteger.ONE), integer(BigInteger.ONE)) + byteArrayOf(0))
        rejects(byteArrayOf(0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))
    }

    @Test
    fun rejectsNegativeZeroAndNonMinimalIntegers() {
        rejects(sequence(byteArrayOf(0x02, 0x01, 0x80.toByte()), integer(BigInteger.ONE)))
        rejects(sequence(byteArrayOf(0x02, 0x01, 0x00), integer(BigInteger.ONE)))
        rejects(sequence(byteArrayOf(0x02, 0x02, 0x00, 0x01), integer(BigInteger.ONE)))
    }

    @Test
    fun rejectsScalarAtOrAboveCurveOrder() {
        rejects(sequence(integer(order), integer(BigInteger.ONE)))
        rejects(sequence(integer(BigInteger.ONE), integer(order)))
    }

    @Test
    fun rejectsNonMinimalAndUnsupportedLengths() {
        rejects(
            byteArrayOf(
                0x30, 0x81.toByte(), 0x06,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
            ),
        )
        rejects(byteArrayOf(0x30, 0x83.toByte(), 0x00, 0x00, 0x06))
        rejects(byteArrayOf(0x30, 0x82.toByte(), 0x00, 0x80.toByte()))
    }

    @Test
    fun deterministicForRepresentativeScalars() {
        val cases = listOf(
            BigInteger.ONE,
            BigInteger.TWO,
            BigInteger("7f", 16),
            BigInteger("80", 16),
            BigInteger.ONE.shiftLeft(255),
            order.subtract(BigInteger.ONE),
        )
        cases.forEach { scalar ->
            val first = DerEs256.toFixedLowS(sequence(integer(BigInteger.ONE), integer(scalar)))
            val second = DerEs256.toFixedLowS(sequence(integer(BigInteger.ONE), integer(scalar)))
            assertArrayEquals(first, second)
        }
    }

    private fun rejects(input: ByteArray) {
        assertThrows(IllegalArgumentException::class.java) { DerEs256.toFixedLowS(input) }
    }

    private fun sequence(vararg values: ByteArray): ByteArray {
        val body = values.fold(ByteArray(0), ByteArray::plus)
        require(body.size < 128)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun integer(value: BigInteger): ByteArray {
        val encoded = value.toByteArray()
        return byteArrayOf(0x02, encoded.size.toByte()) + encoded
    }

    private fun unsignedFixed(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        val unsigned = if (signed.size == 33 && signed[0] == 0.toByte()) {
            signed.copyOfRange(1, signed.size)
        } else {
            signed
        }
        return ByteArray(32 - unsigned.size) + unsigned
    }
}
