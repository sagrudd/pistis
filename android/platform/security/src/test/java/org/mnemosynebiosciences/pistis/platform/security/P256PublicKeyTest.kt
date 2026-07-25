package org.mnemosynebiosciences.pistis.platform.security

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class P256PublicKeyTest {
    @Test
    fun emitsCompressedSec1P256Point() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val publicKey = generator.generateKeyPair().public as ECPublicKey

        val compressed = P256PublicKey.compressed(publicKey)

        assertEquals(33, compressed.size)
        assertTrue(compressed[0] == 0x02.toByte() || compressed[0] == 0x03.toByte())
        val expectedPrefix = if (publicKey.w.affineY.testBit(0)) 0x03 else 0x02
        assertEquals(expectedPrefix.toByte(), compressed[0])
    }

    @Test
    fun rejectsAnotherCurve() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp384r1"))
        val publicKey = generator.generateKeyPair().public as ECPublicKey

        assertThrows(IllegalArgumentException::class.java) {
            P256PublicKey.compressed(publicKey)
        }
    }
}
