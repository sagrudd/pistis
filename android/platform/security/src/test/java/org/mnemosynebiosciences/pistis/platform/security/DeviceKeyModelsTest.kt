package org.mnemosynebiosciences.pistis.platform.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceKeyModelsTest {
    @Test
    fun onlyStrongBoxAndTeeReportHardwareStorage() {
        assertTrue(capability(ReportedSecurityLevel.STRONGBOX).reportsHardwareStorage)
        assertTrue(capability(ReportedSecurityLevel.TRUSTED_ENVIRONMENT).reportsHardwareStorage)
        assertFalse(capability(ReportedSecurityLevel.SOFTWARE).reportsHardwareStorage)
        assertFalse(capability(ReportedSecurityLevel.UNKNOWN_SECURE).reportsHardwareStorage)
        assertFalse(capability(ReportedSecurityLevel.UNKNOWN).reportsHardwareStorage)
    }

    @Test
    fun byteArrayOutcomesUseContentEquality() {
        val first = KeyGenerationOutcome.Created("key", byteArrayOf(2, 3), capability())
        val second = KeyGenerationOutcome.Created("key", byteArrayOf(2, 3), capability())
        val signatureOne = SigningOutcome.Signed(byteArrayOf(4, 5), LocalAuthorization.BIOMETRIC)
        val signatureTwo = SigningOutcome.Signed(byteArrayOf(4, 5), LocalAuthorization.BIOMETRIC)

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertEquals(signatureOne, signatureTwo)
        assertEquals(signatureOne.hashCode(), signatureTwo.hashCode())
    }

    private fun capability(
        level: ReportedSecurityLevel = ReportedSecurityLevel.TRUSTED_ENVIRONMENT,
    ) = ReportedKeyCapability(
        securityLevel = level,
        signingPurpose = true,
        sha256Digest = true,
        generatedInKeystore = true,
        userAuthenticationRequired = true,
        perOperationAuthentication = true,
        authorizationPolicy = AuthorizationPolicy.STRONG_BIOMETRIC,
    )
}
