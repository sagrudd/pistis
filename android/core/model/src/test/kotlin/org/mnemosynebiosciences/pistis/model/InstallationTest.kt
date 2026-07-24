package org.mnemosynebiosciences.pistis.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class InstallationTest {
    private val original = Sha256Fingerprint.parse("01".repeat(32))
    private val replacement = Sha256Fingerprint.parse("02".repeat(32))

    @Test
    fun `fingerprint substitution blocks trust until explicit repair`() {
        val installation = Installation(
            id = DomainIdentifier.parse("installation:01"),
            label = "Laboratory workstation",
            fingerprint = original,
            trustState = InstallationTrustState.TRUSTED,
        )

        val changed = installation.observe(replacement)
        assertEquals(InstallationTrustState.CHANGED, changed.trustState)
        assertEquals(original, changed.fingerprint)

        val repaired = changed.repair(replacement)
        assertEquals(InstallationTrustState.TRUSTED, repaired.trustState)
        assertEquals(replacement, repaired.fingerprint)
    }

    @Test
    fun `revoked installation cannot be repaired`() {
        val revoked = Installation(
            DomainIdentifier.parse("installation:02"),
            "Revoked workstation",
            original,
            InstallationTrustState.REVOKED,
        )
        assertFailsWith<IllegalArgumentException> { revoked.repair(replacement) }
    }
}
