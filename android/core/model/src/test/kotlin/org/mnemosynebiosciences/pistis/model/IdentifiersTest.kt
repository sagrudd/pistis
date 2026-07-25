package org.mnemosynebiosciences.pistis.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class IdentifiersTest {
    @Test
    fun `identifier syntax is closed and bounded`() {
        assertEquals("identity:01", DomainIdentifier.parse("identity:01").value)
        assertFailsWith<IllegalArgumentException> { DomainIdentifier.parse("") }
        assertFailsWith<IllegalArgumentException> { DomainIdentifier.parse("../identity") }
        assertFailsWith<IllegalArgumentException> { DomainIdentifier.parse("a".repeat(129)) }
    }

    @Test
    fun `fingerprint accepts only canonical lowercase sha256`() {
        val canonical = "ab".repeat(32)
        assertEquals(canonical, Sha256Fingerprint.parse(canonical).value)
        assertFailsWith<IllegalArgumentException> {
            Sha256Fingerprint.parse(canonical.uppercase())
        }
        assertFailsWith<IllegalArgumentException> { Sha256Fingerprint.parse("ab") }
    }
}
