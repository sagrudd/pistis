package org.mnemosynebiosciences.pistis.model

private val identifierPattern = Regex("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
private val fingerprintPattern = Regex("[0-9a-f]{64}")

/** A validated, opaque domain identifier. */
@JvmInline
public value class DomainIdentifier private constructor(public val value: String) {
    public companion object {
        /** Creates an identifier after applying the closed syntax and length bound. */
        public fun parse(value: String): DomainIdentifier {
            require(identifierPattern.matches(value)) { "invalid domain identifier" }
            return DomainIdentifier(value)
        }
    }
}

/** A canonical lower-case SHA-256 fingerprint. */
@JvmInline
public value class Sha256Fingerprint private constructor(public val value: String) {
    public companion object {
        /** Creates a fingerprint only from exactly 32 lower-case hexadecimal bytes. */
        public fun parse(value: String): Sha256Fingerprint {
            require(fingerprintPattern.matches(value)) { "invalid SHA-256 fingerprint" }
            return Sha256Fingerprint(value)
        }
    }
}
