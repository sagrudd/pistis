package org.mnemosynebiosciences.pistis.model

/** Provider identities supported by the reference application. */
public enum class IdentityProvider {
    GITHUB,
    GOOGLE,
}

/** Lifecycle state of an external identity binding. */
public enum class IdentityBindingState {
    ACTIVE,
    REAUTHENTICATION_REQUIRED,
    REVOKED,
}

/** A redacted external identity; provider credentials are deliberately absent. */
public data class ExternalIdentity(
    public val id: DomainIdentifier,
    public val provider: IdentityProvider,
    public val displayName: String,
    public val state: IdentityBindingState,
) {
    init {
        require(displayName.isNotBlank() && displayName.length <= 128) {
            "invalid display name"
        }
    }
}
