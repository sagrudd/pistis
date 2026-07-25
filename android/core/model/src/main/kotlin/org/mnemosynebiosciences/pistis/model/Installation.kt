package org.mnemosynebiosciences.pistis.model

/** Trust is blocked on any observed fingerprint change until explicit re-pairing. */
public enum class InstallationTrustState {
    TRUSTED,
    CHANGED,
    REVOKED,
}

/** A paired installation and its currently accepted public-key fingerprint. */
public data class Installation(
    public val id: DomainIdentifier,
    public val label: String,
    public val fingerprint: Sha256Fingerprint,
    public val trustState: InstallationTrustState,
) {
    init {
        require(label.isNotBlank() && label.length <= 128) { "invalid installation label" }
    }

    /** Observes a fingerprint without silently accepting a changed key. */
    public fun observe(observed: Sha256Fingerprint): Installation =
        if (observed == fingerprint) {
            this
        } else {
            copy(trustState = InstallationTrustState.CHANGED)
        }

    /** Explicitly accepts a replacement key unless the installation was revoked. */
    public fun repair(observed: Sha256Fingerprint): Installation {
        require(trustState != InstallationTrustState.REVOKED) {
            "revoked installation cannot be repaired"
        }
        require(trustState == InstallationTrustState.CHANGED) {
            "repair is not required"
        }
        return copy(fingerprint = observed, trustState = InstallationTrustState.TRUSTED)
    }
}
