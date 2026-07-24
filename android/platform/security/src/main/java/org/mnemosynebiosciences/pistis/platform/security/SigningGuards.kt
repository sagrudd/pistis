package org.mnemosynebiosciences.pistis.platform.security

import java.util.concurrent.atomic.AtomicReference

/** Exact challenge deadline used immediately before a private-key operation. */
internal data class SigningDeadline(val expiresAtEpochSeconds: Long) {
    init {
        require(expiresAtEpochSeconds >= 0) { "invalid signing deadline" }
    }

    fun isExpired(nowEpochSeconds: Long): Boolean = nowEpochSeconds >= expiresAtEpochSeconds
}

/** Injectable wall clock used to enforce a signed challenge's exact expiry. */
fun interface EpochSecondsClock {
    fun now(): Long
}

/**
 * Atomic one-use gate: one prompt may start and exactly one terminal path wins.
 *
 * A success caller must claim [finish] before invoking a private-key operation.
 */
internal class OneUseOperationGate {
    private val state = AtomicReference(State.NEW)

    fun start(): Boolean = state.compareAndSet(State.NEW, State.ACTIVE)

    fun finish(): Boolean = state.compareAndSet(State.ACTIVE, State.TERMINAL)

    fun cancel(): Boolean {
        while (true) {
            val observed = state.get()
            if (observed == State.TERMINAL) return false
            if (state.compareAndSet(observed, State.TERMINAL)) return true
        }
    }

    private enum class State {
        NEW,
        ACTIVE,
        TERMINAL,
    }
}
