package org.mnemosynebiosciences.pistis.evidence

import org.mnemosynebiosciences.pistis.model.DomainIdentifier

/** Redacted informational event kinds observed by this device. */
public enum class HistoryEventKind {
    REQUEST_RECEIVED,
    REVIEWED,
    HUMAN_DECISION,
    LOCAL_AUTHENTICATION,
    SIGNATURE,
    TRANSFER,
    SERVER_RESULT,
}

/** Whether authoritative external evidence was observed, not inferred. */
public enum class EvidenceAvailability {
    LOCAL_ONLY,
    EXTERNAL_RECEIPT_OBSERVED,
}

/** One canonical local observation. Payloads and credentials are deliberately absent. */
public data class HistoryEvent(
    public val sequence: UInt,
    public val observedAtEpochSeconds: Long,
    public val kind: HistoryEventKind,
    public val summary: String,
) {
    init {
        require(observedAtEpochSeconds >= 0) { "invalid observation time" }
        require(summary.isNotBlank() && summary.length <= 160) { "invalid redacted summary" }
    }
}

/** A deterministic, contiguous local timeline; it is not authoritative server audit evidence. */
public data class LocalHistoryRecord(
    public val id: DomainIdentifier,
    public val availability: EvidenceAvailability,
    public val events: List<HistoryEvent>,
) {
    init {
        require(events.isNotEmpty()) { "history must not be empty" }
        require(events.indices.all { events[it].sequence == it.toUInt() }) {
            "history sequence is not canonical"
        }
        require(events.zipWithNext().all { (first, second) ->
            first.observedAtEpochSeconds <= second.observedAtEpochSeconds
        }) {
            "history time is not monotonic"
        }
    }
}
