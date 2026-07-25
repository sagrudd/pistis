package org.mnemosynebiosciences.pistis.evidence

import org.mnemosynebiosciences.pistis.model.DomainIdentifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class LocalHistoryTest {
    @Test
    fun `canonical redacted timeline is retained as local observation`() {
        val record = LocalHistoryRecord(
            id = DomainIdentifier.parse("evidence:01"),
            availability = EvidenceAvailability.LOCAL_ONLY,
            events = listOf(
                HistoryEvent(0u, 100, HistoryEventKind.REQUEST_RECEIVED, "Request received"),
                HistoryEvent(1u, 101, HistoryEventKind.HUMAN_DECISION, "Request approved"),
            ),
        )
        assertEquals(EvidenceAvailability.LOCAL_ONLY, record.availability)
        assertEquals(2, record.events.size)
    }

    @Test
    fun `noncontiguous or nonmonotonic timelines are rejected`() {
        assertFailsWith<IllegalArgumentException> {
            LocalHistoryRecord(
                DomainIdentifier.parse("evidence:02"),
                EvidenceAvailability.LOCAL_ONLY,
                listOf(HistoryEvent(1u, 100, HistoryEventKind.REVIEWED, "Reviewed")),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            LocalHistoryRecord(
                DomainIdentifier.parse("evidence:03"),
                EvidenceAvailability.LOCAL_ONLY,
                listOf(
                    HistoryEvent(0u, 101, HistoryEventKind.REVIEWED, "Reviewed"),
                    HistoryEvent(1u, 100, HistoryEventKind.HUMAN_DECISION, "Denied"),
                ),
            )
        }
    }
}
