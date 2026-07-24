package org.mnemosynebiosciences.pistis.platform.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SigningGuardsTest {
    @Test
    fun onlyOnePromptMayStart() {
        val gate = OneUseOperationGate()

        assertTrue(gate.start())
        assertFalse(gate.start())
    }

    @Test
    fun cancellationBeforeStartPermanentlyPreventsOperation() {
        val gate = OneUseOperationGate()

        assertTrue(gate.cancel())
        assertFalse(gate.start())
        assertFalse(gate.finish())
    }

    @Test
    fun exactlyOneConcurrentTerminalPathWins() {
        repeat(100) {
            val gate = OneUseOperationGate()
            assertTrue(gate.start())
            val ready = CountDownLatch(2)
            val release = CountDownLatch(1)
            val winners = AtomicInteger()
            val executor = Executors.newFixedThreadPool(2)
            val finish = executor.submit {
                ready.countDown()
                release.await()
                if (gate.finish()) winners.incrementAndGet()
            }
            val cancel = executor.submit {
                ready.countDown()
                release.await()
                if (gate.cancel()) winners.incrementAndGet()
            }

            assertTrue(ready.await(2, TimeUnit.SECONDS))
            release.countDown()
            finish.get(2, TimeUnit.SECONDS)
            cancel.get(2, TimeUnit.SECONDS)
            executor.shutdownNow()

            assertEquals(1, winners.get())
            assertFalse(gate.finish())
            assertFalse(gate.cancel())
        }
    }

    @Test
    fun deadlineUsesExclusiveExpiryBoundary() {
        val deadline = SigningDeadline(200)

        assertFalse(deadline.isExpired(199))
        assertTrue(deadline.isExpired(200))
        assertTrue(deadline.isExpired(201))
    }
}
