package org.mnemosynebiosciences.pistis.model

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class OAuthCallbackPolicyTest {
    private val policy = OAuthCallbackPolicy(
        scheme = "https",
        host = "broker.pistis.example",
        path = "/oauth/callback",
    )
    private val state = "fixed-test-state-01"

    @Test
    fun `exact callback and state yield authorization code only`() {
        val callback = URI(
            "https://broker.pistis.example/oauth/callback" +
                "?code=fixed-authorization-code&state=$state",
        )
        assertEquals("fixed-authorization-code", policy.accept(callback, state).authorizationCode)
    }

    @Test
    fun `callback rejects substitution duplicate and unexpected fields`() {
        assertFailsWith<IllegalArgumentException> {
            policy.accept(
                URI("https://attacker.example/oauth/callback?code=fixed-authorization-code&state=$state"),
                state,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            policy.accept(
                URI(
                    "https://broker.pistis.example/oauth/callback" +
                        "?code=fixed-authorization-code&state=$state&state=$state",
                ),
                state,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            policy.accept(
                URI(
                    "https://broker.pistis.example/oauth/callback" +
                        "?code=fixed-authorization-code&state=$state&token=secret",
                ),
                state,
            )
        }
    }

    @Test
    fun `callback rejects state mismatch and custom schemes`() {
        assertFailsWith<IllegalArgumentException> {
            policy.accept(
                URI(
                    "https://broker.pistis.example/oauth/callback" +
                        "?code=fixed-authorization-code&state=$state",
                ),
                "different-state-01",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            OAuthCallbackPolicy("pistis", "oauth", "/callback")
        }
    }

    @Test
    fun `callback rejects alternate and explicitly supplied ports`() {
        listOf(443, 444).forEach { port ->
            assertFailsWith<IllegalArgumentException> {
                policy.accept(
                    URI(
                        "https://broker.pistis.example:$port/oauth/callback" +
                            "?code=fixed-authorization-code&state=$state",
                    ),
                    state,
                )
            }
        }
    }
}
