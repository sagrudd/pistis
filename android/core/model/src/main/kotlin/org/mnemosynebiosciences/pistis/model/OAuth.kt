package org.mnemosynebiosciences.pistis.model

import java.net.URI

/** Browser callback contract for an RFC 8252 external-user-agent ceremony. */
public data class OAuthCallbackPolicy(
    public val scheme: String,
    public val host: String,
    public val path: String,
) {
    init {
        require(scheme == "https") { "only verified HTTPS callbacks are accepted" }
        require(host.isNotBlank() && !host.contains('@')) { "invalid callback host" }
        require(path.startsWith("/") && !path.contains("..")) { "invalid callback path" }
    }

    /** Validates exact origin/path and returns a bounded code only when state matches. */
    public fun accept(callback: URI, expectedState: String): OAuthCallback {
        require(
            callback.scheme == scheme &&
                callback.host == host &&
                callback.port == -1 &&
                callback.path == path,
        ) {
            "callback target mismatch"
        }
        require(callback.rawFragment == null && callback.userInfo == null) {
            "callback contains prohibited URI components"
        }
        val query = callback.rawQuery.orEmpty().split("&")
            .filter { it.isNotEmpty() }
            .map {
                val pieces = it.split("=", limit = 2)
                require(pieces.size == 2) { "malformed callback query" }
                pieces[0] to pieces[1]
            }
        require(query.map { it.first }.distinct().size == query.size) {
            "duplicate callback field"
        }
        val values = query.toMap()
        require(values.keys == setOf("code", "state")) { "unexpected callback fields" }
        val code = values.getValue("code")
        val state = values.getValue("state")
        require(state == expectedState) { "OAuth state mismatch" }
        require(code.length in 16..2048 && state.length in 16..256) {
            "callback value outside bounds"
        }
        return OAuthCallback(code)
    }
}

/** A short-lived authorization code, never a provider token. */
@JvmInline
public value class OAuthCallback internal constructor(public val authorizationCode: String)
