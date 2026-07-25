# pistis-synoptikon

`pistis-synoptikon` is the framework-neutral integration contract accepted in
ADR 0009. It lets a host represent production-readiness evidence, resolve the
complete current authentication binding, reject stale policy or revocation
views, and request issuance from the host's existing session authority.

The crate contains no HTTP framework, database adapter, cookie, raw session
token, central-auditor implementation, or signature format. In particular, it
does not turn the detached EPIC-6 reference envelope into a production COSE
profile. Unknown or missing readiness evidence and incomplete binding state
fail closed.
