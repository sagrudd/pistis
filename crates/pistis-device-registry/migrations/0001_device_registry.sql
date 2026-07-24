CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;

CREATE TABLE devices (
    device_id BLOB PRIMARY KEY CHECK (length(device_id) = 16),
    installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),
    user_id BLOB NOT NULL CHECK (length(user_id) = 16),
    external_identity_id BLOB NOT NULL CHECK (length(external_identity_id) = 16),
    platform TEXT NOT NULL
        CHECK (platform IN ('ios', 'android')),
    app_version TEXT NOT NULL CHECK (
        length(app_version) BETWEEN 1 AND 128
    ),
    status TEXT NOT NULL CHECK (
        status IN ('active', 'suspended', 'revoked')
    ),
    enrolled_at_ms INTEGER NOT NULL CHECK (enrolled_at_ms >= 0),
    last_used_at_ms INTEGER CHECK (
        last_used_at_ms IS NULL OR last_used_at_ms >= enrolled_at_ms
    ),
    suspended_at_ms INTEGER CHECK (
        suspended_at_ms IS NULL OR suspended_at_ms >= enrolled_at_ms
    ),
    suspension_reason TEXT CHECK (
        suspension_reason IS NULL OR length(suspension_reason) BETWEEN 1 AND 512
    ),
    revoked_at_ms INTEGER CHECK (
        revoked_at_ms IS NULL OR revoked_at_ms >= enrolled_at_ms
    ),
    revocation_reason TEXT CHECK (
        revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 512
    ),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    enrolment_evidence_id BLOB NOT NULL CHECK (length(enrolment_evidence_id) = 16),
    CHECK (
        (status = 'active'
            AND suspended_at_ms IS NULL
            AND suspension_reason IS NULL
            AND revoked_at_ms IS NULL
            AND revocation_reason IS NULL)
        OR
        (status = 'suspended'
            AND suspended_at_ms IS NOT NULL
            AND suspension_reason IS NOT NULL
            AND revoked_at_ms IS NULL
            AND revocation_reason IS NULL)
        OR
        (status = 'revoked'
            AND revoked_at_ms IS NOT NULL
            AND revocation_reason IS NOT NULL
            AND (
                (suspended_at_ms IS NULL AND suspension_reason IS NULL)
                OR
                (suspended_at_ms IS NOT NULL AND suspension_reason IS NOT NULL)
            ))
    ),
    UNIQUE (device_id, installation_id)
) STRICT;

CREATE INDEX devices_by_user_and_status
    ON devices (installation_id, user_id, status);
CREATE INDEX devices_by_external_identity
    ON devices (installation_id, external_identity_id);

CREATE TABLE device_keys (
    device_id BLOB PRIMARY KEY CHECK (length(device_id) = 16),
    installation_id BLOB NOT NULL CHECK (length(installation_id) = 16),
    key_id BLOB NOT NULL CHECK (length(key_id) = 32),
    algorithm TEXT NOT NULL CHECK (algorithm = 'ES256'),
    public_key BLOB NOT NULL CHECK (
        length(public_key) = 33
        AND (substr(public_key, 1, 1) = x'02'
            OR substr(public_key, 1, 1) = x'03')
    ),
    registered_at_ms INTEGER NOT NULL CHECK (registered_at_ms >= 0),
    FOREIGN KEY (device_id, installation_id)
        REFERENCES devices(device_id, installation_id) ON DELETE RESTRICT,
    UNIQUE (installation_id, key_id)
) STRICT;

CREATE TABLE device_assurance (
    device_id BLOB PRIMARY KEY
        REFERENCES devices(device_id) ON DELETE RESTRICT,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    app_generated_key INTEGER NOT NULL CHECK (app_generated_key IN (0, 1)),
    hardware_backing TEXT NOT NULL CHECK (
        hardware_backing IN ('verified', 'reported', 'unavailable', 'unknown')
    ),
    user_verification TEXT NOT NULL CHECK (
        user_verification IN ('required', 'not_required', 'unknown')
    ),
    attestation TEXT NOT NULL CHECK (
        attestation IN (
            'verified', 'unavailable', 'not_requested'
        )
    ),
    integrity TEXT NOT NULL CHECK (
        integrity IN (
            'verified', 'unavailable', 'not_requested'
        )
    ),
    evidence_version TEXT NOT NULL CHECK (
        length(evidence_version) BETWEEN 1 AND 128
    ),
    verifier_version TEXT NOT NULL CHECK (
        length(verifier_version) BETWEEN 1 AND 128
    ),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT;

CREATE TABLE device_lifecycle_events (
    device_id BLOB NOT NULL
        REFERENCES devices(device_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    from_status TEXT NOT NULL CHECK (
        from_status IN ('active', 'suspended')
    ),
    to_status TEXT NOT NULL CHECK (
        to_status IN ('active', 'suspended', 'revoked')
    ),
    effective_at_ms INTEGER NOT NULL CHECK (effective_at_ms >= 0),
    reason TEXT CHECK (
        reason IS NULL OR length(reason) BETWEEN 1 AND 512
    ),
    CHECK (
        (from_status = 'suspended' AND to_status = 'active' AND reason IS NULL)
        OR
        (from_status <> to_status AND to_status IN ('suspended', 'revoked')
            AND reason IS NOT NULL)
    ),
    UNIQUE (device_id, sequence)
) STRICT;

CREATE INDEX lifecycle_events_by_device
    ON device_lifecycle_events (device_id, sequence);
