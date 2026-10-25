-- PROPOSED ONLY: ADR 0046 must be accepted before product implementation.
-- SQL integrity guards do not establish authority, typed cancellation or durability.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = FULL;
PRAGMA page_size = 4096;
PRAGMA max_page_count = 16384;
PRAGMA user_version = 1;

CREATE TABLE meta (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  schema_version INTEGER NOT NULL CHECK(schema_version = 1),
  schema_sha256 BLOB NOT NULL CHECK(typeof(schema_sha256)='blob' AND length(schema_sha256)=32),
  site BLOB NOT NULL CHECK(typeof(site)='blob' AND length(site)=16),
  device_key_id BLOB NOT NULL CHECK(typeof(device_key_id)='blob' AND length(device_key_id)=32),
  device_generation BLOB NOT NULL CHECK(typeof(device_generation)='blob' AND length(device_generation)=8 AND device_generation>x'0000000000000000')
);
CREATE TABLE attempts (
  operation_uuid BLOB PRIMARY KEY NOT NULL CHECK(typeof(operation_uuid)='blob' AND length(operation_uuid)=16),
  attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('PCAP','PCUR','CPEI_AUTHN','CPEI_ACK','CPEC_AUTHN','PCPG_ACK')),
  bootstrap BLOB CHECK(bootstrap IS NULL OR (typeof(bootstrap)='blob' AND length(bootstrap)=16)),
  challenge BLOB NOT NULL CHECK(typeof(challenge)='blob' AND length(challenge)=32),
  canonical_body BLOB NOT NULL CHECK(typeof(canonical_body)='blob' AND length(canonical_body) BETWEEN 1 AND 8192),
  body_sha256 BLOB NOT NULL CHECK(typeof(body_sha256)='blob' AND length(body_sha256)=32),
  state TEXT NOT NULL CHECK(state IN ('prepared-no-key-invocation','dispatch-fenced','signed-retained','terminal-proven-unsigned','unresolved')),
  permission_revision BLOB CHECK(permission_revision IS NULL OR (typeof(permission_revision)='blob' AND length(permission_revision)=8)),
  delegation_serial TEXT CHECK(delegation_serial IS NULL OR (typeof(delegation_serial)='text' AND length(CAST(delegation_serial AS BLOB)) BETWEEN 1 AND 128 AND instr(delegation_serial,char(0))=0 AND delegation_serial NOT GLOB '*[^A-Za-z0-9._:-]*')),
  captured_revocation BLOB CHECK(captured_revocation IS NULL OR (typeof(captured_revocation)='blob' AND length(captured_revocation)=8)),
  issued_at BLOB NOT NULL CHECK(typeof(issued_at)='blob' AND length(issued_at)=8),
  expires_at BLOB NOT NULL CHECK(typeof(expires_at)='blob' AND length(expires_at)=8 AND expires_at>issued_at),
  exact_result BLOB CHECK(exact_result IS NULL OR (typeof(exact_result)='blob' AND length(exact_result) BETWEEN 1 AND 262144)),
  CHECK((attempt_kind IN ('PCAP','PCUR') AND bootstrap IS NOT NULL AND
         permission_revision IS NOT NULL AND delegation_serial IS NOT NULL AND captured_revocation IS NOT NULL) OR
        (attempt_kind IN ('CPEI_AUTHN','CPEI_ACK','CPEC_AUTHN','PCPG_ACK') AND bootstrap IS NULL AND
         permission_revision IS NULL AND delegation_serial IS NULL AND captured_revocation IS NULL)),
  UNIQUE(challenge,attempt_kind),
  CHECK((state='signed-retained' AND exact_result IS NOT NULL) OR (state<>'signed-retained' AND exact_result IS NULL))
) WITHOUT ROWID;
CREATE UNIQUE INDEX legacy_challenge_identity ON attempts(challenge)
  WHERE attempt_kind IN ('PCAP','PCUR');
CREATE TABLE history (
  operation_uuid BLOB NOT NULL REFERENCES attempts(operation_uuid) ON DELETE RESTRICT,
  sequence BLOB NOT NULL CHECK(typeof(sequence)='blob' AND length(sequence)=8 AND sequence>x'0000000000000000'),
  prior_state TEXT NOT NULL CHECK(prior_state IN ('prepared-no-key-invocation','dispatch-fenced','unresolved')),
  next_state TEXT NOT NULL CHECK(next_state IN ('dispatch-fenced','signed-retained','terminal-proven-unsigned','unresolved')),
  exact_result_digest BLOB CHECK(exact_result_digest IS NULL OR (typeof(exact_result_digest)='blob' AND length(exact_result_digest)=32)),
  PRIMARY KEY(operation_uuid,sequence),
  CHECK((next_state='signed-retained' AND exact_result_digest IS NOT NULL) OR (next_state<>'signed-retained' AND exact_result_digest IS NULL))
) WITHOUT ROWID;
CREATE TRIGGER meta_insert_guard BEFORE INSERT ON meta BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM meta WHERE singleton=NEW.singleton) THEN RAISE(ABORT,'duplicate meta identity') END;
END;
CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT,'immutable meta'); END;
CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT,'retained meta'); END;
CREATE TRIGGER attempt_insert_guard BEFORE INSERT ON attempts BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM attempts WHERE operation_uuid=NEW.operation_uuid OR (challenge=NEW.challenge AND
    NOT (((attempt_kind='CPEI_AUTHN' AND NEW.attempt_kind='CPEI_ACK') OR
          (attempt_kind='CPEI_ACK' AND NEW.attempt_kind='CPEI_AUTHN')) AND
         canonical_body=NEW.canonical_body AND body_sha256=NEW.body_sha256))) THEN RAISE(ABORT,'duplicate attempt identity') END;
  SELECT CASE WHEN (SELECT count(*) FROM attempts)>=512 THEN RAISE(ABORT,'attempt quota') END;
  SELECT CASE WHEN NEW.state<>'prepared-no-key-invocation' OR NEW.exact_result IS NOT NULL THEN RAISE(ABORT,'initial state') END;
END;
CREATE TRIGGER attempt_no_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'retained attempt'); END;
CREATE TRIGGER attempt_update_guard BEFORE UPDATE ON attempts BEGIN
  SELECT CASE WHEN NEW.operation_uuid IS NOT OLD.operation_uuid OR NEW.attempt_kind IS NOT OLD.attempt_kind OR NEW.bootstrap IS NOT OLD.bootstrap OR NEW.challenge IS NOT OLD.challenge OR NEW.canonical_body IS NOT OLD.canonical_body OR NEW.body_sha256 IS NOT OLD.body_sha256 OR NEW.permission_revision IS NOT OLD.permission_revision OR NEW.delegation_serial IS NOT OLD.delegation_serial OR NEW.captured_revocation IS NOT OLD.captured_revocation OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at THEN RAISE(ABORT,'immutable attempt') END;
  SELECT CASE WHEN NOT ((OLD.state='prepared-no-key-invocation' AND NEW.state IN ('dispatch-fenced','terminal-proven-unsigned')) OR (OLD.state='dispatch-fenced' AND NEW.state IN ('signed-retained','terminal-proven-unsigned','unresolved')) OR (OLD.state='unresolved' AND NEW.state IN ('signed-retained','terminal-proven-unsigned'))) THEN RAISE(ABORT,'invalid transition') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM history WHERE operation_uuid=OLD.operation_uuid AND sequence=(SELECT max(sequence) FROM history WHERE operation_uuid=OLD.operation_uuid) AND prior_state=OLD.state AND next_state=NEW.state) THEN RAISE(ABORT,'missing transition history') END;
END;
CREATE TRIGGER history_insert_guard BEFORE INSERT ON history BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM history WHERE operation_uuid=NEW.operation_uuid AND sequence=NEW.sequence) THEN RAISE(ABORT,'duplicate history identity') END;
  SELECT CASE WHEN (SELECT count(*) FROM history)>=1536 THEN RAISE(ABORT,'history quota') END;
  SELECT CASE WHEN (SELECT count(*) FROM history WHERE operation_uuid=NEW.operation_uuid)>=3 THEN RAISE(ABORT,'attempt history bound') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM attempts WHERE operation_uuid=NEW.operation_uuid AND state=NEW.prior_state) THEN RAISE(ABORT,'history predecessor') END;
  SELECT CASE WHEN NOT ((NEW.prior_state='prepared-no-key-invocation' AND NEW.next_state IN ('dispatch-fenced','terminal-proven-unsigned')) OR (NEW.prior_state='dispatch-fenced' AND NEW.next_state IN ('signed-retained','terminal-proven-unsigned','unresolved')) OR (NEW.prior_state='unresolved' AND NEW.next_state IN ('signed-retained','terminal-proven-unsigned'))) THEN RAISE(ABORT,'history transition') END;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM history WHERE operation_uuid=NEW.operation_uuid AND sequence>=NEW.sequence) THEN RAISE(ABORT,'history order') END;
END;
CREATE TRIGGER history_no_update BEFORE UPDATE ON history BEGIN SELECT RAISE(ABORT,'immutable history'); END;
CREATE TRIGGER history_no_delete BEFORE DELETE ON history BEGIN SELECT RAISE(ABORT,'retained history'); END;
