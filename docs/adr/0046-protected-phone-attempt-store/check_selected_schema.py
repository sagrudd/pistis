"""Structural SQL checks only; no native typed proof, authority or durability claim."""
import hashlib
import json
from pathlib import Path
import sqlite3

SCHEMA = Path(__file__).with_name("selected-schema-v1.sql").read_text()
U64 = lambda value: value.to_bytes(8, "big")
OP = b"o" * 16
BODY = b"reference body; no authority"
ROW = (OP, "PCAP", b"b" * 16, b"c" * 32, BODY, hashlib.sha256(BODY).digest(),
       "prepared-no-key-invocation", U64(1), "reference-serial", U64(1),
       U64(100), U64(200), None)
RESULTS = []


def database():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA recursive_triggers=0")
    conn.execute("INSERT INTO meta VALUES(1,1,?,?,?,?)",
                 (b"s" * 32, b"i" * 16, b"k" * 32, U64(1)))
    conn.execute("INSERT INTO attempts VALUES(" + ",".join("?" * len(ROW)) + ")", ROW)
    return conn


def snapshot(conn):
    return [conn.execute("SELECT * FROM " + table).fetchall()
            for table in ("meta", "attempts", "history")]


def deny(conn, name, sql, args=()):
    before = snapshot(conn)
    try:
        conn.execute(sql, args)
    except sqlite3.IntegrityError:
        assert snapshot(conn) == before, name + " changed retained state"
    else:
        raise AssertionError(name + " accepted")
    RESULTS.append(name)


def transition(conn, prior, after, sequence, result=None):
    digest = hashlib.sha256(result).digest() if result is not None else None
    conn.execute("INSERT INTO history VALUES(?,?,?,?,?)",
                 (OP, U64(sequence), prior, after, digest))
    changed = conn.execute("UPDATE attempts SET state=?,exact_result=? "
                           "WHERE operation_uuid=? AND state=?",
                           (after, result, OP, prior)).rowcount
    assert changed == 1


# Derive the complete fixed PCUR26 bound; this is not a valid authority proof.
def cbor_bytes(value):
    n = len(value)
    assert n < 256
    return (bytes([0x40 + n]) if n < 24 else bytes([0x58, n])) + value

hash32 = cbor_bytes(b"h" * 32)
uuid16 = cbor_bytes(b"u" * 16)
u64max = bytes([0x1b]) + b"\xff" * 8
fields = [cbor_bytes(b"PCUR/1"), hash32, hash32, hash32, hash32, uuid16,
          hash32, u64max, uuid16, u64max, uuid16,
          cbor_bytes(b"current-assertion"), uuid16, hash32, hash32, hash32,
          hash32, u64max, cbor_bytes(b"p" * 33), uuid16, hash32, hash32,
          u64max, hash32, u64max, u64max]
assert len(fields) == 26
assert len(bytes([0x98, 26]) + b"".join(fields)) == 609
RESULTS.append("maximum fixed PCUR26 structural payload is609bytes within8192bodybound")

conn = database()
for target, sql, values in [
    ("metadata", "INSERT OR REPLACE INTO meta VALUES(1,1,?,?,?,?)",
     (b"s" * 32, b"x" * 16, b"k" * 32, U64(1))),
    ("operation", "INSERT OR REPLACE INTO attempts VALUES(" + ",".join("?" * len(ROW)) + ")", ROW),
]:
    deny(conn, "replacement rejects duplicate " + target, sql, values)

# A fault after history insertion cannot leave a false cancellation history row.
before = snapshot(conn)
conn.execute("BEGIN IMMEDIATE")
conn.execute("INSERT INTO history VALUES(?,?,?,?,?)",
             (OP, U64(1), "prepared-no-key-invocation", "terminal-proven-unsigned", None))
conn.execute("ROLLBACK")
assert snapshot(conn) == before
RESULTS.append("cancellation transaction rollback preserves prepared state and history")

conn.execute("BEGIN IMMEDIATE")
transition(conn, "prepared-no-key-invocation", "terminal-proven-unsigned", 1)
conn.execute("COMMIT")
assert conn.execute("SELECT state,exact_result FROM attempts").fetchone() == ("terminal-proven-unsigned", None)
assert conn.execute("SELECT prior_state,next_state FROM history").fetchall() == [("prepared-no-key-invocation", "terminal-proven-unsigned")]
RESULTS.append("prepared cancellation reaches retained terminal directly without synthetic fence")
deny(conn, "terminal row cannot be replaced and re-prepared",
     "INSERT OR REPLACE INTO attempts VALUES(" + ",".join("?" * len(ROW)) + ")", ROW)
deny(conn, "terminal row cannot be deleted", "DELETE FROM attempts")
deny(conn, "terminal state cannot resume", "UPDATE attempts SET state='prepared-no-key-invocation'")
deny(conn, "retained cancellation history cannot be replaced",
     "INSERT OR REPLACE INTO history VALUES(?,?,?,?,?)",
     (OP, U64(1), "prepared-no-key-invocation", "dispatch-fenced", None))

# If fence wins, the literal prepared-cancellation history edge is unavailable.
conn = database()
conn.execute("BEGIN IMMEDIATE")
transition(conn, "prepared-no-key-invocation", "dispatch-fenced", 1)
conn.execute("COMMIT")
deny(conn, "fence winner rejects stale prepared cancellation history",
     "INSERT INTO history VALUES(?,?,?,?,?)",
     (OP, U64(2), "prepared-no-key-invocation", "terminal-proven-unsigned", None))
deny(conn, "fenced attempt cannot return to prepared", "UPDATE attempts SET state='prepared-no-key-invocation'")
RESULTS.append("no result remains fenced; SQL does not establish never-invoked evidence")
conn.execute("BEGIN IMMEDIATE")
transition(conn, "dispatch-fenced", "unresolved", 2)
conn.execute("COMMIT")
deny(conn, "unresolved attempt cannot return to prepared", "UPDATE attempts SET state='prepared-no-key-invocation'")
conn.execute("BEGIN IMMEDIATE")
transition(conn, "unresolved", "signed-retained", 3, b"reference exact submission")
conn.execute("COMMIT")
before = snapshot(conn)
assert conn.execute("SELECT exact_result FROM attempts WHERE operation_uuid=?", (OP,)).fetchone()[0] == b"reference exact submission"
assert snapshot(conn) == before
RESULTS.append("settled exact result retrieval is read-only")
deny(conn, "settled result cannot be overwritten", "UPDATE attempts SET exact_result=?", (b"changed",))
# Changed consumer: two distinct named attempts bind one exact CPEI control.
# This projection is an executable contract reference, NOT a native proof factory.
def insert_typed(conn, operation, kind, challenge=b"n" * 32, body=b"same CPEI control7"):
    values = list(ROW)
    values[0:6] = [operation, kind, b"b" * 16, challenge, body, hashlib.sha256(body).digest()]
    if kind not in ("PCAP", "PCUR"):
        for index in (2, 7, 8, 9):
            values[index] = None
    conn.execute("INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)


def fresh_typed_database():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA recursive_triggers=0")
    return conn


def retained_for_reference(conn, operation):
    conn.execute("BEGIN IMMEDIATE")
    for sequence, prior, after, result in [
        (1, "prepared-no-key-invocation", "dispatch-fenced", None),
        (2, "dispatch-fenced", "signed-retained", b"reference complete verified result"),
    ]:
        digest = hashlib.sha256(result).digest() if result else None
        conn.execute("INSERT INTO history VALUES(?,?,?,?,?)", (operation, U64(sequence), prior, after, digest))
        assert conn.execute("UPDATE attempts SET state=?,exact_result=? WHERE operation_uuid=? AND state=?",
                            (after, result, operation, prior)).rowcount == 1
    conn.execute("COMMIT")


def reference_pair_check(conn, authn_id, ack_id):
    # Native implementation MUST additionally require originating private handles,
    # genuine proof verification/currentness and controller-held exclusion.
    if authn_id == ack_id:
        return False
    authn = conn.execute("SELECT attempt_kind,challenge,canonical_body,state FROM attempts WHERE operation_uuid=?", (authn_id,)).fetchone()
    ack = conn.execute("SELECT attempt_kind,challenge,canonical_body,state FROM attempts WHERE operation_uuid=?", (ack_id,)).fetchone()
    return (authn is not None and ack is not None and authn[0] == "CPEI_AUTHN"
            and ack[0] == "CPEI_ACK" and authn[1:3] == ack[1:3]
            and authn[3] == "signed-retained" and ack[3] == "prepared-no-key-invocation")


conn = fresh_typed_database()
authn_id, ack_id = b"a" * 16, b"z" * 16
insert_typed(conn, authn_id, "CPEI_AUTHN")
insert_typed(conn, ack_id, "CPEI_ACK")
RESULTS.append("distinct CPEI typed attempts can retain same exact control nonce")
assert not reference_pair_check(conn, authn_id, ack_id)
RESULTS.append("ACK ordering denies prepared AUTHN predecessor")
conn.execute("BEGIN IMMEDIATE")
conn.execute("INSERT INTO history VALUES(?,?,?,?,?)", (authn_id, U64(1), "prepared-no-key-invocation", "dispatch-fenced", None))
assert conn.execute("UPDATE attempts SET state='dispatch-fenced' WHERE operation_uuid=?", (authn_id,)).rowcount == 1
conn.execute("COMMIT")
assert not reference_pair_check(conn, authn_id, ack_id)
RESULTS.append("ACK ordering denies fenced AUTHN missing retained result")
conn.execute("BEGIN IMMEDIATE")
result = b"reference AUTHN challenge and response"
conn.execute("INSERT INTO history VALUES(?,?,?,?,?)", (authn_id, U64(2), "dispatch-fenced", "signed-retained", hashlib.sha256(result).digest()))
conn.execute("UPDATE attempts SET state='signed-retained',exact_result=? WHERE operation_uuid=?", (result, authn_id))
conn.execute("COMMIT")
assert reference_pair_check(conn, authn_id, ack_id)
assert not reference_pair_check(conn, ack_id, authn_id)
assert not reference_pair_check(conn, authn_id, authn_id)
RESULTS.append("ACK ordering requires named distinct retained AUTHN same-body predecessor")

# Kind is immutable, and globally unique operation IDs cannot be recycled by type.
deny(conn, "attempt kind cannot change to manufacture another operation",
     "UPDATE attempts SET attempt_kind='PCPG_ACK' WHERE operation_uuid=?", (authn_id,))
values = list(ROW)
values[0:6] = [authn_id, "CPEC_AUTHN", None, b"x" * 32, b"other", hashlib.sha256(b"other").digest()]
for index in (7, 8, 9):
    values[index] = None
deny(conn, "another kind cannot reuse operation UUID", "INSERT OR REPLACE INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)
values[0] = b"q" * 16
values[1] = "UNREVIEWED_KIND"
deny(conn, "unreviewed kind rejected", "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)

for kind in ("CPEC_AUTHN", "PCPG_ACK"):
    other = fresh_typed_database()
    insert_typed(other, authn_id, kind)
    insert_typed(other, ack_id, "CPEI_ACK", challenge=b"x" * 32)
    retained_for_reference(other, authn_id)
    assert not reference_pair_check(other, authn_id, ack_id)
    RESULTS.append("ACK ordering denies wrong predecessor kind " + kind)
for changed in ("nonce",):
    other = fresh_typed_database()
    insert_typed(other, authn_id, "CPEI_AUTHN")
    insert_typed(other, ack_id, "CPEI_ACK", challenge=b"x" * 32 if changed == "nonce" else b"n" * 32,
                 body=b"changed control" if changed == "body" else b"same CPEI control7")
    retained_for_reference(other, authn_id)
    assert not reference_pair_check(other, authn_id, ack_id)
    RESULTS.append("ACK ordering denies changed " + changed)
for first, second in (("CPEI_AUTHN", "CPEC_AUTHN"), ("PCPG_ACK", "CPEI_ACK"),
                      ("PCAP", "CPEI_AUTHN"), ("PCUR", "PCPG_ACK")):
    other = fresh_typed_database()
    insert_typed(other, authn_id, first)
    values = list(ROW)
    values[0:6] = [ack_id, second, None, b"n" * 32, b"same CPEI control7", hashlib.sha256(b"same CPEI control7").digest()]
    for index in (7, 8, 9):
        values[index] = None
    deny(other, "unrelated cross-kind nonce collision denied " + first + " to " + second,
         "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)
other = fresh_typed_database()
insert_typed(other, authn_id, "CPEI_AUTHN")
values = list(ROW)
values[0:6] = [ack_id, "CPEI_ACK", None, b"n" * 32, b"changed control", hashlib.sha256(b"changed control").digest()]
for index in (7, 8, 9):
    values[index] = None
deny(other, "CPEI shared nonce with changed control denied",
     "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)
other = fresh_typed_database()
insert_typed(other, authn_id, "PCAP")
values = list(ROW)
values[0:6] = [ack_id, "PCUR", b"b" * 16, b"n" * 32, BODY, hashlib.sha256(BODY).digest()]
deny(other, "legacy PCAP PCUR cross-kind challenge uniqueness preserved",
     "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)

for kind in ("PCAP", "PCUR"):
    for index in (2, 7, 8, 9):
        other = fresh_typed_database()
        values = list(ROW)
        values[1] = kind
        values[index] = None
        deny(other, "legacy " + kind + " missing required authority slot " + str(index),
             "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)
for kind in ("CPEI_AUTHN", "CPEI_ACK", "CPEC_AUTHN", "PCPG_ACK"):
    other = fresh_typed_database()
    values = list(ROW)
    values[1] = kind
    deny(other, "new consent kind cannot relabel legacy authority slots " + kind,
         "INSERT INTO attempts VALUES(" + ",".join("?" * len(values)) + ")", values)
    insert_typed(other, authn_id, kind)
    assert other.execute("SELECT bootstrap,permission_revision,delegation_serial,captured_revocation FROM attempts").fetchone() == (None, None, None, None)
    RESULTS.append("new consent " + kind + " has explicit absence of legacy authority slots")
print(json.dumps({"status": "PASS_STRUCTURAL_PROPOSAL_ONLY", "sqlite": sqlite3.sqlite_version,
                  "schema_sha256": hashlib.sha256(SCHEMA.encode()).hexdigest(),
                  "checks": RESULTS, "native_typed_cancellation": "UNIMPLEMENTED_UNQUALIFIED",
                  "phone_provisioning_signing_or_authority": False}, indent=2))
