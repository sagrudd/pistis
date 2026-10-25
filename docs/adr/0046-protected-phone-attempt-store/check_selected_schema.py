"""Structural SQL checks only; no native typed proof, authority or durability claim."""
import hashlib
import json
from pathlib import Path
import sqlite3

SCHEMA = Path(__file__).with_name("selected-schema-v1.sql").read_text()
U64 = lambda value: value.to_bytes(8, "big")
OP = b"o" * 16
BODY = b"reference body; no authority"
ROW = (OP, b"b" * 16, b"c" * 32, BODY, hashlib.sha256(BODY).digest(),
       "prepared-no-key-invocation", U64(1), "reference-serial", U64(1),
       U64(100), U64(200), None)
RESULTS = []


def database():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA recursive_triggers=0")
    conn.execute("INSERT INTO meta VALUES(1,1,?,?,?,?)",
                 (b"s" * 32, b"i" * 16, b"k" * 32, U64(1)))
    conn.execute("INSERT INTO attempts VALUES(" + ",".join("?" * 12) + ")", ROW)
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
    ("operation", "INSERT OR REPLACE INTO attempts VALUES(" + ",".join("?" * 12) + ")", ROW),
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
     "INSERT OR REPLACE INTO attempts VALUES(" + ",".join("?" * 12) + ")", ROW)
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
print(json.dumps({"status": "PASS_STRUCTURAL_PROPOSAL_ONLY", "sqlite": sqlite3.sqlite_version,
                  "schema_sha256": hashlib.sha256(SCHEMA.encode()).hexdigest(),
                  "checks": RESULTS, "native_typed_cancellation": "UNIMPLEMENTED_UNQUALIFIED",
                  "phone_provisioning_signing_or_authority": False}, indent=2))
