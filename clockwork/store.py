"""Store: PostgreSQL access, append-only event log, content-addressed artifacts.

Design invariants enforced here (not merely documented):

* every mutation is an appended ``case_event``;
* ``seq`` is per-case monotonic and gap-free;
* ``event_hash`` chains to the previous event, so rewriting history is
  detectable by ``verify_chain``;
* the DB itself refuses UPDATE/DELETE/TRUNCATE on ``cw.case_event``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get(
    "CLOCKWORK_DSN",
    "postgresql://clockwork:clockwork@localhost:55432/clockwork",
)
ROOT = Path(__file__).resolve().parent.parent
SQL_DIR = ROOT / "clockwork" / "sql"
def artifact_root() -> Path:
    """Resolved per call so tests (and multi-tenant runs) can redirect storage."""
    return Path(os.environ.get("CLOCKWORK_ARTIFACTS", ROOT / "var" / "artifacts"))


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def event_hash(prev_hash: str | None, payload: dict, actor: str, seq: int,
               event_type: str, case_id: str) -> str:
    body = canonical_json({
        "prev": prev_hash, "actor": actor, "seq": seq,
        "type": event_type, "case": case_id, "payload": payload,
    })
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


class Store:
    def __init__(self, dsn: str | None = None):
        self.dsn = dsn or DSN
        self._conn: psycopg.Connection | None = None

    # ------------------------------------------------------------------ conn
    @property
    def conn(self) -> psycopg.Connection:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(self.dsn, row_factory=dict_row,
                                         autocommit=False)
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()

    def init(self) -> None:
        for path in sorted(SQL_DIR.glob("*.sql")):
            sql = path.read_text()
            with self.conn.cursor() as cur:
                cur.execute(sql)
            self.conn.commit()
        artifact_root().mkdir(parents=True, exist_ok=True)

    def q(self, sql: str, params: Iterable | dict = (),
          lock_caps: bool = True) -> list[dict]:
        try:
            with self.conn.cursor() as cur:
                if not lock_caps:
                    # explicit, audited override used by schema evolution and
                    # record correction; never reachable from an agent request
                    cur.execute("SET LOCAL clockwork.lock_capabilities = 'off'")
                cur.execute(sql, params)
                rows = cur.fetchall() if cur.description is not None else []
            self.conn.commit()
            return rows
        except Exception:
            # a failed statement must never poison the connection for the
            # next authoritative read
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise

    def q1(self, sql: str, params: Iterable | dict = ()) -> dict | None:
        rows = self.q(sql, params)
        return rows[0] if rows else None

    # ---------------------------------------------------------------- events
    def append(self, case_id: str, event_type: str, actor: str, payload: dict,
               orbit: str = "system") -> dict:
        """Append one canonical event and return the stored row."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT seq, event_hash FROM cw.case_event "
                "WHERE case_id=%s ORDER BY seq DESC LIMIT 1",
                (case_id,),
            )
            last = cur.fetchone()
            seq = (last["seq"] + 1) if last else 1
            prev = last["event_hash"] if last else None
            digest = event_hash(prev, payload, actor, seq, event_type, case_id)
            cur.execute(
                """INSERT INTO cw.case_event
                   (case_id, seq, event_type, actor_id, orbit, payload,
                    event_hash, prev_hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   RETURNING *""",
                (case_id, seq, event_type, actor, orbit,
                 psycopg.types.json.Jsonb(payload), digest, prev),
            )
            row = cur.fetchone()
        self.conn.commit()
        return row

    def events(self, case_id: str, upto_seq: int | None = None) -> list[dict]:
        if upto_seq is None:
            return self.q(
                "SELECT * FROM cw.case_event WHERE case_id=%s ORDER BY seq",
                (case_id,))
        return self.q(
            "SELECT * FROM cw.case_event WHERE case_id=%s AND seq<=%s ORDER BY seq",
            (case_id, upto_seq))

    def verify_chain(self, case_id: str) -> tuple[bool, str]:
        prev = None
        expected_seq = 1
        for ev in self.events(case_id):
            if ev["seq"] != expected_seq:
                return False, f"sequence gap at {ev['seq']}"
            expected = event_hash(prev, ev["payload"], ev["actor_id"], ev["seq"],
                                  ev["event_type"], ev["case_id"])
            if expected != ev["event_hash"]:
                return False, f"hash mismatch at seq {ev['seq']}"
            prev, expected_seq = ev["event_hash"], expected_seq + 1
        return True, f"{expected_seq - 1} events verified"

    # ------------------------------------------------------------- artifacts
    def put_artifact(self, case_id: str, data: bytes, media_type: str,
                     produced_by: str) -> str:
        """Content-addressed store. Returns ``sha256:<hex>``."""
        digest = hashlib.sha256(data).hexdigest()
        artifact_id = f"sha256:{digest}"
        path = artifact_root() / digest[:2] / digest
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        self.q(
            """INSERT INTO cw.artifact
               (artifact_id, case_id, media_type, bytes, storage_path, produced_by,
                created_seq)
               VALUES (%s,%s,%s,%s,%s,%s, COALESCE(
                   (SELECT max(seq) FROM cw.case_event WHERE case_id=%s), 0))
               ON CONFLICT DO NOTHING""",
            (artifact_id, case_id, media_type, len(data), str(path),
             produced_by, case_id),
        )
        return artifact_id

    def get_artifact(self, artifact_id: str) -> bytes:
        row = self.q1("SELECT storage_path FROM cw.artifact WHERE artifact_id=%s",
                      (artifact_id,))
        if not row:
            raise KeyError(artifact_id)
        return Path(row["storage_path"]).read_bytes()
