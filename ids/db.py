from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any

# -------------------------
# Database location
# -------------------------

def get_db_path() -> Path:
    """
    Returns the path to the SQLite database file.

    We keep it in ./data/ids.sqlite for MVP (dev/demo friendly).
    """
    return Path(__file__).resolve().parent.parent / "data" / "ids.sqlite"


def connect() -> sqlite3.Connection:
    """
    Opens a connection to SQLite.

    Notes:
    - timeout: waits a bit if DB is temporarily locked
    - row_factory: makes rows behave like dicts (sqlite3.Row)
    """
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=5)
    conn.row_factory = sqlite3.Row

    # Pragmas: small quality-of-life + reliability improvements
    # WAL = better concurrent reads/writes (helpful once you have a dashboard)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn


# -------------------------
# Schema creation
# -------------------------

def init_db() -> None:
    """
    Creates tables + indexes if they do not exist.

    This should be called on app startup so we fail fast if:
    - data/ folder isn't writable
    - DB path is invalid
    """
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_failures (
                event_id TEXT PRIMARY KEY,
                ts       TEXT NOT NULL,
                host     TEXT,
                pid      INTEGER,
                user     TEXT,
                ip       TEXT,
                port     INTEGER,
                count    INTEGER NOT NULL DEFAULT 1,
                raw      TEXT NOT NULL
            );
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_ssh_failures_ip ON ssh_failures(ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ssh_failures_ts ON ssh_failures(ts);")

        conn.commit()


# -------------------------
# Helpers
# -------------------------

def sha256_hex(text: str) -> str:
    """
    Returns SHA256 hex digest for the given text.
    Used for event_id = SHA256(raw_log_line).
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def insert_ssh_failure_events(events: list[dict[str, Any]]) -> int:
    """
    Inserts SSH failure events into SQLite with dedupe.

    Dedupe rule:
      event_id = SHA256(raw)

    Insert rule:
      INSERT OR IGNORE -> if event_id already exists, SQLite ignores it.

    Returns:
      Number of rows inserted (new events only).
    """
    if not events:
        return 0

    rows = []
    for ev in events:
        raw = (ev.get("raw") or "").strip()
        if not raw:
            # If raw is missing, we cannot create a stable event_id.
            # We skip to keep the DB consistent and auditable.
            continue

        event_id = sha256_hex(raw)

        rows.append(
            {
                "event_id": event_id,
                "ts": ev.get("ts") or "",
                "host": ev.get("host"),
                "pid": ev.get("pid"),
                "user": ev.get("user"),
                "ip": ev.get("ip"),
                "port": ev.get("port"),
                "count": ev.get("count", 1),
                "raw": raw,
            }
        )

    if not rows:
        return 0

    sql = """
    INSERT OR IGNORE INTO ssh_failures
        (event_id, ts, host, pid, user, ip, port, count, raw)
    VALUES
        (:event_id, :ts, :host, :pid, :user, :ip, :port, :count, :raw);
    """

    with connect() as conn:
        cur = conn.executemany(sql, rows)
        conn.commit()
        return cur.rowcount

def count_ssh_failures_rows() -> int:
    """
    Returns total number of rows currently stored in ssh_failures.
    Useful for sanity checks.
    """
    with connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM ssh_failures;").fetchone()
        return int(row["n"])


def query_ssh_summary() -> dict[str, int]:
    """
    Returns a DB-backed summary for SSH failures.

    Definitions (matching your IDS v1 mental model):
    - total_failures: SUM(count) across all events
    - attempt_sessions: COUNT(*) rows (each row = one auth.log event/session)
    - unique_ips: COUNT(DISTINCT ip)

    Note: ip can be NULL in some odd log lines; DISTINCT ignores NULL.
    """
    with connect() as conn:
        row = conn.execute(
            """
            SELECT
                COALESCE(SUM(count), 0)          AS total_failures,
                COALESCE(COUNT(*), 0)            AS attempt_sessions,
                COALESCE(COUNT(DISTINCT ip), 0)  AS unique_ips
            FROM ssh_failures;
            """
        ).fetchone()

        return {
            "total_failures": int(row["total_failures"]),
            "attempt_sessions": int(row["attempt_sessions"]),
            "unique_ips": int(row["unique_ips"]),
        }   
def query_ip_breakdown(limit: int = 10) -> list[dict[str, Any]]:
    """
    Returns top IPs with:
    - failures: SUM(count)
    - sessions: COUNT(*) rows
    Ordered by failures desc, then sessions desc.

    limit controls how many IPs to return.
    """
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT
                ip,
                COALESCE(SUM(count), 0) AS failures,
                COALESCE(COUNT(*), 0)   AS sessions
            FROM ssh_failures
            WHERE ip IS NOT NULL AND ip != ''
            GROUP BY ip
            ORDER BY failures DESC, sessions DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()

        return [
            {"ip": r["ip"], "failures": int(r["failures"]), "sessions": int(r["sessions"])}
            for r in rows
        ]
