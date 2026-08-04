from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from config import FP_DB_PATH
from tools.thehive import search_fp_history as _search_fp_history

# SOC-3s-ARCHITECTURE-v3-final.md §7a
_SCHEMA = """
CREATE TABLE IF NOT EXISTS fp_events (
    id INTEGER PRIMARY KEY,
    rule_uuid TEXT NOT NULL,
    host TEXT NOT NULL,
    is_fp BOOLEAN NOT NULL,
    triage_timestamp TEXT NOT NULL,
    verdict_confidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_rule_host_time ON fp_events(rule_uuid, host, triage_timestamp);
"""

LONG_TERM_FP_RATE_THRESHOLD = 0.5
LONG_TERM_MIN_SAMPLES = 5


@contextmanager
def _connect():
    db_dir = os.path.dirname(FP_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(FP_DB_PATH)
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def record_triage_outcome(rule_uuid: str, host: str, is_fp: bool, verdict_confidence: str = "") -> None:
    """Write one row per completed triage, at the point format_output already
    knows the verdict — not gated on case_action.py's human-approval step,
    since that may never run. No-ops gracefully if rule_uuid/host are missing
    (e.g. network-only Suricata alerts with no host context)."""
    if not rule_uuid or not host:
        return
    with _connect() as conn:
        conn.execute(
            "INSERT INTO fp_events (rule_uuid, host, is_fp, triage_timestamp, verdict_confidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (rule_uuid, host, is_fp, datetime.now(timezone.utc).isoformat(), verdict_confidence),
        )


def _window_counts(conn: sqlite3.Connection, rule_uuid: str, host: str, since: datetime) -> tuple[int, int]:
    cur = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN is_fp THEN 1 ELSE 0 END), 0) FROM fp_events "
        "WHERE rule_uuid = ? AND host = ? AND triage_timestamp >= ?",
        (rule_uuid, host, since.isoformat()),
    )
    total, fp_count = cur.fetchone()
    return int(total or 0), int(fp_count or 0)


def get_fp_signal(rule_uuid: str, host: str) -> dict:
    """Two separate time windows, not one running total (AACT, Turcotte et al.
    2025): short-term (24h) captures active-incident noise, long-term (30d)
    captures chronic baseline noise. A flat all-time counter erases exactly
    this distinction."""
    if not rule_uuid or not host:
        return {
            "short_term_fp_rate": 0.0,
            "long_term_fp_rate": 0.0,
            "short_term_total": 0,
            "long_term_total": 0,
        }

    now = datetime.now(timezone.utc)
    with _connect() as conn:
        short_total, short_fp = _window_counts(conn, rule_uuid, host, now - timedelta(hours=24))
        long_total, long_fp = _window_counts(conn, rule_uuid, host, now - timedelta(days=30))

    return {
        "short_term_fp_rate": short_fp / max(short_total, 1),
        "long_term_fp_rate": long_fp / max(long_total, 1),
        "short_term_total": short_total,
        "long_term_total": long_total,
    }


def thehive_fp_history(rule_uuid: str, host: str, limit: int = 3) -> list[dict]:
    """Conditional TheHive query for the actual reasoning text behind past
    closures of this rule/host combo. Gated in code (not just prompt
    guidance) on long_term_fp_rate > 0.5 with >=5 samples to trust — matching
    this repo's pattern of enforcing safety-relevant guardrails defensively
    rather than trusting the LLM to always follow instructions. Returns []
    without touching TheHive when the threshold isn't met; this is rare and
    deliberate by design, keeping added latency near zero for the common case."""
    signal = get_fp_signal(rule_uuid, host)
    if signal["long_term_fp_rate"] <= LONG_TERM_FP_RATE_THRESHOLD or signal["long_term_total"] < LONG_TERM_MIN_SAMPLES:
        return []
    return _search_fp_history(rule_uuid, host, limit)
