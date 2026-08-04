from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from tools.fp_tracking import get_fp_signal, record_triage_outcome, thehive_fp_history


def _db_path(tmp_path):
    return str(tmp_path / "nested" / "fp_events.db")


def test_schema_created_on_first_use_db_does_not_exist_yet(tmp_path):
    db_path = _db_path(tmp_path)
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        signal = get_fp_signal("rule-1", "host-1")

    assert signal == {
        "short_term_fp_rate": 0.0,
        "long_term_fp_rate": 0.0,
        "short_term_total": 0,
        "long_term_total": 0,
    }

    conn = sqlite3.connect(db_path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "fp_events" in tables


def test_get_fp_signal_missing_rule_or_host_is_graceful_noop(tmp_path):
    db_path = _db_path(tmp_path)
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        assert get_fp_signal("", "host-1")["short_term_total"] == 0
        assert get_fp_signal("rule-1", "")["short_term_total"] == 0


def test_record_triage_outcome_missing_rule_or_host_does_not_write(tmp_path):
    db_path = _db_path(tmp_path)
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        record_triage_outcome("", "host-1", is_fp=True)
        record_triage_outcome("rule-1", "", is_fp=True)
        signal = get_fp_signal("rule-1", "host-1")

    assert signal["short_term_total"] == 0
    assert signal["long_term_total"] == 0


def test_record_writes_on_both_tp_and_fp_outcomes(tmp_path):
    db_path = _db_path(tmp_path)
    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        record_triage_outcome("rule-1", "host-1", is_fp=True, verdict_confidence="likely")
        record_triage_outcome("rule-1", "host-1", is_fp=False, verdict_confidence="possible")
        record_triage_outcome("rule-1", "host-1", is_fp=True, verdict_confidence="near_certain")
        signal = get_fp_signal("rule-1", "host-1")

    assert signal["short_term_total"] == 3
    assert signal["short_term_fp_rate"] == 2 / 3
    assert signal["long_term_total"] == 3
    assert signal["long_term_fp_rate"] == 2 / 3


def _insert_raw(db_path: str, rule_uuid: str, host: str, is_fp: bool, timestamp: datetime) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS fp_events (id INTEGER PRIMARY KEY, rule_uuid TEXT NOT NULL, "
        "host TEXT NOT NULL, is_fp BOOLEAN NOT NULL, triage_timestamp TEXT NOT NULL, verdict_confidence TEXT)"
    )
    conn.execute(
        "INSERT INTO fp_events (rule_uuid, host, is_fp, triage_timestamp, verdict_confidence) VALUES (?, ?, ?, ?, ?)",
        (rule_uuid, host, is_fp, timestamp.isoformat(), "high"),
    )
    conn.commit()
    conn.close()


def test_short_term_and_long_term_windows_are_distinct(tmp_path):
    """A row from 10 days ago must count toward the 30d long-term window but
    not the 24h short-term one -- this distinction is the entire point of
    AACT's two-window design (a flat all-time counter erases it)."""
    db_path = _db_path(tmp_path)
    now = datetime.now(timezone.utc)
    _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now - timedelta(hours=1))
    _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now - timedelta(days=10))
    _insert_raw(db_path, "rule-1", "host-1", is_fp=False, timestamp=now - timedelta(days=45))

    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        signal = get_fp_signal("rule-1", "host-1")

    assert signal["short_term_total"] == 1
    assert signal["short_term_fp_rate"] == 1.0
    assert signal["long_term_total"] == 2
    assert signal["long_term_fp_rate"] == 1.0


def test_windows_are_scoped_per_rule_and_host(tmp_path):
    db_path = _db_path(tmp_path)
    now = datetime.now(timezone.utc)
    _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now)
    _insert_raw(db_path, "rule-2", "host-1", is_fp=True, timestamp=now)
    _insert_raw(db_path, "rule-1", "host-2", is_fp=True, timestamp=now)

    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        signal = get_fp_signal("rule-1", "host-1")

    assert signal["short_term_total"] == 1


@patch("tools.fp_tracking._search_fp_history")
def test_thehive_fp_history_does_not_query_below_threshold(mock_search, tmp_path):
    db_path = _db_path(tmp_path)
    now = datetime.now(timezone.utc)
    # 3 of 10 long-term events are FP -> 0.3 rate, below the 0.5 threshold
    for i in range(7):
        _insert_raw(db_path, "rule-1", "host-1", is_fp=False, timestamp=now - timedelta(days=1))
    for i in range(3):
        _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now - timedelta(days=1))

    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        result = thehive_fp_history("rule-1", "host-1")

    assert result == []
    mock_search.assert_not_called()


@patch("tools.fp_tracking._search_fp_history")
def test_thehive_fp_history_queries_above_threshold(mock_search, tmp_path):
    mock_search.return_value = [{"alert_id": "a1", "title": "t", "comment": "c", "closed_at": "x"}]
    db_path = _db_path(tmp_path)
    now = datetime.now(timezone.utc)
    # 6 of 10 long-term events are FP -> 0.6 rate, >= 5 samples -> above threshold
    for i in range(4):
        _insert_raw(db_path, "rule-1", "host-1", is_fp=False, timestamp=now - timedelta(days=1))
    for i in range(6):
        _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now - timedelta(days=1))

    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        result = thehive_fp_history("rule-1", "host-1", limit=3)

    assert result == [{"alert_id": "a1", "title": "t", "comment": "c", "closed_at": "x"}]
    mock_search.assert_called_once_with("rule-1", "host-1", 3)


@patch("tools.fp_tracking._search_fp_history")
def test_thehive_fp_history_high_rate_but_too_few_samples_does_not_query(mock_search, tmp_path):
    db_path = _db_path(tmp_path)
    now = datetime.now(timezone.utc)
    # 2 of 2 events are FP -> 1.0 rate, but only 2 samples, below the min of 5
    for i in range(2):
        _insert_raw(db_path, "rule-1", "host-1", is_fp=True, timestamp=now - timedelta(days=1))

    with patch("tools.fp_tracking.FP_DB_PATH", db_path):
        result = thehive_fp_history("rule-1", "host-1")

    assert result == []
    mock_search.assert_not_called()
