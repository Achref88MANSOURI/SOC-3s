from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _isolate_fp_db(tmp_path):
    """Every test gets its own throwaway FP-tracking SQLite path. Without this,
    any test that runs format_output() (directly or via the full graph, e.g.
    test_e2e.py) with a real hostname on the alert writes to the actual
    production default (./data/fp_events.db) as a side effect of running the
    suite — tests must never touch real application state."""
    with patch("tools.fp_tracking.FP_DB_PATH", str(tmp_path / "fp_events.db")):
        yield
