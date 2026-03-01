"""Tests for DatabaseManager (db.py)."""

import sqlite3

import pytest

import aws_lighthouse.db as db_module
from aws_lighthouse.db import DatabaseManager


# ---------------------------------------------------------------------------
# Fixture: fresh DatabaseManager pointing at a temp directory
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    return DatabaseManager()


def _tables(tmp_path) -> set:
    """Return the set of table names in the test DB."""
    with sqlite3.connect(tmp_path / "test.db") as conn:
        return {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }


# ---------------------------------------------------------------------------
# _ensure_db — init
# ---------------------------------------------------------------------------


class TestEnsureDb:
    def test_creates_directory_recursively(self, tmp_path, monkeypatch):
        nested = tmp_path / "a" / "b" / "c"
        monkeypatch.setattr(db_module, "DB_DIR", nested)
        monkeypatch.setattr(db_module, "DB_PATH", nested / "test.db")
        DatabaseManager()
        assert nested.exists()

    def test_creates_cost_snapshots_table(self, db, tmp_path):
        assert "cost_snapshots" in _tables(tmp_path)

    def test_creates_scans_table(self, db, tmp_path):
        assert "scans" in _tables(tmp_path)

    def test_idempotent_on_second_init(self, db, tmp_path, monkeypatch):
        """Creating a second manager against the same DB must not raise."""
        monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
        DatabaseManager()  # should not raise
        assert "cost_snapshots" in _tables(tmp_path)


# ---------------------------------------------------------------------------
# record_cost_snapshot
# ---------------------------------------------------------------------------


class TestRecordCostSnapshot:
    def test_round_trip(self, db):
        db.record_cost_snapshot(
            account_id="123456789012",
            start="2024-01-01",
            end="2024-01-31",
            total=123.45,
            breakdown={"EC2": 100.0, "S3": 23.45},
        )
        result = db.get_latest_cost_snapshot("123456789012")
        assert result is not None
        assert result["total_usd"] == 123.45
        assert result["period_start"] == "2024-01-01"
        assert result["period_end"] == "2024-01-31"
        assert result["breakdown"] == {"EC2": 100.0, "S3": 23.45}

    def test_zero_total_stored_correctly(self, db):
        db.record_cost_snapshot("acct", "2024-01-01", "2024-01-31", 0.0, {})
        result = db.get_latest_cost_snapshot("acct")
        assert result is not None
        assert result["total_usd"] == 0.0

    def test_handles_sqlite_error_without_raising(self, db, tmp_path, monkeypatch):
        """An unreachable DB path must log an error, not propagate an exception."""
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "nonexistent" / "x.db")
        db.record_cost_snapshot("acct", "2024-01-01", "2024-01-31", 0.0, {})


# ---------------------------------------------------------------------------
# get_latest_cost_snapshot
# ---------------------------------------------------------------------------


class TestGetLatestCostSnapshot:
    def test_returns_none_when_empty(self, db):
        assert db.get_latest_cost_snapshot("does-not-exist") is None

    def test_returns_most_recent_of_multiple(self, db, tmp_path):
        # Insert rows with explicit, distinct timestamps so ORDER BY is deterministic.
        db_path = tmp_path / "test.db"
        rows = [
            ("acct", "2024-01-01", "2024-01-31", 100.0, "{}", "2024-01-01 10:00:00"),
            ("acct", "2024-02-01", "2024-02-28", 200.0, "{}", "2024-02-01 10:00:00"),
            ("acct", "2024-03-01", "2024-03-31", 300.0, "{}", "2024-03-01 10:00:00"),
        ]
        with sqlite3.connect(db_path) as conn:
            conn.executemany(
                "INSERT INTO cost_snapshots "
                "(account_id, period_start, period_end, total_usd, service_breakdown, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        result = db.get_latest_cost_snapshot("acct")
        assert result is not None
        assert result["total_usd"] == 300.0

    def test_ignores_different_account(self, db):
        db.record_cost_snapshot("acct-A", "2024-01-01", "2024-01-31", 500.0, {})
        assert db.get_latest_cost_snapshot("acct-B") is None

    def test_returned_dict_keys(self, db):
        db.record_cost_snapshot(
            "acct", "2024-01-01", "2024-01-31", 42.0, {"Lambda": 42.0}
        )
        result = db.get_latest_cost_snapshot("acct")
        assert result is not None
        assert set(result.keys()) == {
            "recorded_at",
            "period_start",
            "period_end",
            "total_usd",
            "breakdown",
        }

    def test_breakdown_deserialized_as_dict(self, db):
        breakdown = {"EC2": 50.0, "RDS": 30.0, "Lambda": 20.0}
        db.record_cost_snapshot("acct", "2024-01-01", "2024-01-31", 100.0, breakdown)
        result = db.get_latest_cost_snapshot("acct")
        assert result is not None
        assert result["breakdown"] == breakdown

    def test_handles_sqlite_error_without_raising(self, db, tmp_path, monkeypatch):
        """An unreachable DB path must return None, not raise."""
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "gone" / "x.db")
        result = db.get_latest_cost_snapshot("acct")
        assert result is None
