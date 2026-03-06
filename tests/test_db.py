"""Tests for DatabaseManager (db.py)."""

import json
import sqlite3

import pytest

import aws_lighthouse.db as db_module
from aws_lighthouse.db import DatabaseManager
from aws_lighthouse.opportunities import sync_opportunities_from_scan

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


def _indexes(tmp_path) -> set:
    """Return the set of index names in the test DB."""
    with sqlite3.connect(tmp_path / "test.db") as conn:
        return {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }


def _sync_opportunities(db: DatabaseManager, *, sections: dict) -> dict:
    return sync_opportunities_from_scan(
        db=db,
        account_id="123456789012",
        scanned_at="2026-03-06T10:00:00+00:00",
        scan_scope="multi-region:days=14",
        section_payloads=sections,
        scanned_regions=["us-east-1"],
        enabled_source_kinds=["security", "tagging"],
    )


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

    def test_creates_cost_snapshot_ordering_index(self, db, tmp_path):
        assert "idx_cost_snapshots_account_ts_id" in _indexes(tmp_path)

    def test_creates_scan_snapshots_table(self, db, tmp_path):
        assert "scan_snapshots" in _tables(tmp_path)

    def test_creates_scan_snapshot_ordering_index(self, db, tmp_path):
        assert "idx_scan_snapshots_account_scope_ts_id" in _indexes(tmp_path)

    def test_creates_opportunities_tables(self, db, tmp_path):
        tables = _tables(tmp_path)
        assert "opportunities" in tables
        assert "opportunity_events" in tables

    def test_creates_opportunity_indexes(self, db, tmp_path):
        indexes = _indexes(tmp_path)
        assert "idx_opportunities_account_status_seen" in indexes
        assert "idx_opportunities_account_source_region" in indexes
        assert "idx_opportunity_events_account_fp_id" in indexes

    def test_existing_db_gains_opportunity_tables(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    account_id TEXT,
                    region TEXT,
                    scan_type TEXT,
                    data TEXT
                )
                """
            )
        monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_module, "DB_PATH", db_path)

        DatabaseManager()

        tables = _tables(tmp_path)
        assert "opportunities" in tables
        assert "opportunity_events" in tables


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

    def test_tie_breaker_uses_higher_id_when_timestamps_equal(self, db, tmp_path):
        db_path = tmp_path / "test.db"
        rows = [
            ("acct", "2024-01-01", "2024-01-31", 100.0, "{}", "2024-01-01 10:00:00"),
            ("acct", "2024-02-01", "2024-02-28", 200.0, "{}", "2024-01-01 10:00:00"),
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
        assert result["total_usd"] == 200.0


class TestGetLatestScanActivity:
    def test_returns_none_when_no_scan_snapshots_exist(self, db):
        assert db.get_latest_scan_activity() is None

    def test_returns_most_recent_scan_metadata(self, db):
        db.record_scan_snapshot(
            account_id="acct-a",
            scope_key="multi-region:days=14",
            data={"security_findings": []},
        )
        db.record_scan_snapshot(
            account_id="acct-b",
            scope_key="single-region:us-east-1:days=14",
            data={"security_findings": []},
        )

        latest = db.get_latest_scan_activity()

        assert latest is not None
        assert latest["account_id"] == "acct-b"
        assert latest["scope_key"] == "single-region:us-east-1:days=14"

    def test_filters_latest_scan_metadata_by_account(self, db):
        db.record_scan_snapshot(
            account_id="acct-a",
            scope_key="multi-region:days=14",
            data={"security_findings": []},
        )
        db.record_scan_snapshot(
            account_id="acct-b",
            scope_key="single-region:us-east-1:days=14",
            data={"security_findings": []},
        )

        latest = db.get_latest_scan_activity("acct-a")

        assert latest is not None
        assert latest["account_id"] == "acct-a"
        assert latest["scope_key"] == "multi-region:days=14"


class TestSummarizeOpportunities:
    def test_returns_zero_summary_when_empty(self, db):
        assert db.summarize_opportunities(account_id="123456789012") == {
            "total": 0,
            "by_source": {},
            "by_severity": {},
            "by_status": {},
        }

    def test_groups_by_source_severity_and_status(self, db):
        _sync_opportunities(
            db,
            sections={
                "cost_anomalies": [],
                "cost_waste": [],
                "security_findings": [
                    {
                        "severity": "HIGH",
                        "resource": "sg-123",
                        "finding": "Open SSH from the internet",
                    }
                ],
                "iam_findings": [],
                "cloudwatch_findings": [],
                "tagging_findings": [
                    {
                        "resource_type": "S3",
                        "resource_id": "bucket-1",
                        "resource_name": "bucket-1",
                        "missing_tags": ["Owner"],
                    }
                ],
            },
        )

        summary = db.summarize_opportunities(account_id="123456789012")

        assert summary["total"] == 2
        assert summary["by_source"] == {"security": 1, "tagging": 1}
        assert summary["by_severity"] == {"HIGH": 1, "UNSPECIFIED": 1}
        assert summary["by_status"] == {"open": 2}

    def test_status_filter_limits_summary(self, db):
        _sync_opportunities(
            db,
            sections={
                "cost_anomalies": [],
                "cost_waste": [],
                "security_findings": [
                    {
                        "severity": "HIGH",
                        "resource": "sg-123",
                        "finding": "Open SSH from the internet",
                    }
                ],
                "iam_findings": [],
                "cloudwatch_findings": [],
                "tagging_findings": [],
            },
        )
        opportunity = db.list_opportunities(account_id="123456789012", limit=5)[0]
        db.update_opportunity_state(
            fingerprint=opportunity["fingerprint"],
            account_id="123456789012",
            status="resolved",
        )

        summary = db.summarize_opportunities(
            account_id="123456789012", statuses=["open"]
        )

        assert summary == {
            "total": 0,
            "by_source": {},
            "by_severity": {},
            "by_status": {},
        }


# ---------------------------------------------------------------------------
# record_audit_log
# ---------------------------------------------------------------------------


def _audit_rows(tmp_path) -> list[dict]:
    """Return all audit_log rows as dicts."""
    with sqlite3.connect(tmp_path / "test.db") as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT tool_call_id, tool_name, args_json, decision, execution_status, result, error FROM audit_log ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


class TestAuditLog:
    def test_creates_audit_log_table(self, db, tmp_path):
        assert "audit_log" in _tables(tmp_path)

    def test_record_approved(self, db, tmp_path):
        db.record_audit_log("terminate_ec2", '{"instance_ids": ["i-abc"]}', "approved")
        rows = _audit_rows(tmp_path)
        assert len(rows) == 1
        assert rows[0]["tool_name"] == "terminate_ec2"
        assert rows[0]["decision"] == "approved"
        assert rows[0]["result"] is None

    def test_record_denied(self, db, tmp_path):
        db.record_audit_log("delete_ebs", '{"volume_ids": ["vol-1"]}', "denied")
        rows = _audit_rows(tmp_path)
        assert rows[0]["decision"] == "denied"

    def test_record_auto_approved(self, db, tmp_path):
        db.record_audit_log("tool_run_security_scan", "{}", "auto_approved")
        rows = _audit_rows(tmp_path)
        assert rows[0]["decision"] == "auto_approved"

    def test_record_with_result(self, db, tmp_path):
        db.record_audit_log(
            "terminate_ec2", '{"instance_ids": ["i-abc"]}', "approved", "Terminated 1"
        )
        rows = _audit_rows(tmp_path)
        assert rows[0]["result"] == "Terminated 1"

    def test_record_with_tool_call_id_and_status(self, db, tmp_path):
        db.record_audit_log(
            "tool_run_security_scan",
            "{}",
            "auto_approved",
            tool_call_id="call-123",
            execution_status="pending",
        )
        rows = _audit_rows(tmp_path)
        assert rows[0]["tool_call_id"] == "call-123"
        assert rows[0]["execution_status"] == "pending"
        assert rows[0]["error"] is None

    def test_multiple_entries_ordered(self, db, tmp_path):
        db.record_audit_log("tool_a", "{}", "approved")
        db.record_audit_log("tool_b", "{}", "denied")
        db.record_audit_log("tool_c", "{}", "auto_approved")
        rows = _audit_rows(tmp_path)
        assert len(rows) == 3
        assert [r["tool_name"] for r in rows] == ["tool_a", "tool_b", "tool_c"]

    def test_handles_sqlite_error_without_raising(self, db, tmp_path, monkeypatch):
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "gone" / "x.db")
        db.record_audit_log("tool", "{}", "approved")  # must not raise

    def test_update_audit_log_result_updates_latest_matching_tool_call(
        self, db, tmp_path
    ):
        db.record_audit_log(
            "tool_run_security_scan",
            "{}",
            "auto_approved",
            tool_call_id="call-456",
            execution_status="pending",
        )
        db.record_audit_log(
            "tool_run_security_scan",
            "{}",
            "auto_approved",
            tool_call_id="call-456",
            execution_status="pending",
        )
        db.update_audit_log_result(
            tool_call_id="call-456",
            result="[]",
            execution_status="executed",
        )

        rows = _audit_rows(tmp_path)
        assert rows[0]["execution_status"] == "pending"
        assert rows[1]["execution_status"] == "executed"
        assert rows[1]["result"] == "[]"


class TestCostSnapshotRetention:
    def test_prunes_old_snapshots_per_account(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
        monkeypatch.setattr(db_module, "_MAX_COST_SNAPSHOTS_PER_ACCOUNT", 2)
        db = DatabaseManager()

        db.record_cost_snapshot("acct", "2024-01-01", "2024-01-31", 1.0, {})
        db.record_cost_snapshot("acct", "2024-02-01", "2024-02-28", 2.0, {})
        db.record_cost_snapshot("acct", "2024-03-01", "2024-03-31", 3.0, {})

        with sqlite3.connect(tmp_path / "test.db") as conn:
            rows = conn.execute(
                "SELECT total_usd FROM cost_snapshots WHERE account_id = ? ORDER BY id",
                ("acct",),
            ).fetchall()
        assert [r[0] for r in rows] == [2.0, 3.0]


def _scan_snapshot_rows(tmp_path) -> list[dict]:
    """Return all scan_snapshots rows as dicts."""
    with sqlite3.connect(tmp_path / "test.db") as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT account_id, scope_key, data, timestamp, id FROM scan_snapshots ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


class TestScanSnapshotPersistence:
    def test_round_trip_latest_scan_snapshot(self, db):
        db.record_scan_snapshot(
            account_id="acct",
            scope_key="multi-region",
            data={"inventory": {"ec2": []}},
        )
        latest = db.get_latest_scan_snapshot("acct", "multi-region")
        assert latest is not None
        assert latest["data"]["inventory"] == {"ec2": []}

    def test_previous_scan_snapshot_returns_second_latest(self, db):
        db.record_scan_snapshot("acct", "multi-region", {"run": 1})
        db.record_scan_snapshot("acct", "multi-region", {"run": 2})
        previous = db.get_previous_scan_snapshot("acct", "multi-region")
        assert previous is not None
        assert previous["data"]["run"] == 1

    def test_latest_scan_snapshot_tie_breaker_prefers_higher_id(self, db, tmp_path):
        with sqlite3.connect(tmp_path / "test.db") as conn:
            conn.executemany(
                "INSERT INTO scan_snapshots (account_id, scope_key, data, timestamp) VALUES (?, ?, ?, ?)",
                [
                    ("acct", "multi-region", '{"run": 1}', "2026-03-04 10:00:00"),
                    ("acct", "multi-region", '{"run": 2}', "2026-03-04 10:00:00"),
                ],
            )
        latest = db.get_latest_scan_snapshot("acct", "multi-region")
        assert latest is not None
        assert latest["data"]["run"] == 2

    def test_scan_snapshot_retention_prunes_per_scope(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
        monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
        monkeypatch.setattr(db_module, "_MAX_SCAN_SNAPSHOTS_PER_SCOPE", 2)
        db = DatabaseManager()

        db.record_scan_snapshot("acct", "multi-region", {"run": 1})
        db.record_scan_snapshot("acct", "multi-region", {"run": 2})
        db.record_scan_snapshot("acct", "multi-region", {"run": 3})
        db.record_scan_snapshot("acct", "single-region:us-east-1", {"run": 1})

        rows = _scan_snapshot_rows(tmp_path)
        multi_runs = [
            json.loads(r["data"])["run"]
            for r in rows
            if r["scope_key"] == "multi-region"
        ]
        single_runs = [
            json.loads(r["data"])["run"]
            for r in rows
            if r["scope_key"] == "single-region:us-east-1"
        ]
        assert multi_runs == [2, 3]
        assert single_runs == [1]
