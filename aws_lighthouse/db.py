import json
import sqlite3
from pathlib import Path
from typing import Any

from .logger import logger

DB_DIR = Path.home() / ".aws-lighthouse"
DB_PATH = DB_DIR / "lighthouse.db"
_MAX_COST_SNAPSHOTS_PER_ACCOUNT = 1000
_MAX_SCAN_SNAPSHOTS_PER_SCOPE = 500


class DatabaseManager:
    """Manages the local SQLite database for aws-lighthouse state and trends."""

    def __init__(self) -> None:
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Creates the database directory and initializes tables if they don't exist."""
        DB_DIR.mkdir(parents=True, exist_ok=True)
        DB_DIR.chmod(0o700)  # owner-only: no group/world read on the credentials dir

        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()

                # Scans table: records entire environment snapshots
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        account_id TEXT,
                        region TEXT,
                        scan_type TEXT,
                        data TEXT
                    )
                """)

                # Cost trends table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cost_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        account_id TEXT,
                        period_start TEXT,
                        period_end TEXT,
                        total_usd REAL,
                        service_breakdown TEXT
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_cost_snapshots_account_ts_id
                    ON cost_snapshots(account_id, timestamp DESC, id DESC)
                """)

                # Analyze snapshots table for delta mode and watch baselining
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        account_id TEXT NOT NULL,
                        scope_key TEXT NOT NULL,
                        data TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scan_snapshots_account_scope_ts_id
                    ON scan_snapshots(account_id, scope_key, timestamp DESC, id DESC)
                """)

                # Audit log: every tool invocation the agent attempts, with decision
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        tool_call_id TEXT,
                        tool_name TEXT NOT NULL,
                        args_json TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        execution_status TEXT,
                        result TEXT,
                        error TEXT
                    )
                """)
                self._ensure_audit_log_columns(cursor)
                conn.commit()
            DB_PATH.chmod(0o600)  # owner read/write only — contains cost history
        except (sqlite3.Error, OSError) as e:
            logger.error(f"Failed to initialize SQLite database: {str(e)}")

    def _ensure_audit_log_columns(self, cursor: sqlite3.Cursor) -> None:
        """Apply additive audit_log schema migrations for older local DB files."""
        cols = {
            row[1] for row in cursor.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        if "tool_call_id" not in cols:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN tool_call_id TEXT")
        if "execution_status" not in cols:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN execution_status TEXT")
        if "error" not in cols:
            cursor.execute("ALTER TABLE audit_log ADD COLUMN error TEXT")

    def record_cost_snapshot(
        self,
        account_id: str,
        start: str,
        end: str,
        total: float,
        breakdown: dict[str, float],
    ) -> None:
        """Save a cost snapshot to track trends over time."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO cost_snapshots (account_id, period_start, period_end, total_usd, service_breakdown) VALUES (?, ?, ?, ?, ?)",
                    (account_id, start, end, total, json.dumps(breakdown)),
                )
                self._prune_old_cost_snapshots(cursor=cursor, account_id=account_id)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to record cost snapshot: {str(e)}")

    def _prune_old_cost_snapshots(
        self, cursor: sqlite3.Cursor, account_id: str
    ) -> None:
        """Keep only the newest N cost snapshots per account."""
        cursor.execute(
            """
            DELETE FROM cost_snapshots
            WHERE account_id = ?
              AND id NOT IN (
                SELECT id FROM cost_snapshots
                WHERE account_id = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
              )
            """,
            (account_id, account_id, _MAX_COST_SNAPSHOTS_PER_ACCOUNT),
        )

    def get_latest_cost_snapshot(self, account_id: str) -> dict[str, Any] | None:
        """Retrieve the most recent cost snapshot for comparison."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, period_start, period_end, total_usd, service_breakdown FROM cost_snapshots WHERE account_id = ? ORDER BY timestamp DESC, id DESC LIMIT 1",
                    (account_id,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "recorded_at": row[0],
                        "period_start": row[1],
                        "period_end": row[2],
                        "total_usd": row[3],
                        "breakdown": json.loads(row[4]),
                    }
                return None
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve latest cost snapshot: {str(e)}")
            return None

    def record_scan_snapshot(
        self,
        account_id: str,
        scope_key: str,
        data: dict[str, Any],
    ) -> None:
        """Persist one analyze snapshot for delta computations."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO scan_snapshots (account_id, scope_key, data)
                    VALUES (?, ?, ?)
                    """,
                    (account_id, scope_key, json.dumps(data, default=str)),
                )
                self._prune_old_scan_snapshots(
                    cursor=cursor, account_id=account_id, scope_key=scope_key
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to record scan snapshot: {str(e)}")

    def _prune_old_scan_snapshots(
        self, cursor: sqlite3.Cursor, account_id: str, scope_key: str
    ) -> None:
        """Keep only the newest N analyze snapshots per account/scope key."""
        cursor.execute(
            """
            DELETE FROM scan_snapshots
            WHERE account_id = ?
              AND scope_key = ?
              AND id NOT IN (
                SELECT id FROM scan_snapshots
                WHERE account_id = ?
                  AND scope_key = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
              )
            """,
            (
                account_id,
                scope_key,
                account_id,
                scope_key,
                _MAX_SCAN_SNAPSHOTS_PER_SCOPE,
            ),
        )

    def get_latest_scan_snapshot(
        self, account_id: str, scope_key: str
    ) -> dict[str, Any] | None:
        """Return the newest analyze snapshot for an account/scope."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT timestamp, data
                    FROM scan_snapshots
                    WHERE account_id = ? AND scope_key = ?
                    ORDER BY timestamp DESC, id DESC
                    LIMIT 1
                    """,
                    (account_id, scope_key),
                )
                row = cursor.fetchone()
                if row:
                    return {"recorded_at": row[0], "data": json.loads(row[1])}
                return None
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve latest scan snapshot: {str(e)}")
            return None

    def get_previous_scan_snapshot(
        self, account_id: str, scope_key: str
    ) -> dict[str, Any] | None:
        """Return the second newest analyze snapshot for an account/scope."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT timestamp, data
                    FROM scan_snapshots
                    WHERE account_id = ? AND scope_key = ?
                    ORDER BY timestamp DESC, id DESC
                    LIMIT 1 OFFSET 1
                    """,
                    (account_id, scope_key),
                )
                row = cursor.fetchone()
                if row:
                    return {"recorded_at": row[0], "data": json.loads(row[1])}
                return None
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve previous scan snapshot: {str(e)}")
            return None

    def record_audit_log(
        self,
        tool_name: str,
        args_json: str,
        decision: str,
        result: str | None = None,
        tool_call_id: str | None = None,
        execution_status: str | None = None,
        error: str | None = None,
    ) -> None:
        """Record a tool invocation in the audit log.

        decision is one of: 'approved', 'denied', 'auto_approved'.
        result is the tool output string (may be None when not yet known).
        """
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log
                    (tool_call_id, tool_name, args_json, decision, execution_status, result, error)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tool_call_id,
                        tool_name,
                        args_json,
                        decision,
                        execution_status,
                        result,
                        error,
                    ),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to record audit log entry: {str(e)}")

    def update_audit_log_result(
        self,
        tool_call_id: str,
        result: str,
        execution_status: str,
        error: str | None = None,
    ) -> None:
        """Update the latest audit log row for a tool call with execution outcome."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    UPDATE audit_log
                    SET result = ?, execution_status = ?, error = ?
                    WHERE id = (
                        SELECT id FROM audit_log
                        WHERE tool_call_id = ?
                        ORDER BY id DESC
                        LIMIT 1
                    )
                    """,
                    (result, execution_status, error, tool_call_id),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to update audit log result: {str(e)}")


# Global singleton
db_manager = DatabaseManager()
