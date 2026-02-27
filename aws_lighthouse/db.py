import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, Optional
from .logger import logger

DB_DIR = Path.home() / ".aws-lighthouse"
DB_PATH = DB_DIR / "lighthouse.db"


class DatabaseManager:
    """Manages the local SQLite database for aws-lighthouse state and trends."""

    def __init__(self):
        self._ensure_db()

    def _ensure_db(self):
        """Creates the database directory and initializes tables if they don't exist."""
        DB_DIR.mkdir(parents=True, exist_ok=True)

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
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize SQLite database: {str(e)}")

    def record_cost_snapshot(
        self,
        account_id: str,
        start: str,
        end: str,
        total: float,
        breakdown: Dict[str, float],
    ):
        """Save a cost snapshot to track trends over time."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO cost_snapshots (account_id, period_start, period_end, total_usd, service_breakdown) VALUES (?, ?, ?, ?, ?)",
                    (account_id, start, end, total, json.dumps(breakdown)),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to record cost snapshot: {str(e)}")

    def get_latest_cost_snapshot(self, account_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent cost snapshot for comparison."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, period_start, period_end, total_usd, service_breakdown FROM cost_snapshots WHERE account_id = ? ORDER BY timestamp DESC LIMIT 1",
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


# Global singleton
db_manager = DatabaseManager()
