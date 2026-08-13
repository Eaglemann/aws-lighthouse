"""SQLite schema and additive migrations for local Lighthouse state."""

import sqlite3

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        account_id TEXT,
        region TEXT,
        scan_type TEXT,
        data TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cost_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        account_id TEXT,
        period_start TEXT,
        period_end TEXT,
        total_usd REAL,
        service_breakdown TEXT
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_cost_snapshots_account_ts_id
    ON cost_snapshots(account_id, timestamp DESC, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        account_id TEXT NOT NULL,
        scope_key TEXT NOT NULL,
        data TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scan_snapshots_account_scope_ts_id
    ON scan_snapshots(account_id, scope_key, timestamp DESC, id DESC)
    """,
    """
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
    """,
    """
    CREATE TABLE IF NOT EXISTS opportunities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        severity TEXT,
        resource_type TEXT,
        resource_id TEXT NOT NULL,
        resource_name TEXT,
        region TEXT,
        payload_json TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'open',
        owner TEXT,
        snooze_until TEXT,
        notes TEXT NOT NULL DEFAULT '',
        resolution_reason TEXT,
        resolution_note TEXT,
        resolved_at TEXT,
        last_scan_scope TEXT,
        UNIQUE(account_id, fingerprint)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_opportunities_account_status_seen
    ON opportunities(account_id, status, last_seen_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_opportunities_account_source_region
    ON opportunities(account_id, source_kind, region, status)
    """,
    """
    CREATE TABLE IF NOT EXISTS opportunity_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        account_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        event_type TEXT NOT NULL,
        data_json TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_opportunity_events_account_fp_id
    ON opportunity_events(account_id, fingerprint, id DESC)
    """,
)


def initialize_schema(cursor: sqlite3.Cursor) -> None:
    """Create current tables/indexes and migrate legacy audit tables."""
    for statement in SCHEMA_STATEMENTS:
        cursor.execute(statement)

    columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(audit_log)").fetchall()
    }
    for column, declaration in (
        ("tool_call_id", "TEXT"),
        ("execution_status", "TEXT"),
        ("error", "TEXT"),
    ):
        if column not in columns:
            cursor.execute(f"ALTER TABLE audit_log ADD COLUMN {column} {declaration}")
