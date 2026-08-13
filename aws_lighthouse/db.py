import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .db_schema import initialize_schema
from .logger import logger
from .types import (
    Opportunity,
    OpportunityEvent,
    OpportunityEventType,
    OpportunitySourceKind,
    OpportunityStatus,
    Severity,
)

DB_DIR = Path.home() / ".aws-lighthouse"
DB_PATH = DB_DIR / "lighthouse.db"
_MAX_COST_SNAPSHOTS_PER_ACCOUNT = 1000
_MAX_SCAN_SNAPSHOTS_PER_SCOPE = 500
_ACTIVE_OPPORTUNITY_STATUSES: tuple[OpportunityStatus, ...] = (
    "open",
    "triaged",
    "in_progress",
    "snoozed",
)
_ALL_OPPORTUNITY_STATUSES: set[OpportunityStatus] = {
    "open",
    "triaged",
    "in_progress",
    "snoozed",
    "resolved",
    "ignored",
}
_UNSET = object()


class DatabaseManager:
    """Manages the local SQLite database for aws-lighthouse state and trends."""

    def __init__(self) -> None:
        self._health_issues: dict[str, str] = {}
        self._ensure_db()

    def _record_health_issue(self, operation: str, exc: BaseException) -> None:
        self._health_issues[operation] = f"{type(exc).__name__}: {exc}"

    def _clear_health_issue(self, operation: str) -> None:
        self._health_issues.pop(operation, None)

    def get_health_status(self) -> dict[str, Any]:
        issues = [
            {"operation": operation, "detail": detail}
            for operation, detail in sorted(self._health_issues.items())
        ]
        return {
            "ok": not issues,
            "issue_count": len(issues),
            "issues": issues,
        }

    def _ensure_db(self) -> None:
        """Creates the database directory and initializes tables if they don't exist."""
        DB_DIR.mkdir(parents=True, exist_ok=True)
        DB_DIR.chmod(0o700)  # owner-only: no group/world read on the credentials dir

        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                initialize_schema(cursor)
                conn.commit()
            DB_PATH.chmod(0o600)  # owner read/write only — contains cost history
            self._clear_health_issue("initialize")
        except (sqlite3.Error, OSError) as e:
            self._record_health_issue("initialize", e)
            logger.error(f"Failed to initialize SQLite database: {e!s}")

    def _append_opportunity_event(
        self,
        cursor: sqlite3.Cursor,
        *,
        account_id: str,
        fingerprint: str,
        event_type: OpportunityEventType,
        data: dict[str, Any],
    ) -> None:
        cursor.execute(
            """
            INSERT INTO opportunity_events (account_id, fingerprint, event_type, data_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                account_id,
                fingerprint,
                event_type,
                json.dumps(data, sort_keys=True, default=str),
            ),
        )

    def _row_to_opportunity(self, row: sqlite3.Row) -> Opportunity:
        return {
            "account_id": row["account_id"],
            "fingerprint": row["fingerprint"],
            "source_kind": row["source_kind"],
            "title": row["title"],
            "summary": row["summary"],
            "severity": row["severity"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "resource_name": row["resource_name"],
            "region": row["region"],
            "raw_payload": json.loads(row["payload_json"]),
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "seen_count": row["seen_count"],
            "status": row["status"],
            "owner": row["owner"],
            "snooze_until": row["snooze_until"],
            "notes": row["notes"] or "",
            "resolution_reason": row["resolution_reason"],
            "resolution_note": row["resolution_note"],
            "resolved_at": row["resolved_at"],
            "last_scan_scope": row["last_scan_scope"],
        }

    def _row_to_opportunity_event(self, row: sqlite3.Row) -> OpportunityEvent:
        return {
            "account_id": row["account_id"],
            "fingerprint": row["fingerprint"],
            "event_type": row["event_type"],
            "timestamp": row["timestamp"],
            "data": json.loads(row["data_json"]),
        }

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
            self._clear_health_issue("record_cost_snapshot")
        except sqlite3.Error as e:
            self._record_health_issue("record_cost_snapshot", e)
            logger.error(f"Failed to record cost snapshot: {e!s}")

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
                    self._clear_health_issue("get_latest_cost_snapshot")
                    return {
                        "recorded_at": row[0],
                        "period_start": row[1],
                        "period_end": row[2],
                        "total_usd": row[3],
                        "breakdown": json.loads(row[4]),
                    }
                self._clear_health_issue("get_latest_cost_snapshot")
                return None
        except sqlite3.Error as e:
            self._record_health_issue("get_latest_cost_snapshot", e)
            logger.error(f"Failed to retrieve latest cost snapshot: {e!s}")
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
            self._clear_health_issue("record_scan_snapshot")
        except sqlite3.Error as e:
            self._record_health_issue("record_scan_snapshot", e)
            logger.error(f"Failed to record scan snapshot: {e!s}")

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
                    self._clear_health_issue("get_latest_scan_snapshot")
                    return {"recorded_at": row[0], "data": json.loads(row[1])}
                self._clear_health_issue("get_latest_scan_snapshot")
                return None
        except sqlite3.Error as e:
            self._record_health_issue("get_latest_scan_snapshot", e)
            logger.error(f"Failed to retrieve latest scan snapshot: {e!s}")
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
                    self._clear_health_issue("get_previous_scan_snapshot")
                    return {"recorded_at": row[0], "data": json.loads(row[1])}
                self._clear_health_issue("get_previous_scan_snapshot")
                return None
        except sqlite3.Error as e:
            self._record_health_issue("get_previous_scan_snapshot", e)
            logger.error(f"Failed to retrieve previous scan snapshot: {e!s}")
            return None

    def get_latest_scan_activity(
        self, account_id: str | None = None
    ) -> dict[str, Any] | None:
        """Return the newest scan snapshot metadata across all scopes."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                if account_id:
                    cursor.execute(
                        """
                        SELECT timestamp, account_id, scope_key
                        FROM scan_snapshots
                        WHERE account_id = ?
                        ORDER BY timestamp DESC, id DESC
                        LIMIT 1
                        """,
                        (account_id,),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT timestamp, account_id, scope_key
                        FROM scan_snapshots
                        ORDER BY timestamp DESC, id DESC
                        LIMIT 1
                        """
                    )
                row = cursor.fetchone()
                if row:
                    self._clear_health_issue("get_latest_scan_activity")
                    return {
                        "recorded_at": row[0],
                        "account_id": row[1],
                        "scope_key": row[2],
                    }
                self._clear_health_issue("get_latest_scan_activity")
                return None
        except sqlite3.Error as e:
            self._record_health_issue("get_latest_scan_activity", e)
            logger.error(f"Failed to retrieve latest scan activity: {e!s}")
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
            self._clear_health_issue("record_audit_log")
        except sqlite3.Error as e:
            self._record_health_issue("record_audit_log", e)
            logger.error(f"Failed to record audit log entry: {e!s}")

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
            self._clear_health_issue("update_audit_log_result")
        except sqlite3.Error as e:
            self._record_health_issue("update_audit_log_result", e)
            logger.error(f"Failed to update audit log result: {e!s}")

    def get_audit_log(
        self,
        limit: int = 50,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return audit_log rows newest-first.

        *since* is an ISO 8601 timestamp string; only rows after that time are
        returned.  Returns an empty list on DB errors (never raises).
        """
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                if since:
                    rows = conn.execute(
                        """
                        SELECT id, timestamp, tool_call_id, tool_name, args_json,
                               decision, execution_status, result, error
                        FROM audit_log
                        WHERE timestamp > ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (since, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT id, timestamp, tool_call_id, tool_name, args_json,
                               decision, execution_status, result, error
                        FROM audit_log
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
            self._clear_health_issue("get_audit_log")
            return [dict(r) for r in rows]
        except sqlite3.Error as e:
            self._record_health_issue("get_audit_log", e)
            logger.error(f"Failed to read audit log: {e!s}")
            return []

    def sync_opportunities(
        self,
        *,
        account_id: str,
        scanned_at: str,
        opportunities: list[Opportunity],
        coverage: dict[OpportunitySourceKind, set[str | None]],
    ) -> dict[str, int]:
        """Upsert current findings, reopen recurring ones, and auto-resolve absences."""
        deduped = {
            opportunity["fingerprint"]: opportunity for opportunity in opportunities
        }
        seen_by_scope: dict[tuple[str, str | None], set[str]] = {}
        for opportunity in deduped.values():
            key = (opportunity["source_kind"], opportunity["region"])
            seen_by_scope.setdefault(key, set()).add(opportunity["fingerprint"])

        created = 0
        reopened = 0
        resolved = 0
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                for opportunity in deduped.values():
                    existing_row = cursor.execute(
                        """
                        SELECT *
                        FROM opportunities
                        WHERE account_id = ? AND fingerprint = ?
                        """,
                        (account_id, opportunity["fingerprint"]),
                    ).fetchone()
                    if existing_row is None:
                        cursor.execute(
                            """
                            INSERT INTO opportunities (
                                account_id,
                                fingerprint,
                                source_kind,
                                title,
                                summary,
                                severity,
                                resource_type,
                                resource_id,
                                resource_name,
                                region,
                                payload_json,
                                first_seen_at,
                                last_seen_at,
                                seen_count,
                                status,
                                owner,
                                snooze_until,
                                notes,
                                resolution_reason,
                                resolution_note,
                                resolved_at,
                                last_scan_scope
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                opportunity["account_id"],
                                opportunity["fingerprint"],
                                opportunity["source_kind"],
                                opportunity["title"],
                                opportunity["summary"],
                                opportunity["severity"],
                                opportunity["resource_type"],
                                opportunity["resource_id"],
                                opportunity["resource_name"],
                                opportunity["region"],
                                json.dumps(
                                    opportunity["raw_payload"],
                                    sort_keys=True,
                                    default=str,
                                ),
                                opportunity["first_seen_at"],
                                opportunity["last_seen_at"],
                                opportunity["seen_count"],
                                opportunity["status"],
                                opportunity["owner"],
                                opportunity["snooze_until"],
                                opportunity["notes"],
                                opportunity["resolution_reason"],
                                opportunity["resolution_note"],
                                opportunity["resolved_at"],
                                opportunity["last_scan_scope"],
                            ),
                        )
                        self._append_opportunity_event(
                            cursor,
                            account_id=account_id,
                            fingerprint=opportunity["fingerprint"],
                            event_type="created",
                            data={
                                "source_kind": opportunity["source_kind"],
                                "status": "open",
                                "region": opportunity["region"],
                            },
                        )
                        created += 1
                        continue

                    existing = self._row_to_opportunity(existing_row)
                    next_status = existing["status"]
                    next_snooze_until = existing["snooze_until"]
                    next_resolved_at = existing["resolved_at"]
                    next_resolution_reason = existing["resolution_reason"]
                    next_resolution_note = existing["resolution_note"]
                    if existing["status"] in {"resolved", "ignored"}:
                        next_status = "open"
                        next_snooze_until = None
                        next_resolved_at = None
                        next_resolution_reason = None
                        next_resolution_note = None
                        reopened += 1
                        self._append_opportunity_event(
                            cursor,
                            account_id=account_id,
                            fingerprint=opportunity["fingerprint"],
                            event_type="reopened",
                            data={"previous_status": existing["status"]},
                        )

                    cursor.execute(
                        """
                        UPDATE opportunities
                        SET title = ?,
                            summary = ?,
                            severity = ?,
                            resource_type = ?,
                            resource_id = ?,
                            resource_name = ?,
                            region = ?,
                            payload_json = ?,
                            last_seen_at = ?,
                            seen_count = ?,
                            status = ?,
                            snooze_until = ?,
                            resolution_reason = ?,
                            resolution_note = ?,
                            resolved_at = ?,
                            last_scan_scope = ?
                        WHERE account_id = ? AND fingerprint = ?
                        """,
                        (
                            opportunity["title"],
                            opportunity["summary"],
                            opportunity["severity"],
                            opportunity["resource_type"],
                            opportunity["resource_id"],
                            opportunity["resource_name"],
                            opportunity["region"],
                            json.dumps(
                                opportunity["raw_payload"], sort_keys=True, default=str
                            ),
                            scanned_at,
                            existing["seen_count"] + 1,
                            next_status,
                            next_snooze_until,
                            next_resolution_reason,
                            next_resolution_note,
                            next_resolved_at,
                            opportunity["last_scan_scope"],
                            account_id,
                            opportunity["fingerprint"],
                        ),
                    )

                for source_kind, covered_regions in coverage.items():
                    region_values = sorted(
                        region for region in covered_regions if region is not None
                    )
                    where_clauses = [
                        "account_id = ?",
                        "source_kind = ?",
                        "status != 'resolved'",
                    ]
                    params: list[Any] = [account_id, source_kind]
                    if None in covered_regions and region_values:
                        placeholders = ", ".join("?" for _ in region_values)
                        where_clauses.append(
                            f"(region IS NULL OR region IN ({placeholders}))"
                        )
                        params.extend(region_values)
                    elif None in covered_regions:
                        where_clauses.append("region IS NULL")
                    elif region_values:
                        placeholders = ", ".join("?" for _ in region_values)
                        where_clauses.append(f"region IN ({placeholders})")
                        params.extend(region_values)

                    query = f"""
                        SELECT fingerprint, status, region
                        FROM opportunities
                        WHERE {" AND ".join(where_clauses)}
                        """  # noqa: S608 - where clauses are built from fixed SQL fragments
                    rows = cursor.execute(query, params).fetchall()
                    for row in rows:
                        region = row["region"]
                        if row["fingerprint"] in seen_by_scope.get(
                            (source_kind, region), set()
                        ):
                            continue
                        cursor.execute(
                            """
                            UPDATE opportunities
                            SET status = 'resolved',
                                resolved_at = ?,
                                resolution_reason = ?,
                                resolution_note = ?,
                                snooze_until = NULL
                            WHERE account_id = ? AND fingerprint = ?
                            """,
                            (
                                scanned_at,
                                "not_seen_in_scan",
                                "Automatically resolved because the finding was absent from the latest covered scan.",
                                account_id,
                                row["fingerprint"],
                            ),
                        )
                        self._append_opportunity_event(
                            cursor,
                            account_id=account_id,
                            fingerprint=row["fingerprint"],
                            event_type="resolved",
                            data={
                                "previous_status": row["status"],
                                "reason": "not_seen_in_scan",
                                "region": region,
                            },
                        )
                        resolved += 1

                still_open = cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM opportunities
                    WHERE account_id = ?
                      AND status IN (?, ?, ?, ?)
                    """,
                    (account_id, *_ACTIVE_OPPORTUNITY_STATUSES),
                ).fetchone()[0]
                conn.commit()
                self._clear_health_issue("sync_opportunities")
                return {
                    "created": created,
                    "reopened": reopened,
                    "resolved": resolved,
                    "still_open": int(still_open),
                }
        except sqlite3.Error as e:
            self._record_health_issue("sync_opportunities", e)
            logger.error(f"Failed to sync opportunities: {e!s}")
            return {"created": 0, "reopened": 0, "resolved": 0, "still_open": 0}

    def list_opportunities(
        self,
        *,
        account_id: str | None = None,
        statuses: list[OpportunityStatus] | None = None,
        source_kinds: list[OpportunitySourceKind] | None = None,
        severities: list[Severity] | None = None,
        region: str | None = None,
        owner: str | None = None,
        limit: int = 25,
    ) -> list[Opportunity]:
        """Return filtered opportunities ordered by severity, status, and recency."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                where_clauses = ["1 = 1"]
                params: list[Any] = []
                if account_id:
                    where_clauses.append("account_id = ?")
                    params.append(account_id)
                if statuses:
                    placeholders = ", ".join("?" for _ in statuses)
                    where_clauses.append(f"status IN ({placeholders})")
                    params.extend(statuses)
                if source_kinds:
                    placeholders = ", ".join("?" for _ in source_kinds)
                    where_clauses.append(f"source_kind IN ({placeholders})")
                    params.extend(source_kinds)
                if severities:
                    placeholders = ", ".join("?" for _ in severities)
                    where_clauses.append(f"severity IN ({placeholders})")
                    params.extend(severities)
                if region is None:
                    pass
                elif region == "":
                    where_clauses.append("region IS NULL")
                else:
                    where_clauses.append("region = ?")
                    params.append(region)
                if owner:
                    where_clauses.append("owner = ?")
                    params.append(owner)
                params.append(max(limit, 1))
                query = f"""
                    SELECT *
                    FROM opportunities
                    WHERE {" AND ".join(where_clauses)}
                    ORDER BY
                        CASE severity
                            WHEN 'HIGH' THEN 0
                            WHEN 'MEDIUM' THEN 1
                            WHEN 'LOW' THEN 2
                            ELSE 3
                        END,
                        CASE status
                            WHEN 'open' THEN 0
                            WHEN 'triaged' THEN 1
                            WHEN 'in_progress' THEN 2
                            WHEN 'snoozed' THEN 3
                            WHEN 'ignored' THEN 4
                            WHEN 'resolved' THEN 5
                            ELSE 6
                        END,
                        last_seen_at DESC,
                        id DESC
                    LIMIT ?
                    """  # noqa: S608 - where clauses are built from fixed SQL fragments
                rows = conn.execute(query, params).fetchall()
                self._clear_health_issue("list_opportunities")
                return [self._row_to_opportunity(row) for row in rows]
        except sqlite3.Error as e:
            self._record_health_issue("list_opportunities", e)
            logger.error(f"Failed to list opportunities: {e!s}")
            return []

    def summarize_opportunities(
        self,
        *,
        account_id: str | None = None,
        statuses: list[OpportunityStatus] | None = None,
    ) -> dict[str, Any]:
        """Return aggregate counts for the current opportunity set."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                where_clauses = ["1 = 1"]
                params: list[Any] = []
                if account_id:
                    where_clauses.append("account_id = ?")
                    params.append(account_id)
                if statuses:
                    placeholders = ", ".join("?" for _ in statuses)
                    where_clauses.append(f"status IN ({placeholders})")
                    params.extend(statuses)

                where_sql = " AND ".join(where_clauses)
                total_query = f"SELECT COUNT(*) FROM opportunities WHERE {where_sql}"  # noqa: S608 - built from fixed SQL fragments
                total = int(conn.execute(total_query, params).fetchone()[0])

                source_query = f"""
                    SELECT source_kind, COUNT(*)
                    FROM opportunities
                    WHERE {where_sql}
                    GROUP BY source_kind
                """  # noqa: S608 - built from fixed SQL fragments
                severity_query = f"""
                    SELECT COALESCE(severity, 'UNSPECIFIED'), COUNT(*)
                    FROM opportunities
                    WHERE {where_sql}
                    GROUP BY COALESCE(severity, 'UNSPECIFIED')
                """  # noqa: S608 - built from fixed SQL fragments
                status_query = f"""
                    SELECT status, COUNT(*)
                    FROM opportunities
                    WHERE {where_sql}
                    GROUP BY status
                """  # noqa: S608 - built from fixed SQL fragments

                by_source = {
                    row[0]: int(row[1]) for row in conn.execute(source_query, params)
                }
                by_severity = {
                    row[0]: int(row[1]) for row in conn.execute(severity_query, params)
                }
                by_status = {
                    row[0]: int(row[1]) for row in conn.execute(status_query, params)
                }
                self._clear_health_issue("summarize_opportunities")
                return {
                    "total": total,
                    "by_source": dict(sorted(by_source.items())),
                    "by_severity": dict(sorted(by_severity.items())),
                    "by_status": dict(sorted(by_status.items())),
                }
        except sqlite3.Error as e:
            self._record_health_issue("summarize_opportunities", e)
            logger.error(f"Failed to summarize opportunities: {e!s}")
            return {"total": 0, "by_source": {}, "by_severity": {}, "by_status": {}}

    def get_opportunity(
        self, fingerprint: str, account_id: str | None = None
    ) -> Opportunity | None:
        """Return one opportunity, rejecting ambiguous account-less lookups."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                if account_id:
                    row = conn.execute(
                        """
                        SELECT *
                        FROM opportunities
                        WHERE account_id = ? AND fingerprint = ?
                        """,
                        (account_id, fingerprint),
                    ).fetchone()
                    self._clear_health_issue("get_opportunity")
                    return self._row_to_opportunity(row) if row else None

                rows = conn.execute(
                    """
                    SELECT *
                    FROM opportunities
                    WHERE fingerprint = ?
                    ORDER BY last_seen_at DESC, id DESC
                    LIMIT 2
                    """,
                    (fingerprint,),
                ).fetchall()
                if not rows:
                    self._clear_health_issue("get_opportunity")
                    return None
                if len(rows) > 1:
                    raise ValueError(
                        "fingerprint is ambiguous across multiple accounts; supply account_id"
                    )
                self._clear_health_issue("get_opportunity")
                return self._row_to_opportunity(rows[0])
        except sqlite3.Error as e:
            self._record_health_issue("get_opportunity", e)
            logger.error(f"Failed to get opportunity: {e!s}")
            return None

    def get_opportunity_events(
        self,
        *,
        fingerprint: str,
        account_id: str | None = None,
        limit: int = 50,
    ) -> list[OpportunityEvent]:
        """Return lifecycle events for an opportunity."""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                if account_id:
                    rows = conn.execute(
                        """
                        SELECT account_id, fingerprint, event_type, timestamp, data_json
                        FROM opportunity_events
                        WHERE account_id = ? AND fingerprint = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (account_id, fingerprint, max(limit, 1)),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT account_id, fingerprint, event_type, timestamp, data_json
                        FROM opportunity_events
                        WHERE fingerprint = ?
                        ORDER BY id DESC
                        LIMIT ?
                        """,
                        (fingerprint, max(limit, 1)),
                    ).fetchall()
                self._clear_health_issue("get_opportunity_events")
                return [self._row_to_opportunity_event(row) for row in rows]
        except sqlite3.Error as e:
            self._record_health_issue("get_opportunity_events", e)
            logger.error(f"Failed to get opportunity events: {e!s}")
            return []

    def update_opportunity_state(  # noqa: C901
        self,
        *,
        fingerprint: str,
        account_id: str | None = None,
        status: OpportunityStatus | None = None,
        owner: str | object | None = _UNSET,
        snooze_until: str | object | None = _UNSET,
        note: str | object | None = _UNSET,
    ) -> Opportunity | None:
        """Update local-only opportunity state such as status, owner, snooze, and notes."""
        if status is not None and status not in _ALL_OPPORTUNITY_STATUSES:
            raise ValueError(f"invalid opportunity status: {status}")

        existing = self.get_opportunity(fingerprint=fingerprint, account_id=account_id)
        if existing is None:
            return None

        now = datetime.now(UTC).isoformat()
        next_status = existing["status"]
        next_owner = existing["owner"]
        next_snooze_until = existing["snooze_until"]
        next_notes = existing["notes"]
        next_resolved_at = existing["resolved_at"]
        next_resolution_reason = existing["resolution_reason"]
        next_resolution_note = existing["resolution_note"]

        events: list[tuple[OpportunityEventType, dict[str, Any]]] = []
        if owner is not _UNSET:
            normalized_owner = owner.strip() if isinstance(owner, str) else None
            normalized_owner = normalized_owner or None
            if normalized_owner != existing["owner"]:
                next_owner = normalized_owner
                events.append(
                    (
                        "owner_updated",
                        {
                            "previous_owner": existing["owner"],
                            "owner": normalized_owner,
                        },
                    )
                )

        if snooze_until is not _UNSET:
            normalized_snooze = (
                snooze_until.strip() if isinstance(snooze_until, str) else None
            )
            normalized_snooze = normalized_snooze or None
            if normalized_snooze != existing["snooze_until"]:
                next_snooze_until = normalized_snooze
                if normalized_snooze is not None and status is None:
                    next_status = "snoozed"
                elif (
                    normalized_snooze is None
                    and existing["status"] == "snoozed"
                    and status is None
                ):
                    next_status = "open"
                events.append(
                    (
                        "snoozed",
                        {
                            "previous_snooze_until": existing["snooze_until"],
                            "snooze_until": normalized_snooze,
                        },
                    )
                )

        if note is not _UNSET:
            note_text = note.strip() if isinstance(note, str) else ""
            if note_text:
                prefix = "\n" if next_notes else ""
                next_notes = f"{next_notes}{prefix}[{now}] {note_text}"
                events.append(("note_added", {"note": note_text}))

        if status is not None and status != existing["status"]:
            previous_status = existing["status"]
            next_status = status
            if status == "resolved":
                next_resolved_at = now
                next_resolution_reason = "manual_resolved"
                next_resolution_note = next_resolution_note
                next_snooze_until = None
                events.append(
                    (
                        "resolved",
                        {
                            "previous_status": previous_status,
                            "reason": "manual_resolved",
                        },
                    )
                )
            elif previous_status in {"resolved", "ignored"} and status == "open":
                next_resolved_at = None
                next_resolution_reason = None
                next_resolution_note = None
                next_snooze_until = None
                events.append(("reopened", {"previous_status": previous_status}))
            else:
                next_resolved_at = None
                next_resolution_reason = None
                next_resolution_note = None
                if status != "snoozed" and snooze_until is _UNSET:
                    next_snooze_until = None
                event_type: OpportunityEventType = (
                    "snoozed" if status == "snoozed" else "status_updated"
                )
                events.append(
                    (
                        event_type,
                        {
                            "previous_status": previous_status,
                            "status": status,
                        },
                    )
                )

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE opportunities
                    SET status = ?,
                        owner = ?,
                        snooze_until = ?,
                        notes = ?,
                        resolved_at = ?,
                        resolution_reason = ?,
                        resolution_note = ?
                    WHERE account_id = ? AND fingerprint = ?
                    """,
                    (
                        next_status,
                        next_owner,
                        next_snooze_until,
                        next_notes,
                        next_resolved_at,
                        next_resolution_reason,
                        next_resolution_note,
                        existing["account_id"],
                        fingerprint,
                    ),
                )
                for event_type, data in events:
                    self._append_opportunity_event(
                        cursor,
                        account_id=existing["account_id"],
                        fingerprint=fingerprint,
                        event_type=event_type,
                        data=data,
                    )
                conn.commit()
            self._clear_health_issue("update_opportunity_state")
        except sqlite3.Error as e:
            self._record_health_issue("update_opportunity_state", e)
            logger.error(f"Failed to update opportunity state: {e!s}")
            return None

        return self.get_opportunity(
            fingerprint=fingerprint, account_id=existing["account_id"]
        )


# Global singleton
db_manager = DatabaseManager()
