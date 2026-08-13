# Local database schema

Default path: `~/.aws-lighthouse/lighthouse.db`. The directory is created with
mode `0700` and the database file with mode `0600`. SQLite is local state, not a
remote evidence store.

## Tables

### `scans`

Legacy generic scan storage: `id`, `timestamp`, `account_id`, `region`,
`scan_type`, `data`.

### `cost_snapshots`

Cost trend history: `account_id`, period bounds, total USD, and JSON service
breakdown. Indexed by account and descending timestamp/id. Retention is the
latest 1,000 snapshots per account.

### `scan_snapshots`

Analyze baselines: `account_id`, `scope_key`, JSON payload, timestamp. Indexed
by account/scope and descending timestamp/id. Retention is the latest 500 rows
per account/scope.

The payload is already fail-closed for persistence: degraded list sections keep
prior evidence plus current positive evidence, and degraded mappings keep the
prior mapping.

### `audit_log`

Agent tool decisions and outcomes:

| Column | Meaning |
|---|---|
| `tool_call_id` | LangChain call identity |
| `tool_name` | Exact tool name |
| `args_json` | Proposed arguments |
| `decision` | `auto_approved`, `approved`, or `denied` |
| `execution_status` | Pending/success/error status |
| `result` / `error` | Execution summary |

Older databases receive additive migrations for `tool_call_id`,
`execution_status`, and `error`.

### `opportunities`

One current row per `(account_id, fingerprint)`. It stores the normalized source,
resource identity, severity, region, raw payload, first/last seen timestamps,
seen count, workflow status, owner, snooze, notes, resolution metadata, and last
scan scope.

Statuses: `open`, `triaged`, `in_progress`, `snoozed`, `resolved`, `ignored`.
Only source/region scopes successfully scanned in the current run can be used to
auto-resolve absent opportunities.

### `opportunity_events`

Append-only lifecycle events keyed by account/fingerprint with JSON data. Used
for history and reopen/resolve/triage auditability.

## Backups and deletion

Stop Lighthouse before copying the database so a backup is transactionally
consistent. Deleting the file removes local baselines, audit history, and
opportunity workflow state; the next run creates a new database and cannot
calculate deltas against prior scans.
