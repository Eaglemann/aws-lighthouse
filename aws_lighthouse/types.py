from typing import Any, Literal, NotRequired, TypedDict

# Canonical severity levels used across all scan findings.
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
OpportunityStatus = Literal[
    "open",
    "triaged",
    "in_progress",
    "snoozed",
    "resolved",
    "ignored",
]
OpportunitySourceKind = Literal[
    "cost_anomaly",
    "cost_waste",
    "security",
    "iam",
    "cloudwatch",
    "tagging",
]
OpportunityEventType = Literal[
    "created",
    "reopened",
    "resolved",
    "status_updated",
    "owner_updated",
    "note_added",
    "snoozed",
]


class ScanError(TypedDict):
    """Structured scanner error metadata surfaced in result envelopes."""

    code: str
    message: str
    service: str
    operation: str
    region: NotRequired[str]
    retryable: NotRequired[bool]


class ScanResult(TypedDict):
    """Generic scanner result envelope used across runtime boundaries."""

    ok: bool
    data: Any
    errors: list[ScanError]


class SecurityFinding(TypedDict):
    """One finding emitted by run_security_scan()."""

    severity: Severity
    resource: str
    finding: str
    remediation_type: NotRequired[str]
    remediation_label: NotRequired[str]
    region: NotRequired[str]


class CostFinding(TypedDict):
    """One finding emitted by run_cost_scan()."""

    resource: str
    finding: str
    remediation_type: NotRequired[str]
    remediation_label: NotRequired[str]
    region: NotRequired[str]


class TagFinding(TypedDict):
    """One finding emitted by check_tagging_compliance()."""

    resource_type: str
    resource_id: str
    resource_name: str
    missing_tags: list[str]
    region: NotRequired[str]


class CloudWatchFinding(TypedDict):
    """One finding emitted by detect_cloudwatch_gaps()."""

    resource_type: str
    resource_id: str
    resource_name: str
    missing_alarms: list[str]
    region: NotRequired[str]


class IAMFinding(TypedDict):
    """One finding emitted by detect_overpermissive_iam()."""

    severity: Severity
    principal_type: str
    principal_name: str
    policy_type: str
    policy_name: str
    reason: str


class CostAnomaly(TypedDict):
    """One anomaly emitted by detect_cost_anomalies()."""

    service: str
    baseline_30d: float
    recent_30d: float
    pct_change: float
    detection_type: str


class CostAttributionEvent(TypedDict):
    """One CloudTrail event surfaced by get_cost_attribution()."""

    event_name: str
    actor: str
    event_time: str  # ISO 8601
    region: str


class CostAttribution(TypedDict):
    """Attribution result for one anomalous service."""

    service: str
    pct_change: float
    events: list[CostAttributionEvent]


class Opportunity(TypedDict):
    """One persistent local opportunity synced from scan findings."""

    account_id: str
    fingerprint: str
    source_kind: OpportunitySourceKind
    title: str
    summary: str
    severity: Severity | None
    resource_type: str | None
    resource_id: str
    resource_name: str | None
    region: str | None
    raw_payload: dict[str, Any]
    first_seen_at: str
    last_seen_at: str
    seen_count: int
    status: OpportunityStatus
    owner: str | None
    snooze_until: str | None
    notes: str
    resolution_reason: str | None
    resolution_note: str | None
    resolved_at: str | None
    last_scan_scope: str | None


class OpportunityEvent(TypedDict):
    """One lifecycle event attached to a persistent opportunity."""

    account_id: str
    fingerprint: str
    event_type: OpportunityEventType
    timestamp: str
    data: dict[str, Any]
