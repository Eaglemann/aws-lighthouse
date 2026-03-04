from typing import Any, Literal, NotRequired, TypedDict

# Canonical severity levels used across all scan findings.
Severity = Literal["HIGH", "MEDIUM", "LOW"]


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
    baseline_7d: float
    recent_7d: float
    pct_change: float
