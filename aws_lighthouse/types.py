from typing import List, NotRequired, TypedDict


class SecurityFinding(TypedDict):
    """One finding emitted by run_security_scan()."""

    severity: str
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
    missing_tags: List[str]
    region: NotRequired[str]


class CloudWatchFinding(TypedDict):
    """One finding emitted by detect_cloudwatch_gaps()."""

    resource_type: str
    resource_id: str
    resource_name: str
    missing_alarms: List[str]
    region: NotRequired[str]


class IAMFinding(TypedDict):
    """One finding emitted by detect_overpermissive_iam()."""

    severity: str
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
