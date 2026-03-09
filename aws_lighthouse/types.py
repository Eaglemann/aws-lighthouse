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


class RIRecommendation(TypedDict):
    """One RI purchase recommendation from CE get_reservation_purchase_recommendation."""

    service: str
    instance_type: str
    region: str
    platform: str
    term: str  # "1yr" | "3yr"
    payment_option: str
    count: int
    monthly_savings_usd: float
    break_even_months: float
    estimated_monthly_on_demand_usd: float
    estimated_monthly_ri_usd: float
    upfront_cost_usd: float


class SPRecommendation(TypedDict):
    """One SP purchase recommendation from CE get_savings_plans_purchase_recommendation."""

    savings_plan_type: str
    term: str  # "1yr" | "3yr"
    payment_option: str
    hourly_commitment_usd: float
    estimated_monthly_savings_usd: float
    estimated_savings_pct: float
    estimated_monthly_on_demand_usd: float
    upfront_cost_usd: float


class RemediationAction(TypedDict):
    """One action in a batch remediation plan."""

    action_id: str
    phase: int
    remediation_type: str
    resource: str
    label: str
    region: str | None
    source: str  # "security" | "cost_waste"


class PlanPhase(TypedDict):
    """A phase grouping in a batch remediation plan."""

    phase: int
    title: str
    risk: str  # "REVERSIBLE" | "PERMANENT" | "DESTRUCTIVE"
    color: str  # "green" | "yellow" | "red"
    actions: list[RemediationAction]


class RemediationPlan(TypedDict):
    """A full batch remediation plan grouped by risk phase."""

    phases: list[PlanPhase]
    total: int


class SGAttachedResource(TypedDict):
    """One resource attached to a security group via an ENI."""

    resource_type: str  # "EC2" | "RDS" | "Lambda" | "Other"
    resource_id: str
    resource_name: str
    private_ip: str
    public_ip: str | None


class SGBlastRadius(TypedDict):
    """Blast-radius analysis for one open security group."""

    sg_id: str
    sg_name: str
    region: str | None
    attached_resources: list[SGAttachedResource]
    has_public_ip: bool
    has_igw: bool
    exposure: str  # "INTERNET_EXPOSED" | "PRIVATE" | "UNKNOWN"
    recent_connection_count: int  # CloudTrail events found in lookback window
    top_source_ips: list[str]  # up to 3 most frequent source IPs from CT


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


class TerraformResourceInfo(TypedDict):
    """A Terraform resource block that matched a scan finding."""

    resource_type: str  # e.g. "aws_s3_bucket"
    resource_name: str  # Terraform logical name
    tf_file: str  # filename e.g. "main.tf"


class TerraformDriftFinding(TypedDict):
    """One classified finding from classify_findings_by_iac()."""

    source_kind: str
    resource_id: str
    finding: str
    severity: str | None
    iac_managed: bool
    shadow_infra: bool
    tf_resource: TerraformResourceInfo | None
    hcl_fix: str | None
