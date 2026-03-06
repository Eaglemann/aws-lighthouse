import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any, cast

from .db import DatabaseManager
from .types import Opportunity, OpportunitySourceKind, OpportunityStatus, Severity

TRACKED_SOURCE_KINDS: tuple[OpportunitySourceKind, ...] = (
    "cost_anomaly",
    "cost_waste",
    "security",
    "iam",
    "cloudwatch",
    "tagging",
)

SECTION_TO_SOURCE_KIND: dict[str, OpportunitySourceKind] = {
    "cost_anomalies": "cost_anomaly",
    "cost_waste": "cost_waste",
    "security_findings": "security",
    "iam_findings": "iam",
    "cloudwatch_findings": "cloudwatch",
    "tagging_findings": "tagging",
}

_GLOBAL_ONLY_SOURCES = {"cost_anomaly", "iam"}
_MIXED_SCOPE_SOURCES = {"security", "tagging"}
_DEFAULT_LIST_STATUSES: tuple[OpportunityStatus, ...] = (
    "open",
    "triaged",
    "in_progress",
    "snoozed",
)
_SEVERITY_PRIORITY: dict[Severity | None, int] = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
    None: 3,
}
_STATUS_PRIORITY: dict[OpportunityStatus, int] = {
    "open": 0,
    "triaged": 1,
    "in_progress": 2,
    "snoozed": 3,
    "ignored": 4,
    "resolved": 5,
}
_PLAN_RECOMMENDATIONS: dict[OpportunitySourceKind, list[str]] = {
    "security": [
        "Prioritize HIGH findings first and verify blast radius before mutating AWS state.",
        "Use approval-gated remediation tools only after reviewing the exact affected resources.",
    ],
    "iam": [
        "Review wildcard policies and reduce permissions to the smallest resource scope possible.",
        "Stage IAM changes carefully to avoid locking out automation or humans.",
    ],
    "cost_anomaly": [
        "Validate whether the spend increase was intentional before remediating.",
        "Check recent deployments or traffic shifts for the affected service.",
    ],
    "cost_waste": [
        "Confirm the resource is truly unused, then batch safe cleanup actions.",
        "Prefer deleting the highest-cost idle resources first.",
    ],
    "cloudwatch": [
        "Add the missing alarms for production resources before lower-risk environments.",
        "Group by resource type so alarm coverage work can be done in batches.",
    ],
    "tagging": [
        "Assign ownership before enforcing tags so remediation lands with the right team.",
        "Fix shared tag templates or IaC defaults to stop the finding from reappearing.",
    ],
}


def is_global_security_finding(finding: dict[str, Any]) -> bool:
    return _is_global_security_finding(finding)


def is_global_tagging_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("resource_type", "")) == "S3"


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _normalize_json(val)
            for key, val in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        normalized_items = [_normalize_json(item) for item in value]
        try:
            return sorted(
                normalized_items,
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), default=str
                ),
            )
        except TypeError:
            return normalized_items
    return value


def _fingerprint(
    *,
    source_kind: OpportunitySourceKind,
    resource_id: str,
    region: str | None,
    payload: dict[str, Any],
) -> str:
    encoded = json.dumps(
        {
            "source_kind": source_kind,
            "resource_id": resource_id,
            "region": region,
            "payload": _normalize_json(payload),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def _cost_anomaly_severity(finding: dict[str, Any]) -> Severity:
    pct_change = float(finding.get("pct_change", 0.0))
    if pct_change >= 200:
        return "HIGH"
    if pct_change >= 100:
        return "MEDIUM"
    return "LOW"


def _guess_cost_waste_resource_type(finding: dict[str, Any]) -> str | None:
    resource = str(finding.get("resource", ""))
    detail = str(finding.get("finding", ""))
    if resource.startswith("vol-"):
        return "EBS"
    if resource.startswith("snap-"):
        return "EBSSnapshot"
    if resource.startswith("i-"):
        return "EC2"
    if detail.startswith("Elastic IP "):
        return "EIP"
    return None


def _is_global_security_finding(finding: dict[str, Any]) -> bool:
    resource = str(finding.get("resource", ""))
    detail = str(finding.get("finding", ""))
    return (
        resource == "root"
        or detail.startswith("IAM user ")
        or detail.startswith("Access key ")
        or detail.startswith("S3 bucket ")
    )


def _map_cost_anomaly(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
) -> Opportunity:
    resource_id = str(finding["service"])
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="cost_anomaly",
            resource_id=resource_id,
            region=None,
            payload=payload,
        ),
        "source_kind": "cost_anomaly",
        "title": f"Cost anomaly: {resource_id}",
        "summary": (
            f"7-day spend increased to ${float(finding['recent_7d']):.2f} "
            f"from ${float(finding['baseline_7d']):.2f} "
            f"({float(finding['pct_change']):.1f}% change)"
        ),
        "severity": _cost_anomaly_severity(finding),
        "resource_type": "AWSService",
        "resource_id": resource_id,
        "resource_name": resource_id,
        "region": None,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def _map_cost_waste(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
    default_region: str | None,
) -> Opportunity:
    resource_id = str(finding["resource"])
    region = cast(str | None, finding.get("region") or default_region)
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="cost_waste",
            resource_id=resource_id,
            region=region,
            payload=payload,
        ),
        "source_kind": "cost_waste",
        "title": f"Cost waste: {resource_id}",
        "summary": str(finding["finding"]),
        "severity": None,
        "resource_type": _guess_cost_waste_resource_type(finding),
        "resource_id": resource_id,
        "resource_name": resource_id,
        "region": region,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def _map_security(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
    default_region: str | None,
) -> Opportunity:
    resource_id = str(finding["resource"])
    region = (
        None
        if _is_global_security_finding(finding)
        else cast(str | None, finding.get("region") or default_region)
    )
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="security",
            resource_id=resource_id,
            region=region,
            payload=payload,
        ),
        "source_kind": "security",
        "title": f"Security finding: {resource_id}",
        "summary": str(finding["finding"]),
        "severity": cast(Severity, finding["severity"]),
        "resource_type": None,
        "resource_id": resource_id,
        "resource_name": resource_id,
        "region": region,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def _map_iam(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
) -> Opportunity:
    principal_name = str(finding["principal_name"])
    resource_id = (
        f"{finding['principal_type']}:{principal_name}:"
        f"{finding['policy_type']}:{finding['policy_name']}"
    )
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="iam",
            resource_id=resource_id,
            region=None,
            payload=payload,
        ),
        "source_kind": "iam",
        "title": f"IAM finding: {principal_name}",
        "summary": str(finding["reason"]),
        "severity": cast(Severity, finding["severity"]),
        "resource_type": str(finding["principal_type"]),
        "resource_id": resource_id,
        "resource_name": principal_name,
        "region": None,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def _map_cloudwatch(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
    default_region: str | None,
) -> Opportunity:
    resource_id = str(finding["resource_id"])
    region = cast(str | None, finding.get("region") or default_region)
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="cloudwatch",
            resource_id=resource_id,
            region=region,
            payload=payload,
        ),
        "source_kind": "cloudwatch",
        "title": f"CloudWatch gap: {finding['resource_name']}",
        "summary": "Missing alarms: "
        + ", ".join(cast(list[str], finding["missing_alarms"])),
        "severity": None,
        "resource_type": str(finding["resource_type"]),
        "resource_id": resource_id,
        "resource_name": str(finding["resource_name"]),
        "region": region,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def _map_tagging(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    finding: dict[str, Any],
    default_region: str | None,
) -> Opportunity:
    resource_id = str(finding["resource_id"])
    region = (
        None
        if str(finding["resource_type"]) == "S3"
        else cast(str | None, finding.get("region") or default_region)
    )
    payload = cast(dict[str, Any], _normalize_json(finding))
    return {
        "account_id": account_id,
        "fingerprint": _fingerprint(
            source_kind="tagging",
            resource_id=resource_id,
            region=region,
            payload=payload,
        ),
        "source_kind": "tagging",
        "title": f"Missing tags: {finding['resource_name']}",
        "summary": "Missing tags: "
        + ", ".join(cast(list[str], finding["missing_tags"])),
        "severity": None,
        "resource_type": str(finding["resource_type"]),
        "resource_id": resource_id,
        "resource_name": str(finding["resource_name"]),
        "region": region,
        "raw_payload": payload,
        "first_seen_at": scanned_at,
        "last_seen_at": scanned_at,
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": scan_scope,
    }


def build_scan_opportunities(
    *,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    section_payloads: dict[str, Any],
    scanned_regions: Iterable[str | None],
) -> list[Opportunity]:
    non_null_regions = [region for region in scanned_regions if region]
    default_region = non_null_regions[0] if len(non_null_regions) == 1 else None
    opportunities: list[Opportunity] = []

    for finding in cast(
        list[dict[str, Any]], section_payloads.get("cost_anomalies", [])
    ):
        opportunities.append(
            _map_cost_anomaly(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
            )
        )
    for finding in cast(list[dict[str, Any]], section_payloads.get("cost_waste", [])):
        opportunities.append(
            _map_cost_waste(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
                default_region=default_region,
            )
        )
    for finding in cast(
        list[dict[str, Any]], section_payloads.get("security_findings", [])
    ):
        opportunities.append(
            _map_security(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
                default_region=default_region,
            )
        )
    for finding in cast(list[dict[str, Any]], section_payloads.get("iam_findings", [])):
        opportunities.append(
            _map_iam(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
            )
        )
    for finding in cast(
        list[dict[str, Any]], section_payloads.get("cloudwatch_findings", [])
    ):
        opportunities.append(
            _map_cloudwatch(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
                default_region=default_region,
            )
        )
    for finding in cast(
        list[dict[str, Any]], section_payloads.get("tagging_findings", [])
    ):
        opportunities.append(
            _map_tagging(
                account_id=account_id,
                scanned_at=scanned_at,
                scan_scope=scan_scope,
                finding=finding,
                default_region=default_region,
            )
        )
    return opportunities


def build_scan_coverage(
    *,
    enabled_source_kinds: Iterable[OpportunitySourceKind],
    scanned_regions: Iterable[str | None],
) -> dict[OpportunitySourceKind, set[str | None]]:
    region_tokens = {region for region in scanned_regions}
    if not region_tokens:
        region_tokens = {None}

    coverage: dict[OpportunitySourceKind, set[str | None]] = {}
    for source_kind in enabled_source_kinds:
        if source_kind in _GLOBAL_ONLY_SOURCES:
            coverage[source_kind] = {None}
        elif source_kind in _MIXED_SCOPE_SOURCES:
            coverage[source_kind] = {None, *region_tokens}
        else:
            coverage[source_kind] = set(region_tokens)
    return coverage


def sync_opportunities_from_scan(
    *,
    db: DatabaseManager,
    account_id: str,
    scanned_at: str,
    scan_scope: str,
    section_payloads: dict[str, Any],
    scanned_regions: Iterable[str | None],
    enabled_source_kinds: Iterable[OpportunitySourceKind],
) -> dict[str, int]:
    opportunities = build_scan_opportunities(
        account_id=account_id,
        scanned_at=scanned_at,
        scan_scope=scan_scope,
        section_payloads=section_payloads,
        scanned_regions=scanned_regions,
    )
    coverage = build_scan_coverage(
        enabled_source_kinds=enabled_source_kinds,
        scanned_regions=scanned_regions,
    )
    return db.sync_opportunities(
        account_id=account_id,
        scanned_at=scanned_at,
        opportunities=opportunities,
        coverage=coverage,
    )


def build_opportunity_plan(
    opportunities: list[Opportunity],
    *,
    limit: int = 10,
) -> dict[str, Any]:
    sorted_opportunities = sorted(
        opportunities,
        key=lambda opportunity: (
            _STATUS_PRIORITY[opportunity["status"]],
            _SEVERITY_PRIORITY[opportunity["severity"]],
            opportunity["last_seen_at"],
        ),
    )
    selected = sorted_opportunities[:limit]
    by_source: dict[OpportunitySourceKind, list[Opportunity]] = defaultdict(list)
    for opportunity in selected:
        by_source[opportunity["source_kind"]].append(opportunity)

    groups: list[dict[str, Any]] = []
    for source_kind in TRACKED_SOURCE_KINDS:
        group = by_source.get(source_kind)
        if not group:
            continue
        severities = [item["severity"] for item in group]
        highest = min(severities, key=lambda severity: _SEVERITY_PRIORITY[severity])
        groups.append(
            {
                "source_kind": source_kind,
                "count": len(group),
                "highest_severity": highest,
                "fingerprints": [item["fingerprint"] for item in group],
                "titles": [item["title"] for item in group],
                "recommended_actions": _PLAN_RECOMMENDATIONS[source_kind],
            }
        )

    status_counts = Counter(opportunity["status"] for opportunity in opportunities)
    source_counts = Counter(opportunity["source_kind"] for opportunity in opportunities)
    severity_counts = Counter(
        opportunity["severity"] or "UNSPECIFIED" for opportunity in opportunities
    )
    return {
        "total_considered": len(opportunities),
        "planned_count": len(selected),
        "status_counts": dict(sorted(status_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "top_fingerprints": [item["fingerprint"] for item in selected],
        "groups": groups,
    }


def default_list_statuses() -> tuple[OpportunityStatus, ...]:
    return _DEFAULT_LIST_STATUSES
