"""
Batch remediation plan builder — groups remediable findings into risk-tiered
phases for bulk approval.

Phase 1 (REVERSIBLE): S3 BPA, S3 encryption, IMDSv2, GuardDuty, CloudTrail
Phase 2 (PERMANENT):  Release EIP (IP lost but no data loss)
Phase 3 (DESTRUCTIVE): Delete EBS volumes, terminate EC2 (data loss / irreversible)
"""

from typing import Any

from ..types import PlanPhase, RemediationAction, RemediationPlan

_PHASE_MAP: dict[str, int] = {
    "s3_block_public_access": 1,
    "s3_default_encryption": 1,
    "enforce_imdsv2": 1,
    "enable_guardduty": 1,
    "enable_cloudtrail_logging": 1,
    "release_eip": 2,
    "delete_ebs_volume": 3,
    "terminate_ec2": 3,
}

_PHASE_META: dict[int, dict[str, str]] = {
    1: {"title": "Phase 1 — Reversible", "risk": "REVERSIBLE", "color": "green"},
    2: {"title": "Phase 2 — Permanent", "risk": "PERMANENT", "color": "yellow"},
    3: {"title": "Phase 3 — Destructive", "risk": "DESTRUCTIVE", "color": "red"},
}


def build_remediation_plan(remediable: list[dict[str, Any]]) -> RemediationPlan:
    """Group a flat list of remediable findings into a phased plan.

    Unknown remediation types default to Phase 2 (PERMANENT) as a safe
    conservative choice.
    """
    phases_map: dict[int, list[RemediationAction]] = {1: [], 2: [], 3: []}
    for i, item in enumerate(remediable):
        rtype = str(item.get("remediation_type", ""))
        phase = _PHASE_MAP.get(rtype, 2)
        phases_map[phase].append(
            {
                "action_id": f"{rtype}_{i}",
                "phase": phase,
                "remediation_type": rtype,
                "resource": str(item.get("resource", "")),
                "label": str(item.get("remediation_label", rtype)),
                "region": item.get("region"),
                "source": str(item.get("_source", "")),
            }
        )

    phases: list[PlanPhase] = [
        {
            "phase": p,
            "title": _PHASE_META[p]["title"],
            "risk": _PHASE_META[p]["risk"],
            "color": _PHASE_META[p]["color"],
            "actions": actions,
        }
        for p, actions in phases_map.items()
        if actions
    ]

    return {"phases": phases, "total": sum(len(ph["actions"]) for ph in phases)}


def parse_phase_selection(raw: str, available_phases: list[int]) -> list[int]:
    """Parse user phase input into a list of phase numbers.

    Accepts:
        "all"   -> all available phases
        "none"  -> []
        "1"     -> [1]
        "1 2"   -> [1, 2]
        ""      -> []

    Raises ValueError for unknown/invalid phases.
    """
    normalized = raw.strip().lower()
    if not normalized or normalized == "none":
        return []
    if normalized == "all":
        return list(available_phases)

    selected: list[int] = []
    for chunk in normalized.split():
        if not chunk.isdigit():
            raise ValueError(f"Invalid phase: {chunk!r}. Expected phase numbers.")
        p = int(chunk)
        if p not in available_phases:
            raise ValueError(
                f"Phase {p} is not in this plan. Available: {available_phases}"
            )
        if p not in selected:
            selected.append(p)
    return sorted(selected)
