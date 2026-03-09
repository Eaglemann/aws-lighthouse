"""AWS Compute Optimizer — EC2 rightsizing and Graviton migration recommendations."""

import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ComputeOptimizerRecommendation, ScanResult

# Regex to detect Graviton instance types: family + generation + "g" suffix before size dot.
# Matches m7g.large, c6g.xlarge, t4g.nano, x2gd.metal, im4gn.large, is4gen.xlarge, etc.
_GRAVITON_RE = re.compile(r"^[a-z]+[0-9]+g[a-z]*\.")


def _is_graviton(instance_type: str) -> bool:
    """Return True if the instance type is an AWS Graviton-based type."""
    return bool(_GRAVITON_RE.match(instance_type))


def _build_recommendation_reason(finding: str, reason_codes: list[str]) -> str:
    """Build a human-readable recommendation reason from finding + reason codes."""
    if reason_codes:
        return f"{finding} ({', '.join(reason_codes)})"
    return finding


def get_compute_optimizer_recommendations(
    region: str | None = None,
    max_results: int = 100,
) -> ScanResult:
    """
    Fetch EC2 rightsizing and Graviton migration recommendations from
    AWS Compute Optimizer.

    Returns ``ok_result(list[ComputeOptimizerRecommendation])`` sorted by
    estimated_monthly_savings_usd descending.
    """
    try:
        ct = get_client("compute-optimizer", region=region)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise Compute Optimizer client: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="compute-optimizer",
                    operation="CreateClient",
                    exc=e,
                )
            ],
        )

    try:
        kwargs: dict[str, Any] = {"maxResults": min(max_results, 100)}
        raw: list[dict[str, Any]] = []
        while True:
            resp = ct.get_ec2_instance_recommendations(**kwargs)
            raw.extend(resp.get("instanceRecommendations", []))
            if "nextToken" not in resp or len(raw) >= max_results:
                break
            kwargs["nextToken"] = resp["nextToken"]
        raw = raw[:max_results]
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch Compute Optimizer recommendations: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="compute-optimizer",
                    operation="GetEC2InstanceRecommendations",
                    exc=e,
                )
            ],
        )

    recommendations: list[ComputeOptimizerRecommendation] = []
    for rec in raw:
        # Skip already-optimal instances
        if rec.get("finding") == "Optimized":
            continue

        options = rec.get("recommendationOptions", [])
        if not options:
            continue

        option = options[0]
        recommended_type = option.get("instanceType", "")
        if not recommended_type:
            continue

        # Extract savings from savingsOpportunity if available
        savings_opp = option.get("savingsOpportunity", {})
        savings_value = savings_opp.get("estimatedMonthlySavings", {})
        savings_usd = float(savings_value.get("value", 0.0))
        savings_pct = float(savings_opp.get("savingsOpportunityPercentage", 0.0))

        instance_id = rec.get("instanceArn", "").rsplit("/", 1)[-1]
        finding = rec.get("finding", "")
        reason_codes = rec.get("findingReasonCodes", [])

        recommendations.append(
            ComputeOptimizerRecommendation(
                account_id=rec.get("accountId", ""),
                instance_id=instance_id,
                instance_name=rec.get("instanceName", ""),
                current_type=rec.get("currentInstanceType", ""),
                recommended_type=recommended_type,
                estimated_monthly_savings_usd=savings_usd,
                estimated_savings_pct=savings_pct,
                performance_risk=str(option.get("performanceRisk", "Low")),
                recommendation_reason=_build_recommendation_reason(
                    finding, reason_codes
                ),
                is_graviton=_is_graviton(recommended_type),
                region=region,
            )
        )

    recommendations.sort(key=lambda r: r["estimated_monthly_savings_usd"], reverse=True)
    return ok_result(recommendations)
