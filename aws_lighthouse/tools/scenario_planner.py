"""Cost Scenario Planner -- model savings from EC2 migration (Graviton, latest-gen)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ScanError, ScanResult, ScenarioEntry, ScenarioPlan

# ---------------------------------------------------------------------------
# Instance-family mapping tables
# ---------------------------------------------------------------------------

# Maps x86 instance family -> Graviton equivalent family
_GRAVITON_MAP: dict[str, str] = {
    # General purpose
    "m4": "m6g",
    "m5": "m7g",
    "m5a": "m7g",
    "m5n": "m7g",
    "m6i": "m7g",
    "m6a": "m7g",
    # Compute optimised
    "c4": "c6g",
    "c5": "c7g",
    "c5a": "c7g",
    "c5n": "c7g",
    "c6i": "c7g",
    "c6a": "c7g",
    # Memory optimised
    "r4": "r6g",
    "r5": "r7g",
    "r5a": "r7g",
    "r5n": "r7g",
    "r6i": "r7g",
    # Burstable
    "t2": "t4g",
    "t3": "t4g",
    "t3a": "t4g",
}

# Maps old-gen family -> current-gen equivalent family (same architecture)
_LATEST_GEN_MAP: dict[str, str] = {
    "m1": "m5",
    "m2": "r5",
    "m3": "m5",
    "m4": "m5",
    "c1": "c5",
    "c3": "c5",
    "c4": "c5",
    "r3": "r5",
    "r4": "r5",
    "i2": "i3",
    "d2": "d3",
    "t1": "t3",
    "t2": "t3",
}

_SCENARIO_MAPS: dict[str, dict[str, str]] = {
    "graviton": _GRAVITON_MAP,
    "latest-gen": _LATEST_GEN_MAP,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INSTANCE_TYPE_RE = re.compile(r"BoxUsage:([a-z][0-9][a-z0-9]*\.[a-z0-9]+)")


def _parse_instance_type_from_usage(usage_type: str) -> str | None:
    """Parse EC2 instance type from a Cost Explorer usage type string.

    Examples:
        >>> _parse_instance_type_from_usage("USE1-BoxUsage:m5.large")
        'm5.large'
        >>> _parse_instance_type_from_usage("NatGateway-Hours")
        # None
    """
    match = _INSTANCE_TYPE_RE.search(usage_type)
    return match.group(1) if match else None


def _map_instance_type(instance_type: str, scenario: str) -> str | None:
    """Map *instance_type* to a target under the given *scenario*.

    Returns ``None`` when the family is not in the mapping table or the
    instance type string is malformed.
    """
    parts = instance_type.split(".")
    if len(parts) != 2:
        return None
    family, size = parts
    mapping = _SCENARIO_MAPS.get(scenario, {})
    target_family = mapping.get(family)
    if target_family is None:
        return None
    return f"{target_family}.{size}"


def _get_ec2_price(pricing_client: object, instance_type: str) -> float | None:
    """Look up on-demand hourly price for *instance_type* via the Pricing API.

    Always queries ``us-east-1`` Linux/Shared/NA/Used filters.
    Returns ``None`` when the price cannot be determined.
    """
    try:
        response = pricing_client.get_products(  # type: ignore[attr-defined]
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "EQUALS", "Field": "instanceType", "Value": instance_type},
                {"Type": "EQUALS", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "EQUALS", "Field": "tenancy", "Value": "Shared"},
                {"Type": "EQUALS", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "EQUALS", "Field": "capacitystatus", "Value": "Used"},
            ],
            MaxResults=10,
        )
        for price_str in response.get("PriceList", []):
            price_item = json.loads(price_str)
            od = price_item.get("terms", {}).get("OnDemand", {})
            for term in od.values():
                for dim in term.get("priceDimensions", {}).values():
                    price = float(dim["pricePerUnit"].get("USD", "0"))
                    if price > 0:
                        return price
        return None
    except (ClientError, BotoCoreError, KeyError, ValueError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def get_scenario_plan(
    scenario: str = "graviton",
    days: int = 30,
    region: str | None = None,
) -> ScanResult:
    """Model cost impact of migrating EC2 instances under *scenario*.

    Reads current EC2 usage from Cost Explorer, maps each instance type to the
    target alternative, looks up on-demand prices, and computes projected
    monthly savings.

    Args:
        scenario: ``"graviton"`` or ``"latest-gen"``.
        days: Look-back window in days (default 30).
        region: Unused -- CE and Pricing are always queried in ``us-east-1``.

    Returns:
        ScanResult with ``data`` as a :class:`ScenarioPlan` dict.
    """
    if scenario not in _SCENARIO_MAPS:
        err: ScanError = {
            "service": "scenario_planner",
            "operation": "validate",
            "code": "InvalidScenario",
            "message": (
                f"Unknown scenario '{scenario}'. Valid: {list(_SCENARIO_MAPS)}"
            ),
        }
        return error_result(data={}, errors=[err])

    ce = get_client("ce", "us-east-1")
    pricing = get_client("pricing", "us-east-1")

    end = datetime.now(UTC).date()
    start = end - timedelta(days=days)

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost", "UsageQuantity"],
            GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["Amazon EC2"]}},
        )
    except (ClientError, BotoCoreError) as e:
        return error_result(
            data={},
            errors=[
                scan_error_from_exception(
                    service="ce", operation="GetCostAndUsage", exc=e
                )
            ],
        )

    # Aggregate usage_type -> {cost, qty} across all periods
    aggregated: dict[str, dict[str, float]] = {}
    for result in resp.get("ResultsByTime", []):
        for group in result.get("Groups", []):
            usage_type = group["Keys"][0] if group.get("Keys") else ""
            metrics = group.get("Metrics", {})
            cost = float(metrics.get("AmortizedCost", {}).get("Amount", "0"))
            qty = float(metrics.get("UsageQuantity", {}).get("Amount", "0"))
            if usage_type not in aggregated:
                aggregated[usage_type] = {"cost": 0.0, "qty": 0.0}
            aggregated[usage_type]["cost"] += cost
            aggregated[usage_type]["qty"] += qty

    # Build entries -- only BoxUsage (EC2 instance hours) that can be mapped
    entries: list[ScenarioEntry] = []
    price_cache: dict[str, float | None] = {}

    for usage_type, vals in aggregated.items():
        cost = vals["cost"]
        qty = vals["qty"]
        if cost < 0.01 or qty == 0:
            continue
        # Parse instance type from usage_type
        instance_type = _parse_instance_type_from_usage(usage_type)
        if instance_type is None:
            continue
        target = _map_instance_type(instance_type, scenario)
        if target is None:
            continue

        # Current effective rate
        current_rate = cost / qty

        # Look up target list price
        if target not in price_cache:
            price_cache[target] = _get_ec2_price(pricing, target)
        target_rate = price_cache[target]

        projected_cost = target_rate * qty if target_rate is not None else None
        monthly_savings = (
            (cost - projected_cost) if projected_cost is not None else None
        )
        savings_pct = (
            (monthly_savings / cost * 100)
            if monthly_savings is not None and cost > 0
            else None
        )

        entries.append(
            {
                "current_instance_type": instance_type,
                "target_instance_type": target,
                "usage_hours": round(qty, 1),
                "current_rate": round(current_rate, 6),
                "target_rate": round(target_rate, 6)
                if target_rate is not None
                else None,
                "current_monthly_cost": round(cost, 2),
                "projected_monthly_cost": (
                    round(projected_cost, 2) if projected_cost is not None else None
                ),
                "monthly_savings": (
                    round(monthly_savings, 2) if monthly_savings is not None else None
                ),
                "savings_pct": (
                    round(savings_pct, 1) if savings_pct is not None else None
                ),
            }
        )

    # Sort by monthly_savings desc (None last)
    entries.sort(key=lambda x: x["monthly_savings"] or 0, reverse=True)

    total_current = sum(e["current_monthly_cost"] for e in entries)
    total_projected_list = [
        e["projected_monthly_cost"]
        for e in entries
        if e["projected_monthly_cost"] is not None
    ]
    total_projected = sum(total_projected_list) if total_projected_list else None
    total_savings = (
        (total_current - total_projected) if total_projected is not None else None
    )

    plan: ScenarioPlan = {
        "scenario": scenario,
        "total_current_cost": round(total_current, 2),
        "total_projected_cost": (
            round(total_projected, 2) if total_projected is not None else None
        ),
        "total_monthly_savings": (
            round(total_savings, 2) if total_savings is not None else None
        ),
        "entries": entries,
    }
    return ok_result(plan)
