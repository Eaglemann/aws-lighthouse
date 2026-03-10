"""Effective Rate Analysis — compares amortized spend rates to on-demand list prices."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import EffectiveRateEntry, ScanResult

_INSTANCE_TYPE_RE = re.compile(r"BoxUsage:([a-z][0-9][a-z0-9]*\.[a-z0-9]+)")


def _parse_instance_type(usage_type: str) -> str | None:
    """Parse EC2 instance type from a Cost Explorer usage type string.

    Examples:
        >>> _parse_instance_type("USE1-BoxUsage:m5.large")
        'm5.large'
        >>> _parse_instance_type("NatGateway-Hours")
        # None
    """
    match = _INSTANCE_TYPE_RE.search(usage_type)
    return match.group(1) if match else None


def _get_ec2_list_price(
    pricing_client: object, instance_type: str, region_name: str
) -> float | None:
    """Look up the on-demand hourly price for an EC2 instance type via the Pricing API.

    Returns ``None`` when the price cannot be determined (API error, no results, etc.).
    The pricing client must target ``us-east-1``.
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


def get_effective_rates(
    days: int = 30, top_n: int = 15, region: str | None = None
) -> ScanResult:
    """Compute effective hourly rates from amortized spend and compare to list prices.

    Queries Cost Explorer for ``AmortizedCost`` and ``UsageQuantity`` grouped by
    SERVICE and USAGE_TYPE, then looks up on-demand list prices for EC2 instance
    types via the Pricing API to derive a discount percentage.

    Args:
        days: Look-back window in days (default 30).
        top_n: Number of top entries to return, sorted by total cost descending.
        region: Unused — CE and Pricing are always queried in ``us-east-1``.

    Returns:
        ScanResult with ``data`` as a list of :class:`EffectiveRateEntry` dicts.
    """
    ce = get_client("ce", "us-east-1")
    pricing = get_client("pricing", "us-east-1")

    end = datetime.now(UTC).date()
    start = end - timedelta(days=days)

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost", "UsageQuantity"],
            GroupBy=[
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        )
    except (ClientError, BotoCoreError) as e:
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="ce", operation="GetCostAndUsage", exc=e
                )
            ],
        )

    # Aggregate across all months (MONTHLY granularity may return multiple periods)
    aggregated: dict[tuple[str, str], dict[str, float]] = {}
    for result in resp.get("ResultsByTime", []):
        for group in result.get("Groups", []):
            keys = group.get("Keys", ["", ""])
            service = keys[0] if len(keys) > 0 else ""
            usage_type = keys[1] if len(keys) > 1 else ""
            metrics = group.get("Metrics", {})
            cost = float(metrics.get("AmortizedCost", {}).get("Amount", "0"))
            qty = float(metrics.get("UsageQuantity", {}).get("Amount", "0"))
            key = (service, usage_type)
            if key not in aggregated:
                aggregated[key] = {"cost": 0.0, "qty": 0.0}
            aggregated[key]["cost"] += cost
            aggregated[key]["qty"] += qty

    # Build entries, filter to meaningful ones (cost > $0.01)
    entries: list[EffectiveRateEntry] = []
    for (service, usage_type), vals in aggregated.items():
        cost = vals["cost"]
        qty = vals["qty"]
        if cost < 0.01:
            continue
        effective_rate = cost / qty if qty > 0 else 0.0
        instance_type = _parse_instance_type(usage_type)
        entries.append(
            {
                "service": service,
                "usage_type": usage_type,
                "instance_type": instance_type,
                "total_cost_usd": round(cost, 4),
                "usage_quantity": round(qty, 4),
                "effective_rate": round(effective_rate, 6),
                "list_rate": None,
                "discount_pct": None,
            }
        )

    # Sort by total_cost_usd desc, take top_n
    entries.sort(key=lambda x: x["total_cost_usd"], reverse=True)
    entries = entries[:top_n]

    # Look up list prices for EC2 entries; cache by instance_type
    price_cache: dict[str, float | None] = {}
    for entry in entries:
        itype = entry["instance_type"]
        if itype is None:
            continue
        if itype not in price_cache:
            price_cache[itype] = _get_ec2_list_price(pricing, itype, "us-east-1")
        list_rate = price_cache[itype]
        entry["list_rate"] = list_rate
        if list_rate and entry["effective_rate"] > 0 and list_rate > 0:
            entry["discount_pct"] = round(
                (1 - entry["effective_rate"] / list_rate) * 100, 1
            )

    return ok_result(entries)
