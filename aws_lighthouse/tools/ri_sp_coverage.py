from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger


def _fetch_ri_coverage(ce, period: dict) -> dict[str, Any]:
    try:
        resp = ce.get_reservation_coverage(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        return {
            "ri_coverage_pct": float(
                totals.get("CoverageHours", {}).get("CoverageHoursPercentage", 0) or 0
            ),
            "ri_on_demand_cost": float(
                totals.get("CoverageCost", {}).get("OnDemandCost", 0) or 0
            ),
        }
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch RI coverage: {e}")
        return {"ri_coverage_pct": None, "ri_on_demand_cost": None}


def _fetch_ri_utilization(ce, period: dict) -> dict[str, Any]:
    try:
        resp = ce.get_reservation_utilization(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        return {
            "ri_utilization_pct": float(totals.get("UtilizationPercentage", 0) or 0),
            "ri_unused_cost": float(totals.get("UnusedRecurringFee", 0) or 0),
        }
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch RI utilization: {e}")
        return {"ri_utilization_pct": None, "ri_unused_cost": None}


def _fetch_sp_coverage(ce, period: dict) -> dict[str, Any]:
    try:
        resp = ce.get_savings_plans_coverage(TimePeriod=period, Granularity="MONTHLY")
        cov = resp.get("Total", {}).get("Coverage", {})
        return {
            "sp_coverage_pct": float(cov.get("CoveragePercentage", 0) or 0),
            "sp_on_demand_cost": float(cov.get("OnDemandCost", 0) or 0),
        }
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch SP coverage: {e}")
        return {"sp_coverage_pct": None, "sp_on_demand_cost": None}


def _fetch_sp_utilization(ce, period: dict) -> dict[str, Any]:
    try:
        resp = ce.get_savings_plans_utilization(
            TimePeriod=period, Granularity="MONTHLY"
        )
        util = resp.get("Total", {}).get("Utilization", {})
        return {
            "sp_utilization_pct": float(util.get("UtilizationPercentage", 0) or 0),
            "sp_unused_commitment": float(util.get("UnusedCommitment", 0) or 0),
        }
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch SP utilization: {e}")
        return {"sp_utilization_pct": None, "sp_unused_commitment": None}


_FETCHERS = [
    _fetch_ri_coverage,
    _fetch_ri_utilization,
    _fetch_sp_coverage,
    _fetch_sp_utilization,
]


def get_ri_sp_coverage(days: int = 30) -> dict[str, Any]:
    """
    Fetch Reserved Instance and Savings Plan coverage + utilization from
    AWS Cost Explorer for the given look-back window.

    The four CE API calls are issued in parallel (ThreadPoolExecutor, 4 workers)
    so total latency is bounded by the slowest single call (~1.5–3 s saved).

    Returned keys (all floats, or None on API error):
      ri_coverage_pct      — % of eligible instance-hours covered by RIs
      ri_on_demand_cost    — uncovered on-demand spend in that window ($)
      ri_utilization_pct   — % of purchased RI capacity actually used
      ri_unused_cost       — recurring fee paid for idle RI capacity ($)
      sp_coverage_pct      — % of eligible spend covered by Savings Plans
      sp_on_demand_cost    — uncovered on-demand spend ($)
      sp_utilization_pct   — % of SP commitment actually consumed
      sp_unused_commitment — dollar value of unused SP commitment ($)
    """
    ce = get_client("ce")  # Cost Explorer is a global service

    end = datetime.now(UTC).date()
    start = end - timedelta(days=days)
    period = {"Start": start.strftime("%Y-%m-%d"), "End": end.strftime("%Y-%m-%d")}

    result: dict[str, Any] = {"period": f"{period['Start']} → {period['End']}"}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fn, ce, period) for fn in _FETCHERS]
        for future in as_completed(futures):
            result.update(future.result())

    return result
