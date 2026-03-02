from datetime import UTC, datetime, timedelta
from typing import Any

from ..auth import get_client
from ..logger import logger


def get_ri_sp_coverage(days: int = 30) -> dict[str, Any]:
    """
    Fetch Reserved Instance and Savings Plan coverage + utilization from
    AWS Cost Explorer for the given look-back window.

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

    # ── RI Coverage ───────────────────────────────────────────────────────────
    try:
        resp = ce.get_reservation_coverage(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        result["ri_coverage_pct"] = float(
            totals.get("CoverageHours", {}).get("CoverageHoursPercentage", 0) or 0
        )
        result["ri_on_demand_cost"] = float(
            totals.get("CoverageCost", {}).get("OnDemandCost", 0) or 0
        )
    except Exception as e:
        logger.error(f"Failed to fetch RI coverage: {e}")
        result["ri_coverage_pct"] = None
        result["ri_on_demand_cost"] = None

    # ── RI Utilization ────────────────────────────────────────────────────────
    try:
        resp = ce.get_reservation_utilization(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        result["ri_utilization_pct"] = float(
            totals.get("UtilizationPercentage", 0) or 0
        )
        result["ri_unused_cost"] = float(totals.get("UnusedRecurringFee", 0) or 0)
    except Exception as e:
        logger.error(f"Failed to fetch RI utilization: {e}")
        result["ri_utilization_pct"] = None
        result["ri_unused_cost"] = None

    # ── SP Coverage ───────────────────────────────────────────────────────────
    try:
        resp = ce.get_savings_plans_coverage(TimePeriod=period, Granularity="MONTHLY")
        cov = resp.get("Total", {}).get("Coverage", {})
        result["sp_coverage_pct"] = float(cov.get("CoveragePercentage", 0) or 0)
        result["sp_on_demand_cost"] = float(cov.get("OnDemandCost", 0) or 0)
    except Exception as e:
        logger.error(f"Failed to fetch SP coverage: {e}")
        result["sp_coverage_pct"] = None
        result["sp_on_demand_cost"] = None

    # ── SP Utilization ────────────────────────────────────────────────────────
    try:
        resp = ce.get_savings_plans_utilization(
            TimePeriod=period, Granularity="MONTHLY"
        )
        util = resp.get("Total", {}).get("Utilization", {})
        result["sp_utilization_pct"] = float(util.get("UtilizationPercentage", 0) or 0)
        result["sp_unused_commitment"] = float(util.get("UnusedCommitment", 0) or 0)
    except Exception as e:
        logger.error(f"Failed to fetch SP utilization: {e}")
        result["sp_utilization_pct"] = None
        result["sp_unused_commitment"] = None

    return result
