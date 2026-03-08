from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import (
    error_result,
    is_expected_unavailable_scan_error,
    ok_result,
    scan_error_from_exception,
)
from ..types import ScanError, ScanResult


def _fetch_ri_coverage(ce, period: dict[str, str]) -> ScanResult:
    try:
        resp = ce.get_reservation_coverage(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        return ok_result(
            {
                "ri_coverage_pct": float(
                    totals.get("CoverageHours", {}).get("CoverageHoursPercentage", 0)
                    or 0
                ),
                "ri_on_demand_cost": float(
                    totals.get("CoverageCost", {}).get("OnDemandCost", 0) or 0
                ),
            }
        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch RI coverage: {e}")
        return error_result(
            data={"ri_coverage_pct": None, "ri_on_demand_cost": None},
            errors=[
                scan_error_from_exception(
                    service="ce",
                    operation="GetReservationCoverage",
                    exc=e,
                )
            ],
        )


def _fetch_ri_utilization(ce, period: dict[str, str]) -> ScanResult:
    try:
        resp = ce.get_reservation_utilization(TimePeriod=period, Granularity="MONTHLY")
        totals = resp.get("Total", {})
        return ok_result(
            {
                "ri_utilization_pct": float(
                    totals.get("UtilizationPercentage", 0) or 0
                ),
                "ri_unused_cost": float(totals.get("UnusedRecurringFee", 0) or 0),
            }
        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch RI utilization: {e}")
        return error_result(
            data={"ri_utilization_pct": None, "ri_unused_cost": None},
            errors=[
                scan_error_from_exception(
                    service="ce",
                    operation="GetReservationUtilization",
                    exc=e,
                )
            ],
        )


def _fetch_sp_coverage(ce, period: dict[str, str]) -> ScanResult:
    try:
        resp = ce.get_savings_plans_coverage(TimePeriod=period, Granularity="MONTHLY")
        cov = resp.get("Total", {}).get("Coverage", {})
        return ok_result(
            {
                "sp_coverage_pct": float(cov.get("CoveragePercentage", 0) or 0),
                "sp_on_demand_cost": float(cov.get("OnDemandCost", 0) or 0),
            }
        )
    except (ClientError, BotoCoreError) as e:
        error = scan_error_from_exception(
            service="ce",
            operation="GetSavingsPlansCoverage",
            exc=e,
        )
        logger.error(
            f"Failed to fetch SP coverage: {e}",
            display=not is_expected_unavailable_scan_error(error),
        )
        return error_result(
            data={"sp_coverage_pct": None, "sp_on_demand_cost": None},
            errors=[error],
        )


def _fetch_sp_utilization(ce, period: dict[str, str]) -> ScanResult:
    try:
        resp = ce.get_savings_plans_utilization(
            TimePeriod=period, Granularity="MONTHLY"
        )
        util = resp.get("Total", {}).get("Utilization", {})
        return ok_result(
            {
                "sp_utilization_pct": float(util.get("UtilizationPercentage", 0) or 0),
                "sp_unused_commitment": float(util.get("UnusedCommitment", 0) or 0),
            }
        )
    except (ClientError, BotoCoreError) as e:
        error = scan_error_from_exception(
            service="ce",
            operation="GetSavingsPlansUtilization",
            exc=e,
        )
        logger.error(
            f"Failed to fetch SP utilization: {e}",
            display=not is_expected_unavailable_scan_error(error),
        )
        return error_result(
            data={"sp_utilization_pct": None, "sp_unused_commitment": None},
            errors=[error],
        )


_FETCHERS = [
    _fetch_ri_coverage,
    _fetch_ri_utilization,
    _fetch_sp_coverage,
    _fetch_sp_utilization,
]


def get_ri_sp_coverage(days: int = 30) -> ScanResult:
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

    result_data: dict[str, float | str | None] = {
        "period": f"{period['Start']} → {period['End']}",
        "ri_coverage_pct": None,
        "ri_on_demand_cost": None,
        "ri_utilization_pct": None,
        "ri_unused_cost": None,
        "sp_coverage_pct": None,
        "sp_on_demand_cost": None,
        "sp_utilization_pct": None,
        "sp_unused_commitment": None,
    }
    errors: list[ScanError] = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fn, ce, period) for fn in _FETCHERS]
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as e:
                logger.error(f"Unexpected error in RI/SP coverage fetch: {e}")
                errors.append(
                    scan_error_from_exception(service="ce", operation="unknown", exc=e)
                )
                continue
            payload = result.get("data", {})
            if isinstance(payload, dict):
                result_data.update(payload)
            errors.extend(result.get("errors", []))

    return error_result(data=result_data, errors=errors)
