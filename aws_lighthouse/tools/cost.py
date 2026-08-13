from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ScanResult


def get_monthly_cost_summary(days: int = 14) -> ScanResult:
    """Retrieve AWS Unblended costs for the past N days, grouped by service."""
    ce = get_client("ce")
    str_end = datetime.today().strftime("%Y-%m-%d")
    str_start = (datetime.today() - timedelta(days=days)).strftime("%Y-%m-%d")
    base_data = {
        "period": f"{str_start} to {str_end}",
        "start": str_start,
        "end": str_end,
        "total_usd": 0.0,
        "breakdown": {},
    }

    try:
        # Granularity MONTHLY requires full month alignment, switch to DAILY for arbitrary days
        response = ce.get_cost_and_usage(
            TimePeriod={"Start": str_start, "End": str_end},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )

        service_costs: dict[str, float] = {}
        total_cost = 0.0

        # Aggregate the daily results
        for day in response.get("ResultsByTime", []):
            for group in day.get("Groups", []):
                service = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if service in service_costs:
                    service_costs[service] += amount
                else:
                    service_costs[service] = amount
                total_cost += amount

        # Sort top costs descending
        sorted_sc = dict(
            sorted(service_costs.items(), key=lambda i: i[1], reverse=True)[:15]
        )

        data = {
            **base_data,
            "total_usd": total_cost,
            "breakdown": sorted_sc,
        }
        return ok_result(data)

    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to retrieve cost explorer metrics: {e!s}")
        return error_result(
            data=base_data,
            errors=[
                scan_error_from_exception(
                    service="ce",
                    operation="GetCostAndUsage",
                    exc=e,
                )
            ],
        )


def get_cost_forecast(forecast_days: int = 30) -> ScanResult:
    """Retrieve a 30-day cost forecast using AWS Cost Explorer's ML model.

    Calls ``GetCostForecast`` with UNBLENDED_COST at MONTHLY granularity and
    requests an 80% prediction interval. Cost Explorer requires the forecast
    to start on the current date; the end is ``forecast_days`` days from today.

    Returns:
        ScanResult with data dict containing:
          ``forecast_start``  — ISO date the forecast period begins
          ``forecast_end``    — ISO date the forecast period ends
          ``total_usd``       — mean point estimate for the period ($)
          ``lower_bound_usd`` — sum of per-period lower interval bounds ($)
          ``upper_bound_usd`` — sum of per-period upper interval bounds ($)
    """
    today = datetime.now(UTC).date()
    forecast_start = today
    forecast_end = today + timedelta(days=forecast_days)
    base_data: dict[str, object] = {
        "forecast_start": forecast_start.isoformat(),
        "forecast_end": forecast_end.isoformat(),
        "total_usd": None,
        "lower_bound_usd": None,
        "upper_bound_usd": None,
    }
    try:
        ce = get_client("ce")
        response = ce.get_cost_forecast(
            TimePeriod={
                "Start": forecast_start.isoformat(),
                "End": forecast_end.isoformat(),
            },
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
            PredictionIntervalLevel=80,
        )
        total = response.get("Total", {})
        prediction = response.get("ForecastResultsByTime", [])

        def _sum_interval(key: str) -> float | None:
            values = [period.get(key) for period in prediction]
            if not values or any(value is None for value in values):
                return None
            return sum(float(value) for value in values)

        lower = _sum_interval("PredictionIntervalLowerBound")
        upper = _sum_interval("PredictionIntervalUpperBound")
        return ok_result(
            {
                **base_data,
                "total_usd": float(total.get("Amount", 0) or 0),
                "lower_bound_usd": lower,
                "upper_bound_usd": upper,
            }
        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to retrieve cost forecast: {e}")
        return error_result(
            data=base_data,
            errors=[
                scan_error_from_exception(
                    service="ce", operation="GetCostForecast", exc=e
                )
            ],
        )
