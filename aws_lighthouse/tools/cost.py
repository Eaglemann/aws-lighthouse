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
        logger.error(f"Failed to retrieve cost explorer metrics: {str(e)}")
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

    Calls ``GetCostForecast`` with UNBLENDED_COST at MONTHLY granularity.
    The forecast start is tomorrow (CE requires future dates); end is
    ``forecast_days`` days from today.

    Returns:
        ScanResult with data dict containing:
          ``forecast_start``  — ISO date the forecast period begins
          ``forecast_end``    — ISO date the forecast period ends
          ``total_usd``       — mean point estimate for the period ($)
          ``lower_bound_usd`` — lower confidence bound ($)
          ``upper_bound_usd`` — upper confidence bound ($)
    """
    today = datetime.now(UTC).date()
    # CE forecast start must be a future date (tomorrow at earliest)
    forecast_start = today + timedelta(days=1)
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
        )
        total = response.get("Total", {})
        prediction = response.get("ForecastResultsByTime", [])
        lower = min((float(p.get("MeanValue", 0)) for p in prediction), default=0.0)
        upper = max((float(p.get("MeanValue", 0)) for p in prediction), default=0.0)
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
