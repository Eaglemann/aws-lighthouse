from datetime import date, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_aws_client
from ..logger import logger
from ..types import CostAnomaly

# Minimum baseline spend (USD) for a service to be evaluated.
# Avoids noise from $0.01 → $0.02 triggering a 100% "anomaly".
_MIN_BASELINE_USD = 1.0


def detect_cost_anomalies(threshold_pct: float = 50.0) -> list[CostAnomaly]:
    """
    Compare the last 7 days of per-service spend against the prior 7-day baseline.
    Returns services whose recent spend exceeds the baseline by more than threshold_pct.
    Services with no prior baseline (new services) or negligible spend are skipped.
    """
    ce = get_aws_client("ce")

    today = date.today()
    end_str = today.strftime("%Y-%m-%d")
    mid_str = (today - timedelta(days=7)).strftime("%Y-%m-%d")
    start_str = (today - timedelta(days=14)).strftime("%Y-%m-%d")

    try:
        response = ce.get_cost_and_usage(
            TimePeriod={"Start": start_str, "End": end_str},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch cost data for anomaly detection: {e}")
        return []

    baseline: dict[str, float] = {}
    recent: dict[str, float] = {}

    for day in response.get("ResultsByTime", []):
        day_start = day["TimePeriod"]["Start"]
        bucket = recent if day_start >= mid_str else baseline
        for group in day.get("Groups", []):
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            bucket[service] = bucket.get(service, 0.0) + amount

    anomalies: list[CostAnomaly] = []
    for service, recent_total in recent.items():
        baseline_total = baseline.get(service, 0.0)

        # Skip new services (no baseline) and negligible spenders
        if baseline_total < _MIN_BASELINE_USD:
            continue

        pct_change = ((recent_total - baseline_total) / baseline_total) * 100
        if pct_change >= threshold_pct:
            anomalies.append(
                {
                    "service": service,
                    "baseline_7d": round(baseline_total, 2),
                    "recent_7d": round(recent_total, 2),
                    "pct_change": round(pct_change, 1),
                }
            )

    anomalies.sort(key=lambda x: float(x["pct_change"]), reverse=True)
    return anomalies
