"""Cost allocation tag enforcer: untagged spend by required tag key via Cost Explorer."""

from datetime import date, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..scan_contract import error_result, ok_result
from ..types import ScanResult, UntaggedSpend

_DEFAULT_TAG_KEYS: list[str] = ["Environment", "Project", "Owner", "CostCenter"]


def get_untagged_spend(
    tag_keys: list[str] | None = None,
    days: int = 30,
    region: str | None = None,
) -> ScanResult:
    """Return untagged vs tagged spend for each required tag key."""
    keys = tag_keys if tag_keys is not None else _DEFAULT_TAG_KEYS
    end = date.today()
    start = end - timedelta(days=days)
    try:
        ce = get_client("ce", region=region)
        results: list[UntaggedSpend] = []
        for tag_key in keys:
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "TAG", "Key": tag_key}],
            )
            untagged_usd = 0.0
            total_usd = 0.0
            for period in resp.get("ResultsByTime", []):
                for group in period.get("Groups", []):
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    total_usd += amount
                    tag_value = group["Keys"][0].split("$", 1)[-1]
                    if tag_value == "":
                        untagged_usd += amount
            if total_usd <= 0:
                continue
            tagged_usd = total_usd - untagged_usd
            results.append(
                UntaggedSpend(
                    tag_key=tag_key,
                    untagged_usd=round(untagged_usd, 2),
                    tagged_usd=round(tagged_usd, 2),
                    total_usd=round(total_usd, 2),
                    untagged_pct=round(untagged_usd / total_usd * 100, 1),
                    period_days=days,
                )
            )
        results.sort(key=lambda r: r["untagged_usd"], reverse=True)
        return ok_result(results)
    except (ClientError, BotoCoreError) as exc:
        return error_result(
            data=[],
            errors=[
                {
                    "code": (
                        getattr(exc, "response", {})
                        .get("Error", {})
                        .get("Code", "CE_ERROR")
                        if hasattr(exc, "response")
                        else "CE_ERROR"
                    ),
                    "message": str(exc),
                    "service": "ce",
                    "operation": "get_cost_and_usage",
                }
            ],
        )
