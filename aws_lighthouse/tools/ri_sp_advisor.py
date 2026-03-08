"""
RI/SP Purchase Advisor — translates Cost Explorer coverage gaps into specific
what-to-buy recommendations with monthly savings, break-even, and hourly
commitment numbers.

Uses:
  ce.get_reservation_purchase_recommendation  — per service (EC2/RDS/ElastiCache/Redshift)
  ce.get_savings_plans_purchase_recommendation — per SP type (Compute/EC2/SageMaker)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import RIRecommendation, ScanError, ScanResult, SPRecommendation

# Services supported by get_reservation_purchase_recommendation.
_RI_SERVICES = [
    "AmazonEC2",
    "AmazonRDS",
    "AmazonElastiCache",
    "AmazonRedshift",
]

# Savings Plan types supported by get_savings_plans_purchase_recommendation.
_SP_TYPES = [
    "COMPUTE_SP",
    "EC2_INSTANCE_SP",
    "SAGEMAKER_SP",
]

_LOOKBACK_MAP = {7: "SEVEN_DAYS", 30: "THIRTY_DAYS", 60: "SIXTY_DAYS"}

_TERM_MAP = {
    "ONE_YEAR": "1yr",
    "THREE_YEARS": "3yr",
}

_PAYMENT_MAP = {
    "NO_UPFRONT": "No Upfront",
    "PARTIAL_UPFRONT": "Partial Upfront",
    "ALL_UPFRONT": "All Upfront",
    "LIGHT_UTILIZATION": "Light Utilization",
    "MEDIUM_UTILIZATION": "Medium Utilization",
    "HEAVY_UTILIZATION": "Heavy Utilization",
}

_SERVICE_DISPLAY = {
    "AmazonEC2": "EC2",
    "AmazonRDS": "RDS",
    "AmazonElastiCache": "ElastiCache",
    "AmazonRedshift": "Redshift",
}

_SP_DISPLAY = {
    "COMPUTE_SP": "Compute SP",
    "EC2_INSTANCE_SP": "EC2 Instance SP",
    "SAGEMAKER_SP": "SageMaker SP",
}


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert CE string-encoded floats to Python float; return default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_instance_details(detail: dict[str, Any]) -> tuple[str, str, str]:
    """
    Extract (instance_type, region, platform) from a RecommendationDetail entry.

    The shape of InstanceDetails varies by service:
    - EC2InstanceDetails  → InstanceType, Region, Platform
    - RDSInstanceDetails  → InstanceType, Region, DatabaseEngine
    - ElastiCacheInstanceDetails → NodeType, Region, ProductDescription
    - RedshiftInstanceDetails    → NodeType, Region
    - ESInstanceDetails          → InstanceClass + InstanceSize, Region
    """
    for key, spec in detail.get("InstanceDetails", {}).items():
        if key == "EC2InstanceDetails":
            return (
                spec.get("InstanceType", ""),
                spec.get("Region", ""),
                spec.get("Platform", ""),
            )
        if key == "RDSInstanceDetails":
            return (
                spec.get("InstanceType", ""),
                spec.get("Region", ""),
                spec.get("DatabaseEngine", ""),
            )
        if key == "ElastiCacheInstanceDetails":
            return (
                spec.get("NodeType", ""),
                spec.get("Region", ""),
                spec.get("ProductDescription", ""),
            )
        if key == "RedshiftInstanceDetails":
            return (spec.get("NodeType", ""), spec.get("Region", ""), "")
        if key == "ESInstanceDetails":
            instance_type = (
                f"{spec.get('InstanceClass', '')}.{spec.get('InstanceSize', '')}"
            )
            return (instance_type, spec.get("Region", ""), "")
    return ("", "", "")


def _fetch_ri_for_service(
    ce: Any,
    service: str,
    lookback_days: int,
    term: str,
    payment_option: str,
) -> list[RIRecommendation]:
    """
    Call get_reservation_purchase_recommendation for one service and parse
    all RecommendationDetails into RIRecommendation dicts.
    """
    lookback_str = _LOOKBACK_MAP.get(lookback_days, "SIXTY_DAYS")
    resp = ce.get_reservation_purchase_recommendation(
        Service=service,
        LookbackPeriodInDays=lookback_str,
        TermInYears=term,
        PaymentOption=payment_option,
    )

    results: list[RIRecommendation] = []
    for rec in resp.get("Recommendations", []):
        term_label = _TERM_MAP.get(
            rec.get("TermInYears", ""), rec.get("TermInYears", "")
        )
        payment_label = _PAYMENT_MAP.get(
            rec.get("PaymentOption", ""), rec.get("PaymentOption", "")
        )
        for detail in rec.get("RecommendationDetails", []):
            instance_type, region, platform = _extract_instance_details(detail)
            count_raw = detail.get("RecommendedNumberOfInstancesToPurchase", "0")
            results.append(
                {
                    "service": _SERVICE_DISPLAY.get(service, service),
                    "instance_type": instance_type,
                    "region": region,
                    "platform": platform,
                    "term": term_label,
                    "payment_option": payment_label,
                    "count": int(_safe_float(count_raw)),
                    "monthly_savings_usd": _safe_float(
                        detail.get("EstimatedMonthlySavingsAmount")
                    ),
                    "break_even_months": _safe_float(
                        detail.get("EstimatedBreakevenInMonths")
                    ),
                    "estimated_monthly_on_demand_usd": _safe_float(
                        detail.get("EstimatedMonthlyOnDemandCost")
                    ),
                    "estimated_monthly_ri_usd": _safe_float(
                        detail.get("EstimatedMonthlyAmortizedOnDemandFee")
                    ),
                    "upfront_cost_usd": _safe_float(detail.get("UpfrontCost")),
                }
            )
    return results


def get_ri_recommendations(
    lookback_days: int = 60,
    term: str = "ONE_YEAR",
    payment_option: str = "NO_UPFRONT",
) -> ScanResult:
    """
    Fetch RI purchase recommendations across AmazonEC2, AmazonRDS,
    AmazonElastiCache, and AmazonRedshift in parallel.

    Returns ``ok_result(list[RIRecommendation])`` sorted by monthly_savings_usd
    descending.  If some services error but others succeed, returns
    ``error_result`` with partial data and the accumulated errors.
    """
    try:
        ce = get_client("ce")
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise CE client for RI advisor: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(service="ce", operation="CreateClient", exc=e)
            ],
        )

    recommendations: list[RIRecommendation] = []
    errors: list[ScanError] = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(
                _fetch_ri_for_service, ce, service, lookback_days, term, payment_option
            ): service
            for service in _RI_SERVICES
        }
        for future in as_completed(futures):
            service = futures[future]
            try:
                recommendations.extend(future.result())
            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to fetch RI recommendations for {service}: {e}")
                errors.append(
                    scan_error_from_exception(
                        service="ce",
                        operation="GetReservationPurchaseRecommendation",
                        exc=e,
                    )
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error fetching RI recommendations for {service}: {e}"
                )

    recommendations.sort(key=lambda r: r["monthly_savings_usd"], reverse=True)

    if errors:
        return error_result(data=recommendations, errors=errors)
    return ok_result(recommendations)


def _fetch_sp_for_type(
    ce: Any,
    sp_type: str,
    lookback_days: int,
    term: str,
    payment_option: str,
    lookback_days_int: int,
) -> SPRecommendation | None:
    """
    Call get_savings_plans_purchase_recommendation for one SP type and parse
    the summary into an SPRecommendation dict.  Returns None if the API
    returns no meaningful recommendation (zero commitment).
    """
    lookback_str = _LOOKBACK_MAP.get(lookback_days, "SIXTY_DAYS")
    resp = ce.get_savings_plans_purchase_recommendation(
        SavingsPlansType=sp_type,
        LookbackPeriodInDays=lookback_str,
        TermInYears=term,
        PaymentOption=payment_option,
    )

    rec = resp.get("SavingsPlansPurchaseRecommendation", {})
    summary = rec.get("SavingsPlansPurchaseRecommendationSummary", {})

    hourly = _safe_float(summary.get("HourlyCommitmentToPurchase"))
    monthly_savings = _safe_float(summary.get("EstimatedMonthlySavingsAmount"))

    # Skip if no useful recommendation
    if hourly <= 0.0 and monthly_savings <= 0.0:
        return None

    # CurrentOnDemandSpend is cumulative over the lookback window; convert to monthly.
    monthly_factor = 30.0 / max(lookback_days_int, 1)
    estimated_monthly_on_demand = (
        _safe_float(summary.get("CurrentOnDemandSpend")) * monthly_factor
    )

    return {
        "savings_plan_type": _SP_DISPLAY.get(sp_type, sp_type),
        "term": _TERM_MAP.get(rec.get("TermInYears", ""), rec.get("TermInYears", "")),
        "payment_option": _PAYMENT_MAP.get(
            rec.get("PaymentOption", ""), rec.get("PaymentOption", "")
        ),
        "hourly_commitment_usd": hourly,
        "estimated_monthly_savings_usd": monthly_savings,
        "estimated_savings_pct": _safe_float(summary.get("EstimatedSavingsPercentage")),
        "estimated_monthly_on_demand_usd": estimated_monthly_on_demand,
        "upfront_cost_usd": _safe_float(summary.get("TotalRecommendationCount", "0"))
        * 0.0,
    }


def get_sp_recommendations(
    lookback_days: int = 60,
    term: str = "ONE_YEAR",
    payment_option: str = "NO_UPFRONT",
) -> ScanResult:
    """
    Fetch Savings Plan purchase recommendations for COMPUTE_SP, EC2_INSTANCE_SP,
    and SAGEMAKER_SP in parallel.

    Returns ``ok_result(list[SPRecommendation])`` sorted by
    estimated_monthly_savings_usd descending.  SP types with no meaningful
    recommendation (zero hourly commitment and zero savings) are excluded.
    """
    try:
        ce = get_client("ce")
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise CE client for SP advisor: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(service="ce", operation="CreateClient", exc=e)
            ],
        )

    recommendations: list[SPRecommendation] = []
    errors: list[ScanError] = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(
                _fetch_sp_for_type,
                ce,
                sp_type,
                lookback_days,
                term,
                payment_option,
                lookback_days,
            ): sp_type
            for sp_type in _SP_TYPES
        }
        for future in as_completed(futures):
            sp_type = futures[future]
            try:
                result = future.result()
                if result is not None:
                    recommendations.append(result)
            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to fetch SP recommendations for {sp_type}: {e}")
                errors.append(
                    scan_error_from_exception(
                        service="ce",
                        operation="GetSavingsPlansPurchaseRecommendation",
                        exc=e,
                    )
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error fetching SP recommendations for {sp_type}: {e}"
                )

    recommendations.sort(key=lambda r: r["estimated_monthly_savings_usd"], reverse=True)

    if errors:
        return error_result(data=recommendations, errors=errors)
    return ok_result(recommendations)
