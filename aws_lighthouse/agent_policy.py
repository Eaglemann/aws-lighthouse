"""Fail-closed approval classification for the local LangGraph agent."""

from collections.abc import Iterable

AUTO_APPROVED_TOOL_NAMES = frozenset(
    {
        "tool_get_enabled_regions",
        "tool_get_ec2_inventory",
        "tool_get_rds_inventory",
        "tool_get_s3_inventory",
        "tool_get_lambda_inventory",
        "tool_get_ri_sp_coverage",
        "tool_get_ri_sp_recommendations",
        "tool_detect_cost_anomalies",
        "tool_get_cost_attribution",
        "tool_get_compute_optimizer",
        "tool_get_tag_cost_coverage",
        "tool_get_effective_rates",
        "tool_get_scenario_plan",
        "tool_estimate_build_cost",
        "tool_plan_remediation",
        "tool_get_sg_blast_radius",
        "tool_run_cost_scan",
        "tool_check_tagging_compliance",
        "tool_detect_overpermissive_iam",
        "tool_detect_cloudwatch_gaps",
        "tool_run_security_scan",
        "tool_list_opportunities",
        "tool_get_opportunity_details",
        "tool_plan_opportunities",
    }
)


def tool_batch_requires_approval(tool_names: Iterable[str]) -> bool:
    """Return true when any tool is sensitive or unknown."""
    return any(name not in AUTO_APPROVED_TOOL_NAMES for name in tool_names)
