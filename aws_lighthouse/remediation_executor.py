"""Typed execution boundary for explicitly approved remediation actions."""

from collections.abc import Callable, Mapping
from typing import Literal, TypedDict

from .types import RemediationAction

RemediationFunction = Callable[..., bool]


class RemediationExecution(TypedDict):
    status: Literal["applied", "failed", "invalid"]
    error: str | None


_REGION_REQUIRED = frozenset(
    {
        "delete_ebs_volume",
        "release_eip",
        "enable_guardduty",
        "enable_cloudtrail_logging",
        "enforce_imdsv2",
    }
)


def remediation_actions() -> Mapping[str, RemediationFunction]:
    """Build the action registry lazily so imports never initialize AWS clients."""
    from .tools.remediation_actions import (
        apply_s3_block_public_access,
        apply_s3_default_encryption,
        delete_ebs_volume,
        enable_cloudtrail_logging,
        enable_guardduty,
        enforce_imdsv2,
        release_eip,
    )

    return {
        "s3_block_public_access": apply_s3_block_public_access,
        "delete_ebs_volume": delete_ebs_volume,
        "release_eip": release_eip,
        "enable_guardduty": enable_guardduty,
        "enable_cloudtrail_logging": enable_cloudtrail_logging,
        "enforce_imdsv2": enforce_imdsv2,
        "s3_default_encryption": apply_s3_default_encryption,
    }


def validate_remediation_action(
    action: RemediationAction,
    *,
    actions: Mapping[str, RemediationFunction] | None = None,
) -> str | None:
    registry = actions if actions is not None else remediation_actions()
    remediation_type = action["remediation_type"]
    if remediation_type not in registry:
        return f"Unknown remediation type: {remediation_type}"
    if remediation_type in _REGION_REQUIRED and not action["region"]:
        return (
            f"Missing region for {remediation_type} on {action['resource']}; skipping."
        )
    return None


def execute_remediation_action(
    action: RemediationAction,
    *,
    actions: Mapping[str, RemediationFunction] | None = None,
) -> RemediationExecution:
    """Execute one already-approved action through the explicit registry."""
    registry = actions if actions is not None else remediation_actions()
    validation_error = validate_remediation_action(action, actions=registry)
    if validation_error:
        return {"status": "invalid", "error": validation_error}

    action_fn = registry[action["remediation_type"]]
    applied = action_fn(action["resource"], region=action["region"])
    return {"status": "applied" if applied else "failed", "error": None}
