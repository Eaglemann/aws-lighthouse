"""Fail-closed configuration for opt-in live AWS qualification tests."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class LiveQualificationError(ValueError):
    """Raised when a live test is not bound to an explicitly named sandbox."""


@dataclass(frozen=True)
class AwsLiveConfig:
    profile: str
    expected_account_id: str
    regions: tuple[str, ...]
    allow_partial_permissions: bool


def load_aws_live_config(environment: Mapping[str, str]) -> AwsLiveConfig:
    if environment.get("AWS_LIGHTHOUSE_LIVE_AWS") != "1":
        raise LiveQualificationError(
            "set AWS_LIGHTHOUSE_LIVE_AWS=1 to opt in to live AWS qualification"
        )
    profile = environment.get("AWS_PROFILE", "").strip()
    if not profile:
        raise LiveQualificationError(
            "AWS_PROFILE must name the dedicated Lighthouse sandbox profile"
        )
    expected_account_id = environment.get(
        "AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID", ""
    ).strip()
    if not re.fullmatch(r"\d{12}", expected_account_id):
        raise LiveQualificationError(
            "AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID must be a 12-digit sandbox account ID"
        )
    regions = tuple(
        dict.fromkeys(
            region.strip()
            for region in environment.get("AWS_LIGHTHOUSE_LIVE_REGIONS", "").split(",")
            if region.strip()
        )
    )
    return AwsLiveConfig(
        profile=profile,
        expected_account_id=expected_account_id,
        regions=regions,
        allow_partial_permissions=(
            environment.get("AWS_LIGHTHOUSE_ALLOW_PARTIAL") == "1"
        ),
    )


def verify_expected_aws_identity(
    session: Any, expected_account_id: str
) -> dict[str, str]:
    identity = session.client("sts").get_caller_identity()
    actual_account_id = str(identity.get("Account", ""))
    if actual_account_id != expected_account_id:
        raise LiveQualificationError(
            "AWS account mismatch: expected "
            f"{expected_account_id}, authenticated as {actual_account_id or 'unknown'}"
        )
    return {
        "account_id": actual_account_id,
        "arn": str(identity.get("Arn", "")),
    }
