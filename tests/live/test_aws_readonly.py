"""Read-only live qualification against an explicitly identified AWS sandbox."""

import os

import boto3
import pytest
from langchain_core.messages import AIMessage

from aws_lighthouse.agent import should_require_approval, tool_get_enabled_regions
from aws_lighthouse.auth import profile_context
from aws_lighthouse.live_qualification import (
    LiveQualificationError,
    load_aws_live_config,
    verify_expected_aws_identity,
)
from aws_lighthouse.tools.inventory import (
    get_ec2_inventory,
    get_lambda_inventory,
    get_rds_inventory,
    get_s3_inventory,
)
from aws_lighthouse.tools.multi_region import get_enabled_regions

pytestmark = [pytest.mark.integration, pytest.mark.live]


def _config():
    try:
        return load_aws_live_config(os.environ)
    except LiveQualificationError as exc:
        pytest.skip(str(exc))


def _assert_scan_acceptable(result, *, allow_partial):
    assert set(result) == {"ok", "data", "errors"}
    if not allow_partial:
        assert result["ok"], result["errors"]


def test_read_only_scans_and_agent_tool_against_expected_sandbox():
    config = _config()
    session = boto3.Session(profile_name=config.profile)
    verify_expected_aws_identity(session, config.expected_account_id)

    with profile_context(config.profile):
        enabled = get_enabled_regions()
        _assert_scan_acceptable(enabled, allow_partial=config.allow_partial_permissions)
        discovered = list(enabled["data"])
        regions = list(config.regions or tuple(discovered[:2]))
        assert regions, "no enabled region available for qualification"

        for region in regions:
            assert region in discovered
            for scanner in (
                get_ec2_inventory,
                get_rds_inventory,
                get_lambda_inventory,
            ):
                _assert_scan_acceptable(
                    scanner(region=region),
                    allow_partial=config.allow_partial_permissions,
                )
        _assert_scan_acceptable(
            get_s3_inventory(), allow_partial=config.allow_partial_permissions
        )

        tool_payload = tool_get_enabled_regions.invoke({})
        assert tool_payload


def test_live_agent_approval_gate_never_executes_mutation_implicitly():
    _config()
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "terminate_ec2",
                "id": "live-approval-proof",
                "args": {"instance_id": "i-never-executed"},
            }
        ],
    )
    assert should_require_approval({"messages": [message]}) == "approval"
