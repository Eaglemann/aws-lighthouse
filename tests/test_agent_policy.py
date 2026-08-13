from aws_lighthouse.agent_policy import (
    AUTO_APPROVED_TOOL_NAMES,
    tool_batch_requires_approval,
)


def test_read_only_inventory_tool_is_auto_approved():
    assert "tool_get_ec2_inventory" in AUTO_APPROVED_TOOL_NAMES
    assert not tool_batch_requires_approval(["tool_get_ec2_inventory"])


def test_local_reads_and_mutations_are_not_auto_approved():
    assert tool_batch_requires_approval(
        [
            "parse_terraform_context",
            "tool_get_terraform_drift",
            "tool_update_opportunity",
        ]
    )


def test_unknown_tool_fails_closed():
    assert tool_batch_requires_approval(["prompt_injected_tool"])


def test_mixed_batch_requires_approval():
    assert tool_batch_requires_approval(["tool_get_ec2_inventory", "terminate_ec2"])
