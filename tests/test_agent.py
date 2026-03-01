"""
Tests for the LangGraph agent security gate (should_require_approval)
and the approval_node approval/denial paths.
"""

from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, ToolMessage

from aws_lighthouse.agent import (
    SAFE_TOOLS,
    approval_node,
    should_require_approval,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DESTRUCTIVE_TOOLS = {
    "tool_write_file",
    "tool_execute_bash",
    "terminate_ec2",
    "delete_ebs",
    "s3_block_public_access",
    "tool_read_file",  # intentionally removed from SAFE_TOOLS — must require approval
}


def _state(tool_calls: list) -> dict:
    """Build a minimal AgentState dict with one AIMessage."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = tool_calls
    msg.content = ""
    return {"messages": [msg]}


def _tc(name: str) -> dict:
    """Shorthand for a tool call dict."""
    return {"name": name, "id": f"call-{name}", "args": {}}


# ---------------------------------------------------------------------------
# should_require_approval — routing logic
# ---------------------------------------------------------------------------


def test_no_tool_calls_returns_end():
    assert should_require_approval(_state([])) == "end"


def test_every_safe_tool_bypasses_approval():
    """Every entry in SAFE_TOOLS must route directly to 'tools', not 'approval'."""
    for name in SAFE_TOOLS:
        result = should_require_approval(_state([_tc(name)]))
        assert result == "tools", (
            f"Expected 'tools' for safe tool {name!r} but got {result!r}. "
            "If this tool is mutative, remove it from SAFE_TOOLS."
        )


def test_destructive_tool_requires_approval():
    for name in _DESTRUCTIVE_TOOLS:
        result = should_require_approval(_state([_tc(name)]))
        assert result == "approval", (
            f"Expected 'approval' for destructive tool {name!r} but got {result!r}."
        )


def test_mixed_batch_with_one_destructive_requires_approval():
    """A batch containing any destructive tool must go through approval."""
    tcs = [_tc("tool_get_ec2_inventory"), _tc("terminate_ec2")]
    assert should_require_approval(_state(tcs)) == "approval"


def test_unknown_tool_name_requires_approval():
    """An unrecognised tool name must never silently bypass approval."""
    assert (
        should_require_approval(_state([_tc("tool_injected_by_prompt")])) == "approval"
    )


def test_tool_read_file_is_not_in_safe_tools():
    """tool_read_file must require approval — it can access sensitive local paths."""
    assert "tool_read_file" not in SAFE_TOOLS, (
        "tool_read_file must NOT be in SAFE_TOOLS. "
        "It can read ~/.aws/credentials and ~/.ssh/id_rsa without restriction."
    )


def test_safe_tools_contains_no_destructive_tools():
    """No destructive tool may appear in SAFE_TOOLS."""
    overlap = SAFE_TOOLS & _DESTRUCTIVE_TOOLS
    assert not overlap, (
        f"Destructive tools found in SAFE_TOOLS: {overlap}. "
        "This silently removes user approval for those tools."
    )


# ---------------------------------------------------------------------------
# approval_node — approval path
# ---------------------------------------------------------------------------


def test_approval_node_returns_empty_dict_on_approval():
    """Approval must return {} (empty state update), not None."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2")]
    msg.content = "I will terminate the instance."
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="y"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result == {}, (
        "approval_node must return {} on approval to satisfy the LangGraph node contract."
    )


# ---------------------------------------------------------------------------
# approval_node — denial path
# ---------------------------------------------------------------------------


def test_approval_node_denial_injects_tool_message_per_call():
    """On denial, one ToolMessage rejection must be returned per pending tool call."""
    tc1 = {"name": "terminate_ec2", "id": "call-abc", "args": {"instance_ids": ["i-1"]}}
    tc2 = {"name": "delete_ebs", "id": "call-def", "args": {"volume_ids": ["vol-1"]}}
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [tc1, tc2]
    msg.content = ""
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result is not None
    assert "messages" in result
    rejections = result["messages"]
    assert len(rejections) == 2
    ids = {r.tool_call_id for r in rejections}
    assert ids == {"call-abc", "call-def"}
    for r in rejections:
        assert isinstance(r, ToolMessage)
        assert "denied" in r.content.lower()


def test_approval_node_denial_does_not_return_none():
    """Denial must never return None — that would be interpreted as approval."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2")]
    msg.content = ""
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result is not None, (
        "approval_node returned None on denial. "
        "This is equivalent to approving the action."
    )
