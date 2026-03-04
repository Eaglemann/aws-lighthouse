import asyncio
from unittest.mock import MagicMock, patch

from langchain_core.tools import BaseTool

from aws_lighthouse.tools.mcp_client import (
    _run_coro_in_new_thread,
    get_mcp_tools,
)


def test_get_mcp_tools_uses_asyncio_run_without_running_loop():
    tools = [MagicMock(spec=BaseTool)]

    async def _ok():
        return tools

    with (
        patch(
            "aws_lighthouse.tools.mcp_client.asyncio.get_running_loop",
            side_effect=RuntimeError,
        ),
        patch("aws_lighthouse.tools.mcp_client.mcp_manager.initialize_tools", new=_ok),
    ):
        result = get_mcp_tools()

    assert result == tools


def test_get_mcp_tools_returns_empty_list_on_timeout():
    async def _slow():
        await asyncio.sleep(0.05)
        return []

    with (
        patch(
            "aws_lighthouse.tools.mcp_client.asyncio.get_running_loop",
            side_effect=RuntimeError,
        ),
        patch("aws_lighthouse.tools.mcp_client._MCP_INIT_TIMEOUT_SECONDS", 0.001),
        patch(
            "aws_lighthouse.tools.mcp_client.mcp_manager.initialize_tools", new=_slow
        ),
        patch("aws_lighthouse.tools.mcp_client.logger.error") as mock_error,
    ):
        result = get_mcp_tools()

    assert result == []
    mock_error.assert_called_once()


def test_get_mcp_tools_uses_thread_path_with_running_loop():
    tools = [MagicMock(spec=BaseTool)]
    with (
        patch(
            "aws_lighthouse.tools.mcp_client.asyncio.get_running_loop",
            return_value=object(),
        ),
        patch(
            "aws_lighthouse.tools.mcp_client._run_coro_in_new_thread",
            return_value=tools,
        ) as run_thread,
    ):
        result = get_mcp_tools()

    assert result == tools
    run_thread.assert_called_once()


def test_run_coro_in_new_thread_returns_result():
    async def _ok():
        return [MagicMock(spec=BaseTool)]

    result = _run_coro_in_new_thread(factory=_ok, timeout_seconds=1.0)
    assert len(result) == 1


def test_run_coro_in_new_thread_times_out():
    async def _slow():
        await asyncio.sleep(0.05)
        return [MagicMock(spec=BaseTool)]

    with patch("aws_lighthouse.tools.mcp_client.logger.error") as mock_error:
        result = _run_coro_in_new_thread(factory=_slow, timeout_seconds=0.001)

    assert result == []
    mock_error.assert_called()


def test_run_coro_in_new_thread_handles_unexpected_exception():
    async def _boom():
        raise ValueError("unexpected")

    with patch("aws_lighthouse.tools.mcp_client.logger.error") as mock_error:
        result = _run_coro_in_new_thread(factory=_boom, timeout_seconds=1.0)

    assert result == []
    mock_error.assert_called_once_with("AWS MCP initialization failed: unexpected")
