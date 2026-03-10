import asyncio
import threading
from collections.abc import Awaitable, Callable

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..logger import logger

_MCP_INIT_TIMEOUT_SECONDS = 20.0


class AWSMCPManager:
    """Manages the lifecycle of the AWS MCP Server via NPX."""

    def __init__(self):
        self._server_params = StdioServerParameters(
            command="npx", args=["-y", "@aws-mcp/server"], env=None
        )
        self.tools: list[BaseTool] = []

    async def initialize_tools(self) -> list[BaseTool]:
        """Spins up the MCP server and extracts Langchain-compatible tools."""
        if self.tools:
            return self.tools

        logger.action_start(
            "Starting the official AWS MCP Server in the background via NPX..."
        )
        try:
            # We use langchain-mcp-adapters for rapid, clean tool parsing
            async with (
                stdio_client(self._server_params) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                self.tools = await load_mcp_tools(session)
                logger.success(
                    f"Successfully loaded {len(self.tools)} tools from AWS MCP."
                )
                return self.tools
        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to initialize AWS MCP Server: {e!s}")
            return []


mcp_manager = AWSMCPManager()


def _run_coro_in_new_thread(
    *,
    factory: Callable[[], Awaitable[list[BaseTool]]],
    timeout_seconds: float,
) -> list[BaseTool]:
    """Run an async initializer on a dedicated event loop thread with timeout."""
    result: list[BaseTool] = []
    error: Exception | None = None

    def _runner() -> None:
        nonlocal result, error
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            coro = factory()
            result = loop.run_until_complete(
                asyncio.wait_for(coro, timeout=timeout_seconds)
            )
        except Exception as exc:
            error = exc
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds + 1.0)

    if thread.is_alive():
        logger.error(
            f"Timed out waiting for AWS MCP initialization after {timeout_seconds:.1f}s."
        )
        return []
    if isinstance(error, TimeoutError):
        logger.error(
            f"Timed out waiting for AWS MCP initialization after {timeout_seconds:.1f}s."
        )
        return []
    if error:
        logger.error(f"AWS MCP initialization failed: {error!s}")
        return []
    return result


def get_mcp_tools() -> list[BaseTool]:
    """Sync wrapper to fetch MCP tools without event-loop deadlocks."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            return asyncio.run(
                asyncio.wait_for(
                    mcp_manager.initialize_tools(), timeout=_MCP_INIT_TIMEOUT_SECONDS
                )
            )
        except Exception as exc:
            logger.error(f"AWS MCP initialization failed: {exc!s}")
            return []

    return _run_coro_in_new_thread(
        factory=lambda: mcp_manager.initialize_tools(),
        timeout_seconds=_MCP_INIT_TIMEOUT_SECONDS,
    )
