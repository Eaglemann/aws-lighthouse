import asyncio

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..logger import logger


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
            async with stdio_client(self._server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.tools = await load_mcp_tools(session)
                    logger.success(
                        f"Successfully loaded {len(self.tools)} tools from AWS MCP."
                    )
                    return self.tools
        except Exception as e:
            logger.error(f"Failed to initialize AWS MCP Server: {str(e)}")
            return []


mcp_manager = AWSMCPManager()


def get_mcp_tools() -> list[BaseTool]:
    """Sync wrapper to fetch the MCP tools."""
    # This assumes we are in a running event loop, or we can use asyncio.run
    try:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(mcp_manager.initialize_tools())
    except RuntimeError:
        return asyncio.run(mcp_manager.initialize_tools())
