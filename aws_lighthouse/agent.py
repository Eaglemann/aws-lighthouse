# ruff: noqa: E402
import json
from typing import TypedDict, Annotated, Sequence
from langchain_core.messages import BaseMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.tools import tool

from .logger import logger
from .tools.bash import read_file, write_file, execute_bash


# 1. State Definition
class AgentState(TypedDict):
    """The complete state of the LangGraph execution loop."""

    messages: Annotated[Sequence[BaseMessage], add_messages]
    # We will expand this with approval states in Step 3.3


# 2. LLM Initialization
# Using the model strictly defined by the user for complex orchestration
llm = ChatOllama(model="gpt-oss:120b-cloud", temperature=0)


# 3. Tool Binding
# Convert bare functions to LangChain @tools based on Bash specs from Phase 1
@tool
def tool_read_file(filepath: str, max_lines: int = None) -> str:
    """Reads the contents of a local file safely."""
    # Convert kwargs to BaseModel instance dynamically or pass directly
    from .tools.bash import ReadFileInput

    return read_file(ReadFileInput(filepath=filepath, max_lines=max_lines))


@tool
def tool_write_file(filepath: str, content: str, overwrite: bool = False) -> str:
    """Writes content to a local file, creating parent directories if needed."""
    from .tools.bash import WriteFileInput

    return write_file(
        WriteFileInput(filepath=filepath, content=content, overwrite=overwrite)
    )


@tool
def tool_execute_bash(command: str, cwd: str = None, timeout_seconds: int = 60) -> str:
    """Executes a bash command and returns stdout/stderr."""
    from .tools.bash import ExecuteBashInput

    res = execute_bash(
        ExecuteBashInput(command=command, cwd=cwd, timeout_seconds=timeout_seconds)
    )
    return json.dumps(res)


from .tools.remediation import terminate_ec2, delete_ebs
from .tools.security import s3_block_public_access
from .tools.terraform import parse_terraform_context
from .tools.inventory import get_ec2_inventory, get_rds_inventory, get_s3_inventory

tools = [
    tool_read_file,
    tool_write_file,
    tool_execute_bash,
    terminate_ec2,
    delete_ebs,
    s3_block_public_access,
    parse_terraform_context,
    get_ec2_inventory,
    get_rds_inventory,
    get_s3_inventory,
]

llm_with_tools = llm.bind_tools(tools)

from langgraph.prebuilt import ToolNode


# 4. Node Constructors
def agent_node(state: AgentState):
    """The primary reasoning node."""
    logger.action_start("Agent is thinking...")
    response = llm_with_tools.invoke(state["messages"])
    return {"messages": [response]}


# The ToolNode executes the functions requested by the LLM
tool_node = ToolNode(tools)


def approval_node(state: AgentState):
    """The Human-in-the-loop intercept node."""
    import typer

    # Find the last AIMessage with tool calls
    last_message = state["messages"][-1]

    logger.print_header("AWS Lighthouse - Execution Plan")
    logger.warn("The agent has proposed the following infrastructure changes:")

    if last_message.content:
        logger.console.print(f"\n[bold yellow]Agent Reasoning:[/bold yellow]\n{last_message.content}\n")

    for tc in last_message.tool_calls:
        logger.step(f"Tool: [bold cyan]{tc['name']}[/bold cyan]")
        logger.step(f"Arguments: {json.dumps(tc['args'], indent=2)}")

    choice = typer.prompt("\nDo you approve these actions? (y/n)", default="n")
    if choice.lower() != "y":
        logger.error("User denied the execution plan.")
        # Returning a synthetic tool error so the LLM knows it was rejected
        from langchain_core.messages import ToolMessage

        rejections = []
        for tc in last_message.tool_calls:
            rejections.append(
                ToolMessage(
                    content="User explicitly denied execution of this tool.",
                    tool_call_id=tc["id"],
                )
            )
        return {"messages": rejections}

    logger.success("Execution plan approved. Proceeding...")
    return None  # Proceed down the state graph


SAFE_TOOLS = {"tool_read_file", "parse_terraform_context", "get_ec2_inventory", "get_rds_inventory", "get_s3_inventory"}


def should_require_approval(state: AgentState) -> str:
    """Routing logic to intercept dangerous tools before they hit ToolNode."""
    last_message = state["messages"][-1]
    if not last_message.tool_calls:
        return "end"

    # Only require approval if at least one called tool is destructive
    for tc in last_message.tool_calls:
        if tc["name"] not in SAFE_TOOLS:
            return "approval"

    return "tools"


def create_agent_graph() -> StateGraph:
    """Instantiate and compile the baseline LangGraph agent."""
    workflow = StateGraph(AgentState)

    workflow.add_node("agent", agent_node)
    workflow.add_node("approval", approval_node)
    workflow.add_node("tools", tool_node)

    workflow.set_entry_point("agent")

    # After the agent thinks, it either ends, goes to approval, or runs safe tools directly
    workflow.add_conditional_edges(
        "agent", should_require_approval, {"end": END, "approval": "approval", "tools": "tools"}
    )

    # After approval, we execute tools
    workflow.add_edge("approval", "tools")

    # After tools execute, we go back to the agent
    workflow.add_edge("tools", "agent")

    return workflow.compile()
