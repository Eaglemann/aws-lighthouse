import os
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from ..logger import logger


class ParseTerraformInput(BaseModel):
    directory: str = Field(
        description="The absolute path to the directory containing .tf files."
    )


@tool("parse_terraform_context")
def parse_terraform_context(args: ParseTerraformInput) -> str:
    """Reads all .tf files in a directory to provide context to the LLM on existing infrastructure."""
    if not os.path.exists(args.directory):
        return f"Error: Directory '{args.directory}' does not exist."

    tf_files = [f for f in os.listdir(args.directory) if f.endswith(".tf")]
    if not tf_files:
        return f"No .tf files found in {args.directory}."

    context = f"Found {len(tf_files)} Terraform files in {args.directory}:\n\n"
    for f in tf_files:
        filepath = os.path.join(args.directory, f)
        try:
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                context += f"--- {f} ---\n{content}\n\n"
        except Exception as e:
            context += f"Error reading {f}: {str(e)}\n\n"

    # Truncate if insanely large to protect context window
    if len(context) > 100000:
        return context[:100000] + "\n...[TRUNCATED DUE TO SIZE]..."

    logger.success(
        f"Successfully parsed {len(tf_files)} Terraform files for LLM context."
    )
    return context
