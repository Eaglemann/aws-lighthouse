import subprocess
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

# These are standard functions, not Langchain `@tool`s yet,
# so they can be easily tested and reused. We will wrap them in `@tool` later.


class ReadFileInput(BaseModel):
    filepath: str = Field(
        description="The absolute or relative path to the file to read."
    )
    max_lines: Optional[int] = Field(
        None,
        description="Maximum number of lines to read to avoid blowing up context window.",
    )


def read_file(args: ReadFileInput) -> str:
    """Reads the contents of a local file safely."""
    if not os.path.exists(args.filepath):
        return f"Error: File '{args.filepath}' does not exist."
    try:
        with open(args.filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if args.max_lines and len(lines) > args.max_lines:
                return "".join(lines[: args.max_lines]) + "\n...[TRUNCATED]..."
            return "".join(lines)
    except Exception as e:
        return f"Error reading file '{args.filepath}': {str(e)}"


class WriteFileInput(BaseModel):
    filepath: str = Field(
        description="The absolute or relative path to the file to write."
    )
    content: str = Field(
        description="The complete string content to write to the file."
    )
    overwrite: bool = Field(
        False, description="Whether to overwrite if the file already exists."
    )


def write_file(args: WriteFileInput) -> str:
    """Writes content to a local file, creating parent directories if needed."""
    if os.path.exists(args.filepath) and not args.overwrite:
        return f"Error: File '{args.filepath}' exists and overwrite is set to False."
    try:
        os.makedirs(os.path.dirname(os.path.abspath(args.filepath)), exist_ok=True)
        with open(args.filepath, "w", encoding="utf-8") as f:
            f.write(args.content)
        return f"Successfully wrote to {args.filepath}"
    except Exception as e:
        return f"Error writing file '{args.filepath}': {str(e)}"


class ExecuteBashInput(BaseModel):
    command: str = Field(description="The bash command string to execute.")
    cwd: Optional[str] = Field(None, description="The working directory to execute in.")
    timeout_seconds: int = Field(60, description="Max execution time before aborting.")


def execute_bash(args: ExecuteBashInput) -> Dict[str, Any]:
    """Executes a bash command and returns stdout, stderr, and return code."""
    try:
        result = subprocess.run(
            args.command,
            shell=True,
            cwd=args.cwd,
            capture_output=True,
            text=True,
            timeout=args.timeout_seconds,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {args.timeout_seconds} seconds.",
            "returncode": -1,
            "error": "Timeout",
        }
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "error": str(e)}
