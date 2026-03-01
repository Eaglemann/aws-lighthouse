import os
import re
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# These are standard functions, not Langchain `@tool`s yet,
# so they can be easily tested and reused. We will wrap them in `@tool` later.

# Paths the LLM must never read or write — checked after symlink/.. resolution.
_BLOCKED_PREFIXES: tuple[str, ...] = tuple(
    str(Path(p).expanduser())
    for p in (
        "~/.aws",
        "~/.ssh",
        "~/.gnupg",
        "~/.config/gcloud",
    )
)
_BLOCKED_EXACT: frozenset[str] = frozenset(
    {
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/master.passwd",
    }
)


def _is_blocked_path(filepath: str) -> bool:
    """Return True if the resolved path falls under a sensitive prefix or exact block."""
    try:
        resolved = str(Path(filepath).expanduser().resolve())
    except (OSError, ValueError):
        resolved = str(Path(filepath).expanduser())
    if resolved in _BLOCKED_EXACT:
        return True
    return any(
        resolved == prefix or resolved.startswith(prefix + os.sep)
        for prefix in _BLOCKED_PREFIXES
    )


# Regex patterns for catastrophically destructive shell commands.
# Each entry: (compiled pattern, human-readable description shown in the error).
# The guard fires BEFORE the approval step — these commands are never presented
# to the user for approval, regardless of how the LLM was prompted.
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # rm with recursive flag targeting / or /* — wipes the root filesystem
    (
        re.compile(
            r"\brm\b"
            r"(?=.*\s(-[a-zA-Z]*[rR]|--recursive))"  # must have -r/-R/--recursive
            r".+\s/(?![a-zA-Z0-9_.~])",  # final path resolves to / (not /tmp/... etc.)
            re.DOTALL,
        ),
        "recursive delete of the root filesystem ('rm -rf /')",
    ),
    # curl/wget piped directly to a shell interpreter — arbitrary remote code execution
    (
        re.compile(
            r"\b(curl|wget)\b[^|&;\n]*\|\s*(bash|sh|zsh|ksh|fish|python3?|perl|ruby)\b",
            re.IGNORECASE,
        ),
        "piping remote content to a shell interpreter (remote code execution risk)",
    ),
    # mkfs — immediately formats a disk partition, irreversible data loss
    (
        re.compile(r"\bmkfs\b"),
        "filesystem format command (mkfs)",
    ),
    # dd writing to a raw block device — overwrites disk data sector by sector
    (
        re.compile(r"\bdd\b.*\bof=/dev/\w", re.IGNORECASE),
        "raw disk write via dd (of=/dev/...)",
    ),
    # Redirect stdout directly to a block device node
    (
        re.compile(
            r">\s*/dev/(sd[a-z]|hd[a-z]|vd[a-z]|nvme|xvd[a-z]|disk)",
            re.IGNORECASE,
        ),
        "stdout redirect to raw block device",
    ),
    # Fork bomb :(){:|:&};:
    (
        re.compile(r":\s*\(\s*\)\s*\{"),
        "fork bomb",
    ),
    # shred on a device node — destroys all data on the disk
    (
        re.compile(r"\bshred\b.+/dev/\w", re.IGNORECASE),
        "disk shred (shred /dev/...)",
    ),
]


def _is_dangerous_command(command: str) -> str | None:
    """Return a human-readable description if the command matches a blocked dangerous
    pattern, or None if the command is safe to present for approval.
    """
    for pattern, description in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return description
    return None


class ReadFileInput(BaseModel):
    filepath: str = Field(
        description="The absolute or relative path to the file to read."
    )
    max_lines: int | None = Field(
        None,
        description="Maximum number of lines to read to avoid blowing up context window.",
    )


def read_file(args: ReadFileInput) -> str:
    """Reads the contents of a local file."""
    if _is_blocked_path(args.filepath):
        return f"Error: Access to '{args.filepath}' is blocked for security reasons."
    if not os.path.exists(args.filepath):
        return f"Error: File '{args.filepath}' does not exist."
    try:
        with open(args.filepath, encoding="utf-8") as f:
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
    if _is_blocked_path(args.filepath):
        return f"Error: Writing to '{args.filepath}' is blocked for security reasons."
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
    cwd: str | None = Field(None, description="The working directory to execute in.")
    timeout_seconds: int = Field(60, description="Max execution time before aborting.")


def execute_bash(args: ExecuteBashInput) -> dict[str, Any]:
    """Executes a bash command and returns stdout, stderr, and return code."""
    danger = _is_dangerous_command(args.command)
    if danger:
        return {
            "stdout": "",
            "stderr": f"Blocked: command matches a dangerous pattern — {danger}.",
            "returncode": -1,
            "error": f"Blocked: {danger}",
        }
    try:
        result = subprocess.run(  # noqa: S602 — intentional: executes user-approved shell commands
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
