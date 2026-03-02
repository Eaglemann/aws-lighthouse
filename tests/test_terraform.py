"""
Tests for parse_terraform_context in aws_lighthouse/tools/terraform.py.
"""

from pathlib import Path

import pytest

from aws_lighthouse.tools.terraform import ParseTerraformInput, parse_terraform_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call(directory: str) -> str:
    """Call the underlying function directly (bypasses the LangChain tool wrapper)."""
    return parse_terraform_context.func(ParseTerraformInput(directory=directory))


# ---------------------------------------------------------------------------
# Path security — blocked directories and symlink targets
# ---------------------------------------------------------------------------


def test_blocked_directory_returns_error():
    """~/.aws must be rejected before the filesystem is touched."""
    aws_dir = str(Path("~/.aws").expanduser())
    result = _call(aws_dir)
    assert "blocked" in result.lower()


def test_blocked_directory_ssh_returns_error():
    result = _call(str(Path("~/.ssh").expanduser()))
    assert "blocked" in result.lower()


def test_path_traversal_attempt_is_blocked():
    """A path with .. components that resolves into ~/.aws must be rejected."""
    home = Path("~").expanduser()
    # /home/user/some_dir/../.aws  →  /home/user/.aws  (blocked)
    traversal = str(home / "some_dir" / ".." / ".aws")
    result = _call(traversal)
    assert "blocked" in result.lower()


def test_symlink_to_blocked_path_is_skipped(tmp_path):
    """A .tf file that is a symlink to a sensitive directory must be skipped, not read."""
    aws_creds = Path("~/.aws/credentials").expanduser()
    if not aws_creds.exists():
        pytest.skip("~/.aws/credentials not present — symlink target does not exist")

    # Create a symlink inside tmp_path pointing at ~/.aws/credentials
    link = tmp_path / "sneaky.tf"
    link.symlink_to(aws_creds)

    result = _call(str(tmp_path))
    # The file must appear as blocked, not be read into context
    assert "blocked" in result.lower()
    # The real credentials content must not appear in the output
    assert "aws_access_key_id" not in result.lower()
    assert "aws_secret_access_key" not in result.lower()


# ---------------------------------------------------------------------------
# Normal error paths
# ---------------------------------------------------------------------------


def test_directory_not_found_returns_error():
    result = _call("/nonexistent/path/for/lighthouse/test")
    assert "does not exist" in result.lower()


def test_no_tf_files_returns_informative_message(tmp_path):
    (tmp_path / "main.txt").write_text("hello")
    result = _call(str(tmp_path))
    assert "no .tf files" in result.lower()


# ---------------------------------------------------------------------------
# Content reading
# ---------------------------------------------------------------------------


def test_reads_tf_files_into_context(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
    (tmp_path / "variables.tf").write_text('variable "env" {}')

    result = _call(str(tmp_path))
    assert "main.tf" in result
    assert "variables.tf" in result
    assert 'resource "aws_s3_bucket"' in result
    assert 'variable "env"' in result


def test_non_tf_files_are_ignored(tmp_path):
    (tmp_path / "main.tf").write_text("# tf content")
    (tmp_path / "readme.md").write_text("# should not appear")

    result = _call(str(tmp_path))
    assert "readme.md" not in result
    assert "should not appear" not in result


def test_content_truncated_when_oversized(tmp_path):
    # Write a .tf file larger than 100 000 characters
    (tmp_path / "big.tf").write_text("x" * 110_000)
    result = _call(str(tmp_path))
    assert "TRUNCATED" in result
    assert len(result) <= 110_000  # output is bounded


def test_unreadable_file_adds_error_to_context(tmp_path):
    tf_file = tmp_path / "locked.tf"
    tf_file.write_text("secret")
    # Make the file unreadable
    tf_file.chmod(0o000)
    try:
        result = _call(str(tmp_path))
        assert "locked.tf" in result
        assert "error" in result.lower()
    finally:
        tf_file.chmod(0o644)  # restore so tmp_path cleanup works
