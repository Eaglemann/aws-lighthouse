"""Tests for file-backed LighthouseLogger behavior."""

import io

from rich.console import Console

from aws_lighthouse.logger import LighthouseLogger


def test_record_exception_writes_traceback_and_tail_reads_it(tmp_path):
    logger = LighthouseLogger()
    logger._log_dir = tmp_path
    logger._log_path = tmp_path / "aws-lighthouse.log"

    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        log_path = logger.record_exception("Shell agent turn failed", exc)

    assert log_path == str(tmp_path / "aws-lighthouse.log")
    content = logger.tail_log(lines=20)
    assert "Shell agent turn failed" in content
    assert "RuntimeError: boom" in content


def test_tail_log_reports_missing_file(tmp_path):
    logger = LighthouseLogger()
    logger._log_dir = tmp_path
    logger._log_path = tmp_path / "aws-lighthouse.log"

    assert logger.tail_log(lines=20) == "No log file has been created yet."


def test_error_can_be_logged_without_terminal_output(tmp_path):
    logger = LighthouseLogger()
    logger._log_dir = tmp_path
    logger._log_path = tmp_path / "aws-lighthouse.log"
    buf = io.StringIO()
    logger.console = Console(file=buf, no_color=True, highlight=False)

    logger.error("Expected degraded scan condition", detail="raw detail", display=False)

    assert buf.getvalue() == ""
    content = logger.tail_log(lines=20)
    assert "Expected degraded scan condition" in content
    assert "raw detail" in content
