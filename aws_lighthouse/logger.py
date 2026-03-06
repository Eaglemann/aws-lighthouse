import traceback
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel


class LighthouseLogger:
    """Custom logger for rendering beautiful, standardized Terminal output using Rich."""

    def __init__(self) -> None:
        self.console = Console()
        self._error_capture_stack: list[list[str]] = []
        self._log_dir = Path.home() / ".aws-lighthouse" / "logs"
        self._log_path = self._log_dir / "aws-lighthouse.log"

    def _ensure_log_dir(self) -> None:
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_dir.chmod(0o700)

    def _write_log_entry(
        self, level: str, message: str, detail: str | None = None
    ) -> None:
        try:
            self._ensure_log_dir()
            timestamp = datetime.now(UTC).isoformat()
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {level} {message}\n")
                if detail:
                    f.write(detail.rstrip() + "\n")
                f.write("\n")
        except OSError:
            # Logging must never break the main CLI flow.
            return

    def get_log_path(self) -> Path:
        self._ensure_log_dir()
        return self._log_path

    def tail_log(self, lines: int = 80) -> str:
        log_path = self.get_log_path()
        if not log_path.exists():
            return "No log file has been created yet."
        try:
            with log_path.open(encoding="utf-8") as f:
                content = f.readlines()
        except OSError as exc:
            return f"Unable to read log file: {exc}"
        return "".join(content[-max(lines, 1) :]).rstrip() or "Log file is empty."

    def print_header(self, title: str) -> None:
        """Prints a major section header."""
        self.console.print(
            Panel.fit(f"[bold blue]{title}[/bold blue]", border_style="blue")
        )

    def action_start(self, message: str) -> None:
        """Prints the start of a minor action or sequence."""
        self.console.print(
            f"[{self.console.get_datetime().strftime('%H:%M:%S')}] [cyan]▶[/cyan] {message}"
        )

    def success(self, message: str) -> None:
        """Prints a success indicator."""
        self.console.print(f"[green]✓[/green] [bold green]{message}[/bold green]")

    def error(self, message: str) -> None:
        """Prints a red error indicator."""
        self.console.print(f"[red]✗[/red] [bold red]{message}[/bold red]")
        self.console.print(f"[dim]Log file: {self.get_log_path()}[/dim]")
        if self._error_capture_stack:
            self._error_capture_stack[-1].append(message)
        self._write_log_entry("ERROR", message)

    def record_exception(self, message: str, exc: BaseException) -> str:
        """Persist an exception traceback to the log file without printing it."""
        summary = f"{message}: {type(exc).__name__}: {exc}"
        traceback_text = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        if self._error_capture_stack:
            self._error_capture_stack[-1].append(summary)
        self._write_log_entry("ERROR", summary, traceback_text)
        return str(self.get_log_path())

    def exception(self, message: str, exc: BaseException) -> str:
        """Print an exception summary and persist the traceback to the log file."""
        summary = f"{message}: {type(exc).__name__}: {exc}"
        log_path = self.record_exception(message, exc)
        self.console.print(f"[red]✗[/red] [bold red]{summary}[/bold red]")
        self.console.print(f"[dim]Traceback written to {log_path}[/dim]")
        return log_path

    def warn(self, message: str) -> None:
        """Prints a yellow warning indicator."""
        self.console.print(f"[yellow]⚠ [/yellow] [bold yellow]{message}[/bold yellow]")

    def step(self, message: str) -> None:
        """Prints a minor granular step trace."""
        self.console.print(f"    [dim]- {message}[/dim]")

    @contextmanager
    def capture_errors(self) -> Generator[list[str], None, None]:
        """Capture logger.error messages emitted inside this context."""
        buf: list[str] = []
        self._error_capture_stack.append(buf)
        try:
            yield buf
        finally:
            self._error_capture_stack.pop()


logger = LighthouseLogger()
