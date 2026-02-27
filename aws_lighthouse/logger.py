from rich.console import Console
from rich.panel import Panel


class LighthouseLogger:
    """Custom logger for rendering beautiful, standardized Terminal output using Rich."""

    def __init__(self):
        self.console = Console()

    def print_header(self, title: str):
        """Prints a major section header."""
        self.console.print(
            Panel.fit(f"[bold blue]{title}[/bold blue]", border_style="blue")
        )

    def action_start(self, message: str):
        """Prints the start of a minor action or sequence."""
        self.console.print(
            f"[{self.console.get_datetime().strftime('%H:%M:%S')}] [cyan]▶[/cyan] {message}"
        )

    def success(self, message: str):
        """Prints a success indicator."""
        self.console.print(f"[green]✓[/green] [bold green]{message}[/bold green]")

    def error(self, message: str):
        """Prints a red error indicator."""
        self.console.print(f"[red]✗[/red] [bold red]{message}[/bold red]")

    def warn(self, message: str):
        """Prints a yellow warning indicator."""
        self.console.print(f"[yellow]![/yellow] [bold yellow]{message}[/bold yellow]")

    def step(self, message: str):
        """Prints a minor granular step trace."""
        self.console.print(f"    [dim]- {message}[/dim]")


logger = LighthouseLogger()
