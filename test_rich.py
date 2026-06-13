import os
from rich.console import Console
from rich.live import Live
from rich.table import Table

os.environ["TERM"] = "dumb"

console = Console(force_terminal=True)
table = Table(title="Test Table")
table.add_column("Col1")
table.add_row("A")

with Live(table, console=console, screen=True):
    print("Live rendered")
