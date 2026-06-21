#!/usr/bin/env python3
"""Measure exact output of Rich Live with screen=True at 100x24."""
from rich.table import Table
from rich.console import Console
from rich.live import Live
import io

def make_table(num_rows):
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.title = (
        "[bold cyan]NETWORK-MONITOR LIVE FEED[/] "
        "[dim white](Rx: 0.12 MB/s | Tx: 0.34 MB/s)[/]"
    )
    
    proc_width = max(16, 100 // 5)
    ip_width = max(22, 100 // 4)
    table.add_column("#",             justify="right", style="cyan",       no_wrap=True, width=3)
    table.add_column("Proto",         style="bold blue",                   no_wrap=True, width=5)
    table.add_column("Dir",           style="bold yellow",                 no_wrap=True, width=4)
    table.add_column("Process",       style="green",                       no_wrap=True, max_width=proc_width)
    table.add_column("PID",           justify="right", style="dim yellow",  no_wrap=True, width=7)
    table.add_column("Remote Address",                                      no_wrap=True, max_width=ip_width)
    
    for i in range(num_rows):
        table.add_row(str(i+1), "TCP", "OUT", "chrome", "12345", "142.251.155.2")
    
    table.caption = (
        "[bold white]Q[/] Quit  |  [bold white]B[/] Block  |  [bold white]I[/] Ignore  "
        "|  [bold white]D[/] Detail  |  [bold white]L[/] Blocked  |  [bold white]H[/] Help"
    )
    return table

# Test with Live screen=True to see actual rendering
buf = io.StringIO()
console = Console(file=buf, width=100, height=24, force_terminal=True)

# Simulate what Live does with screen=True
# Live uses console.screen() which creates a ScreenContext
# Then it renders the content into the screen area

# Let's check what height Live actually uses
from rich.screen import Screen
from rich.text import Text

for num_rows in [10, 12, 14, 16]:
    table = make_table(num_rows)
    
    # Render table to segments to count lines
    rendered_lines = console.render_lines(table, console.options, pad=True)
    line_count = len(rendered_lines)
    
    # Screen renders at console.height lines
    screen = Screen(table, style="")
    screen_lines = console.render_lines(screen, console.options.update_height(24), pad=True)
    screen_line_count = len(screen_lines)
    
    print(f"{num_rows} data rows -> table: {line_count} lines, screen: {screen_line_count} lines")
    if line_count > 24:
        print(f"  *** OVERFLOW by {line_count - 24} lines ***")
