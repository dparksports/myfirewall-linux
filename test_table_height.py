#!/usr/bin/env python3
"""Measure exact line count of Rich table rendering at 100x24."""
from rich.table import Table
from rich.console import Console
import io

def measure_table(num_rows):
    buf = io.StringIO()
    console = Console(file=buf, width=100, force_terminal=True)
    
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.title = (
        "[bold cyan]NETWORK-MONITOR LIVE FEED[/] "
        "[dim white](Rx: 0.12 MB/s | Tx: 0.34 MB/s)[/]"
    )
    
    # MEDIUM layout (100 cols)
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
    
    console.print(table)
    output = buf.getvalue()
    lines = output.split('\n')
    # Remove trailing empty line if present
    while lines and lines[-1] == '':
        lines.pop()
    return len(lines), output

for n in range(8, 18):
    line_count, output = measure_table(n)
    fits = "✓" if line_count <= 24 else "✗"
    print(f"{n} data rows -> {line_count} total lines [{fits}]")

print("\n--- Example with 14 rows ---")
_, output = measure_table(14)
print(output)
print(f"(end of output)")
