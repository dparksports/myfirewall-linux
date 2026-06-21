import sys, os, time, signal
from threading import Event
from rich.live import Live
from rich.table import Table
from rich.console import Console

tty_fd = os.open(os.ttyname(0), os.O_WRONLY)
tty_file = os.fdopen(tty_fd, 'w')

term = os.get_terminal_size(0)
console = Console(file=tty_file, force_terminal=True, width=term.columns, height=term.lines)

resize_event = Event()
def handler(signum, frame):
    term = os.get_terminal_size(0)
    console._width = term.columns
    console._height = term.lines
    # console.clear() # <- We omit this!
    resize_event.set()

signal.signal(signal.SIGWINCH, handler)

def get_table():
    term = os.get_terminal_size(0)
    t = Table(title=f"Terminal {term.columns}x{term.lines}", expand=True)
    t.add_column("Col1")
    t.add_column("Col2")
    max_rows = max(1, term.lines - 8)
    for i in range(max_rows):
        t.add_row(f"Row {i}", "Data")
    return t

try:
    with Live(get_table(), console=console, screen=True, auto_refresh=False) as live:
        while True:
            live.update(get_table(), refresh=True)
            woken = resize_event.wait(timeout=1.0)
            if woken:
                resize_event.clear()
except KeyboardInterrupt:
    pass
