#!/usr/bin/env python3
"""Simulate the EXACT rendering pipeline from main() to measure actual output height."""
import os, sys, io
from rich.table import Table
from rich.console import Console
from rich.live import Live

# Simulate what main() does: redirect stdout/stderr, open tty_file
devnull_fd = os.open(os.devnull, os.O_WRONLY)
orig_1 = os.dup(1)
orig_2 = os.dup(2)

# Before redirect - get real size
real_size = None
for fd in (0, 2, 1):
    try:
        real_size = os.get_terminal_size(fd)
        break
    except OSError:
        continue

os.dup2(devnull_fd, 1)
os.dup2(devnull_fd, 2)

# Now try get_term_size() the same way the code does
def get_term_size():
    for fd in (0, 2, 1):
        try:
            size = os.get_terminal_size(fd)
            if size.columns > 0 and size.lines > 0:
                return size
        except (OSError, ValueError):
            continue
    try:
        cols = int(os.environ.get('COLUMNS', 0))
        lines = int(os.environ.get('LINES', 0))
        if cols > 0 and lines > 0:
            return os.terminal_size((cols, lines))
    except ValueError:
        pass
    return os.terminal_size((100, 24))

after_size = get_term_size()

# Open tty like main() does
tty_fd = None
try:
    tty_name = os.ttyname(0)
    tty_fd = os.open(tty_name, os.O_WRONLY)
except Exception:
    try:
        tty_fd = os.dup(orig_1)
    except:
        pass

# Try get_terminal_size on tty_fd
tty_size = None
if tty_fd is not None:
    try:
        tty_size = os.get_terminal_size(tty_fd)
    except OSError:
        pass

# Restore stdout
os.dup2(orig_1, 1)
os.dup2(orig_2, 2)
os.close(devnull_fd)

print(f"Real terminal size (before redirect): {real_size}")
print(f"get_term_size() after redirect: {after_size}")
print(f"os.get_terminal_size(tty_fd) after redirect: {tty_size}")

if tty_fd:
    # Now test Console auto-detection with tty_file
    tty_file = os.fdopen(tty_fd, 'w')
    
    # Console WITH explicit width/height (current code)
    c1 = Console(file=tty_file, force_terminal=True, width=after_size.columns, height=after_size.lines)
    print(f"Console with explicit size: {c1.width}x{c1.height}")
    
    # Console WITHOUT explicit width/height (proposed fix)  
    tty_fd2 = os.open(os.ttyname(0), os.O_WRONLY)
    tty_file2 = os.fdopen(tty_fd2, 'w')
    c2 = Console(file=tty_file2, force_terminal=True)
    print(f"Console with auto-detect: {c2.width}x{c2.height}")
    
    tty_file.close()
    tty_file2.close()
