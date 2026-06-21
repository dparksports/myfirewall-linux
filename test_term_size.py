#!/usr/bin/env python3
"""Test what get_term_size returns under various fd redirections."""
import os
import sys

# Test 1: Normal state
print("=== Normal state ===")
for fd in (0, 1, 2):
    try:
        size = os.get_terminal_size(fd)
        print(f"  fd {fd}: {size.columns}x{size.lines}")
    except OSError as e:
        print(f"  fd {fd}: OSError - {e}")

# Test 2: After redirecting stdout and stderr to /dev/null (like main() does)
devnull_fd = os.open(os.devnull, os.O_WRONLY)
orig_1 = os.dup(1)
orig_2 = os.dup(2)
os.dup2(devnull_fd, 1)
os.dup2(devnull_fd, 2)

# Now test using fd 0 (stdin) 
try:
    size = os.get_terminal_size(0)
    # Can't print to stdout now, write to file
    with open("/tmp/term_test_result.txt", "w") as f:
        f.write(f"After redirect, fd 0: {size.columns}x{size.lines}\n")
except OSError as e:
    with open("/tmp/term_test_result.txt", "w") as f:
        f.write(f"After redirect, fd 0: OSError - {e}\n")

# Restore
os.dup2(orig_1, 1)
os.dup2(orig_2, 2)
os.close(devnull_fd)

with open("/tmp/term_test_result.txt") as f:
    print(f.read())
