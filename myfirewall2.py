# myfirewall2.py
"""
myfirewall2.py - Bare connection viewer with block and ignore commands.
  B → block/toggle an IP by connection # or raw IP
  I → ignore a process/IP by connection # or name
  Q / Ctrl+C → quit
"""

import sys
import time
import ipaddress
import termios
import tty
import select
from threading import Thread
from rich.live import Live
from rich.table import Table
from rich.console import Console

import myfirewall_core as core

# --- Prompt state (shared between threads) ---
prompt_mode   = None   # None | "BLOCK" | "IGNORE"
input_buffer  = ""


def get_filtered_conns():
    """Returns active, non-local, non-ignored connections."""
    filtered = []
    for c in core.connections_cache:
        ip = c["remote_ip"]
        if core.is_local_ip(ip):
            continue
        if ip in core.ignored_ips:
            continue
        if c["name"] in core.ignored_names:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
            if any(ip_obj in net for net in core.ignored_cidrs):
                continue
        except ValueError:
            pass
        filtered.append(c)
    return filtered


def fmt_duration(first_seen):
    """Formats seconds elapsed since first_seen into a compact string."""
    secs = int(time.time() - first_seen)
    if secs < 0:
        secs = 0
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    h = secs // 3600
    m = (secs % 3600) // 60
    return f"{h}h{m:02d}m"


def fmt_pkts(n):
    """Formats a packet count compactly (None → '—')."""
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)

def generate_table():
    """Builds the live connections table."""
    global prompt_mode, input_buffer

    table = Table(show_header=True, box=None, expand=True, padding=(0, 1))

    mock_tag = " (MOCK MODE)" if core.is_mock_mode() else ""
    table.title = f"[bold cyan]LIVE CONNECTIONS{mock_tag}[/]"

    table.add_column("#",         width=3,  style="cyan",       justify="right")
    table.add_column("Proto",     width=5,  style="bold blue")
    table.add_column("Dir",       width=4,  style="bold yellow")
    table.add_column("Process",   width=22, style="green")
    table.add_column("PID",       width=7,  style="dim yellow", justify="right")
    table.add_column("Remote IP",           style="white")
    table.add_column("Geo / Host",          style="magenta")
    table.add_column("Duration",  width=8,  style="dim cyan",   justify="right")
    table.add_column("Pkts↑",     width=7,  style="dim green",  justify="right")
    table.add_column("Pkts↓",     width=7,  style="dim yellow", justify="right")

    conns = get_filtered_conns()
    now = time.time()
    for i, c in enumerate(conns[:40]):
        ip       = c["remote_ip"]
        proto    = c.get("protocol", "TCP")
        pid      = str(c["pid"]) if c["pid"] else "?"
        dir_val  = c.get("direction", "OUTBOUND")
        dir_disp = "[bold green]IN[/]" if dir_val == "INBOUND" else "[bold blue]OUT[/]"

        geo      = core.geo_cache.get(ip, c.get("geo", ""))
        hostname = core.rdns_cache.get(ip, "")
        geo_disp = f"{geo} / {hostname}" if hostname else geo

        is_blocked = ip in core.blocked_ips
        if is_blocked:
            ip_disp   = f"[bold red]{ip} [BLKD][/]"
            proc_disp = f"[strike red]{c['name']}[/]"
        else:
            ip_disp   = ip
            proc_disp = c["name"]

        duration = fmt_duration(c.get("first_seen", now))
        pkts_tx  = fmt_pkts(c.get("packets_tx"))
        pkts_rx  = fmt_pkts(c.get("packets_rx"))

        table.add_row(str(i + 1), proto, dir_disp, proc_disp, pid, ip_disp, geo_disp,
                      duration, pkts_tx, pkts_rx)

    # Caption: show prompt or key hints
    if prompt_mode == "BLOCK":
        table.caption = f"\n[bold yellow]Block (# or IP): {input_buffer}[/]"
    elif prompt_mode == "IGNORE":
        table.caption = f"\n[bold yellow]Ignore (# or process name): {input_buffer}[/]"
    else:
        table.caption = (
            "\n[bold white]B[/] Block  |  [bold white]I[/] Ignore  |  [bold white]Q[/] Quit"
        )

    return table


# --- Input handlers ---

def handle_block(user_input):
    s = user_input.strip()
    if not s:
        return
    try:
        idx = int(s) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            core.toggle_ip_block(conns[idx]["remote_ip"])
            return
    except ValueError:
        pass
    try:
        ipaddress.ip_address(s)
        core.toggle_ip_block(s)
    except ValueError:
        pass


def handle_ignore(user_input):
    s = user_input.strip()
    if not s:
        return
    try:
        idx = int(s) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            core.toggle_proc_ignore(conns[idx]["name"])
            return
    except ValueError:
        pass
    # Treat as process name or IP
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            if net not in core.ignored_cidrs:
                core.ignored_cidrs.append(net)
                core.save_config()
            return
        ipaddress.ip_address(s)
        core.toggle_ip_ignore(s)
    except ValueError:
        core.toggle_proc_ignore(s)


# --- Keyboard loop ---

def keyboard_input_loop():
    global prompt_mode, input_buffer

    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        while core.running:
            time.sleep(1)
        return

    try:
        tty.setraw(fd)
        while core.running:
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not r:
                continue

            ch = sys.stdin.read(1)
            if not ch:
                break

            # ESC or arrow sequences
            if ord(ch) == 27:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    sys.stdin.read(1)
                    sys.stdin.read(1)
                else:
                    prompt_mode  = None
                    input_buffer = ""
                continue

            # Prompt mode: collect text until Enter
            if prompt_mode:
                if ord(ch) in (10, 13):  # Enter
                    if prompt_mode == "BLOCK":
                        handle_block(input_buffer)
                    elif prompt_mode == "IGNORE":
                        handle_ignore(input_buffer)
                    prompt_mode  = None
                    input_buffer = ""
                elif ord(ch) in (8, 127):  # Backspace
                    input_buffer = input_buffer[:-1]
                elif 32 <= ord(ch) <= 126:
                    input_buffer += ch
                continue

            # Normal key bindings
            c = ch.lower()
            if c == "q" or ord(ch) == 3:   # Q or Ctrl+C
                core.running = False
            elif c == "b":
                prompt_mode  = "BLOCK"
                input_buffer = ""
            elif c == "i":
                prompt_mode  = "IGNORE"
                input_buffer = ""
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except termios.error:
            pass


# --- Main ---

def main():
    core.load_config()
    core.start_core_threads()
    time.sleep(0.5)

    t_input = Thread(target=keyboard_input_loop, daemon=True)
    t_input.start()

    console = Console(force_terminal=True, force_interactive=True)
    console.clear()

    last_error = None
    try:
        # screen=False keeps the table in the normal scroll buffer so it
        # doesn't vanish when the Live context exits.
        with Live(generate_table(), auto_refresh=False, screen=False, console=console) as live:
            while core.running:
                try:
                    live.update(generate_table(), refresh=True)
                except Exception as e:
                    last_error = e
                    break
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        last_error = e
    finally:
        core.running = False
        core.stop_events_monitor.set()
        t_input.join(timeout=0.5)

    if last_error:
        console.print(f"\n[bold red]Error:[/] {last_error}")
        import traceback, core as _c
        try:
            core.log_debug(traceback.format_exc())
        except Exception:
            traceback.print_exc()


if __name__ == "__main__":
    main()
