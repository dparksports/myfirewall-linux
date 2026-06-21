# myfirewall2.py
"""
myfirewall2.py - Bare-minimum read-only connection viewer.
Shows live network connections in a clean columnar layout.
No interactive controls — Ctrl+C to quit.
"""

import time
import ipaddress
from rich.live import Live
from rich.table import Table
from rich.console import Console

import myfirewall_core as core


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


def generate_table():
    """Builds the live connections table."""
    table = Table(show_header=True, box=None, expand=True, padding=(0, 1))

    mock_tag = " (MOCK MODE)" if core.is_mock_mode() else ""
    table.title = f"[bold cyan]LIVE CONNECTIONS{mock_tag}[/]"

    table.add_column("#",        width=3,  style="cyan",       justify="right")
    table.add_column("Proto",    width=5,  style="bold blue")
    table.add_column("Dir",      width=4,  style="bold yellow")
    table.add_column("Process",  width=22, style="green")
    table.add_column("PID",      width=7,  style="dim yellow", justify="right")
    table.add_column("Remote IP",          style="white")
    table.add_column("Geo / Host",         style="magenta")

    conns = get_filtered_conns()
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

        table.add_row(
            str(i + 1),
            proto,
            dir_disp,
            proc_disp,
            pid,
            ip_disp,
            geo_disp,
        )

    table.caption = "\n[dim]Ctrl+C to quit[/dim]"
    return table


def main():
    core.load_config()
    core.start_core_threads()

    # Brief pause to let the first harvest complete
    time.sleep(0.5)

    console = Console(force_terminal=True, force_interactive=True)
    console.clear()

    with Live(generate_table(), auto_refresh=False, screen=True, console=console) as live:
        while True:
            try:
                live.update(generate_table(), refresh=True)
                time.sleep(0.25)
            except KeyboardInterrupt:
                break

    core.running = False
    core.stop_events_monitor.set()


if __name__ == "__main__":
    main()
