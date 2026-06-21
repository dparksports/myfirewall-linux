# myfirewall.py
import sys
import signal
import time
import os
import termios
import select
import tty
import ipaddress
import io
from threading import Thread, Event
from rich.live import Live
from rich.table import Table
from rich.console import Console

# Import the core engine
import myfirewall_core as core

# UI State Globals
view_state = "FEED"  # "FEED", "BLOCKED", "HELP", "PROCESS_DETAIL"
prev_state = "FEED"
prompt_mode = None  # None, "BLOCK", "IGNORE", "UNBLOCK", "DETAIL"
input_buffer = ""
selected_pid = None
custom_console = None

# Layout tier thresholds
_LAYOUT_WIDE   = 130
_LAYOUT_MEDIUM = 100
_LAYOUT_NARROW = 70

def get_term_size():
    """Safely query the current terminal dimensions with multiple fallbacks."""
    # 1. Try OS calls on file descriptors (stdin=0, stderr=2, stdout=1)
    for fd in (0, 2, 1):  
        try:
            size = os.get_terminal_size(fd)
            if size.columns > 0 and size.lines > 0:
                return size
        except (OSError, ValueError):
            continue
            
    # 2. Try environment variables
    try:
        cols = int(os.environ.get('COLUMNS', 0))
        lines = int(os.environ.get('LINES', 0))
        if cols > 0 and lines > 0:
            return os.terminal_size((cols, lines))
    except ValueError:
        pass

    # 3. Try tput (asks the terminal directly via terminfo)
    try:
        import subprocess
        lines = int(subprocess.check_output(['tput', 'lines']))
        cols = int(subprocess.check_output(['tput', 'cols']))
        if cols > 0 and lines > 0:
            return os.terminal_size((cols, lines))
    except Exception:
        pass

    # 4. Ultimate fallback
    return os.terminal_size((100, 24))

def _proto_display(proto, is_active):
    colors = {"TCP": "bold cyan", "UDP": "bold yellow", "RAW": "bold magenta"}
    color = colors.get(proto, "bold white")
    if is_active:
        return f"[{color}]{proto}[/]"
    return f"[dim]{proto}[/dim]"

def get_filtered_conns():
    filtered = []
    for c in core.connections_cache:
        ip = c["remote_ip"]
        if core.is_local_ip(ip) or ip in core.ignored_ips or c["name"] in core.ignored_names:
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
    global view_state, prompt_mode, input_buffer, custom_console

    if custom_console is not None:
        cols = custom_console.size.width
        rows = custom_console.size.height
    else:
        term_size = get_term_size()
        cols = term_size.columns
        rows = term_size.lines
    
    table = Table(show_header=False, box=None, expand=True)
    title_suffix = " (MOCK MODE)" if core.is_mock_mode() else ""

    if view_state == "FEED":
        rx_mb = core.global_rx / 1024 / 1024
        tx_mb = core.global_tx / 1024 / 1024
        table.title = (
            f"[bold cyan]NETWORK-MONITOR LIVE FEED{title_suffix}[/] "
            f"[dim white](Rx: {rx_mb:.2f} MB/s | Tx: {tx_mb:.2f} MB/s)[/]"
        )

        if cols >= _LAYOUT_WIDE:
            proc_width = max(16, cols // 6)
            ip_width = max(16, cols // 6)
            table.add_column("#",              justify="right", style="cyan",      no_wrap=True, width=3)
            table.add_column("Proto",          style="bold blue",                  no_wrap=True, width=5)
            table.add_column("Dir",            style="bold yellow",                no_wrap=True, width=4)
            table.add_column("Process",        style="green",                      no_wrap=True, max_width=proc_width)
            table.add_column("PID",            justify="right", style="dim yellow", no_wrap=True, width=7)
            table.add_column("Remote Address",                                     no_wrap=True, max_width=ip_width)
            table.add_column("Geo / Hostname", style="magenta",                    no_wrap=True, max_width=cols // 4)
        elif cols >= _LAYOUT_MEDIUM:
            proc_width = max(16, cols // 5)
            ip_width = max(22, cols // 4)
            table.add_column("#",             justify="right", style="cyan",       no_wrap=True, width=3)
            table.add_column("Proto",         style="bold blue",                   no_wrap=True, width=5)
            table.add_column("Dir",           style="bold yellow",                 no_wrap=True, width=4)
            table.add_column("Process",       style="green",                       no_wrap=True, max_width=proc_width)
            table.add_column("PID",           justify="right", style="dim yellow",  no_wrap=True, width=7)
            table.add_column("Remote Address",                                      no_wrap=True, max_width=ip_width)
        elif cols >= _LAYOUT_NARROW:
            proc_width = max(12, cols // 4)
            ip_width = max(16, cols // 3)
            table.add_column("#",       justify="right", style="cyan",   no_wrap=True, width=3)
            table.add_column("Proto",   style="bold blue",                no_wrap=True, width=5)
            table.add_column("Process", style="green",                    no_wrap=True, max_width=proc_width)
            table.add_column("Remote IP",                                 no_wrap=True, max_width=ip_width)
        else:
            table.add_column("#",        justify="right", style="cyan",  no_wrap=True, width=3)
            table.add_column("Proto",    style="bold blue",               no_wrap=True, width=5)
            table.add_column("Remote IP",                                 no_wrap=True)

        conns = get_filtered_conns()
        # Dynamically scale rows based on terminal height, leaving 10 lines for UI overhead
        max_rows = max(1, rows - 10)

        for i, c in enumerate(conns[:max_rows]):
            ip          = c["remote_ip"]
            is_blocked  = ip in core.blocked_ips
            is_active   = c.get("status", "ACTIVE") == "ACTIVE"
            proto       = c.get("protocol", "TCP")

            proto_disp = _proto_display(proto, is_active)
            idx_disp   = str(i + 1) if is_active else f"[dim]{i + 1}[/dim]"

            if is_blocked:
                ip_disp   = f"[bold red]{ip}[BLKD][/]"
                proc_disp = f"[strike red]{c['name']}[/]"
            else:
                ip_disp   = f"[white]{ip}[/white]"
                proc_disp = c["name"]

            if not is_active:
                ip_disp   = f"[dim]{ip}[INACT][/dim]"
                proc_disp = f"[dim][strike]{c['name']}[/strike][/dim]" if is_blocked else f"[dim]{c['name']}[/dim]"

            pid_disp = str(c["pid"]) if c["pid"] else "?"
            if not is_active:
                pid_disp = f"[dim]{pid_disp}[/dim]"

            geo_val = core.geo_cache.get(ip, c["geo"])
            if geo_val == "Resolving...":
                geo_disp = "[dim cyan]...[/]"
            elif any(t in geo_val for t in ("Limit", "Error", "Failed")):
                geo_disp = f"[dim red]{geo_val}[/]"
            else:
                geo_disp = geo_val

            hostname = core.rdns_cache.get(ip, "")
            if hostname:
                geo_disp += f" / {hostname}"

            if not is_active:
                geo_disp = f"[dim]{geo_disp}[/dim]"

            dir_val = c.get("direction", "OUTBOUND")
            dir_disp = "[bold green]IN[/]" if dir_val == "INBOUND" else "[bold blue]OUT[/]"
            if not is_active:
                dir_disp = f"[dim]{dir_val[:3].upper()}[/dim]"

            if cols >= _LAYOUT_WIDE:
                table.add_row(idx_disp, proto_disp, dir_disp, proc_disp, pid_disp, ip_disp, geo_disp)
            elif cols >= _LAYOUT_MEDIUM:
                country = core.geo_cache.get(ip, "").split(" /")[0].strip()
                addr_cell = f"{ip_disp} [dim]{country}[/dim]" if country and country not in ("Resolving...", "") else ip_disp
                table.add_row(idx_disp, proto_disp, dir_disp, proc_disp, pid_disp, addr_cell)
            elif cols >= _LAYOUT_NARROW:
                table.add_row(idx_disp, proto_disp, proc_disp, ip_disp)
            else:
                table.add_row(idx_disp, proto_disp, ip_disp)

        if prompt_mode == "BLOCK":
            table.caption = f"[bold yellow]Block/Toggle IP (Enter # or IP, then Enter): {input_buffer}[/]"
        elif prompt_mode == "IGNORE":
            table.caption = f"[bold yellow]Ignore IP/Process/CIDR (Enter #, IP, Name, or CIDR): {input_buffer}[/]"
        elif prompt_mode == "DETAIL":
            table.caption = f"[bold yellow]Process Details (Enter connection #, then Enter): {input_buffer}[/]"
        else:
            table.caption = (
                "[bold white]Q[/] Quit  |  [bold white]B[/] Block  |  [bold white]I[/] Ignore  "
                "|  [bold white]D[/] Detail  |  [bold white]L[/] Blocked  |  [bold white]H[/] Help"
            )

    elif view_state == "PROCESS_DETAIL":
        table.title = f"[bold blue]NETWORK-MONITOR - PROCESS DETAILS{title_suffix}[/]"
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Value",    style="white")

        if selected_pid:
            try:
                import psutil
                p = psutil.Process(selected_pid)
                table.add_row("Process ID",  str(p.pid))
                table.add_row("Name",        p.name())
                table.add_row("Status",      p.status())
                table.add_row("User",        p.username())
                create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.create_time()))
                table.add_row("Created At",  create_time)
                table.add_row("Exe Path",    p.exe() or "Unknown")
                table.add_row("Command Line", " ".join(p.cmdline()))
                mem_mb = p.memory_info().rss / 1024 / 1024
                table.add_row("Memory RSS",  f"{mem_mb:.2f} MB")
            except Exception as e:
                table.add_row("Error", str(e))
        else:
            table.add_row("Error", "No process selected")
        table.caption = "[bold green]Press ESC or Q to return...[/]"

    elif view_state == "BLOCKED":
        table.title = f"[bold red]NETWORK-MONITOR - BLOCKED IP RULES{title_suffix}[/]"
        table.add_column("#",                 justify="right", style="cyan",     no_wrap=True)
        table.add_column("Blocked IP Address",                 style="red",      no_wrap=True)
        table.add_column("Status",                             style="bold red", no_wrap=True)

        blocked_list = list(core.get_blocked_ips())
        max_rows = max(1, rows - 10)
        for i, ip in enumerate(blocked_list[:max_rows]):
            table.add_row(str(i + 1), ip, "BLOCKED (ACTIVE)")

        if prompt_mode == "UNBLOCK":
            table.caption = f"[bold yellow]Unblock IP (Enter index # or IP, then Enter): {input_buffer}[/]"
        else:
            table.caption = "[bold white]Q[/] Quit  |  [bold white]U[/] Unblock  |  [bold white]L[/] Connections  |  [bold white]H[/] Help"

    elif view_state == "HELP":
        table.title = "[bold yellow]NETWORK-MONITOR - HELP MENU[/]"
        table.add_column("Action",      style="green",    no_wrap=True)
        table.add_column("Key",         style="bold white", no_wrap=True)
        table.add_column("Description", style="dim white")

        table.add_row("Quit",          "Q / ESC", "Exit the application")
        table.add_row("Block / Toggle", "B",      "Toggle block on a connection # or custom IP")
        table.add_row("Ignore / Hide",  "I",      "Hide a connection, process, or CIDR from the feed")
        table.add_row("Toggle View",    "L",      "Switch between connections feed and blocked list")
        table.add_row("Help",           "H",      "Show/Hide this help menu")
        table.add_row("Unblock IP",     "U",      "Unblock by index or IP (Blocked List view only)")
        table.add_row("Process Detail", "D",      "Show process details for a connection index")
        table.caption = "[bold green]Press any key to return...[/]"

    return table

# --- Input Handlers ---

def handle_block_input(user_input):
    if not user_input.strip(): return
    try:
        idx = int(user_input) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            core.toggle_ip_block(conns[idx]["remote_ip"])
            return
    except ValueError: pass
    try:
        ipaddress.ip_address(user_input)
        core.toggle_ip_block(user_input)
    except ValueError: pass

def handle_ignore_input(user_input):
    if not user_input.strip(): return
    try:
        idx = int(user_input) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            core.toggle_proc_ignore(conns[idx]["name"])
            return
    except ValueError: pass
    try:
        if "/" in user_input:
            net = ipaddress.ip_network(user_input, strict=False)
            if net not in core.ignored_cidrs:
                core.ignored_cidrs.append(net)
                core.save_config()
            return
        ipaddress.ip_address(user_input)
        core.toggle_ip_ignore(user_input)
    except ValueError:
        core.toggle_proc_ignore(user_input)

def handle_detail_input(user_input):
    global selected_pid, view_state
    if not user_input.strip(): return
    try:
        idx = int(user_input) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            pid = conns[idx]["pid"]
            if pid:
                selected_pid = pid
                view_state = "PROCESS_DETAIL"
    except ValueError: pass

def handle_unblock_input(user_input):
    if not user_input.strip(): return
    try:
        idx = int(user_input) - 1
        current_blocked = core.get_blocked_ips()
        if 0 <= idx < len(current_blocked):
            core.unblock_ip(current_blocked[idx])
            return
    except ValueError: pass
    try:
        ipaddress.ip_address(user_input)
        core.unblock_ip(user_input)
    except ValueError: pass

def keyboard_input_loop():
    global view_state, prev_state, prompt_mode, input_buffer
    
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        while core.running: time.sleep(1)
        return
        
    try:
        tty.setraw(fd)
        while core.running:
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not r: continue
                
            ch = sys.stdin.read(1)
            if not ch: break
                
            if ord(ch) == 27:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    sys.stdin.read(1)
                    sys.stdin.read(1)
                else:
                    if prompt_mode:
                        prompt_mode = None
                        input_buffer = ""
                    elif view_state == "HELP":
                        view_state = prev_state
                continue
                
            if prompt_mode:
                if ord(ch) in (10, 13):
                    if prompt_mode == "BLOCK": handle_block_input(input_buffer)
                    elif prompt_mode == "IGNORE": handle_ignore_input(input_buffer)
                    elif prompt_mode == "UNBLOCK": handle_unblock_input(input_buffer)
                    elif prompt_mode == "DETAIL": handle_detail_input(input_buffer)
                    prompt_mode = None
                    input_buffer = ""
                elif ord(ch) in (8, 127):
                    input_buffer = input_buffer[:-1]
                elif 32 <= ord(ch) <= 126:
                    input_buffer += ch
                continue
                
            ch_lower = ch.lower()
            if view_state in ["HELP", "PROCESS_DETAIL"]:
                if ch_lower == "q" or ord(ch) == 27:
                    view_state = prev_state
                continue
                
            if ch_lower == "q" or ord(ch) == 3:
                core.running = False
            elif ch_lower == "h":
                prev_state = view_state
                view_state = "HELP"
            elif ch_lower == "l":
                view_state = "BLOCKED" if view_state == "FEED" else "FEED"
            elif ch_lower == "b" and view_state == "FEED":
                prompt_mode = "BLOCK"
                input_buffer = ""
            elif ch_lower == "i" and view_state == "FEED":
                prompt_mode = "IGNORE"
                input_buffer = ""
            elif ch_lower == "d" and view_state == "FEED":
                prompt_mode = "DETAIL"
                input_buffer = ""
            elif ch_lower == "u" and view_state == "BLOCKED":
                prompt_mode = "UNBLOCK"
                input_buffer = ""
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except termios.error:
            pass

def main():
    core.load_config()
    core.start_core_threads()
    
    time.sleep(0.5)
    
    t_input = None
    try:
        t_input = Thread(target=keyboard_input_loop)
        t_input.daemon = True
        t_input.start()
    except Exception:
        core.log_debug("Failed to start keyboard processing thread.")
        
    # ==========================================
    # CRITICAL TERMINAL ISOLATION
    # ==========================================
    # We physically redirect the OS file descriptors 1 and 2 to /dev/null 
    # so that NO background thread (eBPF, conntrack, etc.) can print to 
    # the screen and push the UI out of frame.
    # We then open a private descriptor to the TTY just for Rich.
    
    tty_fd = None
    try:
        # stdin (0) is usually the TTY even under sudo
        tty_name = os.ttyname(0)
        tty_fd = os.open(tty_name, os.O_WRONLY)
    except Exception:
        # Fallback: duplicate stdout/stderr before redirecting
        try:
            tty_fd = os.dup(1)
        except Exception:
            try:
                tty_fd = os.dup(2)
            except Exception:
                pass

    # Redirect fd 1 (stdout) and fd 2 (stderr) to /dev/null
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    orig_stdout_fd = os.dup(1)
    orig_stderr_fd = os.dup(2)
    os.dup2(devnull_fd, 1)
    os.dup2(devnull_fd, 2)

    # Redirect Python's sys.stdout and sys.stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = io.StringIO() 
    sys.stderr = io.StringIO()

    try:
        # Create a private file object for the TTY
        tty_file = os.fdopen(tty_fd, 'w') if tty_fd is not None else original_stdout
        
        global custom_console
        custom_console = Console(
            file=tty_file, 
            force_terminal=True, 
            force_interactive=True
        )

        custom_console.clear()

        _resize_event = Event()

        def _handle_sigwinch(signum, frame):
            # Rich automatically fetches the new size on the next render
            # when width/height are not explicitly hardcoded.
            _resize_event.set()

        signal.signal(signal.SIGWINCH, _handle_sigwinch)

        with Live(generate_table(), auto_refresh=False, screen=True, console=custom_console) as live:
            while core.running:
                live.update(generate_table(), refresh=True)
                woken_by_resize = _resize_event.wait(timeout=0.2)
                if woken_by_resize:
                    _resize_event.clear()
                    while _resize_event.wait(timeout=0.08):
                        _resize_event.clear()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        try:
            sys.stderr = original_stderr
            core.log_debug(f"Fatal UI error: {e}")
            import traceback
            core.log_debug(traceback.format_exc())
        except:
            pass
    finally:
        # Restore standard outputs
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        os.dup2(orig_stdout_fd, 1)
        os.dup2(orig_stderr_fd, 2)
        os.close(devnull_fd)
        
        if 'tty_file' in locals() and tty_file is not None:
            tty_file.close()
        elif tty_fd is not None:
            os.close(tty_fd)
            
        core.running = False
        core.stop_events_monitor.set()
        if t_input and t_input.is_alive():
            t_input.join(timeout=0.5)

if __name__ == "__main__":
    main()