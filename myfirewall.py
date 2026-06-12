import sys
import time
import requests
import termios
import tty
import ipaddress
from queue import Queue
from threading import Thread
from rich.live import Live
from rich.table import Table
from rich.console import Console

# Import the new active connections function
from network_monitor import get_active_connections
from process_resolver import get_inode_to_pid_map, get_process_info
from firewall_manager import init_firewall, block_ip, unblock_ip, get_blocked_ips, is_mock_mode

# Globals & Cache
running = True
connections_cache = []
geo_cache = {}
blocked_ips = set()
ignored_ips = set()
ignored_names = set()

view_state = "FEED"  # "FEED", "BLOCKED", "HELP"
prev_state = "FEED"
prompt_mode = None  # None, "BLOCK", "IGNORE", "UNBLOCK"
input_buffer = ""

# Asynchronous Geolocation Resolution Queue
geo_queue = Queue()
geo_pending = set()

# Connection history tracker
history_cache = {}

def is_local_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def log_debug(msg):
    try:
        with open("debug.log", "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def geo_lookup_worker():
    """Asynchronously resolves pending Geolocation lookups without blocking main scan processes."""
    global running
    while running:
        try:
            # Check for next IP to query
            ip = geo_queue.get(timeout=0.5)
        except Exception:
            continue
            
        try:
            # Throttling delay to stay under the 45 requests/minute API limit safely
            time.sleep(1.5)
            
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                geo_cache[ip] = data.get("country", "Unknown")
            elif resp.status_code == 429: # Rate limit hit
                geo_cache[ip] = "Rate Limited"
                time.sleep(5.0)
            else:
                geo_cache[ip] = "Query Error"
        except Exception:
            geo_cache[ip] = "Failed"
        finally:
            geo_pending.discard(ip)
            geo_queue.task_done()

def update_data_loop():
    global connections_cache, running, blocked_ips, history_cache
    try:
        init_firewall()
    except Exception as e:
        log_debug(f"Failed to initialize firewall: {e}")
        
    while running:
        try:
            blocked_ips = set(get_blocked_ips())
            
            # Fetch active TCP, UDP, and RAW connections (High Frequency 5Hz)
            raw_conns = get_active_connections()
            inode_map = get_inode_to_pid_map()
            
            current_time = time.time()
            current_keys = set()
            
            # Process current active connections
            for conn in raw_conns:
                key = (conn["protocol"], conn["local_ip"], conn["local_port"], conn["remote_ip"], conn["remote_port"])
                current_keys.add(key)
                
                if key in history_cache:
                    history_cache[key]["last_seen"] = current_time
                    history_cache[key]["status"] = "ACTIVE"
                    history_cache[key]["inode"] = conn["inode"]
                else:
                    # Enrich and insert new connection
                    inode = conn["inode"]
                    pid = inode_map.get(inode)
                    name = "Unknown"
                    if pid:
                        name, _ = get_process_info(pid)
                        
                    remote_ip = conn["remote_ip"]
                    geo = "Local/Private"
                    if not is_local_ip(remote_ip):
                        if remote_ip not in geo_cache:
                            geo_cache[remote_ip] = "Resolving..."
                            if remote_ip not in geo_pending:
                                geo_pending.add(remote_ip)
                                geo_queue.put(remote_ip)
                        geo = geo_cache[remote_ip]
                        
                    conn["pid"] = pid
                    conn["name"] = name
                    conn["geo"] = geo
                    conn["last_seen"] = current_time
                    conn["status"] = "ACTIVE"
                    
                    history_cache[key] = conn

            # Handle inactive connections and prune those older than 10.0 seconds
            pruned_history = {}
            for key, conn in history_cache.items():
                if key not in current_keys:
                    # If older active check was seen within 10s, maintain in feed labeled INACTIVE
                    if current_time - conn["last_seen"] < 10.0:
                        conn["status"] = "INACTIVE"
                        pruned_history[key] = conn
                else:
                    pruned_history[key] = conn
                    
            history_cache = pruned_history
            connections_cache = list(history_cache.values())
            
            # Reduced sleep interval to 0.2s for highly responsive scanning
            time.sleep(0.2)
        except Exception as e:
            log_debug(f"Error in update loop: {e}")
            time.sleep(0.2)

def generate_table():
    global view_state, prompt_mode, input_buffer, blocked_ips, ignored_ips, ignored_names
    
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    title_suffix = " (MOCK MODE)" if is_mock_mode() else ""
    
    if view_state == "FEED":
        table.title = f"[bold cyan]NETWORK-MONITOR LIVE FEED{title_suffix}[/]"
        
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Proto", style="bold blue")
        table.add_column("Process", style="green")
        table.add_column("PID", justify="right", style="dim yellow")
        table.add_column("Remote Address")
        table.add_column("Geo", style="magenta")
        
        # Filter items
        conns = [c for c in connections_cache if not is_local_ip(c["remote_ip"]) and c["remote_ip"] not in ignored_ips and c["name"] not in ignored_names]
        
        for i, c in enumerate(conns):
            ip = c["remote_ip"]
            is_blocked = ip in blocked_ips
            is_active = c.get("status", "ACTIVE") == "ACTIVE"
            
            # 1. Base display elements
            if is_blocked:
                ip_display = f"[bold red]{ip} (BLOCKED)[/]"
                proc_display = f"[strike red]{c['name']}[/]"
            else:
                ip_display = f"[white]{ip}[/white]"
                proc_display = c["name"]
                
            proto = c.get("protocol", "TCP")
            if proto == "TCP":
                proto_display = f"[bold cyan]TCP[/]"
            elif proto == "UDP":
                proto_display = f"[bold yellow]UDP[/]"
            elif proto == "RAW":
                proto_display = f"[bold magenta]RAW[/]"
            else:
                proto_display = f"[bold white]{proto}[/]"
                
            # Geolocation status checks
            geo_val = geo_cache.get(ip, c["geo"])
            if geo_val == "Resolving...":
                geo_display = "[dim cyan]Resolving...[/]"
            elif "Limit" in geo_val or "Error" in geo_val or "Failed" in geo_val:
                geo_display = f"[dim red]{geo_val}[/]"
            else:
                geo_display = geo_val
                
            # 2. Inactive visual dimming layer (Evasion Risk Remediation)
            if not is_active:
                ip_display = f"[dim gray]{ip} (INACTIVE)[/dim]"
                proc_display = f"[dim gray][strike]{c['name']}[/strike][/dim]" if is_blocked else f"[dim gray]{c['name']}[/dim]"
                proto_display = f"[dim gray]{proto}[/dim]"
                geo_display = f"[dim gray]{geo_display}[/dim]"
                pid_display = f"[dim gray]{c['pid'] if c['pid'] else '?'}[/dim]"
                idx_display = f"[dim gray]{i + 1}[/dim]"
            else:
                pid_display = str(c["pid"]) if c["pid"] else "?"
                idx_display = str(i + 1)
            
            table.add_row(
                idx_display,
                proto_display,
                proc_display,
                pid_display,
                ip_display,
                geo_display
            )
            
        if prompt_mode == "BLOCK":
            table.caption = f"[bold yellow]Block/Toggle IP (Enter connection # or IP, then press Enter): {input_buffer}[/]"
        elif prompt_mode == "IGNORE":
            table.caption = f"[bold yellow]Ignore/Hide IP or Process (Enter #, IP, or Process Name, then press Enter): {input_buffer}[/]"
        else:
            table.caption = "[bold white]Q[/] Quit  |  [bold white]B[/] Block  |  [bold white]I[/] Ignore  |  [bold white]L[/] Blocked List  |  [bold white]H[/] Help"
            
    elif view_state == "BLOCKED":
        table.title = f"[bold red]NETWORK-MONITOR - BLOCKED IP RULES{title_suffix}[/]"
        
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Blocked IP Address", style="red")
        table.add_column("Status", style="bold red")
        
        current_blocked = get_blocked_ips()
        for i, ip in enumerate(current_blocked):
            table.add_row(
                str(i + 1),
                ip,
                "BLOCKED (ACTIVE)"
            )
            
        if prompt_mode == "UNBLOCK":
            table.caption = f"[bold yellow]Unblock IP (Enter index # or IP, then press Enter): {input_buffer}[/]"
        else:
            table.caption = "[bold white]Q[/] Quit  |  [bold white]U[/] Unblock  |  [bold white]L[/] Connections  |  [bold white]H[/] Help"
            
    elif view_state == "HELP":
        table.title = "[bold yellow]NETWORK-MONITOR - HELP MENU[/]"
        
        table.add_column("Action", style="green")
        table.add_column("Key", style="bold white")
        table.add_column("Description", style="dim white")
        
        table.add_row("Quit", "Q / ESC", "Exit the application")
        table.add_row("Block / Toggle", "B", "Enter connection index or custom IP to toggle block status")
        table.add_row("Ignore / Hide", "I", "Enter connection index, custom IP, or process name to ignore/hide from feed")
        table.add_row("Toggle View", "L", "Switch between connections feed and blocked list")
        table.add_row("Help", "H", "Show/Hide this help menu")
        table.add_row("Unblock IP", "U", "Enter index in blocked list or custom IP to unblock (only in Blocked List view)")
        
        table.caption = "[bold green]Press any key to return...[/]"
        
    return table

def toggle_ip_block(ip):
    global blocked_ips
    current_blocked = get_blocked_ips()
    if ip in current_blocked:
        unblock_ip(ip)
    else:
        block_ip(ip)
    blocked_ips = set(get_blocked_ips())

def toggle_ip_ignore(ip):
    global ignored_ips
    if ip in ignored_ips:
        ignored_ips.remove(ip)
    else:
        ignored_ips.add(ip)

def toggle_proc_ignore(name):
    global ignored_names
    if name in ignored_names:
        ignored_names.remove(name)
        log_debug(f"Unignored process: {name}")
    else:
        ignored_names.add(name)
        log_debug(f"Ignored process: {name}")

def handle_block_input(user_input):
    global blocked_ips
    if not user_input.strip():
        return
    try:
        idx = int(user_input) - 1
        conns = [c for c in connections_cache if not is_local_ip(c["remote_ip"]) and c["remote_ip"] not in ignored_ips and c["name"] not in ignored_names]
        if 0 <= idx < len(conns):
            ip = conns[idx]["remote_ip"]
            toggle_ip_block(ip)
            return
    except ValueError:
        pass
        
    try:
        ipaddress.ip_address(user_input)
        toggle_ip_block(user_input)
    except ValueError:
        log_debug(f"Invalid IP for block input: {user_input}")

def handle_ignore_input(user_input):
    if not user_input.strip():
        return
    try:
        idx = int(user_input) - 1
        # Fix: Sync filtering with main dashboard view to align visual row index with selected connection
        conns = [c for c in connections_cache if not is_local_ip(c["remote_ip"]) and c["remote_ip"] not in ignored_ips and c["name"] not in ignored_names]
        if 0 <= idx < len(conns):
            target = conns[idx]
            toggle_ip_ignore(target["remote_ip"])
            return
    except ValueError:
        pass
        
    try:
        ipaddress.ip_address(user_input)
        toggle_ip_ignore(user_input)
    except ValueError:
        toggle_proc_ignore(user_input)

def handle_unblock_input(user_input):
    if not user_input.strip():
        return
    try:
        idx = int(user_input) - 1
        current_blocked = get_blocked_ips()
        if 0 <= idx < len(current_blocked):
            unblock_ip(current_blocked[idx])
            return
    except ValueError:
        pass
        
    try:
        ipaddress.ip_address(user_input)
        unblock_ip(user_input)
    except ValueError:
        pass

def keyboard_input_loop():
    global running, view_state, prev_state, prompt_mode, input_buffer
    
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        log_debug("Not running in a TTY, keyboard input disabled.")
        while running:
            time.sleep(1)
        return
        
    try:
        while running:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
            
            # Escape sequence processing
            if ord(ch) == 27:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                tty.setraw(sys.stdin.fileno())
                next1 = sys.stdin.read(1)
                next2 = sys.stdin.read(1)
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                # Esc maps to returning
                if prompt_mode:
                    prompt_mode = None
                    input_buffer = ""
                elif view_state == "HELP":
                    view_state = prev_state
                continue
                
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            # Handle prompt input mapping
            if prompt_mode:
                if ord(ch) in (10, 13):  # Enter
                    if prompt_mode == "BLOCK":
                        handle_block_input(input_buffer)
                    elif prompt_mode == "IGNORE":
                        handle_ignore_input(input_buffer)
                    elif prompt_mode == "UNBLOCK":
                        handle_unblock_input(input_buffer)
                    prompt_mode = None
                    input_buffer = ""
                elif ord(ch) in (8, 127):  # Backspace
                    input_buffer = input_buffer[:-1]
                elif 32 <= ord(ch) <= 126:
                    input_buffer += ch
                continue
                
            # Global Key Maps
            ch_lower = ch.lower()
            if view_state == "HELP":
                view_state = prev_state
                continue
                
            if ch_lower == "q" or ord(ch) == 3:  # Q or Ctrl+C
                running = False
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
            elif ch_lower == "u" and view_state == "BLOCKED":
                prompt_mode = "UNBLOCK"
                input_buffer = ""
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def main():
    global running
    try:
        # Start background Geolocation lookup thread
        t_geo = Thread(target=geo_lookup_worker)
        t_geo.daemon = True
        t_geo.start()
    except Exception as e:
        log_debug(f"Failed to start GeoIP background worker process: {e}")

    try:
        # Start connections harvesting loop
        t = Thread(target=update_data_loop)
        t.daemon = True
        t.start()
    except Exception:
        log_debug("Failed to start background logic thread.")
        
    # Wait for first fetch
    time.sleep(0.5)
    
    try:
        t_input = Thread(target=keyboard_input_loop)
        t_input.daemon = True
        t_input.start()
    except Exception:
        log_debug("Failed to start keyboard processing thread.")
        
    try:
        with Live(generate_table(), refresh_per_second=5) as live:
            while running:
                live.update(generate_table())
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_debug(f"Fatal UI error: {e}")
        import traceback
        log_debug(traceback.format_exc())
    finally:
        running = False

if __name__ == "__main__":
    main()
