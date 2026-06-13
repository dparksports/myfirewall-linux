import sys
import time
import requests
import termios
import select
import tty
import ipaddress
import json
import socket
import psutil
import os
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
rdns_cache = {}
blocked_ips = set()
ignored_ips = set()
ignored_names = set()
ignored_cidrs = []

view_state = "FEED"  # "FEED", "BLOCKED", "HELP", "PROCESS_DETAIL"
prev_state = "FEED"
prompt_mode = None  # None, "BLOCK", "IGNORE", "UNBLOCK", "DETAIL"
input_buffer = ""
selected_pid = None

# Network metrics
global_rx = 0
global_tx = 0
last_net_io = None

# Asynchronous Geolocation Resolution Queue
geo_queue = Queue()
geo_pending = set()

# Asynchronous RDNS Queue
rdns_queue = Queue()
rdns_pending = set()

# Connection history tracker
history_cache = {}

CONFIG_FILE = os.path.expanduser("~/.config/myfirewall/rules.json")

def load_config():
    global blocked_ips, ignored_ips, ignored_names, ignored_cidrs
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                ignored_ips = set(data.get("ignored_ips", []))
                ignored_names = set(data.get("ignored_names", []))
                
                # Parse CIDRs
                ignored_cidrs.clear()
                for cidr_str in data.get("ignored_cidrs", []):
                    try:
                        ignored_cidrs.append(ipaddress.ip_network(cidr_str, strict=False))
                    except ValueError:
                        pass
                        
                # Sync blocked_ips
                saved_blocked = data.get("blocked_ips", [])
                current_blocked = get_blocked_ips()
                for ip in saved_blocked:
                    if ip not in current_blocked:
                        block_ip(ip)
    except Exception as e:
        log_debug(f"Failed to load config: {e}")

def save_config():
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        data = {
            "blocked_ips": list(get_blocked_ips()),
            "ignored_ips": list(ignored_ips),
            "ignored_names": list(ignored_names),
            "ignored_cidrs": [str(c) for c in ignored_cidrs]
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        log_debug(f"Failed to save config: {e}")

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

def rdns_worker():
    """Asynchronously resolves pending Reverse DNS lookups."""
    global running
    while running:
        try:
            ip = rdns_queue.get(timeout=0.5)
        except Exception:
            continue
            
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            rdns_cache[ip] = hostname
        except Exception:
            rdns_cache[ip] = ""  # No hostname found
        finally:
            rdns_pending.discard(ip)
            rdns_queue.task_done()

def update_data_loop():
    global connections_cache, running, blocked_ips, history_cache, global_rx, global_tx, last_net_io
    try:
        init_firewall()
    except Exception as e:
        log_debug(f"Failed to initialize firewall: {e}")
        
    while running:
        try:
            # Update bandwidth metrics
            net_io = psutil.net_io_counters()
            current_time = time.time()
            if last_net_io:
                last_time, last_io = last_net_io
                dt = current_time - last_time
                if dt > 0:
                    global_rx = (net_io.bytes_recv - last_io.bytes_recv) / dt
                    global_tx = (net_io.bytes_sent - last_io.bytes_sent) / dt
            last_net_io = (current_time, net_io)

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
                        
                        if remote_ip not in rdns_cache and remote_ip not in rdns_pending:
                            rdns_pending.add(remote_ip)
                            rdns_queue.put(remote_ip)
                        
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
    global view_state, prompt_mode, input_buffer, blocked_ips, ignored_ips, ignored_names, global_rx, global_tx
    
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    title_suffix = " (MOCK MODE)" if is_mock_mode() else ""
    
    if view_state == "FEED":
        rx_mb = global_rx / 1024 / 1024
        tx_mb = global_tx / 1024 / 1024
        table.title = f"[bold cyan]NETWORK-MONITOR LIVE FEED{title_suffix}[/] [dim white](Rx: {rx_mb:.2f} MB/s | Tx: {tx_mb:.2f} MB/s)[/]"
        
        # Enabled no_wrap on columns to preserve single-line layout and prevent grid wrapping on resize
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("Proto", style="bold blue", no_wrap=True)
        table.add_column("Process", style="green", no_wrap=True)
        table.add_column("PID", justify="right", style="dim yellow", no_wrap=True)
        table.add_column("Remote Address", no_wrap=True)
        table.add_column("Geo / Hostname", style="magenta", no_wrap=True)
        
        # Filter items
        conns = get_filtered_conns()
        
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
                
            hostname = rdns_cache.get(ip, "Resolving...")
            if hostname and hostname != "Resolving...":
                geo_display += f" / {hostname}"
                
            # 2. Inactive visual dimming layer (Evasion Risk Remediation)
            if not is_active:
                ip_display = f"[dim]{ip} (INACTIVE)[/dim]"
                proc_display = f"[dim][strike]{c['name']}[/strike][/dim]" if is_blocked else f"[dim]{c['name']}[/dim]"
                proto_display = f"[dim]{proto}[/dim]"
                geo_display = f"[dim]{geo_display}[/dim]"
                pid_display = f"[dim]{c['pid'] if c['pid'] else '?'}[/dim]"
                idx_display = f"[dim]{i + 1}[/dim]"
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
            table.caption = f"[bold yellow]Ignore/Hide IP, Process, or CIDR (Enter #, IP, Process Name, or CIDR, then press Enter): {input_buffer}[/]"
        elif prompt_mode == "DETAIL":
            table.caption = f"[bold yellow]Process Details (Enter connection #, then press Enter): {input_buffer}[/]"
        else:
            table.caption = "[bold white]Q[/] Quit  |  [bold white]B[/] Block  |  [bold white]I[/] Ignore  |  [bold white]D[/] Process Detail  |  [bold white]L[/] Blocked List  |  [bold white]H[/] Help"
            
    elif view_state == "PROCESS_DETAIL":
        table.title = f"[bold blue]NETWORK-MONITOR - PROCESS DETAILS{title_suffix}[/]"
        
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        if selected_pid:
            try:
                p = psutil.Process(selected_pid)
                table.add_row("Process ID", str(p.pid))
                table.add_row("Name", p.name())
                table.add_row("Status", p.status())
                table.add_row("User", p.username())
                create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.create_time()))
                table.add_row("Created At", create_time)
                table.add_row("Exe Path", p.exe() or "Unknown")
                cmdline = " ".join(p.cmdline())
                table.add_row("Command Line", cmdline)
                mem_mb = p.memory_info().rss / 1024 / 1024
                table.add_row("Memory RSS", f"{mem_mb:.2f} MB")
            except psutil.NoSuchProcess:
                table.add_row("Error", "Process has terminated")
            except Exception as e:
                table.add_row("Error", str(e))
        else:
            table.add_row("Error", "No process selected")
            
        table.caption = "[bold green]Press ESC or Q to return...[/]"
            
    elif view_state == "BLOCKED":
        table.title = f"[bold red]NETWORK-MONITOR - BLOCKED IP RULES{title_suffix}[/]"
        
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("Blocked IP Address", style="red", no_wrap=True)
        table.add_column("Status", style="bold red", no_wrap=True)
        
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
        
        table.add_column("Action", style="green", no_wrap=True)
        table.add_column("Key", style="bold white", no_wrap=True)
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
    save_config()

def toggle_ip_ignore(ip):
    global ignored_ips
    if ip in ignored_ips:
        ignored_ips.remove(ip)
    else:
        ignored_ips.add(ip)
    save_config()

def toggle_proc_ignore(name):
    global ignored_names
    if name in ignored_names:
        ignored_names.remove(name)
        log_debug(f"Unignored process: {name}")
    else:
        ignored_names.add(name)
        log_debug(f"Ignored process: {name}")
    save_config()

def get_filtered_conns():
    filtered = []
    for c in connections_cache:
        ip = c["remote_ip"]
        if is_local_ip(ip) or ip in ignored_ips or c["name"] in ignored_names:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
            if any(ip_obj in net for net in ignored_cidrs):
                continue
        except ValueError:
            pass
        filtered.append(c)
    return filtered

def handle_block_input(user_input):
    global blocked_ips
    if not user_input.strip():
        return
    try:
        idx = int(user_input) - 1
        conns = get_filtered_conns()
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
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            target = conns[idx]
            toggle_ip_ignore(target["remote_ip"])
            return
    except ValueError:
        pass
        
    try:
        if "/" in user_input:
            net = ipaddress.ip_network(user_input, strict=False)
            if net not in ignored_cidrs:
                ignored_cidrs.append(net)
                save_config()
            return
        ipaddress.ip_address(user_input)
        toggle_ip_ignore(user_input)
    except ValueError:
        toggle_proc_ignore(user_input)

def handle_detail_input(user_input):
    global selected_pid, view_state
    if not user_input.strip():
        return
    try:
        idx = int(user_input) - 1
        conns = get_filtered_conns()
        if 0 <= idx < len(conns):
            pid = conns[idx]["pid"]
            if pid:
                selected_pid = pid
                view_state = "PROCESS_DETAIL"
    except ValueError:
        pass

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
        # Step raw terminal config exactly once before loop entry to prevent tty state corruption
        tty.setraw(fd)
        
        while running:
            # Non-blocking wait for input to allow clean exit
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not r:
                continue
                
            # Read 1 character from standard input in raw mode
            ch = sys.stdin.read(1)
            if not ch:
                break
                
            # Escape sequence processing (Arrow keys / ESC)
            if ord(ch) == 27:
                # Fast check if remaining escape sequence components are waiting in buffer
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    sys.stdin.read(1) # swallow remainder 1
                    sys.stdin.read(1) # swallow remainder 2
                else:
                    # Single ESC key was pressed: Cancel any active prompts or menus
                    if prompt_mode:
                        prompt_mode = None
                        input_buffer = ""
                    elif view_state == "HELP":
                        view_state = prev_state
                continue
                
            # Handle prompt text mapping
            if prompt_mode:
                if ord(ch) in (10, 13):  # Enter key (Newline or CR)
                    if prompt_mode == "BLOCK":
                        handle_block_input(input_buffer)
                    elif prompt_mode == "IGNORE":
                        handle_ignore_input(input_buffer)
                    elif prompt_mode == "UNBLOCK":
                        handle_unblock_input(input_buffer)
                    elif prompt_mode == "DETAIL":
                        handle_detail_input(input_buffer)
                    prompt_mode = None
                    input_buffer = ""
                elif ord(ch) in (8, 127):  # Backspace
                    input_buffer = input_buffer[:-1]
                elif 32 <= ord(ch) <= 126:
                    input_buffer += ch
                continue
                
            # Global Navigation Keys
            ch_lower = ch.lower()
            if view_state in ["HELP", "PROCESS_DETAIL"]:
                if ch_lower == "q" or ord(ch) == 27:
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
            elif ch_lower == "d" and view_state == "FEED":
                prompt_mode = "DETAIL"
                input_buffer = ""
            elif ch_lower == "u" and view_state == "BLOCKED":
                prompt_mode = "UNBLOCK"
                input_buffer = ""
    finally:
        # Safely restore standard cooked settings exactly once upon exit
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def main():
    global running
    load_config()
    
    try:
        # Start background Geolocation lookup thread
        t_geo = Thread(target=geo_lookup_worker)
        t_geo.daemon = True
        t_geo.start()
    except Exception as e:
        log_debug(f"Failed to start GeoIP background worker process: {e}")

    try:
        # Start background Reverse DNS thread
        t_rdns = Thread(target=rdns_worker)
        t_rdns.daemon = True
        t_rdns.start()
    except Exception as e:
        log_debug(f"Failed to start RDNS background worker process: {e}")

    try:
        # Start connections harvesting loop
        t = Thread(target=update_data_loop)
        t.daemon = True
        t.start()
    except Exception:
        log_debug("Failed to start background logic thread.")
        
    # Wait for first fetch
    time.sleep(0.5)
    
    t_input = None
    try:
        t_input = Thread(target=keyboard_input_loop)
        t_input.daemon = True
        t_input.start()
    except Exception:
        log_debug("Failed to start keyboard processing thread.")
        
    try:
        # pkexec strips TERM environment variables (sets TERM=dumb).
        # We explicitly initialize Console to force terminal mode if a TTY is attached, otherwise rich will suppress output.
        custom_console = Console(force_terminal=True) if sys.stdout.isatty() else Console()
        
        # Fixed: Enabled screen=True to activate the alternate screen buffer, completely preventing duplicate screen copies on resize!
        with Live(generate_table(), auto_refresh=False, screen=True, console=custom_console) as live:
            while running:
                # Synchronously trigger refresh at a smooth, stable 5Hz rate (every 0.2s)
                live.update(generate_table(), refresh=True)
                time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log_debug(f"Fatal UI error: {e}")
        import traceback
        log_debug(traceback.format_exc())
    finally:
        running = False
        if t_input and t_input.is_alive():
            t_input.join(timeout=0.5)

if __name__ == "__main__":
    main()
