# myfirewall_core.py
import time
import re
import requests
import ipaddress
import json
import socket
import psutil
import os
from queue import Queue
from threading import Thread, Event

# Import internal dependencies
from network_monitor import get_active_connections
from process_resolver import get_inode_to_pid_map, get_process_info
from firewall_manager import init_firewall, block_ip, unblock_ip, get_blocked_ips, is_mock_mode
from conntrack_monitor import start_conntrack_monitor
from ebpf_monitor import start_ebpf_monitor

# Globals & Cache
running = True
connections_cache = []
geo_cache = {}
rdns_cache = {}
blocked_ips = set()
ignored_ips = set()
ignored_names = set()
ignored_cidrs = []

# Real-time event-based monitoring queues and signals
connection_events_queue = Queue()
stop_events_monitor = Event()

# Asynchronous Geolocation Resolution Queue
geo_queue = Queue()
geo_pending = set()

# Asynchronous RDNS Queue
rdns_queue = Queue()
rdns_pending = set()

# Connection history tracker
history_cache = {}

# Network metrics
global_rx = 0
global_tx = 0
last_net_io = None

CONFIG_FILE = os.path.expanduser("~/.config/myfirewall/rules.json")

def log_debug(msg):
    try:
        with open("debug.log", "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def load_config():
    global ignored_ips, ignored_names, ignored_cidrs
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                ignored_ips = set(data.get("ignored_ips", []))
                ignored_names = set(data.get("ignored_names", []))
                
                ignored_cidrs.clear()
                for cidr_str in data.get("ignored_cidrs", []):
                    try:
                        ignored_cidrs.append(ipaddress.ip_network(cidr_str, strict=False))
                    except ValueError:
                        pass
                        
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

def geo_lookup_worker():
    global running
    while running:
        try:
            ip = geo_queue.get(timeout=0.5)
        except Exception:
            continue
            
        try:
            time.sleep(1.5)
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                geo_cache[ip] = data.get("country", "Unknown")
            elif resp.status_code == 429:
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
            rdns_cache[ip] = ""
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
            raw_conns = get_active_connections()
            inode_map = get_inode_to_pid_map()
            
            current_time = time.time()
            current_keys = set()
            
            for conn in raw_conns:
                key = (conn["protocol"], conn["local_ip"], conn["local_port"], conn["remote_ip"], conn["remote_port"])
                current_keys.add(key)
                
                if key in history_cache:
                    history_cache[key]["last_seen"] = current_time
                    history_cache[key]["status"] = "ACTIVE"
                    history_cache[key]["inode"] = conn["inode"]
                else:
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
                    conn["first_seen"] = current_time
                    conn["last_seen"] = current_time
                    conn["status"] = "ACTIVE"
                    conn["packets_tx"] = None
                    conn["packets_rx"] = None
                    history_cache[key] = conn

            while not connection_events_queue.empty():
                try:
                    event_conn = connection_events_queue.get_nowait()
                except Exception:
                    break
                    
                key = (event_conn["protocol"], event_conn["local_ip"], event_conn["local_port"], event_conn["remote_ip"], event_conn["remote_port"])
                current_keys.add(key)
                
                if key in history_cache:
                    history_cache[key]["last_seen"] = current_time
                    history_cache[key]["status"] = "ACTIVE"
                    if event_conn.get("pid"):
                        history_cache[key]["pid"] = event_conn["pid"]
                        history_cache[key]["name"] = event_conn["name"]
                else:
                    pid = event_conn.get("pid")
                    name = event_conn.get("name", "Unknown")
                    remote_ip = event_conn["remote_ip"]
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
                            
                    event_conn["pid"] = pid
                    event_conn["name"] = name
                    event_conn["geo"] = geo
                    event_conn["first_seen"] = current_time
                    event_conn["last_seen"] = current_time
                    event_conn["status"] = "ACTIVE"
                    event_conn["packets_tx"] = None
                    event_conn["packets_rx"] = None
                    history_cache[key] = event_conn

            pruned_history = {}
            for key, conn in history_cache.items():
                if key not in current_keys:
                    if current_time - conn["last_seen"] < 10.0:
                        conn["status"] = "INACTIVE"
                        pruned_history[key] = conn
                else:
                    pruned_history[key] = conn
                    
            history_cache = pruned_history
            connections_cache = list(history_cache.values())
            time.sleep(0.2)
        except Exception as e:
            log_debug(f"Error in update loop: {e}")
            time.sleep(0.2)

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

def parse_proc_nf_conntrack():
    """
    Reads /proc/net/nf_conntrack and returns a dict keyed by
    (proto, src_ip, src_port, dst_ip, dst_port) -> (packets_tx, packets_rx).

    A typical line (TCP) looks like:
      ipv4 2 tcp 6 ESTABLISHED src=A dst=B sport=P dport=Q packets=N bytes=M \
                               src=B dst=A sport=Q dport=P packets=N2 bytes=M2 ...
    The first src/dst pair is the original (TX) direction;
    the second is the reply (RX) direction.
    """
    result = {}
    try:
        with open("/proc/net/nf_conntrack", "r") as f:
            for line in f:
                parts = line.split()
                proto = None
                # find protocol name (e.g. "tcp", "udp")
                for p in parts:
                    if p in ("tcp", "udp", "TCP", "UDP"):
                        proto = p.upper()
                        break
                if proto is None:
                    continue

                # Extract all src/dst/sport/dport/packets tokens
                srcs    = re.findall(r'src=(\S+)',     line)
                dsts    = re.findall(r'dst=(\S+)',     line)
                sports  = re.findall(r'sport=(\d+)',   line)
                dports  = re.findall(r'dport=(\d+)',   line)
                pkts    = re.findall(r'packets=(\d+)', line)

                if len(srcs) < 1 or len(dsts) < 1:
                    continue

                src_ip  = srcs[0]
                dst_ip  = dsts[0]
                sport   = int(sports[0]) if sports else 0
                dport   = int(dports[0]) if dports else 0
                tx_pkts = int(pkts[0])   if len(pkts) > 0 else 0
                rx_pkts = int(pkts[1])   if len(pkts) > 1 else 0

                key = (proto, src_ip, sport, dst_ip, dport)
                result[key] = (tx_pkts, rx_pkts)
    except FileNotFoundError:
        pass
    except Exception as e:
        log_debug(f"parse_proc_nf_conntrack error: {e}")
    return result


def conntrack_counters_loop():
    """
    Background thread: every ~1 s reads /proc/net/nf_conntrack and
    updates packets_tx / packets_rx on any matching history_cache entry.
    """
    global running, history_cache
    while running:
        try:
            ct = parse_proc_nf_conntrack()
            for key, conn in list(history_cache.items()):
                proto, local_ip, local_port, remote_ip, remote_port = key
                # Try both directions (outbound: local→remote; inbound: remote→local)
                fwd = (proto, local_ip,  local_port,  remote_ip,  remote_port)
                rev = (proto, remote_ip, remote_port, local_ip,   local_port)
                if fwd in ct:
                    tx, rx = ct[fwd]
                    conn["packets_tx"] = tx
                    conn["packets_rx"] = rx
                elif rev in ct:
                    rx, tx = ct[rev]   # reversed: reply direction → swap meaning
                    conn["packets_tx"] = tx
                    conn["packets_rx"] = rx
        except Exception as e:
            log_debug(f"conntrack_counters_loop error: {e}")
        time.sleep(1.0)


def start_core_threads():
    """Initializes and starts all background data/network threads."""
    try:
        t_geo = Thread(target=geo_lookup_worker)
        t_geo.daemon = True
        t_geo.start()
    except Exception as e:
        log_debug(f"Failed to start GeoIP background worker process: {e}")

    try:
        t_rdns = Thread(target=rdns_worker)
        t_rdns.daemon = True
        t_rdns.start()
    except Exception as e:
        log_debug(f"Failed to start RDNS background worker process: {e}")

    try:
        t = Thread(target=update_data_loop)
        t.daemon = True
        t.start()
    except Exception:
        log_debug("Failed to start background logic thread.")

    try:
        t_ct = Thread(target=conntrack_counters_loop, name="ConntrackCountersThread")
        t_ct.daemon = True
        t_ct.start()
    except Exception as e:
        log_debug(f"Failed to start conntrack counters thread: {e}")

    try:
        start_conntrack_monitor(connection_events_queue, stop_events_monitor)
    except Exception as e:
        log_debug(f"Failed to start Conntrack background monitor: {e}")

    try:
        start_ebpf_monitor(connection_events_queue, stop_events_monitor)
    except Exception as e:
        log_debug(f"Failed to start eBPF background monitor: {e}")