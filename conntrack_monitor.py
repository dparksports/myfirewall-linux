import subprocess
import re
import os
import sys
import threading
from network_monitor import get_listening_ports

def log_debug(msg):
    try:
        with open("debug.log", "a") as f:
            f.write(f"[{threading.current_thread().name}] [ConntrackMonitor] {msg}\n")
    except Exception:
        pass

def parse_conntrack_line(line):
    """
    Parses a single line of conntrack -E output to extract connection details.
    Example:
    [NEW] tcp      6 120 SYN_SENT src=192.168.2.34 dst=216.239.32.223 sport=48986 dport=443 ...
    """
    if "[NEW]" not in line:
        return None
        
    # Match protocol, src, dst, sport, dport (using non-greedy matching)
    match = re.search(r'\[NEW\]\s+(\w+)\s+.*?src=([^\s]+)\s+dst=([^\s]+)\s+sport=(\d+)\s+dport=(\d+)', line)
    if not match:
        return None
        
    protocol = match.group(1).upper()
    src_ip = match.group(2)
    dst_ip = match.group(3)
    sport = int(match.group(4))
    dport = int(match.group(5))
    
    return {
        "protocol": protocol,
        "src_ip": src_ip,
        "sport": sport,
        "dst_ip": dst_ip,
        "dport": dport
    }

def conntrack_listener_worker(event_queue, stop_event):
    """Worker function to spawn conntrack -E and push events to event_queue."""
    if os.geteuid() != 0:
        log_debug("Conntrack monitoring disabled: require root privileges.")
        return

    cmd = ["conntrack", "-E"]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
    except Exception as e:
        log_debug(f"Failed to start conntrack subprocess: {e}")
        return

    log_debug("Conntrack background event monitor successfully started.")
    
    # Read output line by line
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
            
        try:
            event_data = parse_conntrack_line(line)
            if event_data:
                listening_ports = get_listening_ports()
                
                # Determine direction:
                # If we are listening on sport, it is an inbound connection.
                # If we are listening on dport but not sport, or sport is ephemeral, it's outbound.
                is_inbound = event_data["sport"] in listening_ports
                
                # Format to uniform connection structure
                conn = {
                    "protocol": event_data["protocol"],
                    "local_ip": event_data["src_ip"] if not is_inbound else event_data["dst_ip"],
                    "local_port": event_data["sport"] if not is_inbound else event_data["dport"],
                    "remote_ip": event_data["dst_ip"] if not is_inbound else event_data["src_ip"],
                    "remote_port": event_data["dport"] if not is_inbound else event_data["sport"],
                    "inode": "N/A",
                    "is_ipv6": ":" in event_data["src_ip"],
                    "direction": "INBOUND" if is_inbound else "OUTBOUND",
                    "pid": None,
                    "name": "Unknown",
                    "status": "ACTIVE"
                }
                event_queue.put(conn)
        except Exception as e:
            log_debug(f"Error parsing conntrack event: {e}")

    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except Exception:
        proc.kill()
    log_debug("Conntrack monitor worker stopped.")

def start_conntrack_monitor(event_queue, stop_event):
    """Starts the conntrack event monitor in a background daemon thread."""
    thread = threading.Thread(
        target=conntrack_listener_worker,
        args=(event_queue, stop_event),
        name="ConntrackMonitorThread",
        daemon=True
    )
    thread.start()
    return thread
