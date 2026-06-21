#!/usr/bin/env python3
import subprocess
import re
import ipaddress
import sys

def is_loopback(ip_str):
    try:
        if "%" in ip_str:
            ip_str = ip_str.split("%")[0]
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False

def is_private_ip(ip_str):
    try:
        if "%" in ip_str:
            ip_str = ip_str.split("%")[0]
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def parse_ss_oneline():
    cmd = ["ss", "-t", "-u", "-i", "-p", "-n", "-O"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"Error running ss: {res.stderr}", file=sys.stderr)
        return []
        
    lines = res.stdout.splitlines()
    connections = []
    
    for line in lines:
        if not line:
            continue
        if line.startswith("Netid") or line.startswith("State"):
            continue
            
        parts = line.split()
        if len(parts) < 6:
            continue
            
        netid = parts[0]
        state = parts[1]
        recv_q = parts[2]
        send_q = parts[3]
        local_addr = parts[4]
        peer_addr = parts[5]
        
        # Parse process info anywhere on the line
        pid = None
        proc_name = "Unknown"
        proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+),', line)
        if proc_match:
            proc_name = proc_match.group(1)
            pid = int(proc_match.group(2))
            
        # Parse IP/ports
        def parse_addr(addr):
            if "]" in addr:
                ip = addr.split("]")[0].replace("[", "")
                port = addr.split("]")[-1].replace(":", "")
            elif addr.count(":") > 1:
                rparts = addr.rsplit(":", 1)
                ip = rparts[0]
                port = rparts[1]
            else:
                rparts = addr.rsplit(":", 1)
                ip = rparts[0]
                port = rparts[1]
            return ip, port
            
        local_ip, local_port = parse_addr(local_addr)
        peer_ip, peer_port = parse_addr(peer_addr)
        
        # Parse metrics anywhere on the line
        bytes_sent = 0
        bytes_received = 0
        
        sent_match = re.search(r'bytes_sent:(\d+)', line)
        if sent_match:
            bytes_sent = int(sent_match.group(1))
            
        rcv_match = re.search(r'bytes_received:(\d+)', line)
        if rcv_match:
            bytes_received = int(rcv_match.group(1))
            
        connections.append({
            "netid": netid,
            "state": state,
            "local_ip": local_ip,
            "local_port": local_port,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "proc_name": proc_name,
            "pid": pid,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received
        })
        
    return connections

def format_bytes(b):
    if b >= 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"
    elif b >= 1024 * 1024:
        return f"{b / (1024 * 1024):.2f} MB"
    elif b >= 1024:
        return f"{b / 1024:.2f} KB"
    else:
        return f"{b} B"

def main():
    connections = parse_ss_oneline()
    
    # Filter outgoing connections:
    # 1. Ignore loopback peer IP
    # 2. Ignore "chrome" process name (case-insensitive check)
    filtered = []
    chrome_count = 0
    loopback_count = 0
    
    for conn in connections:
        pname = conn["proc_name"].lower()
        if "chrome" in pname or "chromium" in pname:
            chrome_count += 1
            continue
            
        if is_loopback(conn["peer_ip"]):
            loopback_count += 1
            continue
            
        filtered.append(conn)
        
    print("=" * 110)
    print(f" OUTGOING NETWORK MONITORING (Ignoring Chrome/Chromium)")
    print(f" Summary: Filtered out {chrome_count} Chrome connections & {loopback_count} loopback connections.")
    print("=" * 110)
    
    if not filtered:
        print(" No other active outgoing connections detected.")
        print("=" * 110)
        return
        
    print(f"{'Protocol':<8} {'State':<12} {'Local Address':<24} {'Peer Address':<32} {'Process (PID)':<20} {'Sent':<12} {'Received':<12}")
    print("-" * 110)
    
    total_sent = 0
    total_received = 0
    
    for conn in filtered:
        proc_str = f"{conn['proc_name']} ({conn['pid'] or '?'})"
        local_str = f"{conn['local_ip']}:{conn['local_port']}"
        peer_str = f"{conn['peer_ip']}:{conn['peer_port']}"
        
        # Determine destination class
        dest_type = " [Private]" if is_private_ip(conn["peer_ip"]) else " [Public]"
        peer_str += dest_type
        
        sent_str = format_bytes(conn["bytes_sent"])
        rcv_str = format_bytes(conn["bytes_received"])
        
        total_sent += conn["bytes_sent"]
        total_received += conn["bytes_received"]
        
        print(f"{conn['netid'].upper():<8} {conn['state']:<12} {local_str:<24} {peer_str:<32} {proc_str:<20} {sent_str:<12} {rcv_str:<12}")
        
    print("-" * 110)
    print(f"{'TOTAL OUTGOING DATA':<78} {format_bytes(total_sent):<12} {format_bytes(total_received):<12}")
    print("=" * 110)

if __name__ == "__main__":
    main()
