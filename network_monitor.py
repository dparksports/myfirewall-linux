import os
import socket
import struct

TCP_STATE_ESTABLISHED = "01"

def hex_to_ip_port(hex_str, is_ipv6=False):
    ip_hex, port_hex = hex_str.split(":")
    port = int(port_hex, 16)
    if is_ipv6:
        # IPv6 parsing
        ip_hex = ip_hex.zfill(32)
        ip_bytes = bytes.fromhex(ip_hex)
        # Linux stores IPv6 addresses in 4 32-bit words, each little-endian
        words = struct.unpack("<4I", ip_bytes)
        ip_bytes_ordered = struct.pack(">4I", *words)
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes_ordered)
    else:
        # IPv4 parsing (little-endian)
        ip_bytes = bytes.fromhex(ip_hex)[::-1]
        ip = socket.inet_ntoa(ip_bytes)
    return ip, port

def get_listening_ports():
    """Reads TCP and TCP6 listening ports from /proc/net/tcp{,6} where state is 0A."""
    ports = set()
    files = [
        ("/proc/net/tcp", False),
        ("/proc/net/tcp6", True)
    ]
    for filepath, is_ipv6 in files:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[3]
                    if state == "0A":  # TCP_LISTEN
                        local_addr = parts[1]
                        try:
                            _, local_port = hex_to_ip_port(local_addr, is_ipv6)
                            ports.add(local_port)
                        except Exception:
                            continue
        except Exception:
            continue
    return ports

def get_active_connections():
    """Reads TCP, UDP, and RAW sockets for IPv4 and IPv6, returning a list of active connections."""
    connections = []
    listening_ports = get_listening_ports()
    
    # Files to monitor: (filepath, protocol, is_ipv6)
    files = [
        ("/proc/net/tcp", "TCP", False),
        ("/proc/net/tcp6", "TCP", True),
        ("/proc/net/udp", "UDP", False),
        ("/proc/net/udp6", "UDP", True),
        ("/proc/net/raw", "RAW", False),
        ("/proc/net/raw6", "RAW", True)
    ]
    
    for filepath, protocol, is_ipv6 in files:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
                for line in lines[1:]: # Skip header
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                        
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    inode = parts[9]
                    
                    # Logic-filter closed or listening TCP connections
                    if protocol == "TCP" and state != TCP_STATE_ESTABLISHED:
                        continue
                        
                    # Skip connections listening or bound to 0.0.0.0 or ::
                    if remote_addr.startswith("00000000:0000") or remote_addr == "00000000000000000000000000000000:0000":
                        continue
                        
                    try:
                        local_ip, local_port = hex_to_ip_port(local_addr, is_ipv6)
                        remote_ip, remote_port = hex_to_ip_port(remote_addr, is_ipv6)
                    except Exception:
                        continue
                        
                    direction = "INBOUND" if local_port in listening_ports else "OUTBOUND"
                    
                    connections.append({
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "inode": inode,
                        "is_ipv6": is_ipv6,
                        "direction": direction
                    })
        except Exception:
            continue
            
    return connections

def get_tcp_connections():
    """Legacy wrapper returning TCP-only connections."""
    return [c for c in get_active_connections() if c["protocol"] == "TCP"]
