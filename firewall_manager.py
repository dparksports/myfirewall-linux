import subprocess

CHAIN_NAME = "MYFIREWALL_BLOCKS"
IS_MOCK = False
MOCK_BLOCKED_IPS = set()

def init_firewall():
    """Initializes the custom iptables chain if it doesn't exist. Falls back to mock mode if not root."""
    global IS_MOCK
    try:
        # Check if chain exists - this will raise subprocess.CalledProcessError or FileNotFoundError if not root/iptables missing
        subprocess.run(["iptables", "-L", CHAIN_NAME], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        IS_MOCK = False
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
        # Let's try to run a generic iptables command to verify if we can use iptables at all
        try:
            subprocess.run(["iptables", "-L"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # If we could list, but CHAIN_NAME didn't exist, we can try creating it
            subprocess.run(["iptables", "-N", CHAIN_NAME], check=True)
            subprocess.run(["iptables", "-I", "OUTPUT", "-j", CHAIN_NAME], check=True)
            IS_MOCK = False
        except Exception:
            # We are not root or iptables is not available; activate mock mode
            IS_MOCK = True

def is_mock_mode():
    """Returns True if the firewall is running in mock mode (not as root)."""
    return IS_MOCK

def block_ip(ip):
    """Adds a drop rule for the specified IP in the custom chain (or mock set)."""
    if IS_MOCK:
        if ip not in MOCK_BLOCKED_IPS:
            MOCK_BLOCKED_IPS.add(ip)
            return True
        return False
        
    try:
        # Check if rule already exists to avoid duplicates
        result = subprocess.run(["iptables", "-C", CHAIN_NAME, "-d", ip, "-j", "DROP"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            subprocess.run(["iptables", "-A", CHAIN_NAME, "-d", ip, "-j", "DROP"], check=True)
            return True
    except subprocess.CalledProcessError:
        pass
    return False

def unblock_ip(ip):
    """Removes a drop rule for the specified IP from the custom chain (or mock set)."""
    if IS_MOCK:
        if ip in MOCK_BLOCKED_IPS:
            MOCK_BLOCKED_IPS.remove(ip)
            return True
        return False
        
    try:
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip, "-j", "DROP"], check=True)
        return True
    except subprocess.CalledProcessError:
        pass
    return False

def get_blocked_ips():
    """Returns a list of IPs currently blocked in the custom chain (or mock set)."""
    if IS_MOCK:
        return list(MOCK_BLOCKED_IPS)
        
    ips = []
    try:
        result = subprocess.run(["iptables", "-L", CHAIN_NAME, "-n"], capture_output=True, text=True, check=True)
        lines = result.stdout.split("\n")[2:] # Skip headers
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "DROP":
                ips.append(parts[3])
    except subprocess.CalledProcessError:
        pass
    return ips
