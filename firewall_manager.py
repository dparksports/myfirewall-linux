import subprocess

CHAIN_NAME = "MYFIREWALL_BLOCKS"
IS_MOCK = False
MOCK_BLOCKED_IPS = set()

def init_firewall():
    """Initializes the custom iptables chain if it doesn't exist. Hooks it to both INPUT and OUTPUT chains."""
    global IS_MOCK
    try:
        # Check if custom chain list succeeds (validates root/iptables availability)
        subprocess.run(["iptables", "-L", CHAIN_NAME], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        IS_MOCK = False
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
        try:
            # Test if a generic command runs
            subprocess.run(["iptables", "-L"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # If the user is root but chain does not exist, initialize it
            subprocess.run(["iptables", "-N", CHAIN_NAME], check=True)
            IS_MOCK = False
        except Exception:
            # Activate Mock mode if iptables or root is missing
            IS_MOCK = True

    if not IS_MOCK:
        try:
            # Ensure custom chain jumps exist in both INPUT and OUTPUT blocks
            try:
                subprocess.run(["iptables", "-C", "INPUT", "-j", CHAIN_NAME], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.run(["iptables", "-I", "INPUT", "-j", CHAIN_NAME], check=True)

            try:
                subprocess.run(["iptables", "-C", "OUTPUT", "-j", CHAIN_NAME], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.run(["iptables", "-I", "OUTPUT", "-j", CHAIN_NAME], check=True)
        except Exception as e:
            # Fallback defensively to Mock mode if configuration fails
            IS_MOCK = True

def is_mock_mode():
    """Returns True if the firewall is running in mock mode (not as root)."""
    return IS_MOCK

def block_ip(ip):
    """Adds drop rules for both inbound (source -s) and outbound (destination -d) traffic for the specified IP."""
    if IS_MOCK:
        if ip not in MOCK_BLOCKED_IPS:
            MOCK_BLOCKED_IPS.add(ip)
            return True
        return False
        
    added = False
    try:
        # 1. outbound block rule (-d)
        result_dst = subprocess.run(["iptables", "-C", CHAIN_NAME, "-d", ip, "-j", "DROP"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result_dst.returncode != 0:
            subprocess.run(["iptables", "-A", CHAIN_NAME, "-d", ip, "-j", "DROP"], check=True)
            added = True

        # 2. inbound block rule (-s)
        result_src = subprocess.run(["iptables", "-C", CHAIN_NAME, "-s", ip, "-j", "DROP"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result_src.returncode != 0:
            subprocess.run(["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"], check=True)
            added = True
            
        return added
    except subprocess.CalledProcessError:
        pass
    return False

def unblock_ip(ip):
    """Removes drop rules for both inbound (source -s) and outbound (destination -d) traffic for the specified IP."""
    if IS_MOCK:
        if ip in MOCK_BLOCKED_IPS:
            MOCK_BLOCKED_IPS.remove(ip)
            return True
        return False
        
    removed = False
    try:
        # Check & delete destination rule
        result_dst = subprocess.run(["iptables", "-C", CHAIN_NAME, "-d", ip, "-j", "DROP"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result_dst.returncode == 0:
            subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip, "-j", "DROP"], check=True)
            removed = True
            
        # Check & delete source rule
        result_src = subprocess.run(["iptables", "-C", CHAIN_NAME, "-s", ip, "-j", "DROP"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result_src.returncode == 0:
            subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip, "-j", "DROP"], check=True)
            removed = True
            
        return removed
    except subprocess.CalledProcessError:
        pass
    return False

def get_blocked_ips():
    """Returns a list of unique IPs currently blocked in the custom chain (or mock set)."""
    if IS_MOCK:
        return list(MOCK_BLOCKED_IPS)
        
    ips = set()
    try:
        result = subprocess.run(["iptables", "-L", CHAIN_NAME, "-n"], capture_output=True, text=True, check=True)
        lines = result.stdout.split("\n")[2:] # Skip headers
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "DROP":
                src = parts[3]
                dst = parts[4]
                # Filter out standard fallback descriptors
                if src != "0.0.0.0/0":
                    ips.add(src)
                if dst != "0.0.0.0/0":
                    ips.add(dst)
    except subprocess.CalledProcessError:
        pass
    return list(ips)
