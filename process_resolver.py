import os

def get_inode_to_pid_map():
    """Builds a map of socket inodes to Process IDs."""
    inode_to_pid = {}
    
    # Iterate over all process directories
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
            
        pid = int(pid_str)
        fd_dir = f"/proc/{pid}/fd"
        
        if not os.access(fd_dir, os.R_OK):
            continue
            
        try:
            for fd in os.listdir(fd_dir):
                fd_path = f"{fd_dir}/{fd}"
                try:
                    # Read where the symlink points
                    link = os.readlink(fd_path)
                    if link.startswith("socket:[") and link.endswith("]"):
                        inode = link[8:-1]
                        inode_to_pid[inode] = pid
                except Exception:
                    pass
        except Exception:
            pass
            
    return inode_to_pid

def get_process_info(pid):
    """Retrieves process name and executable path for a given PID."""
    name = "Unknown"
    exe = "N/A"
    
    try:
        # Get executable path
        exe_path = f"/proc/{pid}/exe"
        if os.path.exists(exe_path):
            exe = os.readlink(exe_path)
            
        # Get process name from status or stat
        status_path = f"/proc/{pid}/status"
        if os.path.exists(status_path):
            with open(status_path, "r") as f:
                for line in f:
                    if line.startswith("Name:"):
                        name = line.split("\t")[1].strip()
                        break
    except Exception:
        pass
        
    return name, exe
