import os
import sys
import socket
import struct
import threading
from network_monitor import get_listening_ports

def log_debug(msg):
    try:
        with open("debug.log", "a") as f:
            f.write(f"[{threading.current_thread().name}] [eBPFMonitor] {msg}\n")
    except Exception:
        pass

# BPF C Program
BPF_TEXT = """
// Workarounds for kernel 7.0+ compatibility on BCC
struct bpf_task_work {
    char dummy[64];
};
#define BPF_TRACE_FSESSION 100
#define BPF_F_CPU (1U << 0)
#define BPF_F_ALL_CPUS (1U << 1)

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    u16 lport;
    u16 rport;
    u32 family;
    u32 saddr[4];
    u32 daddr[4];
    char task[TASK_COMM_LEN];
    u32 protocol; // 1 = TCP, 2 = UDP
};

struct pid_comm_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};

BPF_HASH(socket_to_info_cache, struct sock *, struct pid_comm_t);

BPF_PERF_OUTPUT(events);

// Synchronously cache socket to PID/comm on outbound connection attempts
int kprobe__tcp_v4_connect(struct pt_regs *regs, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_comm_t info = {};
    info.pid = pid;
    bpf_get_current_comm(&info.task, sizeof(info.task));
    socket_to_info_cache.update(&sk, &info);
    return 0;
}

int kprobe__tcp_v6_connect(struct pt_regs *regs, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_comm_t info = {};
    info.pid = pid;
    bpf_get_current_comm(&info.task, sizeof(info.task));
    socket_to_info_cache.update(&sk, &info);
    return 0;
}

// Clean up socket mapping when socket is closed to prevent leaks
int kprobe__tcp_close(struct pt_regs *regs, struct sock *sk) {
    socket_to_info_cache.delete(&sk);
    return 0;
}

// Trace TCP state changes (TCP connections)
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP)
        return 0;
    
    // We only care about connections reaching ESTABLISHED state (1)
    if (args->newstate != 1)
        return 0;
        
    struct sock *sk = (struct sock *)args->skaddr;
    struct pid_comm_t *info = socket_to_info_cache.lookup(&sk);
        
    struct event_t event = {};
    event.lport = args->sport;
    event.rport = args->dport;
    event.family = args->family;
    event.protocol = 1; // TCP
    
    if (info) {
        event.pid = info->pid;
        __builtin_memcpy(event.task, info->task, TASK_COMM_LEN);
    } else {
        event.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event.task, sizeof(event.task));
    }
    
    if (args->family == AF_INET) {
        __builtin_memcpy(&event.saddr[0], args->saddr, 4);
        __builtin_memcpy(&event.daddr[0], args->daddr, 4);
    } else if (args->family == AF_INET6) {
        __builtin_memcpy(event.saddr, args->saddr_v6, 16);
        __builtin_memcpy(event.daddr, args->daddr_v6, 16);
    }
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Trace UDP sendmsg (UDP connections)
int kprobe__udp_sendmsg(struct pt_regs *regs, struct sock *sk) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.protocol = 2; // UDP
    
    u16 family = sk->__sk_common.skc_family;
    event.family = family;
    
    if (family == AF_INET) {
        event.saddr[0] = sk->__sk_common.skc_rcv_saddr;
        event.daddr[0] = sk->__sk_common.skc_daddr;
        event.lport = sk->__sk_common.skc_num;
        event.rport = sk->__sk_common.skc_dport;
        event.rport = bpf_ntohs(event.rport);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        event.lport = sk->__sk_common.skc_num;
        event.rport = sk->__sk_common.skc_dport;
        event.rport = bpf_ntohs(event.rport);
    }
    
    // Only submit if destination IP is set (not 0.0.0.0 or ::)
    if (event.daddr[0] != 0 || event.daddr[1] != 0 || event.daddr[2] != 0 || event.daddr[3] != 0) {
        bpf_get_current_comm(&event.task, sizeof(event.task));
        events.perf_submit(regs, &event, sizeof(event));
    }
    return 0;
}
"""

def parse_ip(family, addr_array):
    if family == 2:  # AF_INET (IPv4)
        ip_bytes = struct.pack("<I", addr_array[0])
        return socket.inet_ntoa(ip_bytes)
    elif family == 10:  # AF_INET6 (IPv6)
        ip_bytes = struct.pack("<4I", *addr_array)
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return "Unknown"

def ebpf_listener_worker(event_queue, stop_event):
    """Worker function to compile BPF and stream events to event_queue."""
    if os.geteuid() != 0:
        log_debug("eBPF monitoring disabled: require root privileges.")
        return

    try:
        from bcc import BPF
    except ImportError:
        log_debug("eBPF monitoring disabled: bcc Python package is not installed.")
        return

    try:
        bpf = BPF(text=BPF_TEXT, cflags=["-fms-extensions", "-Wno-microsoft-anon-tag"])
    except Exception as e:
        log_debug(f"Failed to load or compile eBPF program: {e}")
        return

    log_debug("eBPF background event monitor successfully compiled and started.")

    def callback(cpu, data, size):
        event = bpf["events"].event(data)
        
        try:
            proto = "TCP" if event.protocol == 1 else "UDP"
            local_ip = parse_ip(event.family, event.saddr)
            remote_ip = parse_ip(event.family, event.daddr)
            local_port = event.lport
            remote_port = event.rport
            pid = event.pid
            name = event.task.decode('utf-8', 'ignore')
            
            # Skip loopback
            if local_ip == "127.0.0.1" or local_ip == "::1" or remote_ip == "127.0.0.1" or remote_ip == "::1":
                return
                
            listening_ports = get_listening_ports()
            is_inbound = local_port in listening_ports
            
            conn = {
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "inode": "N/A",
                "is_ipv6": event.family == 10,
                "direction": "INBOUND" if is_inbound else "OUTBOUND",
                "pid": pid,
                "name": name,
                "status": "ACTIVE"
            }
            event_queue.put(conn)
        except Exception as e:
            log_debug(f"Error handling eBPF event: {e}")

    bpf["events"].open_perf_buffer(callback)
    
    while not stop_event.is_set():
        try:
            bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_debug(f"eBPF poll error: {e}")
            break

    log_debug("eBPF monitor worker stopped.")

def start_ebpf_monitor(event_queue, stop_event):
    """Starts the eBPF connection monitor in a background daemon thread."""
    thread = threading.Thread(
        target=ebpf_listener_worker,
        args=(event_queue, stop_event),
        name="eBPFMonitorThread",
        daemon=True
    )
    thread.start()
    return thread
