import unittest
import queue
import threading
import time
import os
from conntrack_monitor import start_conntrack_monitor, parse_conntrack_line
from ebpf_monitor import start_ebpf_monitor

class TestEventMonitors(unittest.TestCase):

    def test_parse_conntrack_line(self):
        line = "[NEW] tcp      6 120 SYN_SENT src=192.168.2.34 dst=216.239.32.223 sport=48986 dport=443 [UNREPLIED] src=216.239.32.223 dst=192.168.2.34 sport=443 dport=48986"
        res = parse_conntrack_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "TCP")
        self.assertEqual(res["src_ip"], "192.168.2.34")
        self.assertEqual(res["dst_ip"], "216.239.32.223")
        self.assertEqual(res["sport"], 48986)
        self.assertEqual(res["dport"], 443)

    def test_parse_conntrack_line_invalid(self):
        # Non-new connection lines or invalid lines should return None
        line = "[UPDATE] tcp      6 120 ESTABLISHED src=192.168.2.34 dst=216.239.32.223 sport=48986 dport=443"
        self.assertIsNone(parse_conntrack_line(line))

    def test_graceful_degradation_non_root(self):
        # Since we are running tests as non-root user 'b650', we expect the monitors to log and return without crashing.
        event_queue = queue.Queue()
        stop_event = threading.Event()
        
        # Clear debug.log if it exists
        if os.path.exists("debug.log"):
            try:
                os.remove("debug.log")
            except Exception:
                pass
                
        # Start monitors
        ct_thread = start_conntrack_monitor(event_queue, stop_event)
        ebpf_thread = start_ebpf_monitor(event_queue, stop_event)
        
        # Allow thread execution
        time.sleep(0.5)
        
        # Stop them
        stop_event.set()
        ct_thread.join(timeout=1.0)
        ebpf_thread.join(timeout=1.0)
        
        # Verify messages in debug.log
        self.assertTrue(os.path.exists("debug.log"))
        with open("debug.log", "r") as f:
            log_content = f.read()
            
        self.assertIn("require root privileges", log_content)

if __name__ == "__main__":
    unittest.main()
