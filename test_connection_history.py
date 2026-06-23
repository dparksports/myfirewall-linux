import unittest
import os
import shutil
import time
from process_resolver import get_detailed_process_info
from myfirewall_core import format_bytes, log_connection_history, parse_proc_nf_conntrack

class TestConnectionHistory(unittest.TestCase):

    def setUp(self):
        # Backup existing connection history logs if they exist
        self.workspace_log = "./connection_history.log"
        self.workspace_backup = "./connection_history.log.bak"
        if os.path.exists(self.workspace_log):
            shutil.copyfile(self.workspace_log, self.workspace_backup)
            os.remove(self.workspace_log)

    def tearDown(self):
        # Restore backup if it exists
        if os.path.exists(self.workspace_log):
            os.remove(self.workspace_log)
        if os.path.exists(self.workspace_backup):
            shutil.copyfile(self.workspace_backup, self.workspace_log)
            os.remove(self.workspace_backup)

    def test_format_bytes(self):
        self.assertEqual(format_bytes(None), "0 B")
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")
        self.assertEqual(format_bytes(1073741824), "1.00 GB")
        self.assertEqual(format_bytes(1572864), "1.50 MB")

    def test_get_detailed_process_info_self(self):
        # Test getting process info for our own process
        pid = os.getpid()
        proc_info = get_detailed_process_info(pid)
        self.assertIsNotNone(proc_info)
        self.assertIn("name", proc_info)
        self.assertIn("exe", proc_info)
        self.assertIn("cmdline", proc_info)
        self.assertIn("username", proc_info)
        self.assertNotEqual(proc_info["username"], "N/A")

    def test_log_connection_history(self):
        test_conn = {
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "local_ip": "192.168.2.34",
            "local_port": 12345,
            "remote_ip": "1.1.1.1",
            "remote_port": 80,
            "pid": os.getpid(),
            "name": "python_test",
            "first_seen": time.time() - 10,
            "last_seen": time.time(),
            "packets_tx": 5,
            "packets_rx": 6,
            "bytes_tx": 500,
            "bytes_rx": 600
        }
        
        log_connection_history(test_conn)
        self.assertTrue(os.path.exists(self.workspace_log))
        
        with open(self.workspace_log, "r") as f:
            content = f.read()
            
        self.assertIn("Proto: TCP", content)
        self.assertIn("Dir: OUTBOUND", content)
        self.assertIn("Local: 192.168.2.34:12345", content)
        self.assertIn("Remote: 1.1.1.1:80", content)
        self.assertIn("TxBytes: 500 B", content)
        self.assertIn("RxBytes: 600 B", content)

if __name__ == "__main__":
    unittest.main()
