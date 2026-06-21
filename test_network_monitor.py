import unittest
from unittest.mock import patch, mock_open
import os

# Import parsing function definitions
from network_monitor import get_active_connections, hex_to_ip_port

class TestNetworkMonitor(unittest.TestCase):

    def test_hex_to_ip_port_ipv4(self):
        # 127.0.0.1 -> 7F 00 00 01 -> in little-endian hex is 0100007F
        # Port 80 -> 0050 in hex
        ip, port = hex_to_ip_port("0100007F:0050", is_ipv6=False)
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 80)

    def test_hex_to_ip_port_ipv6(self):
        # IPv6 loopback ::1 -> stored as 16 little-endian bytes.
        # Word 4: 01000000 in little-endian -> repacks to ::1
        ip, port = hex_to_ip_port("00000000000000000000000001000000:0050", is_ipv6=True)
        self.assertEqual(ip, "::1")
        self.assertEqual(port, 80)

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_active_connections(self, mock_file_open, mock_exists):
        # Map out proc hex sockets context mockup
        mock_tcp_data = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:0050 0100007F:0457 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 00000000\n"
            "   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12348 1 00000000\n" # Listen state (0A != 01)
        )
        
        mock_udp_data = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
            "   0: 0100007F:0035 0200007F:0458 07 00000000:00000000 00:00000000 00000000  1000        0 12346 2 00000000 0\n"
            "   1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 12349 2 00000000 0\n" # Unconnected UDP (remote 0.0.0.0)
        )
        
        mock_raw_data = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
            "   0: 0100007F:0001 0300007F:0000 07 00000000:00000000 00:00000000 00000000  1000        0 12347 2 00000000 0\n"
        )

        def side_effect(path, *args, **kwargs):
            if "tcp6" in path or "udp6" in path or "raw6" in path:
                # Return empty/mock header files for IPv6
                return mock_open(read_data="  sl  local_address rem_address   st\n").return_value
            elif "tcp" in path:
                return mock_open(read_data=mock_tcp_data).return_value
            elif "udp" in path:
                return mock_open(read_data=mock_udp_data).return_value
            elif "raw" in path:
                return mock_open(read_data=mock_raw_data).return_value
            raise FileNotFoundError(path)

        mock_exists.return_value = True
        mock_file_open.side_effect = side_effect

        # Call active connection getter
        conns = get_active_connections()

        # Group connections
        tcp_conns = [c for c in conns if c["protocol"] == "TCP"]
        udp_conns = [c for c in conns if c["protocol"] == "UDP"]
        raw_conns = [c for c in conns if c["protocol"] == "RAW"]

        # Tests counts (should filter listen/all-zeros profiles)
        self.assertEqual(len(tcp_conns), 1)
        self.assertEqual(len(udp_conns), 1)
        self.assertEqual(len(raw_conns), 1)

        # Confirm fields
        self.assertEqual(tcp_conns[0]["remote_ip"], "127.0.0.1")
        self.assertEqual(tcp_conns[0]["remote_port"], 1111)
        self.assertEqual(tcp_conns[0]["inode"], "12345")
        self.assertEqual(tcp_conns[0]["direction"], "INBOUND")

        self.assertEqual(udp_conns[0]["remote_ip"], "127.0.0.2")
        self.assertEqual(udp_conns[0]["remote_port"], 1112)
        self.assertEqual(udp_conns[0]["inode"], "12346")
        self.assertEqual(udp_conns[0]["direction"], "OUTBOUND")

        self.assertEqual(raw_conns[0]["remote_ip"], "127.0.0.3")
        self.assertEqual(raw_conns[0]["remote_port"], 0)
        self.assertEqual(raw_conns[0]["inode"], "12347")

if __name__ == "__main__":
    unittest.main()
