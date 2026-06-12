import unittest
from unittest.mock import patch, MagicMock
import firewall_manager

class TestFirewallManager(unittest.TestCase):

    def setUp(self):
        # Reset mock state before each test
        firewall_manager.MOCK_BLOCKED_IPS = set()
        firewall_manager.IS_MOCK = True

    def test_mock_block_ip(self):
        self.assertTrue(firewall_manager.block_ip("192.168.1.100"))
        # Duplicate block check
        self.assertFalse(firewall_manager.block_ip("192.168.1.100"))
        self.assertIn("192.168.1.100", firewall_manager.get_blocked_ips())

    def test_mock_unblock_ip(self):
        firewall_manager.block_ip("192.168.1.200")
        self.assertTrue(firewall_manager.unblock_ip("192.168.1.200"))
        self.assertNotIn("192.168.1.200", firewall_manager.get_blocked_ips())
        # False unblock check
        self.assertFalse(firewall_manager.unblock_ip("192.168.1.200"))

    @patch("subprocess.run")
    def test_iptables_block_and_unblock(self, mock_run):
        # Force non-mock mode
        firewall_manager.IS_MOCK = False
        
        # Mock subprocess outputs for checking rule doesn't exist (returncode 1)
        mock_c_result = MagicMock()
        mock_c_result.returncode = 1
        mock_run.return_value = mock_c_result
        
        self.assertTrue(firewall_manager.block_ip("8.8.8.8"))
        # Check that we ran iptables commands
        self.assertTrue(mock_run.called)

if __name__ == "__main__":
    unittest.main()
