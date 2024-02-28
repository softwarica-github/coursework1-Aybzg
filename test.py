import threading
import unittest
from unittest.mock import patch
from main import valid_ip, scan_port

class TestPortScanner(unittest.TestCase):
    def test_valid_ip_true(self):
        """Test valid IP addresses"""
        self.assertTrue(valid_ip("192.168.1.1"))
        self.assertTrue(valid_ip("8.8.8.8"))

    def test_valid_ip_false(self):
        """Test invalid IP addresses"""
        self.assertFalse(valid_ip("256.256.256.256"))
        self.assertFalse(valid_ip("not_an_ip"))
        self.assertFalse(valid_ip("192.168.1.256"))

    @patch('port_scanner.socket.socket')
    def test_scan_port_open(self, mock_socket):
        """Test scanning an open port by mocking socket's connect_ex method to return 0"""
        mock_socket.return_value.connect_ex.return_value = 0
        # Simplify scan_port function for demonstration, to return "Open" or "Closed"
        output = []
        sem = threading.Semaphore(1)
        results = []
        status_var = "Status"
        scan_btn = "Button"
        scan_port("127.0.0.1", 80, output, sem, results, status_var, scan_btn)
        self.assertIn("Port 80: Open\n", output)

    @patch('port_scanner.socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """Test scanning a closed port by mocking socket's connect_ex method to return 1"""
        mock_socket.return_value.connect_ex.return_value = 1
        output = []
        sem = threading.Semaphore(1)
        results = []
        status_var = "Status"
        scan_btn = "Button"
        scan_port("127.0.0.1", 80, output, sem, results, status_var, scan_btn)
        self.assertIn("Port 80: Closed\n", output)

if __name__ == '__main__':
    unittest.main()
