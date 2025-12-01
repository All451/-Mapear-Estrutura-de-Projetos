"""Unit tests for the scanner module."""
import unittest
from unittest.mock import Mock, patch, MagicMock
import os

from cybersec.core.scanner import SecurityScanner
from cybersec.core.system import SystemScanner
from cybersec.core.network import NetworkScanner
from cybersec.core.firewall import FirewallManager
from cybersec.core.docker import DockerScanner
from cybersec.core.filesystem import FilesystemScanner


class TestSecurityScanner(unittest.TestCase):
    """Test cases for the SecurityScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = SecurityScanner()
    
    @patch.object(SystemScanner, 'scan')
    def test_scan_system(self, mock_scan):
        """Test system scan method."""
        mock_scan.return_value = [{'title': 'Test Finding', 'severity': 'high'}]
        
        result = self.scanner.scan_system()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Test Finding')
        self.assertEqual(result[0]['severity'], 'high')
        mock_scan.assert_called_once()
    
    @patch.object(NetworkScanner, 'scan')
    def test_scan_network(self, mock_scan):
        """Test network scan method."""
        mock_scan.return_value = [{'title': 'Network Finding', 'severity': 'medium'}]
        
        result = self.scanner.scan_network()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Network Finding')
        self.assertEqual(result[0]['severity'], 'medium')
        mock_scan.assert_called_once()
    
    @patch.object(FirewallManager, 'scan')
    def test_scan_firewall(self, mock_scan):
        """Test firewall scan method."""
        mock_scan.return_value = [{'title': 'Firewall Finding', 'severity': 'low'}]
        
        result = self.scanner.scan_firewall()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Firewall Finding')
        self.assertEqual(result[0]['severity'], 'low')
        mock_scan.assert_called_once()
    
    @patch.object(DockerScanner, 'scan')
    def test_scan_docker(self, mock_scan):
        """Test Docker scan method."""
        mock_scan.return_value = [{'title': 'Docker Finding', 'severity': 'critical'}]
        
        result = self.scanner.scan_docker()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Docker Finding')
        self.assertEqual(result[0]['severity'], 'critical')
        mock_scan.assert_called_once()
    
    @patch.object(FilesystemScanner, 'scan')
    def test_scan_filesystem(self, mock_scan):
        """Test filesystem scan method."""
        mock_scan.return_value = [{'title': 'Filesystem Finding', 'severity': 'high'}]
        
        result = self.scanner.scan_filesystem("/")
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['title'], 'Filesystem Finding')
        self.assertEqual(result[0]['severity'], 'high')
        mock_scan.assert_called_once()
    
    @patch.object(SystemScanner, 'scan')
    @patch.object(NetworkScanner, 'scan')
    @patch.object(FirewallManager, 'scan')
    def test_quick_scan(self, mock_fw_scan, mock_net_scan, mock_sys_scan):
        """Test quick scan method."""
        mock_sys_scan.return_value = [{'title': 'System Finding', 'severity': 'high'}]
        mock_net_scan.return_value = [{'title': 'Network Finding', 'severity': 'medium'}]
        mock_fw_scan.return_value = []
        
        result = self.scanner.quick_scan()
        
        self.assertIn('system', result)
        self.assertIn('network', result)
        self.assertEqual(len(result['system']), 1)
        self.assertEqual(len(result['network']), 1)
        self.assertEqual(len(result['firewall']), 0)
        
        mock_sys_scan.assert_called_once()
        mock_net_scan.assert_called_once()
        mock_fw_scan.assert_called_once()
    
    def test_get_summary(self):
        """Test get_summary method."""
        # Set up scan results directly
        self.scanner.scan_results = {
            'system': [
                {'severity': 'critical'},
                {'severity': 'high'},
                {'severity': 'medium'},
                {'severity': 'low'}
            ],
            'network': [
                {'severity': 'high'},
                {'severity': 'low'}
            ]
        }
        
        summary = self.scanner.get_summary()
        
        self.assertEqual(summary['critical'], 1)
        self.assertEqual(summary['high'], 2)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 2)
        self.assertEqual(summary['total'], 6)
    
    def test_reset_results(self):
        """Test reset_results method."""
        self.scanner.scan_results = {
            'system': [{'title': 'Test', 'severity': 'high'}],
            'network': [],
            'firewall': [],
            'docker': [],
            'filesystem': []
        }
        
        self.scanner.reset_results()
        
        for scan_type in self.scanner.scan_results:
            self.assertEqual(len(self.scanner.scan_results[scan_type]), 0)


if __name__ == '__main__':
    unittest.main()