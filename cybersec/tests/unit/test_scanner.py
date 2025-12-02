"""Unit tests for the scanner module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
from datetime import datetime

from cybersec.core.scanner import SecurityScanner, ScanType
from cybersec.utils.config import ConfigManager


class TestSecurityScanner:
    """Test class for SecurityScanner."""

    def test_scanner_initialization(self, temp_config_file):
        """Test scanner initialization with config."""
        config = ConfigManager(temp_config_file)
        scanner = SecurityScanner(config)
        
        assert scanner.config == config
        assert scanner.results == {}
        assert scanner.scan_types == set()

    def test_add_scan_type(self):
        """Test adding scan types."""
        config = Mock()
        scanner = SecurityScanner(config)
        
        scanner.add_scan_type(ScanType.SYSTEM)
        assert ScanType.SYSTEM in scanner.scan_types
        
        scanner.add_scan_type(ScanType.NETWORK)
        assert ScanType.NETWORK in scanner.scan_types
        assert len(scanner.scan_types) == 2

    def test_add_scan_type_duplicate(self):
        """Test adding duplicate scan types."""
        config = Mock()
        scanner = SecurityScanner(config)
        
        scanner.add_scan_type(ScanType.SYSTEM)
        scanner.add_scan_type(ScanType.SYSTEM)  # Should not duplicate
        
        assert len(scanner.scan_types) == 1
        assert ScanType.SYSTEM in scanner.scan_types

    @patch('cybersec.core.system.SystemScanner.scan')
    def test_execute_system_scan(self, mock_system_scan, mock_system_scan_data):
        """Test executing system scan."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.SYSTEM)
        
        mock_system_scan.return_value = mock_system_scan_data
        
        results = scanner.execute_scan()
        
        assert 'system' in results
        assert results['system'] == mock_system_scan_data
        mock_system_scan.assert_called_once()

    @patch('cybersec.core.network.NetworkScanner.scan')
    def test_execute_network_scan(self, mock_network_scan, mock_network_scan_data):
        """Test executing network scan."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.NETWORK)
        
        mock_network_scan.return_value = mock_network_scan_data
        
        results = scanner.execute_scan()
        
        assert 'network' in results
        assert results['network'] == mock_network_scan_data
        mock_network_scan.assert_called_once()

    @patch('cybersec.core.firewall.FirewallScanner.scan')
    def test_execute_firewall_scan(self, mock_firewall_scan, mock_firewall_data):
        """Test executing firewall scan."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.FIREWALL)
        
        mock_firewall_scan.return_value = mock_firewall_data
        
        results = scanner.execute_scan()
        
        assert 'firewall' in results
        assert results['firewall'] == mock_firewall_data
        mock_firewall_scan.assert_called_once()

    @patch('cybersec.core.docker.DockerScanner.scan')
    def test_execute_docker_scan(self, mock_docker_scan, mock_docker_data):
        """Test executing docker scan."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.DOCKER)
        
        mock_docker_scan.return_value = mock_docker_data
        
        results = scanner.execute_scan()
        
        assert 'docker' in results
        assert results['docker'] == mock_docker_data
        mock_docker_scan.assert_called_once()

    @patch('cybersec.core.filesystem.FilesystemScanner.scan')
    def test_execute_filesystem_scan(self, mock_filesystem_scan, mock_filesystem_scan_data):
        """Test executing filesystem scan."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.FILESYSTEM)
        
        mock_filesystem_scan.return_value = mock_filesystem_scan_data
        
        results = scanner.execute_scan()
        
        assert 'filesystem' in results
        assert results['filesystem'] == mock_filesystem_scan_data
        mock_filesystem_scan.assert_called_once()

    @patch('cybersec.core.system.SystemScanner.scan')
    @patch('cybersec.core.network.NetworkScanner.scan')
    def test_execute_multiple_scans(self, mock_network_scan, mock_system_scan, 
                                    mock_system_scan_data, mock_network_scan_data):
        """Test executing multiple scan types."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.SYSTEM)
        scanner.add_scan_type(ScanType.NETWORK)
        
        mock_system_scan.return_value = mock_system_scan_data
        mock_network_scan.return_value = mock_network_scan_data
        
        results = scanner.execute_scan()
        
        assert 'system' in results
        assert 'network' in results
        assert results['system'] == mock_system_scan_data
        assert results['network'] == mock_network_scan_data
        mock_system_scan.assert_called_once()
        mock_network_scan.assert_called_once()

    def test_execute_scan_no_types(self):
        """Test executing scan with no scan types added."""
        config = Mock()
        scanner = SecurityScanner(config)
        
        results = scanner.execute_scan()
        
        assert results == {}

    @patch('cybersec.core.system.SystemScanner.scan')
    def test_execute_scan_with_exception(self, mock_system_scan):
        """Test executing scan when a scan module raises an exception."""
        config = Mock()
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.SYSTEM)
        
        mock_system_scan.side_effect = Exception("Test error")
        
        # Should handle the exception gracefully
        results = scanner.execute_scan()
        
        # The result should still contain the error information
        assert 'system' in results
        assert isinstance(results['system'], dict)
        assert 'error' in results['system']

    def test_scan_type_from_string(self):
        """Test creating ScanType from string."""
        assert ScanType.from_string('system') == ScanType.SYSTEM
        assert ScanType.from_string('network') == ScanType.NETWORK
        assert ScanType.from_string('firewall') == ScanType.FIREWALL
        assert ScanType.from_string('docker') == ScanType.DOCKER
        assert ScanType.from_string('filesystem') == ScanType.FILESYSTEM
        assert ScanType.from_string('quick') == ScanType.QUICK
        assert ScanType.from_string('full') == ScanType.FULL
        
        with pytest.raises(ValueError):
            ScanType.from_string('invalid')