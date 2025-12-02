"""Unit tests for the network module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import socket
from datetime import datetime

from cybersec.core.network import NetworkScanner


class TestNetworkScanner:
    """Test class for NetworkScanner."""

    def test_network_scanner_initialization(self):
        """Test network scanner initialization."""
        scanner = NetworkScanner()
        
        assert scanner.open_ports == []
        assert scanner.interfaces == []
        assert scanner.routes == []

    @patch('subprocess.run')
    def test_get_open_ports(self, mock_subprocess):
        """Test getting open ports."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = 'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n' \
                            'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n' \
                            'tcp        0      0 :::443                  :::*                    LISTEN\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        open_ports = scanner.get_open_ports()
        
        assert 22 in open_ports
        assert 80 in open_ports
        assert 443 in open_ports
        mock_subprocess.assert_called_once_with(['ss', '-tuln'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_network_interfaces(self, mock_subprocess):
        """Test getting network interfaces."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP\n' \
                            '    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n' \
                            '3: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n' \
                            '    inet 127.0.0.1/8 scope host lo\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        interfaces = scanner.get_network_interfaces()
        
        assert len(interfaces) >= 2
        eth0_found = any(iface['name'] == 'eth0' for iface in interfaces)
        lo_found = any(iface['name'] == 'lo' for iface in interfaces)
        assert eth0_found
        assert lo_found
        mock_subprocess.assert_called_once_with(['ip', 'addr', 'show'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_routing_table(self, mock_subprocess):
        """Test getting routing table."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = 'default via 192.168.1.1 dev eth0 proto dhcp metric 100\n' \
                            '192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        routes = scanner.get_routing_table()
        
        assert len(routes) >= 1
        mock_subprocess.assert_called_once_with(['ip', 'route', 'show'], capture_output=True, text=True)

    @patch('socket.socket')
    def test_check_port_open(self, mock_socket):
        """Test checking if a port is open."""
        scanner = NetworkScanner()
        mock_sock_instance = Mock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 0  # Connection successful
        
        result = scanner.check_port('127.0.0.1', 22)
        
        assert result is True
        mock_socket.assert_called_once()
        mock_sock_instance.connect_ex.assert_called_once_with(('127.0.0.1', 22))
        mock_sock_instance.close.assert_called_once()

    @patch('socket.socket')
    def test_check_port_closed(self, mock_socket):
        """Test checking if a port is closed."""
        scanner = NetworkScanner()
        mock_sock_instance = Mock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 1  # Connection failed
        
        result = scanner.check_port('127.0.0.1', 22)
        
        assert result is False

    @patch('socket.socket')
    def test_check_port_exception(self, mock_socket):
        """Test checking port when socket raises an exception."""
        scanner = NetworkScanner()
        mock_sock_instance = Mock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.side_effect = Exception("Socket error")
        
        result = scanner.check_port('127.0.0.1', 22)
        
        assert result is False

    @patch('cybersec.core.network.NetworkScanner.get_open_ports')
    @patch('cybersec.core.network.NetworkScanner.get_network_interfaces')
    @patch('cybersec.core.network.NetworkScanner.get_routing_table')
    def test_scan_success(self, mock_get_routes, mock_get_interfaces, mock_get_ports, mock_network_scan_data):
        """Test successful network scan."""
        scanner = NetworkScanner()
        
        # Mock the methods
        mock_get_ports.return_value = [22, 80, 443]
        mock_get_interfaces.return_value = [
            {'name': 'eth0', 'ip': '192.168.1.100', 'status': 'UP'},
            {'name': 'lo', 'ip': '127.0.0.1', 'status': 'UP'}
        ]
        mock_get_routes.return_value = [
            {'destination': '0.0.0.0', 'gateway': '192.168.1.1', 'interface': 'eth0'}
        ]
        
        scan_results = scanner.scan()
        
        assert 'open_ports' in scan_results
        assert 'interfaces' in scan_results
        assert 'routes' in scan_results
        assert 22 in scan_results['open_ports']
        assert len(scan_results['interfaces']) >= 2
        assert len(scan_results['routes']) >= 1

    @patch('subprocess.run')
    def test_get_open_ports_error(self, mock_subprocess):
        """Test getting open ports when command fails."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        open_ports = scanner.get_open_ports()
        
        assert open_ports == []

    @patch('subprocess.run')
    def test_get_network_interfaces_error(self, mock_subprocess):
        """Test getting network interfaces when command fails."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        interfaces = scanner.get_network_interfaces()
        
        assert interfaces == []

    @patch('subprocess.run')
    def test_get_routing_table_error(self, mock_subprocess):
        """Test getting routing table when command fails."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        routes = scanner.get_routing_table()
        
        assert routes == []

    @patch('cybersec.core.network.NetworkScanner.get_open_ports')
    @patch('cybersec.core.network.NetworkScanner.get_network_interfaces')
    @patch('cybersec.core.network.NetworkScanner.get_routing_table')
    def test_scan_with_method_errors(self, mock_get_routes, mock_get_interfaces, mock_get_ports):
        """Test network scan when individual methods fail."""
        scanner = NetworkScanner()
        
        # Make the methods return empty lists to simulate errors
        mock_get_ports.return_value = []
        mock_get_interfaces.return_value = []
        mock_get_routes.return_value = []
        
        scan_results = scanner.scan()
        
        assert 'open_ports' in scan_results
        assert 'interfaces' in scan_results
        assert 'routes' in scan_results
        assert scan_results['open_ports'] == []
        assert scan_results['interfaces'] == []
        assert scan_results['routes'] == []

    @patch('subprocess.run')
    def test_get_open_ports_parse_error(self, mock_subprocess):
        """Test getting open ports with malformed output."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = 'invalid output format\nwith no ports'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        open_ports = scanner.get_open_ports()
        
        # Should handle malformed output gracefully
        assert isinstance(open_ports, list)

    @patch('subprocess.run')
    def test_get_network_interfaces_parse_error(self, mock_subprocess):
        """Test getting network interfaces with malformed output."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = 'invalid interface output'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        interfaces = scanner.get_network_interfaces()
        
        # Should handle malformed output gracefully
        assert isinstance(interfaces, list)

    @patch('subprocess.run')
    def test_get_routing_table_parse_error(self, mock_subprocess):
        """Test getting routing table with malformed output."""
        scanner = NetworkScanner()
        mock_result = Mock()
        mock_result.stdout = 'invalid route output'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        routes = scanner.get_routing_table()
        
        # Should handle malformed output gracefully
        assert isinstance(routes, list)