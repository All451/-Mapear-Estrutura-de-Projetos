"""Unit tests for the firewall module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from cybersec.core.firewall import FirewallScanner


class TestFirewallScanner:
    """Test class for FirewallScanner."""

    def test_firewall_scanner_initialization(self):
        """Test firewall scanner initialization."""
        scanner = FirewallScanner()
        
        assert scanner.rules == []
        assert scanner.status is None

    @patch('subprocess.run')
    def test_get_ufw_status_active(self, mock_subprocess):
        """Test getting UFW status when active."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Status: active\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        status = scanner.get_ufw_status()
        
        assert status == 'active'
        mock_subprocess.assert_called_once_with(['ufw', 'status'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_ufw_status_inactive(self, mock_subprocess):
        """Test getting UFW status when inactive."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Status: inactive\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        status = scanner.get_ufw_status()
        
        assert status == 'inactive'

    @patch('subprocess.run')
    def test_get_ufw_status_error(self, mock_subprocess):
        """Test getting UFW status when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command not found'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        status = scanner.get_ufw_status()
        
        assert status is None

    @patch('subprocess.run')
    def test_get_ufw_rules(self, mock_subprocess):
        """Test getting UFW rules."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = '''Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
443/tcp                    ALLOW       Anywhere                  
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
443/tcp (v6)               ALLOW       Anywhere (v6)'''
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        rules = scanner.get_ufw_rules()
        
        assert len(rules) >= 3  # At least the 3 main rules
        # Check that we have rules for ports 22, 80, 443
        rule_ports = [rule['rule'] for rule in rules]
        assert '22/tcp' in rule_ports
        assert '80/tcp' in rule_ports
        assert '443/tcp' in rule_ports

    @patch('subprocess.run')
    def test_get_ufw_rules_empty(self, mock_subprocess):
        """Test getting UFW rules when none exist."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Status: inactive\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        rules = scanner.get_ufw_rules()
        
        assert rules == []

    @patch('subprocess.run')
    def test_get_ufw_rules_error(self, mock_subprocess):
        """Test getting UFW rules when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command not found'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        rules = scanner.get_ufw_rules()
        
        assert rules == []

    @patch('subprocess.run')
    def test_get_ufw_rules_parse_error(self, mock_subprocess):
        """Test getting UFW rules with malformed output."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'invalid rule output format'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        rules = scanner.get_ufw_rules()
        
        # Should handle malformed output gracefully
        assert isinstance(rules, list)

    @patch('subprocess.run')
    def test_ban_ip_success(self, mock_subprocess):
        """Test banning an IP successfully."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Skipping adding existing rule...\nRule added\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = scanner.ban_ip('192.168.1.100')
        
        assert result is True
        mock_subprocess.assert_called_once_with(['ufw', 'deny', 'from', '192.168.1.100'], 
                                                capture_output=True, text=True)

    @patch('subprocess.run')
    def test_ban_ip_with_reason(self, mock_subprocess):
        """Test banning an IP with a reason."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Rule added\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = scanner.ban_ip('192.168.1.100', reason='Suspicious activity')
        
        assert result is True
        # Note: The reason is not directly passed to the ufw command in this implementation
        mock_subprocess.assert_called_once()

    @patch('subprocess.run')
    def test_ban_ip_error(self, mock_subprocess):
        """Test banning an IP when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Error: Invalid IP address'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        result = scanner.ban_ip('invalid_ip')
        
        assert result is False

    @patch('subprocess.run')
    def test_unban_ip_success(self, mock_subprocess):
        """Test unbanning an IP successfully."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Rule deleted\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = scanner.unban_ip('192.168.1.100')
        
        assert result is True
        mock_subprocess.assert_called_once_with(['ufw', 'delete', 'deny', 'from', '192.168.1.100'], 
                                                capture_output=True, text=True)

    @patch('subprocess.run')
    def test_unban_ip_error(self, mock_subprocess):
        """Test unbanning an IP when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Error: Rule not found'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        result = scanner.unban_ip('192.168.1.100')
        
        assert result is False

    @patch('subprocess.run')
    def test_list_banned_ips(self, mock_subprocess):
        """Test listing banned IPs."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = '''Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY        192.168.1.100             
Anywhere                   DENY        10.0.0.50'''
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        banned_ips = scanner.list_banned_ips()
        
        assert '192.168.1.100' in banned_ips
        assert '10.0.0.50' in banned_ips

    @patch('subprocess.run')
    def test_list_banned_ips_empty(self, mock_subprocess):
        """Test listing banned IPs when none exist."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = 'Status: active\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        banned_ips = scanner.list_banned_ips()
        
        assert banned_ips == []

    @patch('subprocess.run')
    def test_list_banned_ips_error(self, mock_subprocess):
        """Test listing banned IPs when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        banned_ips = scanner.list_banned_ips()
        
        assert banned_ips == []

    @patch('cybersec.core.firewall.FirewallScanner.get_ufw_status')
    @patch('cybersec.core.firewall.FirewallScanner.get_ufw_rules')
    @patch('cybersec.core.firewall.FirewallScanner.list_banned_ips')
    def test_scan_success(self, mock_list_banned, mock_get_rules, mock_get_status, mock_firewall_data):
        """Test successful firewall scan."""
        scanner = FirewallScanner()
        
        # Mock the methods
        mock_get_status.return_value = 'active'
        mock_get_rules.return_value = [
            {'rule': '22/tcp', 'action': 'ALLOW', 'from': 'Anywhere'},
            {'rule': '80/tcp', 'action': 'ALLOW', 'from': 'Anywhere'}
        ]
        mock_list_banned.return_value = ['192.168.1.100']
        
        scan_results = scanner.scan()
        
        assert 'ufw_status' in scan_results
        assert 'rules' in scan_results
        assert 'banned_ips' in scan_results
        assert scan_results['ufw_status'] == 'active'
        assert len(scan_results['rules']) >= 2
        assert '192.168.1.100' in scan_results['banned_ips']

    @patch('cybersec.core.firewall.FirewallScanner.get_ufw_status')
    @patch('cybersec.core.firewall.FirewallScanner.get_ufw_rules')
    @patch('cybersec.core.firewall.FirewallScanner.list_banned_ips')
    def test_scan_with_method_errors(self, mock_list_banned, mock_get_rules, mock_get_status):
        """Test firewall scan when individual methods fail."""
        scanner = FirewallScanner()
        
        # Make the methods return None or empty values to simulate errors
        mock_get_status.return_value = None
        mock_get_rules.return_value = []
        mock_list_banned.return_value = []
        
        scan_results = scanner.scan()
        
        assert 'ufw_status' in scan_results
        assert 'rules' in scan_results
        assert 'banned_ips' in scan_results
        assert scan_results['ufw_status'] is None
        assert scan_results['rules'] == []
        assert scan_results['banned_ips'] == []

    @patch('subprocess.run')
    def test_check_ip_status_banned(self, mock_subprocess):
        """Test checking if an IP is banned."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = '''Status: active

To                         Action      From
--                         ------      ----
Anywhere                   DENY        192.168.1.100'''
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        status = scanner.check_ip_status('192.168.1.100')
        
        assert status == 'banned'

    @patch('subprocess.run')
    def test_check_ip_status_not_banned(self, mock_subprocess):
        """Test checking if an IP is not banned."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = '''Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere'''
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        status = scanner.check_ip_status('192.168.1.100')
        
        assert status == 'not_banned'

    @patch('subprocess.run')
    def test_check_ip_status_error(self, mock_subprocess):
        """Test checking IP status when command fails."""
        scanner = FirewallScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        status = scanner.check_ip_status('192.168.1.100')
        
        assert status == 'unknown'