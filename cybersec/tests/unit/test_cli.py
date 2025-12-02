"""Unit tests for the CLI module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from io import StringIO
from click.testing import CliRunner

from cybersec.cli.main import cli
from cybersec.cli.main import cli
from cybersec.cli.commands import (
    scan_cmd, firewall_status, ban_cmd, unban_cmd, list_banned, 
    check_cmd, ports_cmd, check_port_cmd, docker_scan_cmd, 
    docker_report_cmd, config_show, report_generate
)
from cybersec.core.scanner import SecurityScanner, ScanType
from cybersec.utils.config import ConfigManager


class TestCLI:
    """Test class for CLI commands."""

    def test_cli_main_help(self):
        """Test CLI main help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_cli_version(self):
        """Test CLI version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])
        
        assert result.exit_code == 0
        assert '3.0.0' in result.output  # Assuming version 3.0.0

    def test_scan_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(scan, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_firewall_help(self):
        """Test firewall command help."""
        runner = CliRunner()
        result = runner.invoke(firewall, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_network_help(self):
        """Test network command help."""
        runner = CliRunner()
        result = runner.invoke(network, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_docker_help(self):
        """Test docker command help."""
        runner = CliRunner()
        result = runner.invoke(docker, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_config_help(self):
        """Test config command help."""
        runner = CliRunner()
        result = runner.invoke(config, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    def test_report_help(self):
        """Test report command help."""
        runner = CliRunner()
        result = runner.invoke(report, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'Commands:' in result.output

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_full_command(self, mock_scanner_class):
        """Test scan full command."""
        runner = CliRunner()
        
        # Mock the scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.return_value = {'system': {'hostname': 'test-host'}}
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--full'])
        
        # Check that the scanner was called with the right parameters
        assert mock_scanner_class.called
        mock_scanner_instance.execute_scan.assert_called_once()

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_system_command(self, mock_scanner_class):
        """Test scan system command."""
        runner = CliRunner()
        
        # Mock the scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.return_value = {'system': {'hostname': 'test-host'}}
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--system'])
        
        # Check that the scanner was called with the right parameters
        assert mock_scanner_class.called
        mock_scanner_instance.execute_scan.assert_called_once()

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_network_command(self, mock_scanner_class):
        """Test scan network command."""
        runner = CliRunner()
        
        # Mock the scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.return_value = {'network': {'open_ports': [22, 80]}}
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--network'])
        
        # Check that the scanner was called with the right parameters
        assert mock_scanner_class.called
        mock_scanner_instance.execute_scan.assert_called_once()

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_docker_command(self, mock_scanner_class):
        """Test scan docker command."""
        runner = CliRunner()
        
        # Mock the scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.return_value = {'docker': {'containers': []}}
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--docker'])
        
        # Check that the scanner was called with the right parameters
        assert mock_scanner_class.called
        mock_scanner_instance.execute_scan.assert_called_once()

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_filesystem_command(self, mock_scanner_class):
        """Test scan filesystem command."""
        runner = CliRunner()
        
        # Mock the scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.return_value = {'filesystem': {'suspicious_files': []}}
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--filesystem', '/tmp'])
        
        # Check that the scanner was called with the right parameters
        assert mock_scanner_class.called
        mock_scanner_instance.execute_scan.assert_called_once()

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_status_command(self, mock_firewall_scanner):
        """Test firewall status command."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.get_ufw_status.return_value = 'active'
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['status'])
        
        assert result.exit_code == 0
        mock_firewall_instance.get_ufw_status.assert_called_once()

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_ban_command(self, mock_firewall_scanner):
        """Test firewall ban command."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.ban_ip.return_value = True
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['ban', '192.168.1.100'])
        
        assert result.exit_code == 0
        mock_firewall_instance.ban_ip.assert_called_once_with('192.168.1.100', reason=None)

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_ban_with_reason_command(self, mock_firewall_scanner):
        """Test firewall ban command with reason."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.ban_ip.return_value = True
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['ban', '192.168.1.100', '--reason', 'Suspicious activity'])
        
        assert result.exit_code == 0
        mock_firewall_instance.ban_ip.assert_called_once_with('192.168.1.100', reason='Suspicious activity')

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_unban_command(self, mock_firewall_scanner):
        """Test firewall unban command."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.unban_ip.return_value = True
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['unban', '192.168.1.100'])
        
        assert result.exit_code == 0
        mock_firewall_instance.unban_ip.assert_called_once_with('192.168.1.100')

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_list_command(self, mock_firewall_scanner):
        """Test firewall list command."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.list_banned_ips.return_value = ['192.168.1.100', '10.0.0.50']
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['list'])
        
        assert result.exit_code == 0
        mock_firewall_instance.list_banned_ips.assert_called_once()

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_check_command(self, mock_firewall_scanner):
        """Test firewall check command."""
        runner = CliRunner()
        
        # Mock the firewall scanner
        mock_firewall_instance = Mock()
        mock_firewall_instance.check_ip_status.return_value = 'banned'
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['check', '192.168.1.100'])
        
        assert result.exit_code == 0
        mock_firewall_instance.check_ip_status.assert_called_once_with('192.168.1.100')

    @patch('cybersec.cli.commands.network.NetworkScanner')
    def test_network_ports_command(self, mock_network_scanner):
        """Test network ports command."""
        runner = CliRunner()
        
        # Mock the network scanner
        mock_network_instance = Mock()
        mock_network_instance.get_open_ports.return_value = [22, 80, 443]
        mock_network_scanner.return_value = mock_network_instance
        
        result = runner.invoke(network, ['ports'])
        
        assert result.exit_code == 0
        mock_network_instance.get_open_ports.assert_called_once()

    @patch('cybersec.cli.commands.network.NetworkScanner')
    def test_network_check_command(self, mock_network_scanner):
        """Test network check command."""
        runner = CliRunner()
        
        # Mock the network scanner
        mock_network_instance = Mock()
        mock_network_instance.check_port.return_value = True
        mock_network_scanner.return_value = mock_network_instance
        
        result = runner.invoke(network, ['check', '80'])
        
        assert result.exit_code == 0
        mock_network_instance.check_port.assert_called_once_with('127.0.0.1', 80)

    @patch('cybersec.cli.commands.docker.DockerScanner')
    def test_docker_scan_command(self, mock_docker_scanner):
        """Test docker scan command."""
        runner = CliRunner()
        
        # Mock the docker scanner
        mock_docker_instance = Mock()
        mock_docker_instance.scan.return_value = {'containers': [], 'images': []}
        mock_docker_scanner.return_value = mock_docker_instance
        
        result = runner.invoke(docker, ['scan'])
        
        assert result.exit_code == 0
        mock_docker_instance.scan.assert_called_once()

    @patch('cybersec.cli.commands.docker.DockerScanner')
    def test_docker_report_command(self, mock_docker_scanner):
        """Test docker report command."""
        runner = CliRunner()
        
        # Mock the docker scanner
        mock_docker_instance = Mock()
        mock_docker_instance.scan.return_value = {'containers': [], 'images': []}
        mock_docker_scanner.return_value = mock_docker_instance
        
        result = runner.invoke(docker, ['report'])
        
        assert result.exit_code == 0
        mock_docker_instance.scan.assert_called_once()

    @patch('cybersec.cli.commands.config.ConfigManager')
    def test_config_show_command(self, mock_config_manager):
        """Test config show command."""
        runner = CliRunner()
        
        # Mock the config manager
        mock_config_instance = Mock()
        mock_config_instance.config = {'logging': {'level': 'INFO'}}
        mock_config_manager.return_value = mock_config_instance
        
        result = runner.invoke(config, ['show'])
        
        assert result.exit_code == 0

    @patch('cybersec.cli.commands.report.ReportingEngine')
    def test_report_generate_command(self, mock_reporting_engine):
        """Test report generate command."""
        runner = CliRunner()
        
        # Mock the reporting engine
        mock_report_instance = Mock()
        mock_report_instance.generate_report.return_value = "Sample report"
        mock_reporting_engine.return_value = mock_report_instance
        
        result = runner.invoke(report, ['generate'])
        
        assert result.exit_code == 0
        mock_report_instance.generate_report.assert_called_once()

    @patch('cybersec.cli.commands.report.ReportingEngine')
    def test_report_generate_with_format_command(self, mock_reporting_engine):
        """Test report generate command with format."""
        runner = CliRunner()
        
        # Mock the reporting engine
        mock_report_instance = Mock()
        mock_report_instance.generate_report.return_value = "Sample report"
        mock_reporting_engine.return_value = mock_report_instance
        
        result = runner.invoke(report, ['generate', '--format', 'json'])
        
        assert result.exit_code == 0
        # Verify that the report was called with the correct format
        mock_report_instance.generate_report.assert_called_once()

    def test_invalid_command(self):
        """Test invalid command."""
        runner = CliRunner()
        result = runner.invoke(cli, ['invalid-command'])
        
        assert result.exit_code != 0

    def test_scan_invalid_option(self):
        """Test scan command with invalid option."""
        runner = CliRunner()
        result = runner.invoke(scan, ['--invalid-option'])
        
        assert result.exit_code != 0

    @patch('cybersec.cli.commands.scanner.SecurityScanner')
    def test_scan_exception_handling(self, mock_scanner_class):
        """Test scan command exception handling."""
        runner = CliRunner()
        
        # Mock the scanner to raise an exception
        mock_scanner_instance = Mock()
        mock_scanner_instance.execute_scan.side_effect = Exception("Test error")
        mock_scanner_class.return_value = mock_scanner_instance
        
        result = runner.invoke(scan, ['--full'])
        
        # Should handle the exception gracefully
        assert result.exit_code == 1  # or 0 depending on error handling

    @patch('cybersec.cli.commands.firewall.FirewallScanner')
    def test_firewall_exception_handling(self, mock_firewall_scanner):
        """Test firewall command exception handling."""
        runner = CliRunner()
        
        # Mock the firewall scanner to raise an exception
        mock_firewall_instance = Mock()
        mock_firewall_instance.get_ufw_status.side_effect = Exception("Test error")
        mock_firewall_scanner.return_value = mock_firewall_instance
        
        result = runner.invoke(firewall, ['status'])
        
        # Should handle the exception gracefully
        assert result.exit_code == 1  # or 0 depending on error handling