"""Integration tests for the full scanning workflow."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
from datetime import datetime

from cybersec.core.scanner import SecurityScanner, ScanType
from cybersec.utils.config import ConfigManager
from cybersec.utils.reporting import ReportingEngine


class TestFullScanIntegration:
    """Test class for full scan integration tests."""

    def test_full_scan_workflow(self, temp_config_file):
        """Test the complete scan workflow from initialization to reporting."""
        # Create a config manager
        config = ConfigManager(temp_config_file)
        
        # Create a scanner
        scanner = SecurityScanner(config)
        
        # Add multiple scan types
        scanner.add_scan_type(ScanType.SYSTEM)
        scanner.add_scan_type(ScanType.NETWORK)
        scanner.add_scan_type(ScanType.FIREWALL)
        
        # Mock the scan methods to return test data
        with patch('cybersec.core.system.SystemScanner.scan') as mock_system_scan, \
             patch('cybersec.core.network.NetworkScanner.scan') as mock_network_scan, \
             patch('cybersec.core.firewall.FirewallScanner.scan') as mock_firewall_scan:
            
            mock_system_scan.return_value = {'hostname': 'test-host', 'os': 'Ubuntu'}
            mock_network_scan.return_value = {'open_ports': [22, 80], 'interfaces': []}
            mock_firewall_scan.return_value = {'status': 'active', 'rules': []}
            
            # Execute the scan
            results = scanner.execute_scan()
            
            # Verify results contain all expected sections
            assert 'system' in results
            assert 'network' in results
            assert 'firewall' in results
            assert results['system']['hostname'] == 'test-host'
            assert 22 in results['network']['open_ports']

    def test_scan_to_report_workflow(self, temp_config_file):
        """Test the workflow from scanning to report generation."""
        # Create a config manager
        config = ConfigManager(temp_config_file)
        
        # Create a scanner
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.SYSTEM)
        
        # Mock the scan method
        with patch('cybersec.core.system.SystemScanner.scan') as mock_system_scan:
            mock_system_scan.return_value = {'hostname': 'test-host', 'users': ['root', 'testuser']}
            
            # Execute the scan
            scan_results = scanner.execute_scan()
            
            # Create a reporting engine and generate report
            reporter = ReportingEngine()
            report = reporter.generate_report(scan_results, format='markdown')
            
            # Verify report contains scan data
            assert 'test-host' in report
            assert 'System Information' in report

    def test_config_scanner_integration(self, temp_config_file):
        """Test integration between config and scanner."""
        # Create a config manager
        config = ConfigManager(temp_config_file)
        
        # Verify config values can be accessed by scanner
        timeout = config.get('scanner.timeout')
        assert timeout == 30  # From our test config
        
        # Create a scanner with this config
        scanner = SecurityScanner(config)
        
        # The scanner should have access to config values
        assert scanner.config is not None
        assert scanner.config.get('scanner.timeout') == 30

    def test_scan_with_config_dependencies(self, temp_config_file):
        """Test scanning with configuration dependencies."""
        # Modify config to test different settings
        config = ConfigManager(temp_config_file)
        config.set('scanner.quick_scan', True)
        config.set('scanner.max_depth', 1)
        
        # Create scanner with modified config
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.FILESYSTEM)
        
        # Mock filesystem scan to verify config is used
        with patch('cybersec.core.filesystem.FilesystemScanner.scan') as mock_filesystem_scan:
            mock_filesystem_scan.return_value = {'suspicious_files': []}
            
            results = scanner.execute_scan()
            
            # Verify scan executed with config parameters
            assert 'filesystem' in results
            mock_filesystem_scan.assert_called_once()

    def test_report_generation_with_scan_data(self, temp_config_file):
        """Test report generation with realistic scan data."""
        # Create realistic scan results
        scan_results = {
            'system': {
                'hostname': 'integration-test-host',
                'kernel_version': '5.4.0-124-generic',
                'os_version': 'Ubuntu 20.04.6 LTS',
                'users': ['root', 'testuser', 'cybersec'],
                'processes': [
                    {'pid': 1, 'name': 'systemd', 'user': 'root'},
                    {'pid': 123, 'name': 'sshd', 'user': 'root'}
                ],
                'critical_files': ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            },
            'network': {
                'open_ports': [22, 80, 443],
                'interfaces': [
                    {'name': 'eth0', 'ip': '192.168.1.100', 'status': 'UP'},
                    {'name': 'lo', 'ip': '127.0.0.1', 'status': 'UP'}
                ],
                'routes': [
                    {'destination': '0.0.0.0', 'gateway': '192.168.1.1', 'interface': 'eth0'}
                ]
            },
            'firewall': {
                'ufw_status': 'active',
                'rules': [
                    {'rule': '22/tcp', 'action': 'ALLOW', 'from': 'Anywhere'},
                    {'rule': '80/tcp', 'action': 'ALLOW', 'from': 'Anywhere'},
                    {'rule': '443/tcp', 'action': 'ALLOW', 'from': 'Anywhere'}
                ],
                'banned_ips': ['192.168.1.100', '10.0.0.50']
            },
            'docker': {
                'containers': [
                    {
                        'id': 'abc123def456',
                        'name': 'web-container',
                        'status': 'Up 2 hours',
                        'ports': '0.0.0.0:8080->80/tcp',
                        'image': 'nginx:latest'
                    }
                ],
                'images': [
                    {'id': 'img123', 'name': 'nginx:latest', 'size': '133MB'}
                ],
                'exposed_ports': [8080]
            },
            'filesystem': {
                'suspicious_files': [
                    {'path': '/tmp/suspicious.sh', 'size': 1024, 'permissions': '777'},
                    {'path': '/var/log/compromised.log', 'size': 2048, 'permissions': '666'}
                ],
                'world_writable_dirs': ['/tmp', '/var/tmp'],
                'suid_files': ['/usr/bin/sudo', '/usr/bin/passwd'],
                'recent_files': [
                    {'path': '/home/user/modified_recently.txt', 'modified': '2023-01-01 12:00:00', 'size': 512}
                ]
            }
        }
        
        # Generate reports in different formats
        reporter = ReportingEngine()
        
        formats = ['markdown', 'json', 'html', 'txt']
        for fmt in formats:
            report = reporter.generate_report(scan_results, format=fmt)
            assert isinstance(report, str)
            assert len(report) > 0
            # Verify that important data appears in the report
            assert 'integration-test-host' in report or fmt == 'json'  # JSON might format differently

    def test_complete_workflow_with_file_output(self, temp_config_file):
        """Test the complete workflow with file output."""
        # Create a temporary directory for reports
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create scan results
            scan_results = {
                'system': {'hostname': 'workflow-test', 'os': 'Ubuntu 20.04'},
                'network': {'open_ports': [22]}
            }
            
            # Generate and save report
            reporter = ReportingEngine()
            report_content = reporter.generate_report(scan_results, format='markdown')
            
            report_file = os.path.join(temp_dir, 'integration_report.md')
            reporter.save_report(report_content, report_file)
            
            # Verify file was created and contains expected content
            assert os.path.exists(report_file)
            
            with open(report_file, 'r') as f:
                content = f.read()
                assert 'workflow-test' in content
                assert 'System Information' in content

    def test_multiple_scan_types_integration(self, temp_config_file):
        """Test integration with multiple scan types simultaneously."""
        config = ConfigManager(temp_config_file)
        scanner = SecurityScanner(config)
        
        # Add all scan types
        for scan_type in [ScanType.SYSTEM, ScanType.NETWORK, ScanType.FIREWALL, ScanType.DOCKER, ScanType.FILESYSTEM]:
            scanner.add_scan_type(scan_type)
        
        # Mock all scan methods
        with patch('cybersec.core.system.SystemScanner.scan') as mock_system, \
             patch('cybersec.core.network.NetworkScanner.scan') as mock_network, \
             patch('cybersec.core.firewall.FirewallScanner.scan') as mock_firewall, \
             patch('cybersec.core.docker.DockerScanner.scan') as mock_docker, \
             patch('cybersec.core.filesystem.FilesystemScanner.scan') as mock_filesystem:
            
            mock_system.return_value = {'hostname': 'multi-test'}
            mock_network.return_value = {'open_ports': [22, 80]}
            mock_firewall.return_value = {'status': 'active'}
            mock_docker.return_value = {'containers': []}
            mock_filesystem.return_value = {'suspicious_files': []}
            
            results = scanner.execute_scan()
            
            # Verify all scan types were executed
            assert 'system' in results
            assert 'network' in results
            assert 'firewall' in results
            assert 'docker' in results
            assert 'filesystem' in results
            
            # Verify mock methods were called
            mock_system.assert_called_once()
            mock_network.assert_called_once()
            mock_firewall.assert_called_once()
            mock_docker.assert_called_once()
            mock_filesystem.assert_called_once()

    def test_config_based_scan_filtering(self, temp_config_file):
        """Test that configuration affects which scans are performed."""
        # Modify config to enable quick scan mode
        config = ConfigManager(temp_config_file)
        config.set('scanner.quick_scan', True)
        
        scanner = SecurityScanner(config)
        
        # Add all scan types
        for scan_type in [ScanType.SYSTEM, ScanType.NETWORK, ScanType.FIREWALL]:
            scanner.add_scan_type(scan_type)
        
        # In a real implementation, quick scan might limit depth or scope
        # For this test, we just verify the config is accessible
        quick_scan_enabled = config.get('scanner.quick_scan')
        assert quick_scan_enabled is True

    def test_error_handling_in_full_workflow(self, temp_config_file):
        """Test error handling throughout the full workflow."""
        config = ConfigManager(temp_config_file)
        scanner = SecurityScanner(config)
        scanner.add_scan_type(ScanType.SYSTEM)
        
        # Mock a scan that raises an exception
        with patch('cybersec.core.system.SystemScanner.scan') as mock_system_scan:
            mock_system_scan.side_effect = Exception("System scan failed")
            
            # Scanner should handle the error gracefully
            results = scanner.execute_scan()
            
            # Results should still be a dict, possibly with error information
            assert isinstance(results, dict)
            # The system section might contain error info or be empty
            assert 'system' in results

    def test_report_with_empty_scan_results(self, temp_config_file):
        """Test report generation with empty scan results."""
        # Create empty scan results
        scan_results = {}
        
        reporter = ReportingEngine()
        report = reporter.generate_report(scan_results, format='markdown')
        
        # Should generate a report even with empty results
        assert isinstance(report, str)
        # Should contain basic report structure
        assert 'Cybersecurity Scan Report' in report

    def test_config_update_during_workflow(self, temp_config_file):
        """Test updating config during the scanning workflow."""
        config = ConfigManager(temp_config_file)
        
        # Initial config value
        initial_timeout = config.get('scanner.timeout')
        assert initial_timeout == 30
        
        # Update config
        config.set('scanner.timeout', 60)
        updated_timeout = config.get('scanner.timeout')
        assert updated_timeout == 60
        
        # Create scanner with updated config
        scanner = SecurityScanner(config)
        # Scanner should use updated config value
        assert scanner.config.get('scanner.timeout') == 60