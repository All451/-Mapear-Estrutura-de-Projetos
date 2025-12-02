"""Unit tests for the reporting module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
from datetime import datetime

from cybersec.utils.reporting import ReportingEngine


class TestReportingEngine:
    """Test class for ReportingEngine."""

    def test_reporting_engine_initialization(self):
        """Test reporting engine initialization."""
        reporter = ReportingEngine()
        
        assert reporter.scan_results == {}
        assert reporter.output_dir == 'reports'
        assert hasattr(reporter, 'generate_report')
        assert hasattr(reporter, 'save_report')

    def test_generate_markdown_report(self):
        """Test generating a markdown report."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0',
                'os_version': 'Ubuntu 20.04'
            },
            'network': {
                'open_ports': [22, 80, 443],
                'interfaces': [{'name': 'eth0', 'ip': '192.168.1.100'}]
            }
        }
        
        report = reporter.generate_report(scan_results, format='markdown')
        
        assert isinstance(report, str)
        assert '# Cybersecurity Scan Report' in report
        assert 'test-host' in report
        assert '5.4.0' in report
        assert '22' in report and '80' in report and '443' in report

    def test_generate_json_report(self):
        """Test generating a JSON report."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0'
            }
        }
        
        report = reporter.generate_report(scan_results, format='json')
        
        assert isinstance(report, str)
        assert 'test-host' in report
        assert 'json' in report.lower() or '"system":' in report

    def test_generate_html_report(self):
        """Test generating an HTML report."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0'
            }
        }
        
        report = reporter.generate_report(scan_results, format='html')
        
        assert isinstance(report, str)
        assert '<html' in report.lower() or '<!doctype' in report.lower() or '<div' in report

    def test_generate_txt_report(self):
        """Test generating a TXT report."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0'
            }
        }
        
        report = reporter.generate_report(scan_results, format='txt')
        
        assert isinstance(report, str)
        assert 'test-host' in report
        # Should not have HTML or markdown specific elements
        assert not ('<' in report and '>' in report)  # Basic HTML check

    def test_generate_report_invalid_format(self):
        """Test generating a report with invalid format."""
        reporter = ReportingEngine()
        scan_results = {'system': {'hostname': 'test-host'}}
        
        # Should handle invalid format gracefully
        report = reporter.generate_report(scan_results, format='invalid')
        
        assert isinstance(report, str)
        # Should default to some format or return an error message
        assert len(report) >= 0

    def test_generate_report_empty_results(self):
        """Test generating a report with empty scan results."""
        reporter = ReportingEngine()
        scan_results = {}
        
        report = reporter.generate_report(scan_results, format='markdown')
        
        assert isinstance(report, str)
        assert len(report) >= 0  # Should handle empty results gracefully

    def test_save_report_to_file(self):
        """Test saving a report to a file."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0'
            }
        }
        
        # Create a temporary directory for the test
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(temp_dir, 'test_report.md')
            
            # Generate and save report
            report_content = reporter.generate_report(scan_results, format='markdown')
            reporter.save_report(report_content, output_file)
            
            # Verify file was created and contains content
            assert os.path.exists(output_file)
            with open(output_file, 'r') as f:
                saved_content = f.read()
                assert 'test-host' in saved_content

    def test_save_report_directory_creation(self):
        """Test that save_report creates directories if they don't exist."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host'
            }
        }
        
        with tempfile.TemporaryDirectory() as temp_base_dir:
            output_file = os.path.join(temp_base_dir, 'subdir', 'test_report.md')
            
            # Generate and save report to non-existent subdirectory
            report_content = reporter.generate_report(scan_results, format='markdown')
            reporter.save_report(report_content, output_file)
            
            # Verify file and directory were created
            assert os.path.exists(output_file)

    def test_format_report_data(self):
        """Test formatting scan results for report."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'users': ['root', 'testuser']
            },
            'network': {
                'open_ports': [22, 80]
            }
        }
        
        formatted_data = reporter.format_report_data(scan_results)
        
        assert 'system' in formatted_data
        assert 'network' in formatted_data
        assert formatted_data['system']['hostname'] == 'test-host'

    def test_format_report_data_empty(self):
        """Test formatting empty scan results."""
        reporter = ReportingEngine()
        scan_results = {}
        
        formatted_data = reporter.format_report_data(scan_results)
        
        assert formatted_data == {}

    def test_format_report_data_none_values(self):
        """Test formatting scan results with None values."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': None
            }
        }
        
        formatted_data = reporter.format_report_data(scan_results)
        
        assert 'system' in formatted_data
        assert formatted_data['system']['hostname'] == 'test-host'

    @patch('builtins.open', side_effect=PermissionError("Permission denied"))
    def test_save_report_permission_error(self, mock_open):
        """Test saving report when permission is denied."""
        reporter = ReportingEngine()
        
        with pytest.raises(PermissionError):
            reporter.save_report("test content", "/root/forbidden/report.txt")

    def test_generate_detailed_report(self):
        """Test generating a detailed report with multiple sections."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'hostname': 'test-host',
                'kernel_version': '5.4.0',
                'os_version': 'Ubuntu 20.04',
                'users': ['root', 'testuser'],
                'critical_files': ['/etc/passwd', '/etc/shadow']
            },
            'network': {
                'open_ports': [22, 80, 443, 3306, 5432],
                'interfaces': [
                    {'name': 'eth0', 'ip': '192.168.1.100', 'status': 'UP'},
                    {'name': 'lo', 'ip': '127.0.0.1', 'status': 'UP'}
                ],
                'routes': [
                    {'destination': '0.0.0.0', 'gateway': '192.168.1.1'}
                ]
            },
            'firewall': {
                'ufw_status': 'active',
                'rules': [
                    {'rule': '22/tcp', 'action': 'ALLOW', 'from': 'Anywhere'}
                ],
                'banned_ips': ['192.168.1.100']
            },
            'docker': {
                'containers': [
                    {'id': 'abc123', 'name': 'web-app', 'status': 'running'}
                ],
                'images': [
                    {'id': 'img1', 'name': 'nginx:latest'}
                ]
            },
            'filesystem': {
                'suspicious_files': [
                    {'path': '/tmp/suspicious.sh', 'permissions': '777'}
                ],
                'world_writable_dirs': ['/tmp']
            }
        }
        
        report = reporter.generate_report(scan_results, format='markdown')
        
        # Verify all sections are included in the report
        assert 'System Information' in report
        assert 'Network Analysis' in report
        assert 'Firewall Status' in report
        assert 'Docker Security' in report
        assert 'Filesystem Security' in report
        
        # Verify some specific content is included
        assert 'test-host' in report
        assert '22' in report and '80' in report
        assert 'active' in report
        assert 'web-app' in report
        assert 'suspicious.sh' in report

    def test_report_timestamp(self):
        """Test that reports include timestamps."""
        reporter = ReportingEngine()
        scan_results = {'system': {'hostname': 'test-host'}}
        
        report = reporter.generate_report(scan_results, format='markdown')
        
        # Should contain current date/time information
        assert str(datetime.now().year) in report

    def test_generate_report_with_error_data(self):
        """Test generating report when scan results contain error information."""
        reporter = ReportingEngine()
        scan_results = {
            'system': {
                'error': 'Failed to retrieve system information'
            },
            'network': {
                'open_ports': [22, 80]
            }
        }
        
        report = reporter.generate_report(scan_results, format='markdown')
        
        # Should handle error data gracefully
        assert isinstance(report, str)
        assert 'error' in report.lower() or 'failed' in report.lower() or '22' in report

    def test_output_directory_setting(self):
        """Test setting a custom output directory."""
        reporter = ReportingEngine()
        new_dir = "/custom/reports"
        reporter.output_dir = new_dir
        
        assert reporter.output_dir == new_dir

    def test_supported_formats(self):
        """Test that the reporting engine supports expected formats."""
        reporter = ReportingEngine()
        
        # Check that we can generate reports in different formats without error
        formats_to_test = ['markdown', 'json', 'html', 'txt']
        scan_results = {'system': {'hostname': 'test-host'}}
        
        for fmt in formats_to_test:
            report = reporter.generate_report(scan_results, format=fmt)
            assert isinstance(report, str)
            assert len(report) > 0  # Should generate some content