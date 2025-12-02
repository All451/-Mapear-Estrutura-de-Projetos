"""Unit tests for the system module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import subprocess
from datetime import datetime

from cybersec.core.system import SystemScanner


class TestSystemScanner:
    """Test class for SystemScanner."""

    def test_system_scanner_initialization(self):
        """Test system scanner initialization."""
        scanner = SystemScanner()
        
        assert scanner.hostname is None
        assert scanner.kernel_version is None
        assert scanner.os_version is None

    @patch('subprocess.run')
    def test_get_hostname(self, mock_subprocess):
        """Test getting hostname."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = 'test-host\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        hostname = scanner.get_hostname()
        
        assert hostname == 'test-host'
        mock_subprocess.assert_called_once_with(['hostname'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_kernel_version(self, mock_subprocess):
        """Test getting kernel version."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = '5.4.0-124-generic\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        kernel_version = scanner.get_kernel_version()
        
        assert kernel_version == '5.4.0-124-generic'
        mock_subprocess.assert_called_once_with(['uname', '-r'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_os_version(self, mock_subprocess):
        """Test getting OS version."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        os_version = scanner.get_os_version()
        
        assert 'Ubuntu' in os_version
        assert '20.04.6' in os_version
        mock_subprocess.assert_called_once_with(['cat', '/etc/os-release'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_users(self, mock_subprocess):
        """Test getting system users."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = 'root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        users = scanner.get_users()
        
        assert 'root' in users
        assert 'testuser' in users
        mock_subprocess.assert_called_once_with(['cat', '/etc/passwd'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_processes(self, mock_subprocess):
        """Test getting system processes."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = '  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  100 ?        00:00:00 sshd\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        processes = scanner.get_processes()
        
        assert len(processes) >= 2  # At least the header and two processes
        mock_subprocess.assert_called_once_with(['ps', 'aux'], capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_services(self, mock_subprocess):
        """Test getting system services."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = '  UNIT              LOAD   ACTIVE SUB       DESCRIPTION\n  ssh.service       loaded active running SSH Daemon\n  docker.service    loaded active running Docker Application Container Engine\n'
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        services = scanner.get_services()
        
        assert 'ssh' in services
        assert 'docker' in services
        mock_subprocess.assert_called_once_with(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                                capture_output=True, text=True)

    @patch('subprocess.run')
    def test_get_critical_files(self, mock_subprocess):
        """Test getting critical system files."""
        scanner = SystemScanner()
        # Test when files exist
        with patch('os.path.exists', return_value=True):
            critical_files = scanner.get_critical_files()
            
            for file_path in ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/crontab']:
                assert file_path in critical_files

    @patch('subprocess.run')
    def test_scan_success(self, mock_subprocess, mock_system_scan_data):
        """Test successful system scan."""
        scanner = SystemScanner()
        
        # Mock all the subprocess calls
        mock_hostname_result = Mock()
        mock_hostname_result.stdout = 'test-host\n'
        mock_hostname_result.returncode = 0
        
        mock_kernel_result = Mock()
        mock_kernel_result.stdout = '5.4.0\n'
        mock_kernel_result.returncode = 0
        
        mock_os_result = Mock()
        mock_os_result.stdout = 'Ubuntu 20.04\n'
        mock_os_result.returncode = 0
        
        mock_users_result = Mock()
        mock_users_result.stdout = 'root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n'
        mock_users_result.returncode = 0
        
        mock_processes_result = Mock()
        mock_processes_result.stdout = '  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  100 ?        00:00:00 sshd\n'
        mock_processes_result.returncode = 0
        
        mock_services_result = Mock()
        mock_services_result.stdout = '  UNIT              LOAD   ACTIVE SUB       DESCRIPTION\n  ssh.service       loaded active running SSH Daemon\n'
        mock_services_result.returncode = 0
        
        mock_subprocess.side_effect = [
            mock_hostname_result, mock_kernel_result, mock_os_result,
            mock_users_result, mock_processes_result, mock_services_result
        ]
        
        with patch('os.path.exists', return_value=True):
            scan_results = scanner.scan()
        
        assert 'hostname' in scan_results
        assert 'kernel_version' in scan_results
        assert 'os_version' in scan_results
        assert 'users' in scan_results
        assert 'processes' in scan_results
        assert 'services' in scan_results
        assert 'critical_files' in scan_results

    @patch('subprocess.run')
    def test_scan_with_error(self, mock_subprocess):
        """Test system scan with subprocess error."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command not found'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        # Even with errors, scan should return a dict with error info
        scan_results = scanner.scan()
        
        assert isinstance(scan_results, dict)

    @patch('subprocess.run')
    def test_get_hostname_error(self, mock_subprocess):
        """Test getting hostname when command fails."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        hostname = scanner.get_hostname()
        
        assert hostname is None

    @patch('subprocess.run')
    def test_get_kernel_version_error(self, mock_subprocess):
        """Test getting kernel version when command fails."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        kernel_version = scanner.get_kernel_version()
        
        assert kernel_version is None

    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_get_os_version_file_not_found(self, mock_open):
        """Test getting OS version when file doesn't exist."""
        scanner = SystemScanner()
        
        os_version = scanner.get_os_version()
        
        assert os_version is None

    @patch('subprocess.run')
    def test_get_processes_error(self, mock_subprocess):
        """Test getting processes when command fails."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        processes = scanner.get_processes()
        
        assert processes == []

    @patch('subprocess.run')
    def test_get_services_error(self, mock_subprocess):
        """Test getting services when command fails."""
        scanner = SystemScanner()
        mock_result = Mock()
        mock_result.stdout = ''
        mock_result.stderr = 'Command failed'
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result
        
        services = scanner.get_services()
        
        assert services == []