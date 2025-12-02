"""Test configuration and fixtures for cybersec toolkit."""
import pytest
import tempfile
import os
from unittest.mock import Mock, patch
import yaml


@pytest.fixture
def temp_config_file():
    """Create a temporary config file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        config = {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': '/tmp/test_cybersec.log'
            },
            'scanner': {
                'quick_scan': True,
                'full_scan': False,
                'timeout': 30,
                'max_depth': 3,
                'include_hidden': False
            },
            'network': {
                'ports_to_check': [22, 80, 443, 3306, 5432],
                'timeout': 5
            },
            'firewall': {
                'ban_duration': 3600,
                'threshold': 5
            },
            'docker': {
                'check_running_only': True,
                'expose_ports': True
            }
        }
        yaml.dump(config, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    os.unlink(temp_path)


@pytest.fixture
def mock_system_scan_data():
    """Mock data for system scanning tests."""
    return {
        'hostname': 'test-host',
        'kernel_version': '5.4.0',
        'os_version': 'Ubuntu 20.04',
        'users': ['root', 'testuser'],
        'processes': [
            {'pid': 1, 'name': 'init', 'user': 'root'},
            {'pid': 100, 'name': 'sshd', 'user': 'root'}
        ],
        'services': ['ssh', 'docker'],
        'critical_files': ['/etc/passwd', '/etc/shadow']
    }


@pytest.fixture
def mock_network_scan_data():
    """Mock data for network scanning tests."""
    return {
        'open_ports': [22, 80, 443],
        'services': {
            22: 'ssh',
            80: 'http',
            443: 'https'
        },
        'interfaces': [
            {'name': 'eth0', 'ip': '192.168.1.100', 'status': 'UP'},
            {'name': 'lo', 'ip': '127.0.0.1', 'status': 'UP'}
        ],
        'routes': [
            {'destination': '0.0.0.0', 'gateway': '192.168.1.1', 'interface': 'eth0'}
        ]
    }


@pytest.fixture
def mock_firewall_data():
    """Mock data for firewall tests."""
    return {
        'ufw_status': 'active',
        'rules': [
            {'rule': '22/tcp', 'action': 'ALLOW', 'from': 'Anywhere'},
            {'rule': '80/tcp', 'action': 'ALLOW', 'from': 'Anywhere'},
            {'rule': '443/tcp', 'action': 'ALLOW', 'from': 'Anywhere'}
        ],
        'banned_ips': ['192.168.1.100', '10.0.0.50']
    }


@pytest.fixture
def mock_docker_data():
    """Mock data for Docker tests."""
    return {
        'containers': [
            {
                'id': 'abc123',
                'name': 'web-app',
                'status': 'Up 2 hours',
                'ports': '0.0.0.0:8080->80/tcp',
                'image': 'nginx:latest'
            },
            {
                'id': 'def456',
                'name': 'db',
                'status': 'Up 3 hours',
                'ports': '3306/tcp',
                'image': 'mysql:5.7'
            }
        ],
        'images': [
            {'id': 'img1', 'name': 'nginx:latest', 'size': '133MB'},
            {'id': 'img2', 'name': 'mysql:5.7', 'size': '450MB'}
        ],
        'exposed_ports': [8080]
    }


@pytest.fixture
def mock_filesystem_scan_data():
    """Mock data for filesystem scanning tests."""
    return {
        'suspicious_files': [
            {'path': '/tmp/suspicious.sh', 'size': 1024, 'permissions': '777'},
            {'path': '/var/log/compromised.log', 'size': 2048, 'permissions': '666'}
        ],
        'world_writable_dirs': ['/tmp', '/var/tmp'],
        'suid_files': ['/usr/bin/sudo', '/usr/bin/passwd'],
        'recent_files': [
            {'path': '/home/user/test.txt', 'modified': '2023-01-01 12:00:00', 'size': 100}
        ]
    }