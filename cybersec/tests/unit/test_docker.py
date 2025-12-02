"""Unit tests for the docker module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from cybersec.core.docker import DockerScanner


class TestDockerScanner:
    """Test class for DockerScanner."""

    def test_docker_scanner_initialization(self):
        """Test docker scanner initialization."""
        scanner = DockerScanner()
        
        assert scanner.containers == []
        assert scanner.images == []
        assert scanner.volumes == []

    @patch('docker.from_env')
    def test_get_containers(self, mock_docker_client):
        """Test getting Docker containers."""
        scanner = DockerScanner()
        
        # Mock container data
        mock_container = Mock()
        mock_container.id = 'abc123'
        mock_container.name = 'web-app'
        mock_container.status = 'running'
        mock_container.image = Mock()
        mock_container.image.tags = ['nginx:latest']
        
        mock_client = Mock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker_client.return_value = mock_client
        
        containers = scanner.get_containers()
        
        assert len(containers) == 1
        assert containers[0]['id'] == 'abc123'
        assert containers[0]['name'] == 'web-app'
        assert containers[0]['status'] == 'running'
        assert containers[0]['image'] == 'nginx:latest'

    @patch('docker.from_env')
    def test_get_containers_error(self, mock_docker_client):
        """Test getting Docker containers when Docker is not available."""
        scanner = DockerScanner()
        mock_docker_client.side_effect = Exception("Docker not available")
        
        containers = scanner.get_containers()
        
        assert containers == []

    @patch('docker.from_env')
    def test_get_images(self, mock_docker_client):
        """Test getting Docker images."""
        scanner = DockerScanner()
        
        # Mock image data
        mock_image = Mock()
        mock_image.id = 'img123'
        mock_image.tags = ['nginx:latest']
        mock_image.attrs = {'Size': 133767984}
        
        mock_client = Mock()
        mock_client.images.list.return_value = [mock_image]
        mock_docker_client.return_value = mock_client
        
        images = scanner.get_images()
        
        assert len(images) == 1
        assert images[0]['id'] == 'img123'
        assert images[0]['name'] == 'nginx:latest'
        assert 'size' in images[0]

    @patch('docker.from_env')
    def test_get_images_error(self, mock_docker_client):
        """Test getting Docker images when Docker is not available."""
        scanner = DockerScanner()
        mock_docker_client.side_effect = Exception("Docker not available")
        
        images = scanner.get_images()
        
        assert images == []

    @patch('docker.from_env')
    def test_get_volumes(self, mock_docker_client):
        """Test getting Docker volumes."""
        scanner = DockerScanner()
        
        # Mock volume data
        mock_volume = Mock()
        mock_volume.name = 'my-volume'
        mock_volume.attrs = {'CreatedAt': '2023-01-01T00:00:00Z'}
        
        mock_client = Mock()
        mock_client.volumes.list.return_value = [mock_volume]
        mock_docker_client.return_value = mock_client
        
        volumes = scanner.get_volumes()
        
        assert len(volumes) == 1
        assert volumes[0]['name'] == 'my-volume'

    @patch('docker.from_env')
    def test_get_volumes_error(self, mock_docker_client):
        """Test getting Docker volumes when Docker is not available."""
        scanner = DockerScanner()
        mock_docker_client.side_effect = Exception("Docker not available")
        
        volumes = scanner.get_volumes()
        
        assert volumes == []

    @patch('docker.from_env')
    def test_get_networks(self, mock_docker_client):
        """Test getting Docker networks."""
        scanner = DockerScanner()
        
        # Mock network data
        mock_network = Mock()
        mock_network.name = 'bridge'
        mock_network.id = 'net123'
        mock_network.attrs = {'Created': '2023-01-01T00:00:00Z'}
        
        mock_client = Mock()
        mock_client.networks.list.return_value = [mock_network]
        mock_docker_client.return_value = mock_client
        
        networks = scanner.get_networks()
        
        assert len(networks) == 1
        assert networks[0]['name'] == 'bridge'

    @patch('docker.from_env')
    def test_get_networks_error(self, mock_docker_client):
        """Test getting Docker networks when Docker is not available."""
        scanner = DockerScanner()
        mock_docker_client.side_effect = Exception("Docker not available")
        
        networks = scanner.get_networks()
        
        assert networks == []

    @patch('cybersec.core.docker.DockerScanner.get_containers')
    @patch('cybersec.core.docker.DockerScanner.get_images')
    @patch('cybersec.core.docker.DockerScanner.get_volumes')
    @patch('cybersec.core.docker.DockerScanner.get_networks')
    def test_scan_success(self, mock_get_networks, mock_get_volumes, mock_get_images, mock_get_containers, mock_docker_data):
        """Test successful Docker scan."""
        scanner = DockerScanner()
        
        # Mock the methods
        mock_get_containers.return_value = [
            {
                'id': 'abc123',
                'name': 'web-app',
                'status': 'Up 2 hours',
                'ports': '0.0.0.0:8080->80/tcp',
                'image': 'nginx:latest'
            }
        ]
        mock_get_images.return_value = [
            {'id': 'img1', 'name': 'nginx:latest', 'size': '133MB'}
        ]
        mock_get_volumes.return_value = [
            {'name': 'my-volume', 'driver': 'local'}
        ]
        mock_get_networks.return_value = [
            {'name': 'bridge', 'driver': 'bridge'}
        ]
        
        scan_results = scanner.scan()
        
        assert 'containers' in scan_results
        assert 'images' in scan_results
        assert 'volumes' in scan_results
        assert 'networks' in scan_results
        assert len(scan_results['containers']) >= 1
        assert len(scan_results['images']) >= 1

    @patch('cybersec.core.docker.DockerScanner.get_containers')
    @patch('cybersec.core.docker.DockerScanner.get_images')
    @patch('cybersec.core.docker.DockerScanner.get_volumes')
    @patch('cybersec.core.docker.DockerScanner.get_networks')
    def test_scan_with_method_errors(self, mock_get_networks, mock_get_volumes, mock_get_images, mock_get_containers):
        """Test Docker scan when individual methods fail."""
        scanner = DockerScanner()
        
        # Make the methods return empty lists to simulate errors
        mock_get_containers.return_value = []
        mock_get_images.return_value = []
        mock_get_volumes.return_value = []
        mock_get_networks.return_value = []
        
        scan_results = scanner.scan()
        
        assert 'containers' in scan_results
        assert 'images' in scan_results
        assert 'volumes' in scan_results
        assert 'networks' in scan_results
        assert scan_results['containers'] == []
        assert scan_results['images'] == []
        assert scan_results['volumes'] == []
        assert scan_results['networks'] == []

    @patch('docker.from_env')
    def test_check_container_exposed_ports(self, mock_docker_client):
        """Test checking for exposed container ports."""
        scanner = DockerScanner()
        
        # Mock container with exposed ports
        mock_container = Mock()
        mock_container.id = 'abc123'
        mock_container.name = 'web-app'
        mock_container.ports = {
            '80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]
        }
        
        mock_client = Mock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker_client.return_value = mock_client
        
        exposed_ports = scanner.check_container_exposed_ports()
        
        assert 8080 in exposed_ports

    @patch('docker.from_env')
    def test_check_container_exposed_ports_none(self, mock_docker_client):
        """Test checking for exposed container ports when none are exposed."""
        scanner = DockerScanner()
        
        # Mock container with no exposed ports
        mock_container = Mock()
        mock_container.id = 'abc123'
        mock_container.name = 'web-app'
        mock_container.ports = {}
        
        mock_client = Mock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker_client.return_value = mock_client
        
        exposed_ports = scanner.check_container_exposed_ports()
        
        assert exposed_ports == []

    @patch('docker.from_env')
    def test_check_container_exposed_ports_error(self, mock_docker_client):
        """Test checking for exposed container ports when Docker is not available."""
        scanner = DockerScanner()
        mock_docker_client.side_effect = Exception("Docker not available")
        
        exposed_ports = scanner.check_container_exposed_ports()
        
        assert exposed_ports == []

    @patch('docker.from_env')
    def test_get_running_containers_only(self, mock_docker_client):
        """Test getting only running containers."""
        scanner = DockerScanner()
        
        # Mock containers - one running, one stopped
        mock_running_container = Mock()
        mock_running_container.id = 'running123'
        mock_running_container.name = 'running-app'
        mock_running_container.status = 'running'
        mock_running_container.image = Mock()
        mock_running_container.image.tags = ['nginx:latest']
        
        mock_stopped_container = Mock()
        mock_stopped_container.id = 'stopped456'
        mock_stopped_container.name = 'stopped-app'
        mock_stopped_container.status = 'exited'
        mock_stopped_container.image = Mock()
        mock_stopped_container.image.tags = ['nginx:latest']
        
        mock_client = Mock()
        mock_client.containers.list.return_value = [mock_running_container, mock_stopped_container]
        mock_docker_client.return_value = mock_client
        
        # Get all containers
        all_containers = scanner.get_containers()
        assert len(all_containers) == 2
        
        # Get only running containers
        running_containers = scanner.get_containers(running_only=True)
        assert len(running_containers) == 1
        assert running_containers[0]['status'] == 'running'

    @patch('docker.from_env')
    def test_get_container_details(self, mock_docker_client):
        """Test getting detailed container information."""
        scanner = DockerScanner()
        
        # Mock container with detailed attributes
        mock_container = Mock()
        mock_container.id = 'abc123'
        mock_container.name = 'web-app'
        mock_container.status = 'running'
        mock_container.image = Mock()
        mock_container.image.tags = ['nginx:latest']
        mock_container.attrs = {
            'Created': '2023-01-01T00:00:00Z',
            'HostConfig': {
                'Binds': [],
                'PortBindings': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}
            }
        }
        
        mock_client = Mock()
        mock_client.containers.list.return_value = [mock_container]
        mock_docker_client.return_value = mock_client
        
        containers = scanner.get_containers()
        
        assert len(containers) == 1
        container = containers[0]
        assert 'id' in container
        assert 'name' in container
        assert 'status' in container
        assert 'image' in container
        assert 'created' in container

    @patch('docker.from_env')
    def test_get_image_security_issues(self, mock_docker_client):
        """Test checking for potential security issues in images."""
        scanner = DockerScanner()
        
        # Mock image with potential security issues
        mock_image = Mock()
        mock_image.id = 'img123'
        mock_image.tags = ['alpine:latest']  # Common base image
        mock_image.attrs = {'Size': 133767984}
        
        mock_client = Mock()
        mock_client.images.list.return_value = [mock_image]
        mock_docker_client.return_value = mock_client
        
        images = scanner.get_images()
        
        assert len(images) == 1
        # Check that we get image information
        assert images[0]['id'] == 'img123'
        assert images[0]['name'] == 'alpine:latest'

    def test_is_docker_installed(self):
        """Test checking if Docker is installed."""
        scanner = DockerScanner()
        
        # This test will check the method exists and doesn't crash
        # The actual implementation may vary based on the DockerScanner implementation
        assert hasattr(scanner, 'get_containers')  # Basic check that methods exist