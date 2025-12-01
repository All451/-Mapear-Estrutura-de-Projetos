"""Docker security scanner for the Cybersecurity Toolkit."""
import docker
import subprocess
import json
import os
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import DockerError

logger = logging.getLogger(__name__)


class DockerScanner:
    """Scans Docker containers and images for security issues."""
    
    def __init__(self):
        """Initialize Docker scanner."""
        self.config = get_config()
        self.client = None
        self.check_running_containers = self.config.get("docker.check_running_containers", True)
        self.check_exposed_ports = self.config.get("docker.exposed_ports", True)
        self.internal_networks = self.config.get("docker.internal_networks", ["bridge", "host"])
        self.ignored_ports = self.config.get("docker.ignored_ports", [53, 123])  # DNS, NTP
        
        # Try to initialize Docker client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Docker client."""
        try:
            self.client = docker.from_env()
            # Test connection
            self.client.version()
            logger.debug("Docker client initialized successfully")
        except Exception as e:
            logger.warning(f"Could not initialize Docker client: {e}")
            self.client = None
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available and accessible.
        
        Returns:
            True if Docker is available, False otherwise
        """
        return self.client is not None
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform comprehensive Docker security scan.
        
        Returns:
            List of security findings
        """
        if not self.is_docker_available():
            logger.warning("Docker not available, skipping Docker scan")
            return []
        
        findings = []
        
        try:
            # Check running containers
            if self.check_running_containers:
                findings.extend(self._scan_running_containers())
            
            # Check images
            findings.extend(self._scan_images())
            
            # Check Docker daemon configuration
            findings.extend(self._scan_daemon_config())
            
            # Check Docker security best practices
            findings.extend(self._check_security_best_practices())
        
        except Exception as e:
            logger.error(f"Error during Docker scan: {e}")
            raise DockerError(f"Docker scan failed: {e}")
        
        logger.info(f"Docker scan completed with {len(findings)} findings")
        return findings
    
    def _scan_running_containers(self) -> List[Dict[str, Any]]:
        """Scan running containers for security issues."""
        findings = []
        
        try:
            containers = self.client.containers.list()
            
            for container in containers:
                container_info = container.attrs
                
                # Check if container is running as root
                if 'User' in container_info['Config']:
                    user = container_info['Config']['User']
                    if user == '' or user == '0' or user.startswith('root'):
                        findings.append({
                            'title': f'Container Running as Root: {container.name}',
                            'severity': 'high',
                            'description': f'Container {container.name} is running as root user',
                            'recommendation': 'Run container with non-root user using USER instruction in Dockerfile',
                            'location': f'Container: {container.name}'
                        })
                
                # Check for privileged mode
                if container_info['HostConfig'].get('Privileged', False):
                    findings.append({
                        'title': f'Privileged Container: {container.name}',
                        'severity': 'critical',
                        'description': f'Container {container.name} is running in privileged mode',
                        'recommendation': 'Remove privileged mode unless absolutely necessary',
                        'location': f'Container: {container.name}'
                    })
                
                # Check for added capabilities
                added_caps = container_info['HostConfig'].get('CapAdd', [])
                if added_caps:
                    findings.append({
                        'title': f'Additional Capabilities in Container: {container.name}',
                        'severity': 'medium',
                        'description': f'Container {container.name} has additional capabilities: {", ".join(added_caps)}',
                        'recommendation': 'Review and remove unnecessary capabilities',
                        'location': f'Container: {container.name}'
                    })
                
                # Check for exposed ports
                if self.check_exposed_ports and 'NetworkSettings' in container_info:
                    ports = container_info['NetworkSettings'].get('Ports', {})
                    exposed_ports = []
                    
                    for container_port, host_mapping in ports.items():
                        if host_mapping is not None:  # Port is exposed
                            container_port_num = container_port.split('/')[0]  # Remove protocol
                            host_port = host_mapping[0].get('HostPort', '')
                            
                            if (host_port and container_port_num not in self.ignored_ports and 
                                not host_port.startswith('127.')):  # Not bound to localhost only
                                exposed_ports.append(f"{container_port_num}->{host_port}")
                    
                    if exposed_ports:
                        findings.append({
                            'title': f'Exposed Ports in Container: {container.name}',
                            'severity': 'medium',
                            'description': f'Container {container.name} has exposed ports: {", ".join(exposed_ports)}',
                            'recommendation': 'Review exposed ports and limit access to necessary ports only',
                            'location': f'Container: {container.name}'
                        })
                
                # Check for sensitive mounts
                mounts = container_info['Mounts'] or []
                for mount in mounts:
                    source_path = mount.get('Source', '')
                    sensitive_paths = ['/etc', '/root', '/home', '/var', '/proc', '/sys', '/dev']
                    
                    for sensitive_path in sensitive_paths:
                        if source_path.startswith(sensitive_path) and source_path != '/':
                            findings.append({
                                'title': f'Sensitive Directory Mounted: {container.name}',
                                'severity': 'high',
                                'description': f'Container {container.name} has sensitive directory mounted: {source_path}',
                                'recommendation': 'Avoid mounting sensitive host directories unless absolutely necessary',
                                'location': f'Container: {container.name}, Mount: {source_path}'
                            })
        
        except Exception as e:
            logger.error(f"Error scanning running containers: {e}")
            raise DockerError(f"Error scanning running containers: {e}")
        
        return findings
    
    def _scan_images(self) -> List[Dict[str, Any]]:
        """Scan Docker images for security issues."""
        findings = []
        
        try:
            images = self.client.images.list()
            
            for image in images:
                # Get image details
                image_info = image.attrs
                
                # Check for latest tag (which might be outdated)
                tags = image.tags
                if not tags:
                    continue  # Skip if no tags
                
                for tag in tags:
                    if ':latest' in tag:
                        findings.append({
                            'title': f'Image Using Latest Tag: {tag}',
                            'severity': 'medium',
                            'description': f'Image {tag} uses "latest" tag which can lead to inconsistent deployments',
                            'recommendation': 'Use specific version tags instead of "latest"',
                            'location': f'Image: {tag}'
                        })
                    
                    # Check for base image issues (simplified check)
                    if any(base in tag.lower() for base in ['ubuntu:14', 'ubuntu:16', 'debian:7', 'debian:8']):
                        findings.append({
                            'title': f'Outdated Base Image: {tag}',
                            'severity': 'high',
                            'description': f'Image {tag} uses outdated base image with known vulnerabilities',
                            'recommendation': 'Update to a more recent base image version',
                            'location': f'Image: {tag}'
                        })
        
        except Exception as e:
            logger.error(f"Error scanning images: {e}")
            raise DockerError(f"Error scanning images: {e}")
        
        return findings
    
    def _scan_daemon_config(self) -> List[Dict[str, Any]]:
        """Scan Docker daemon configuration for security issues."""
        findings = []
        
        try:
            # Check Docker daemon configuration file
            daemon_config_paths = [
                '/etc/docker/daemon.json',
                '/etc/default/docker',  # Ubuntu/Debian
                '/etc/sysconfig/docker'  # RHEL/CentOS
            ]
            
            for config_path in daemon_config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            if config_path.endswith('.json'):
                                config = json.load(f)
                                
                                # Check for insecure registries
                                if 'insecure-registries' in config:
                                    findings.append({
                                        'title': 'Insecure Docker Registries Configured',
                                        'severity': 'high',
                                        'description': f'Docker daemon configured with insecure registries: {config["insecure-registries"]}',
                                        'recommendation': 'Use TLS-secured registries instead of insecure ones',
                                        'location': f'Daemon config: {config_path}'
                                    })
                                
                                # Check for experimental features
                                if config.get('experimental', False):
                                    findings.append({
                                        'title': 'Docker Experimental Features Enabled',
                                        'severity': 'medium',
                                        'description': 'Docker daemon has experimental features enabled',
                                        'recommendation': 'Disable experimental features in production environments',
                                        'location': f'Daemon config: {config_path}'
                                    })
                    except Exception as e:
                        logger.warning(f"Could not read daemon config {config_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning daemon config: {e}")
            raise DockerError(f"Error scanning daemon config: {e}")
        
        return findings
    
    def _check_security_best_practices(self) -> List[Dict[str, Any]]:
        """Check for Docker security best practices."""
        findings = []
        
        try:
            # Check if Docker content trust is enabled
            content_trust = os.environ.get('DOCKER_CONTENT_TRUST', '0')
            if content_trust == '0':
                findings.append({
                    'title': 'Docker Content Trust Disabled',
                    'severity': 'medium',
                    'description': 'Docker Content Trust is disabled, making images vulnerable to tampering',
                    'recommendation': 'Enable Docker Content Trust: export DOCKER_CONTENT_TRUST=1',
                    'location': 'Docker environment'
                })
            
            # Check if user namespace remapping is enabled
            # This requires checking daemon configuration or running a test
            try:
                result = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    if 'Rootless' not in result.stdout and 'Namespace' not in result.stdout:
                        findings.append({
                            'title': 'User Namespace Remapping Not Enabled',
                            'severity': 'medium',
                            'description': 'Docker is not configured with user namespace remapping',
                            'recommendation': 'Enable user namespace remapping for better isolation',
                            'location': 'Docker configuration'
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # Docker command not available
        
        except Exception as e:
            logger.error(f"Error checking security best practices: {e}")
            raise DockerError(f"Error checking security best practices: {e}")
        
        return findings
    
    def scan_container(self, container_id: str) -> List[Dict[str, Any]]:
        """Scan a specific container for security issues.
        
        Args:
            container_id: ID of the container to scan
            
        Returns:
            List of security findings for the container
        """
        if not self.is_docker_available():
            logger.warning("Docker not available")
            return []
        
        findings = []
        
        try:
            container = self.client.containers.get(container_id)
            container_info = container.attrs
            
            # Perform the same checks as in _scan_running_containers but for a specific container
            # Check if container is running as root
            if 'User' in container_info['Config']:
                user = container_info['Config']['User']
                if user == '' or user == '0' or user.startswith('root'):
                    findings.append({
                        'title': f'Container Running as Root: {container.name}',
                        'severity': 'high',
                        'description': f'Container {container.name} is running as root user',
                        'recommendation': 'Run container with non-root user using USER instruction in Dockerfile',
                        'location': f'Container: {container.name}'
                    })
            
            # Check for privileged mode
            if container_info['HostConfig'].get('Privileged', False):
                findings.append({
                    'title': f'Privileged Container: {container.name}',
                    'severity': 'critical',
                    'description': f'Container {container.name} is running in privileged mode',
                    'recommendation': 'Remove privileged mode unless absolutely necessary',
                    'location': f'Container: {container.name}'
                })
        
        except Exception as e:
            logger.error(f"Error scanning container {container_id}: {e}")
            raise DockerError(f"Error scanning container {container_id}: {e}")
        
        return findings
    
    def get_docker_security_info(self) -> Dict[str, Any]:
        """Get comprehensive Docker security information.
        
        Returns:
            Dictionary with Docker security information
        """
        if not self.is_docker_available():
            return {'available': False, 'timestamp': datetime.now().isoformat()}
        
        info = {
            'available': True,
            'timestamp': datetime.now().isoformat(),
            'containers_running': 0,
            'images_count': 0,
            'security_features': {}
        }
        
        try:
            # Get container count
            containers = self.client.containers.list()
            info['containers_running'] = len(containers)
            
            # Get image count
            images = self.client.images.list()
            info['images_count'] = len(images)
            
            # Get Docker version info
            version_info = self.client.version()
            info['version'] = version_info.get('Version', 'unknown')
            
            # Get Docker info for security features
            docker_info = self.client.info()
            security_options = docker_info.get('SecurityOptions', [])
            info['security_features'] = {
                'app_armor': 'name=apparmor' in security_options,
                'seccomp': 'name=seccomp' in security_options,
                'rootless': 'rootless' in security_options,
                'user_namespace': docker_info.get('ExperimentalBuild', False)
            }
        
        except Exception as e:
            logger.error(f"Error getting Docker security info: {e}")
        
        return info


# For compatibility
import time