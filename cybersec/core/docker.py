"""Docker scanner module for the cybersecurity toolkit."""
import docker
import logging
from typing import Dict, List, Any, Optional


class DockerScanner:
    """Scanner for Docker container security checks."""

    def __init__(self):
        """Initialize the Docker scanner."""
        self.containers = []
        self.images = []
        self.volumes = []
        self.networks = []
        self.logger = logging.getLogger(__name__)
        try:
            self.client = docker.from_env()
        except Exception as e:
            self.logger.error(f"Error initializing Docker client: {e}")
            self.client = None

    def get_containers(self, running_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get list of Docker containers.
        
        Args:
            running_only: If True, only return running containers
            
        Returns:
            List of container information
        """
        containers = []
        if not self.client:
            self.logger.error("Docker client not available")
            return containers
        
        try:
            container_list = self.client.containers.list(all=not running_only)
            
            for container in container_list:
                container_info = {
                    'id': container.id[:12],  # Short ID
                    'name': container.name,
                    'status': container.status,
                    'image': container.image.tags[0] if container.image.tags else str(container.image.id),
                    'ports': str(container.ports) if container.ports else 'N/A',
                    'created': container.attrs.get('Created', 'N/A')
                }
                containers.append(container_info)
        except Exception as e:
            self.logger.error(f"Error getting containers: {e}")
        
        return containers

    def get_images(self) -> List[Dict[str, Any]]:
        """
        Get list of Docker images.
        
        Returns:
            List of image information
        """
        images = []
        if not self.client:
            self.logger.error("Docker client not available")
            return images
        
        try:
            image_list = self.client.images.list()
            
            for image in image_list:
                image_info = {
                    'id': image.id[:12],  # Short ID
                    'name': image.tags[0] if image.tags else '<none>:<none>',
                    'size': f"{image.attrs.get('Size', 0) // (1024*1024)}MB",
                    'created': image.attrs.get('Created', 'N/A')
                }
                images.append(image_info)
        except Exception as e:
            self.logger.error(f"Error getting images: {e}")
        
        return images

    def get_volumes(self) -> List[Dict[str, Any]]:
        """
        Get list of Docker volumes.
        
        Returns:
            List of volume information
        """
        volumes = []
        if not self.client:
            self.logger.error("Docker client not available")
            return volumes
        
        try:
            volume_list = self.client.volumes.list()
            
            for volume in volume_list:
                volume_info = {
                    'name': volume.name,
                    'driver': volume.attrs.get('Driver', 'N/A'),
                    'mountpoint': volume.attrs.get('Mountpoint', 'N/A'),
                    'created': volume.attrs.get('CreatedAt', 'N/A')
                }
                volumes.append(volume_info)
        except Exception as e:
            self.logger.error(f"Error getting volumes: {e}")
        
        return volumes

    def get_networks(self) -> List[Dict[str, Any]]:
        """
        Get list of Docker networks.
        
        Returns:
            List of network information
        """
        networks = []
        if not self.client:
            self.logger.error("Docker client not available")
            return networks
        
        try:
            network_list = self.client.networks.list()
            
            for network in network_list:
                network_info = {
                    'name': network.name,
                    'id': network.id[:12],  # Short ID
                    'driver': network.attrs.get('Driver', 'N/A'),
                    'created': network.attrs.get('Created', 'N/A'),
                    'scope': network.attrs.get('Scope', 'N/A')
                }
                networks.append(network_info)
        except Exception as e:
            self.logger.error(f"Error getting networks: {e}")
        
        return networks

    def check_container_exposed_ports(self) -> List[int]:
        """
        Check for exposed container ports.
        
        Returns:
            List of exposed host ports
        """
        exposed_ports = []
        if not self.client:
            self.logger.error("Docker client not available")
            return exposed_ports
        
        try:
            containers = self.client.containers.list()
            
            for container in containers:
                ports = container.ports
                if ports:
                    for container_port, host_mapping in ports.items():
                        if host_mapping:
                            for mapping in host_mapping:
                                host_port = mapping.get('HostPort')
                                if host_port and host_port not in exposed_ports:
                                    try:
                                        exposed_ports.append(int(host_port))
                                    except ValueError:
                                        continue
        except Exception as e:
            self.logger.error(f"Error checking exposed ports: {e}")
        
        return exposed_ports

    def scan(self) -> Dict[str, Any]:
        """
        Perform a complete Docker security scan.
        
        Returns:
            Dictionary containing Docker scan results
        """
        self.logger.info("Starting Docker scan...")
        
        results = {
            'containers': self.get_containers(),
            'images': self.get_images(),
            'volumes': self.get_volumes(),
            'networks': self.get_networks(),
            'exposed_ports': self.check_container_exposed_ports()
        }
        
        self.logger.info("Docker scan completed.")
        return results