#!/usr/bin/env python3
"""
Docker Container Exposure Checker
Module to verify if Docker containers are exposed to the internet
"""

import subprocess
import json
import socket
import requests
import logging
from typing import List, Dict, Any

# Handle docker module import gracefully
try:
    import docker
except ImportError:
    docker = None
    print("Warning: docker module not found. Docker checking functionality will be limited.")

class DockerExposureChecker:
    """
    A class to check for exposed Docker containers that might be accessible from the internet.
    """
    
    def __init__(self):
        self.client = None
        self.logger = logging.getLogger(__name__)
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def get_docker_client(self):
        """Initialize Docker client"""
        try:
            if self.client is None:
                if docker is None:
                    self.logger.error("Docker module not available")
                    return None
                self.client = docker.from_env()
            return self.client
        except Exception as e:
            self.logger.error(f"Failed to connect to Docker daemon: {e}")
            return None
    
    def get_running_containers(self) -> List[Dict[str, Any]]:
        """Get list of running containers with their port mappings"""
        client = self.get_docker_client()
        if not client:
            return []
        
        containers = []
        try:
            running_containers = client.containers.list()
            for container in running_containers:
                container_info = {
                    'id': container.id[:12],
                    'name': container.name,
                    'image': container.image.tags[0] if container.image.tags else 'N/A',
                    'ports': self._get_port_mappings(container),
                    'status': container.status,
                    'ports_exposed': []
                }
                
                # Check if ports are exposed to the host
                for port_info in container_info['ports']:
                    if port_info['host_port'] is not None:
                        container_info['ports_exposed'].append(port_info)
                
                containers.append(container_info)
        except Exception as e:
            self.logger.error(f"Error getting container list: {e}")
        
        return containers
    
    def _get_port_mappings(self, container) -> List[Dict[str, Any]]:
        """Get port mappings for a container"""
        ports = []
        try:
            # Get container details
            container_json = container.attrs
            
            # Extract port bindings
            network_settings = container_json.get('NetworkSettings', {})
            port_bindings = network_settings.get('Ports', {})
            
            for container_port, host_mapping in port_bindings.items():
                if host_mapping is not None:  # Only if port is mapped to host
                    for mapping in host_mapping:
                        ports.append({
                            'container_port': container_port.replace('/tcp', '').replace('/udp', ''),
                            'host_ip': mapping.get('HostIp', '0.0.0.0'),
                            'host_port': mapping.get('HostPort'),
                            'protocol': 'tcp' if '/tcp' in container_port else 'udp'
                        })
        except Exception as e:
            self.logger.error(f"Error getting port mappings for container {container.name}: {e}")
        
        return ports
    
    def check_port_exposure(self, host_ip: str, host_port: str) -> Dict[str, Any]:
        """Check if a specific port is accessible from the internet"""
        result = {
            'accessible_internally': False,
            'accessible_externally': False,
            'service_info': None,
            'risk_level': 'low'
        }
        
        # Check internal accessibility (localhost)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            # Try connecting to the port on localhost
            local_result = sock.connect_ex(('127.0.0.1', int(host_port)))
            if local_result == 0:
                result['accessible_internally'] = True
            sock.close()
        except Exception:
            pass
        
        # Check external accessibility (if host IP is not localhost or 0.0.0.0)
        if host_ip not in ['127.0.0.1', 'localhost', '0.0.0.0']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                external_result = sock.connect_ex((host_ip, int(host_port)))
                if external_result == 0:
                    result['accessible_externally'] = True
                sock.close()
            except Exception:
                pass
        
        # Determine risk level
        if result['accessible_externally']:
            result['risk_level'] = 'high'
        elif result['accessible_internally']:
            result['risk_level'] = 'medium'
        
        # Try to get service info if accessible
        if result['accessible_internally']:
            result['service_info'] = self._identify_service(host_ip, host_port)
        
        return result
    
    def _identify_service(self, host_ip: str, host_port: str) -> str:
        """Try to identify what service is running on the port"""
        try:
            # Try HTTP/HTTPS
            for scheme in ['http', 'https']:
                try:
                    url = f"{scheme}://{host_ip}:{host_port}"
                    response = requests.get(url, timeout=5)
                    return f"{scheme.upper()} service - Status: {response.status_code}"
                except requests.exceptions.RequestException:
                    continue
            
            # If HTTP/HTTPS didn't work, just return that something is listening
            return "Service listening on port"
        except Exception:
            return "Unknown service"
    
    def scan_exposed_containers(self) -> List[Dict[str, Any]]:
        """Scan all running containers for exposed ports"""
        containers = self.get_running_containers()
        exposed_containers = []
        
        for container in containers:
            if container['ports_exposed']:
                exposed_info = {
                    'container_id': container['id'],
                    'container_name': container['name'],
                    'image': container['image'],
                    'exposed_ports': []
                }
                
                for port_info in container['ports_exposed']:
                    exposure_check = self.check_port_exposure(
                        port_info['host_ip'], 
                        port_info['host_port']
                    )
                    
                    exposed_port_info = {
                        'container_port': port_info['container_port'],
                        'host_ip': port_info['host_ip'],
                        'host_port': port_info['host_port'],
                        'protocol': port_info['protocol'],
                        'exposure_status': exposure_check
                    }
                    
                    exposed_info['exposed_ports'].append(exposed_port_info)
                
                if exposed_info['exposed_ports']:
                    exposed_containers.append(exposed_info)
        
        return exposed_containers
    
    def generate_report(self) -> str:
        """Generate a human-readable report of exposed containers"""
        exposed_containers = self.scan_exposed_containers()
        
        if not exposed_containers:
            return "No exposed Docker containers found."
        
        report_lines = ["Docker Container Exposure Report", "=" * 40]
        
        for container in exposed_containers:
            report_lines.append(f"\nContainer: {container['container_name']} ({container['container_id']})")
            report_lines.append(f"Image: {container['image']}")
            report_lines.append("Exposed Ports:")
            
            for port in container['exposed_ports']:
                exposure = port['exposure_status']
                risk = exposure['risk_level'].upper()
                report_lines.append(f"  - Container Port {port['container_port']} -> Host {port['host_ip']}:{port['host_port']} ({port['protocol']})")
                report_lines.append(f"    Risk Level: {risk}")
                report_lines.append(f"    Internal Access: {'Yes' if exposure['accessible_internally'] else 'No'}")
                report_lines.append(f"    External Access: {'Yes' if exposure['accessible_externally'] else 'No'}")
                if exposure['service_info']:
                    report_lines.append(f"    Service: {exposure['service_info']}")
        
        return "\n".join(report_lines)
    
    def get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on findings"""
        exposed_containers = self.scan_exposed_containers()
        recommendations = []
        
        if not exposed_containers:
            recommendations.append("No exposed containers found - good security posture!")
            return recommendations
        
        recommendations.append("Security Recommendations:")
        recommendations.append("- Review exposed ports and consider if they need to be accessible")
        recommendations.append("- Use Docker networks to isolate containers when possible")
        recommendations.append("- Implement proper firewall rules to restrict access")
        recommendations.append("- Regularly audit container configurations")
        recommendations.append("- Consider using 'docker run --publish 127.0.0.1:PORT:PORT' to bind to localhost only")
        
        # Count high-risk exposures
        high_risk_count = 0
        for container in exposed_containers:
            for port in container['exposed_ports']:
                if port['exposure_status']['risk_level'] == 'high':
                    high_risk_count += 1
        
        if high_risk_count > 0:
            recommendations.append(f"- CRITICAL: {high_risk_count} high-risk exposures detected - immediate action recommended")
        
        return recommendations


def main():
    """Main function to run the Docker exposure checker"""
    checker = DockerExposureChecker()
    
    print("Scanning for exposed Docker containers...")
    print("\n" + checker.generate_report())
    
    print("\n" + "\n".join(checker.get_security_recommendations()))


if __name__ == "__main__":
    main()