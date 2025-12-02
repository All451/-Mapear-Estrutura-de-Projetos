"""Network scanner module for the cybersecurity toolkit."""
import subprocess
import socket
import logging
from typing import Dict, List, Any


class NetworkScanner:
    """Scanner for network-level security checks."""

    def __init__(self):
        """Initialize the network scanner."""
        self.open_ports = []
        self.interfaces = []
        self.routes = []
        self.logger = logging.getLogger(__name__)

    def get_open_ports(self) -> List[int]:
        """
        Get list of open ports on the system.
        
        Returns:
            List of open port numbers
        """
        open_ports = []
        try:
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if 'LISTEN' in line:
                    # Parse the line to extract port numbers
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[4]  # Local Address:Port
                        if ':' in local_addr:
                            port_str = local_addr.split(':')[-1]
                            if port_str.isdigit():
                                port = int(port_str)
                                if port not in open_ports:
                                    open_ports.append(port)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting open ports: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing open ports: {e}")
        
        return open_ports

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get list of network interfaces.
        
        Returns:
            List of interface information
        """
        interfaces = []
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            current_interface = None
            for line in lines:
                line = line.strip()
                if line and line[0].isdigit():  # New interface starts
                    # Extract interface name
                    parts = line.split()
                    if len(parts) >= 2:
                        iface_name = parts[1].rstrip(':')
                        current_interface = {
                            'name': iface_name,
                            'ip': None,
                            'status': 'UNKNOWN'
                        }
                        # Extract status
                        if 'UP' in line:
                            current_interface['status'] = 'UP'
                        elif 'DOWN' in line:
                            current_interface['status'] = 'DOWN'
                        
                        interfaces.append(current_interface)
                elif 'inet ' in line and current_interface:
                    # Extract IP address
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_with_cidr = parts[1]
                        ip = ip_with_cidr.split('/')[0]
                        current_interface['ip'] = ip
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting network interfaces: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing network interfaces: {e}")
        
        return interfaces

    def get_routing_table(self) -> List[Dict[str, str]]:
        """
        Get the routing table.
        
        Returns:
            List of routing information
        """
        routes = []
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        route = {
                            'destination': parts[0],
                            'gateway': parts[2] if len(parts) > 2 else 'N/A',
                            'interface': parts[-1] if parts[-1] != 'dev' else 'N/A'
                        }
                        routes.append(route)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting routing table: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing routing table: {e}")
        
        return routes

    def check_port(self, host: str, port: int) -> bool:
        """
        Check if a specific port is open on a host.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.error(f"Error checking port {host}:{port}: {e}")
            return False

    def scan(self) -> Dict[str, Any]:
        """
        Perform a complete network security scan.
        
        Returns:
            Dictionary containing network scan results
        """
        self.logger.info("Starting network scan...")
        
        results = {
            'open_ports': self.get_open_ports(),
            'interfaces': self.get_network_interfaces(),
            'routes': self.get_routing_table()
        }
        
        self.logger.info("Network scan completed.")
        return results