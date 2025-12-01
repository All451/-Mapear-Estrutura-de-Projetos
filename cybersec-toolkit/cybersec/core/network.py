"""Network security scanner for the Cybersecurity Toolkit."""
import socket
import subprocess
import threading
from typing import List, Dict, Any, Tuple
import logging
import nmap
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import NetworkError

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Scans network-related security issues."""
    
    def __init__(self):
        """Initialize network scanner."""
        self.config = get_config()
        self.ports_to_check = self.config.get("network.ports_to_check", 
                                            [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080])
        self.timeout = self.config.get("network.timeout", 5)
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform comprehensive network security scan.
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check local open ports
        findings.extend(self._check_local_ports())
        
        # Check network connectivity
        findings.extend(self._check_network_connectivity())
        
        # Check for common network vulnerabilities
        findings.extend(self._check_network_vulnerabilities())
        
        # Check firewall configuration
        findings.extend(self._check_firewall_status())
        
        logger.info(f"Network scan completed with {len(findings)} findings")
        return findings
    
    def _check_local_ports(self) -> List[Dict[str, Any]]:
        """Check for open ports on the local system."""
        findings = []
        
        try:
            # Get list of open ports using netstat or ss
            open_ports = self._get_open_ports()
            
            for port, protocol, process in open_ports:
                # Check if port is in the list of ports we're concerned about
                if port in self.ports_to_check:
                    severity = 'medium' if port in [22, 80, 443] else 'high'  # Common services vs dangerous ones
                    findings.append({
                        'title': f'Open Port: {port}/{protocol}',
                        'severity': severity,
                        'description': f'Port {port} ({protocol}) is open and being used by {process}',
                        'recommendation': f'Ensure port {port} is properly secured and only accessible from authorized sources',
                        'location': f'Port: {port}, Protocol: {protocol}'
                    })
                
                # Check for dangerous ports
                dangerous_ports = {
                    21: 'FTP - Unencrypted file transfer',
                    23: 'Telnet - Unencrypted remote access',
                    25: 'SMTP - May allow spam relay',
                    135: 'RPC Endpoint Mapper',
                    139: 'NetBIOS Session Service',
                    445: 'SMB - File sharing (vulnerable)',
                    3389: 'RDP - Remote Desktop Protocol',
                    5900: 'VNC - Remote access'
                }
                
                if port in dangerous_ports:
                    findings.append({
                        'title': f'Dangerous Service on Port: {port}',
                        'severity': 'high',
                        'description': f'Dangerous service running on port {port}: {dangerous_ports[port]}',
                        'recommendation': f'Disable service on port {port} if not required, or properly secure it',
                        'location': f'Port: {port}'
                    })
        
        except Exception as e:
            logger.error(f"Error checking local ports: {e}")
            raise NetworkError(f"Error checking local ports: {e}")
        
        return findings
    
    def _get_open_ports(self) -> List[Tuple[int, str, str]]:
        """Get list of open ports using system commands.
        
        Returns:
            List of tuples (port, protocol, process)
        """
        open_ports = []
        
        try:
            # Try using ss command first (modern Linux systems)
            try:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                # Extract port from address:port
                                address_port = parts[4]
                                if ':' in address_port:
                                    port_str = address_port.split(':')[-1]
                                    try:
                                        port = int(port_str)
                                        protocol = 'tcp' if 'tcp' in line else 'udp'
                                        open_ports.append((port, protocol, 'Unknown'))
                                    except ValueError:
                                        continue
            except FileNotFoundError:
                # Fall back to netstat
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                # Extract port from address:port
                                address_port = parts[3]
                                if ':' in address_port:
                                    port_str = address_port.split(':')[-1]
                                    try:
                                        port = int(port_str)
                                        protocol = 'tcp' if 'tcp' in line else 'udp'
                                        open_ports.append((port, protocol, 'Unknown'))
                                    except ValueError:
                                        continue
        except subprocess.TimeoutExpired:
            logger.error("Port scanning command timed out")
        except Exception as e:
            logger.error(f"Error getting open ports: {e}")
        
        return open_ports
    
    def _check_network_connectivity(self) -> List[Dict[str, Any]]:
        """Check network connectivity and configuration."""
        findings = []
        
        try:
            # Check if system can reach external networks
            external_hosts = ['8.8.8.8', '1.1.1.1', 'google.com']
            can_reach_external = False
            
            for host in external_hosts:
                try:
                    # Try to resolve DNS
                    socket.gethostbyname(host)
                    can_reach_external = True
                    break
                except socket.gaierror:
                    continue
            
            if not can_reach_external:
                findings.append({
                    'title': 'No External Network Connectivity',
                    'severity': 'medium',
                    'description': 'System cannot reach external networks (DNS resolution failed)',
                    'recommendation': 'Check network configuration and DNS settings',
                    'location': 'Network configuration'
                })
            
            # Check local network interfaces
            interfaces = self._get_network_interfaces()
            for interface in interfaces:
                name, ip, netmask, mac = interface
                if ip and ip.startswith('169.254.'):  # DHCP failed, APIPA address
                    findings.append({
                        'title': 'APIPA Address Assigned',
                        'severity': 'medium',
                        'description': f'Interface {name} has APIPA address {ip}, indicating DHCP failure',
                        'recommendation': 'Check DHCP configuration or set static IP',
                        'location': f'Interface: {name}, IP: {ip}'
                    })
        
        except Exception as e:
            logger.error(f"Error checking network connectivity: {e}")
            raise NetworkError(f"Error checking network connectivity: {e}")
        
        return findings
    
    def _get_network_interfaces(self) -> List[Tuple[str, str, str, str]]:
        """Get network interface information.
        
        Returns:
            List of tuples (name, ip, netmask, mac)
        """
        interfaces = []
        
        try:
            # Use ip command to get interface information
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_interface = None
                for line in lines:
                    if line.strip().startswith('inet '):
                        # Extract IP and netmask
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip_net = parts[1]
                            ip, netmask = ip_net.split('/')
                            if current_interface:
                                interfaces.append((current_interface, ip, netmask, 'Unknown'))
                    elif line.strip().endswith(':'):
                        # Interface name line
                        name = line.strip().rstrip(':').split()[-1]
                        current_interface = name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback to ifconfig
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_interface = None
                    for line in lines:
                        if 'flags=' in line:
                            # Interface name line
                            name = line.split()[0].rstrip(':')
                            current_interface = name
                        elif 'inet ' in line and 'netmask' in line:
                            # IP address line
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                ip = parts[1]
                                netmask = parts[3]
                                if current_interface:
                                    interfaces.append((current_interface, ip, netmask, 'Unknown'))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning("Could not get network interface information")
        
        return interfaces
    
    def _check_network_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for common network vulnerabilities."""
        findings = []
        
        try:
            # Check for common network misconfigurations
            # Check if IPv6 is enabled but not properly secured
            try:
                result = subprocess.run(['sysctl', 'net.ipv6.conf.all.disable_ipv6'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    ipv6_disabled = result.stdout.strip().split()[-1] == '1'
                    if not ipv6_disabled:
                        findings.append({
                            'title': 'IPv6 Enabled',
                            'severity': 'low',
                            'description': 'IPv6 is enabled but may not be properly secured',
                            'recommendation': 'Ensure IPv6 is properly configured and firewalled if enabled',
                            'location': 'Network configuration'
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # sysctl not available
            
            # Check for promiscuous mode interfaces
            interfaces = self._get_network_interfaces()
            for interface_name, _, _, _ in interfaces:
                try:
                    result = subprocess.run(['ip', 'link', 'show', interface_name], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and 'PROMISC' in result.stdout:
                        findings.append({
                            'title': f'Interface in Promiscuous Mode: {interface_name}',
                            'severity': 'high',
                            'description': f'Network interface {interface_name} is in promiscuous mode',
                            'recommendation': 'Disable promiscuous mode unless required for network analysis',
                            'location': f'Interface: {interface_name}'
                        })
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
        
        except Exception as e:
            logger.error(f"Error checking network vulnerabilities: {e}")
            raise NetworkError(f"Error checking network vulnerabilities: {e}")
        
        return findings
    
    def _check_firewall_status(self) -> List[Dict[str, Any]]:
        """Check firewall status and configuration."""
        findings = []
        
        try:
            # Check if iptables is available and active
            iptables_active = False
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=10)
                iptables_active = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Check if UFW is available and active
            ufw_active = False
            ufw_status = "inactive"
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ufw_active = "Status: active" in result.stdout
                    ufw_status = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Check if firewalld is available and active
            firewalld_active = False
            try:
                result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=10)
                firewalld_active = result.returncode == 0 and result.stdout.strip() == 'running'
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Determine if any firewall is active
            firewall_active = iptables_active or ufw_active or firewalld_active
            
            if not firewall_active:
                findings.append({
                    'title': 'No Active Firewall',
                    'severity': 'high',
                    'description': 'No active firewall detected on the system',
                    'recommendation': 'Enable and configure a firewall (UFW, iptables, or firewalld)',
                    'location': 'System security configuration'
                })
            else:
                # Check if firewall is properly configured
                if ufw_active:
                    # Check if default policy is restrictive
                    if "Default: allow" in ufw_status:
                        findings.append({
                            'title': 'Permissive Firewall Default Policy',
                            'severity': 'medium',
                            'description': 'UFW default policy allows all connections',
                            'recommendation': 'Set UFW default policy to deny incoming connections',
                            'location': 'UFW configuration'
                        })
        
        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            raise NetworkError(f"Error checking firewall status: {e}")
        
        return findings
    
    def scan_port(self, host: str, port: int) -> bool:
        """Check if a specific port is open on a host.
        
        Args:
            host: Host to scan
            port: Port to check
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def scan_host(self, host: str) -> Dict[str, Any]:
        """Scan a specific host for open ports.
        
        Args:
            host: Host to scan
            
        Returns:
            Dictionary with scan results
        """
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.config.get("scan.cores", 4)) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in self.ports_to_check}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                except Exception as e:
                    logger.error(f"Error scanning port {port} on {host}: {e}")
        
        return {
            'host': host,
            'open_ports': open_ports,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }
    
    def scan_network_range(self, network_range: str) -> List[Dict[str, Any]]:
        """Scan a network range for active hosts and open ports.
        
        Args:
            network_range: Network range to scan (e.g., '192.168.1.0/24')
            
        Returns:
            List of scan results for each host
        """
        results = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            # Limit to first 256 hosts to prevent very large scans
            hosts = hosts[:256]
            
            with ThreadPoolExecutor(max_workers=self.config.get("scan.cores", 4)) as executor:
                futures = {executor.submit(self.scan_host, str(host)): host for host in hosts}
                
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        result = future.result()
                        if result['open_ports']:  # Only include hosts with open ports
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Error scanning host {host}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning network range {network_range}: {e}")
            raise NetworkError(f"Error scanning network range: {e}")
        
        return results


# For backward compatibility, import time here too
import time