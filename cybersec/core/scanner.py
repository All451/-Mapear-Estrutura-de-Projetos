"""Scanner module for the cybersecurity toolkit."""
from enum import Enum
from typing import Dict, List, Any, Set
import logging

from cybersec.utils.config import ConfigManager
from cybersec.core.system import SystemScanner
from cybersec.core.network import NetworkScanner
from cybersec.core.firewall import FirewallScanner
from cybersec.core.docker import DockerScanner
from cybersec.core.filesystem import FilesystemScanner


class ScanType(Enum):
    """Enumeration of available scan types."""
    SYSTEM = "system"
    NETWORK = "network"
    FIREWALL = "firewall"
    DOCKER = "docker"
    FILESYSTEM = "filesystem"
    QUICK = "quick"
    FULL = "full"

    @classmethod
    def from_string(cls, value: str):
        """Create ScanType from string value."""
        for scan_type in cls:
            if scan_type.value == value.lower():
                return scan_type
        raise ValueError(f"Invalid scan type: {value}")


class SecurityScanner:
    """Main security scanner class that orchestrates different types of scans."""

    def __init__(self, config: ConfigManager):
        """
        Initialize the security scanner.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.results: Dict[str, Any] = {}
        self.scan_types: Set[ScanType] = set()
        self.logger = logging.getLogger(__name__)

    def add_scan_type(self, scan_type: ScanType):
        """
        Add a scan type to be executed.
        
        Args:
            scan_type: Type of scan to add
        """
        self.scan_types.add(scan_type)

    def execute_scan(self) -> Dict[str, Any]:
        """
        Execute all added scan types and return results.
        
        Returns:
            Dictionary containing scan results
        """
        self.results = {}
        
        for scan_type in self.scan_types:
            try:
                if scan_type in [ScanType.SYSTEM, ScanType.QUICK, ScanType.FULL]:
                    self.logger.info("Starting system scan...")
                    system_scanner = SystemScanner()
                    self.results['system'] = system_scanner.scan()
                
                if scan_type in [ScanType.NETWORK, ScanType.QUICK, ScanType.FULL]:
                    self.logger.info("Starting network scan...")
                    network_scanner = NetworkScanner()
                    self.results['network'] = network_scanner.scan()
                
                if scan_type in [ScanType.FIREWALL, ScanType.QUICK, ScanType.FULL]:
                    self.logger.info("Starting firewall scan...")
                    firewall_scanner = FirewallScanner()
                    self.results['firewall'] = firewall_scanner.scan()
                
                if scan_type in [ScanType.DOCKER, ScanType.FULL]:
                    self.logger.info("Starting Docker scan...")
                    docker_scanner = DockerScanner()
                    self.results['docker'] = docker_scanner.scan()
                
                if scan_type in [ScanType.FILESYSTEM, ScanType.FULL]:
                    self.logger.info("Starting filesystem scan...")
                    filesystem_scanner = FilesystemScanner()
                    scan_path = self.config.get('scanner.filesystem_scan_path', '/tmp')
                    self.results['filesystem'] = filesystem_scanner.scan(scan_path)
                    
            except Exception as e:
                self.logger.error(f"Error during {scan_type.value} scan: {str(e)}")
                self.results[scan_type.value] = {"error": str(e)}
        
        return self.results