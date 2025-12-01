"""Main scanner module for the Cybersecurity Toolkit."""
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
import psutil

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import ScanError, PermissionError
from cybersec.core.system import SystemScanner
from cybersec.core.network import NetworkScanner
from cybersec.core.firewall import FirewallManager
from cybersec.core.docker import DockerScanner
from cybersec.core.filesystem import FilesystemScanner

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner that coordinates all security checks."""
    
    def __init__(self):
        """Initialize the security scanner."""
        self.config = get_config()
        self.system_scanner = SystemScanner()
        self.network_scanner = NetworkScanner()
        self.firewall_manager = FirewallManager()
        self.docker_scanner = DockerScanner()
        self.filesystem_scanner = FilesystemScanner()
        
        # Results storage
        self.scan_results = {
            'system': [],
            'network': [],
            'firewall': [],
            'docker': [],
            'filesystem': []
        }
    
    def scan_system(self) -> List[Dict[str, Any]]:
        """Perform system security scan."""
        logger.info("Starting system security scan...")
        try:
            results = self.system_scanner.scan()
            logger.info(f"System scan completed with {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"System scan failed: {e}")
            raise ScanError(f"System scan failed: {e}")
    
    def scan_network(self) -> List[Dict[str, Any]]:
        """Perform network security scan."""
        logger.info("Starting network security scan...")
        try:
            results = self.network_scanner.scan()
            logger.info(f"Network scan completed with {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            raise ScanError(f"Network scan failed: {e}")
    
    def scan_firewall(self) -> List[Dict[str, Any]]:
        """Perform firewall security scan."""
        logger.info("Starting firewall security scan...")
        try:
            results = self.firewall_manager.scan()
            logger.info(f"Firewall scan completed with {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"Firewall scan failed: {e}")
            raise ScanError(f"Firewall scan failed: {e}")
    
    def scan_docker(self) -> List[Dict[str, Any]]:
        """Perform Docker security scan."""
        logger.info("Starting Docker security scan...")
        try:
            results = self.docker_scanner.scan()
            logger.info(f"Docker scan completed with {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"Docker scan failed: {e}")
            raise ScanError(f"Docker scan failed: {e}")
    
    def scan_filesystem(self, path: str = "/") -> List[Dict[str, Any]]:
        """Perform filesystem security scan."""
        logger.info(f"Starting filesystem security scan for {path}...")
        try:
            results = self.filesystem_scanner.scan(path)
            logger.info(f"Filesystem scan completed with {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"Filesystem scan failed: {e}")
            raise ScanError(f"Filesystem scan failed: {e}")
    
    def quick_scan(self) -> Dict[str, List[Dict[str, Any]]]:
        """Perform a quick security scan."""
        logger.info("Starting quick security scan...")
        start_time = time.time()
        
        # Quick scan - just system and network
        with ThreadPoolExecutor(max_workers=self.config.get("scan.cores", 4)) as executor:
            futures = {
                executor.submit(self.scan_system): 'system',
                executor.submit(self.scan_network): 'network',
            }
            
            for future in as_completed(futures):
                scan_type = futures[future]
                try:
                    self.scan_results[scan_type] = future.result()
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
                    self.scan_results[scan_type] = []
        
        duration = time.time() - start_time
        logger.info(f"Quick scan completed in {duration:.2f} seconds")
        
        return self.scan_results.copy()
    
    def full_scan(self) -> Dict[str, List[Dict[str, Any]]]:
        """Perform a full security scan."""
        logger.info("Starting full security scan...")
        start_time = time.time()
        
        # Check if we have sudo privileges for some operations
        has_sudo = self._check_sudo_privileges()
        if not has_sudo:
            logger.warning("Running without sudo privileges - some checks may be limited")
        
        # Run all scans in parallel where possible
        with ThreadPoolExecutor(max_workers=self.config.get("scan.cores", 4)) as executor:
            futures = {
                executor.submit(self.scan_system): 'system',
                executor.submit(self.scan_network): 'network',
                executor.submit(self.scan_firewall): 'firewall',
            }
            
            # Add Docker scan if Docker is available
            if self.docker_scanner.is_docker_available():
                futures[executor.submit(self.scan_docker)] = 'docker'
            
            for future in as_completed(futures):
                scan_type = futures[future]
                try:
                    self.scan_results[scan_type] = future.result()
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
                    self.scan_results[scan_type] = []
        
        duration = time.time() - start_time
        logger.info(f"Full scan completed in {duration:.2f} seconds")
        
        return self.scan_results.copy()
    
    def scan_specific(self, scan_types: List[str], path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Perform specific types of security scans."""
        logger.info(f"Starting specific scans: {scan_types}")
        start_time = time.time()
        
        # Map scan types to methods
        scan_methods = {
            'system': self.scan_system,
            'network': self.scan_network,
            'firewall': self.scan_firewall,
            'docker': self.scan_docker,
            'filesystem': lambda: self.scan_filesystem(path or "/")
        }
        
        with ThreadPoolExecutor(max_workers=self.config.get("scan.cores", 4)) as executor:
            futures = {}
            
            for scan_type in scan_types:
                if scan_type in scan_methods:
                    if scan_type == 'filesystem' and path:
                        futures[executor.submit(scan_methods[scan_type])] = scan_type
                    else:
                        futures[executor.submit(scan_methods[scan_type])] = scan_type
                else:
                    logger.warning(f"Unknown scan type: {scan_type}")
            
            for future in as_completed(futures):
                scan_type = futures[future]
                try:
                    self.scan_results[scan_type] = future.result()
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
                    self.scan_results[scan_type] = []
        
        duration = time.time() - start_time
        logger.info(f"Specific scans completed in {duration:.2f} seconds")
        
        return self.scan_results.copy()
    
    def _check_sudo_privileges(self) -> bool:
        """Check if the current user has sudo privileges."""
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary of scan results."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }
        
        for scan_type, findings in self.scan_results.items():
            for finding in findings:
                severity = finding.get('severity', 'low').lower()
                if severity in summary:
                    summary[severity] += 1
                    summary['total'] += 1
        
        return summary
    
    def reset_results(self):
        """Reset scan results."""
        self.scan_results = {
            'system': [],
            'network': [],
            'firewall': [],
            'docker': [],
            'filesystem': []
        }


# Global scanner instance
_scanner: Optional[SecurityScanner] = None


def get_scanner() -> SecurityScanner:
    """Get global scanner instance.
    
    Returns:
        SecurityScanner instance
    """
    global _scanner
    if _scanner is None:
        _scanner = SecurityScanner()
    return _scanner