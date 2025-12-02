"""System scanner module for the cybersecurity toolkit."""
import subprocess
import os
import logging
from typing import Dict, List, Any


class SystemScanner:
    """Scanner for system-level security checks."""

    def __init__(self):
        """Initialize the system scanner."""
        self.hostname = None
        self.kernel_version = None
        self.os_version = None
        self.logger = logging.getLogger(__name__)

    def get_hostname(self) -> str:
        """
        Get the system hostname.
        
        Returns:
            System hostname or None if error
        """
        try:
            result = subprocess.run(['hostname'], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting hostname: {e}")
            return None

    def get_kernel_version(self) -> str:
        """
        Get the kernel version.
        
        Returns:
            Kernel version or None if error
        """
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting kernel version: {e}")
            return None

    def get_os_version(self) -> str:
        """
        Get the OS version information.
        
        Returns:
            OS version information or None if error
        """
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                return content
        except FileNotFoundError:
            self.logger.error("Error: /etc/os-release not found")
            return None
        except Exception as e:
            self.logger.error(f"Error getting OS version: {e}")
            return None

    def get_users(self) -> List[str]:
        """
        Get list of system users.
        
        Returns:
            List of usernames
        """
        users = []
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.strip():
                        username = line.split(':')[0]
                        users.append(username)
        except FileNotFoundError:
            self.logger.error("Error: /etc/passwd not found")
        except Exception as e:
            self.logger.error(f"Error getting users: {e}")
        
        return users

    def get_processes(self) -> List[Dict[str, Any]]:
        """
        Get list of running processes.
        
        Returns:
            List of process information
        """
        processes = []
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        process = {
                            'pid': parts[1],
                            'user': parts[0],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'command': ' '.join(parts[10:])
                        }
                        processes.append(process)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting processes: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing processes: {e}")
        
        return processes

    def get_services(self) -> List[str]:
        """
        Get list of active services.
        
        Returns:
            List of active service names
        """
        services = []
        try:
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                    capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip() and '.service' in line:
                    service_name = line.split()[0]
                    if service_name.endswith('.service'):
                        services.append(service_name.replace('.service', ''))
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting services: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing services: {e}")
        
        return services

    def get_critical_files(self) -> List[str]:
        """
        Get list of critical system files.
        
        Returns:
            List of critical file paths
        """
        critical_files = []
        critical_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/crontab',
            '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/group'
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                critical_files.append(path)
        
        return critical_files

    def scan(self) -> Dict[str, Any]:
        """
        Perform a complete system security scan.
        
        Returns:
            Dictionary containing system scan results
        """
        self.logger.info("Starting system scan...")
        
        results = {
            'hostname': self.get_hostname(),
            'kernel_version': self.get_kernel_version(),
            'os_version': self.get_os_version(),
            'users': self.get_users(),
            'processes': self.get_processes(),
            'services': self.get_services(),
            'critical_files': self.get_critical_files()
        }
        
        self.logger.info("System scan completed.")
        return results