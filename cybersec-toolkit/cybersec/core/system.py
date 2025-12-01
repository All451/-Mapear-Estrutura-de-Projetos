"""System security scanner for the Cybersecurity Toolkit."""
import os
import subprocess
import pwd
import grp
import psutil
import socket
from typing import List, Dict, Any
import logging
from pathlib import Path
import re

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import ScanError

logger = logging.getLogger(__name__)


class SystemScanner:
    """Scans system-level security issues."""
    
    def __init__(self):
        """Initialize system scanner."""
        self.config = get_config()
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform comprehensive system security scan.
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check system information
        findings.extend(self._check_system_info())
        
        # Check users and permissions
        findings.extend(self._check_users_and_permissions())
        
        # Check services
        findings.extend(self._check_services())
        
        # Check processes
        findings.extend(self._check_processes())
        
        # Check kernel parameters
        findings.extend(self._check_kernel_params())
        
        # Check system logs for security events
        findings.extend(self._check_security_logs())
        
        logger.info(f"System scan completed with {len(findings)} findings")
        return findings
    
    def _check_system_info(self) -> List[Dict[str, Any]]:
        """Check basic system information for security issues."""
        findings = []
        
        try:
            # Get system information
            uname = os.uname()
            hostname = socket.gethostname()
            
            # Check for outdated kernel
            kernel_version = uname.release
            # In a real implementation, we would check against known vulnerable versions
            if kernel_version.startswith("2.6") or kernel_version.startswith("3."):
                findings.append({
                    'title': 'Outdated Kernel Version',
                    'severity': 'high',
                    'description': f'Running kernel {kernel_version} which may have known vulnerabilities',
                    'recommendation': 'Update kernel to latest stable version',
                    'location': f'Kernel: {kernel_version}'
                })
            
            # Check system uptime
            uptime_seconds = psutil.boot_time()
            uptime = time.time() - uptime_seconds
            
            # Check system load
            load_avg = os.getloadavg()
            
            logger.debug(f"System info - Hostname: {hostname}, Kernel: {kernel_version}, Load: {load_avg}")
        except Exception as e:
            logger.error(f"Error checking system info: {e}")
        
        return findings
    
    def _check_users_and_permissions(self) -> List[Dict[str, Any]]:
        """Check user accounts and permissions for security issues."""
        findings = []
        
        try:
            # Check for users with UID 0 (root) other than root
            for user in pwd.getpwall():
                if user.pw_uid == 0 and user.pw_name != 'root':
                    findings.append({
                        'title': 'Multiple Root Users',
                        'severity': 'critical',
                        'description': f'User {user.pw_name} has UID 0 (root privileges)',
                        'recommendation': 'Remove or disable non-root users with UID 0',
                        'location': f'User: {user.pw_name}'
                    })
            
            # Check for users with empty passwords
            try:
                import spwd
                for shadow_entry in spwd.getspall():
                    if shadow_entry.sp_pwd == '' or shadow_entry.sp_pwd == '!!':
                        # Empty password or locked account
                        if shadow_entry.sp_pwd == '':
                            findings.append({
                                'title': 'User with Empty Password',
                                'severity': 'critical',
                                'description': f'User {shadow_entry.sp_namp} has an empty password',
                                'recommendation': 'Set a strong password for the user account',
                                'location': f'User: {shadow_entry.sp_namp}'
                            })
            except PermissionError:
                logger.warning("Cannot access shadow file - running without sufficient privileges")
            except ImportError:
                logger.debug("spwd module not available on this system")
            
            # Check for writable system files
            system_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    for item in os.listdir(sys_dir):
                        item_path = os.path.join(sys_dir, item)
                        if os.path.isfile(item_path):
                            stat_info = os.stat(item_path)
                            # Check if world-writable
                            if stat_info.st_mode & 0o002:
                                findings.append({
                                    'title': 'World-Writable System File',
                                    'severity': 'high',
                                    'description': f'System file {item_path} is world-writable',
                                    'recommendation': 'Change file permissions to remove world-write access',
                                    'location': item_path
                                })
        
        except Exception as e:
            logger.error(f"Error checking users and permissions: {e}")
        
        return findings
    
    def _check_services(self) -> List[Dict[str, Any]]:
        """Check running services for security issues."""
        findings = []
        
        try:
            # Get list of running services
            running_services = []
            
            # Try systemctl first (systemd systems)
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines[1:]:  # Skip header
                        if '.service' in line and 'running' in line:
                            service_name = line.split()[0]
                            running_services.append(service_name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("systemctl not available or timed out")
            
            # Check for potentially dangerous services
            dangerous_services = [
                'telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 
                'smbd', 'nfsd', 'rpcbind', 'snmpd'
            ]
            
            for service in running_services:
                service_name = service.replace('.service', '')
                for dangerous in dangerous_services:
                    if dangerous in service_name.lower():
                        findings.append({
                            'title': f'Dangerous Service Running: {service_name}',
                            'severity': 'high',
                            'description': f'Dangerous service {service_name} is currently running',
                            'recommendation': f'Consider disabling the {service_name} service if not needed',
                            'location': f'Service: {service_name}'
                        })
        
        except Exception as e:
            logger.error(f"Error checking services: {e}")
        
        return findings
    
    def _check_processes(self) -> List[Dict[str, Any]]:
        """Check running processes for security issues."""
        findings = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    process_info = proc.info
                    
                    # Check for processes running as root
                    if process_info['username'] == 'root':
                        cmd = ' '.join(process_info['cmdline'] or [])
                        
                        # Check for suspicious processes
                        suspicious_patterns = [
                            r'miner', r'crypto', r'bitcoin', r'xmr', r'xmrig',
                            r'nc', r'netcat', r'socat', r'bash -i', r'/dev/tcp'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if re.search(pattern, cmd, re.IGNORECASE):
                                findings.append({
                                    'title': f'Suspicious Root Process: {process_info["name"]}',
                                    'severity': 'high',
                                    'description': f'Process {process_info["name"]} (PID: {process_info["pid"]}) is running as root with suspicious command: {cmd}',
                                    'recommendation': 'Investigate and terminate unauthorized processes',
                                    'location': f'Process: {process_info["name"]} (PID: {process_info["pid"]})'
                                })
                                break  # Only add once per process
                    
                    # Check for processes with network connections that might be suspicious
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            if conn.status == 'LISTEN':
                                # Check if non-standard ports are being listened on
                                if conn.laddr.port not in [22, 80, 443, 3306, 5432, 6379]:  # Common ports
                                    if conn.laddr.port < 1024:  # Well-known ports
                                        findings.append({
                                            'title': f'Process Listening on Privileged Port',
                                            'severity': 'medium',
                                            'description': f'Process {process_info["name"]} is listening on privileged port {conn.laddr.port}',
                                            'recommendation': 'Verify if this is expected behavior',
                                            'location': f'Process: {process_info["name"]}, Port: {conn.laddr.port}'
                                        })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            logger.error(f"Error checking processes: {e}")
        
        return findings
    
    def _check_kernel_params(self) -> List[Dict[str, Any]]:
        """Check kernel security parameters."""
        findings = []
        
        try:
            # Security-related kernel parameters to check
            security_params = {
                'net.ipv4.ip_forward': '0',  # IP forwarding off
                'net.ipv4.conf.all.send_redirects': '0',
                'net.ipv4.conf.default.send_redirects': '0',
                'net.ipv4.conf.all.accept_source_route': '0',
                'net.ipv4.conf.default.accept_source_route': '0',
                'net.ipv4.conf.all.accept_redirects': '0',
                'net.ipv4.conf.default.accept_redirects': '0',
                'net.ipv4.conf.all.secure_redirects': '0',
                'net.ipv4.conf.default.secure_redirects': '0',
                'net.ipv4.conf.all.log_martians': '1',
                'net.ipv4.icmp_echo_ignore_broadcasts': '1',
                'net.ipv4.icmp_ignore_bogus_error_responses': '1',
                'net.ipv4.tcp_syncookies': '1',
                'net.ipv4.conf.all.rp_filter': '1',
                'net.ipv4.conf.default.rp_filter': '1',
                'kernel.randomize_va_space': '2'  # ASLR enabled
            }
            
            for param, expected_value in security_params.items():
                try:
                    result = subprocess.run(['sysctl', '-n', param], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        current_value = result.stdout.strip()
                        if current_value != expected_value:
                            findings.append({
                                'title': f'Kernel Parameter Misconfigured: {param}',
                                'severity': 'medium',
                                'description': f'Parameter {param} is set to {current_value}, expected {expected_value}',
                                'recommendation': f'Set {param} to {expected_value}',
                                'location': f'Kernel parameter: {param}'
                            })
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    # sysctl not available
                    continue
        
        except Exception as e:
            logger.error(f"Error checking kernel parameters: {e}")
        
        return findings
    
    def _check_security_logs(self) -> List[Dict[str, Any]]:
        """Check system logs for security events."""
        findings = []
        
        try:
            # Common log files to check
            log_files = [
                '/var/log/auth.log',  # Debian/Ubuntu
                '/var/log/secure',    # RHEL/CentOS
                '/var/log/messages',  # General messages
                '/var/log/syslog'     # General syslog
            ]
            
            # Patterns indicating security issues
            security_patterns = [
                r'Failed password',
                r'Invalid user',
                r'root login',
                r'Authentication failure',
                r'Connection closed by',
                r'POSSIBLE BREAK-IN ATTEMPT',
                r'killed process'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        # Check last 1000 lines for security events
                        result = subprocess.run(['tail', '-n', '1000', log_file], 
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            lines = result.stdout.split('\n')
                            for line in lines:
                                for pattern in security_patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        findings.append({
                                            'title': 'Security Event in Logs',
                                            'severity': 'medium',
                                            'description': f'Security event found in {log_file}: {line.strip()}',
                                            'recommendation': 'Review log entries and investigate potential security incidents',
                                            'location': f'Log file: {log_file}'
                                        })
                                        break  # Don't add same line multiple times
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
        
        except Exception as e:
            logger.error(f"Error checking security logs: {e}")
        
        return findings


import time  # Import time for boot_time calculation