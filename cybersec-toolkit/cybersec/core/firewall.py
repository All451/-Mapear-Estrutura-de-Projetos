"""Firewall management for the Cybersecurity Toolkit."""
import subprocess
import time
import re
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import FirewallError, PermissionError

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manages firewall operations and security."""
    
    def __init__(self):
        """Initialize firewall manager."""
        self.config = get_config()
        self.ban_duration = self.config.get("firewall.ban_duration", 3600)  # 1 hour
        self.threshold = self.config.get("firewall.threshold", 5)
        self.auto_ban = self.config.get("firewall.auto_ban", True)
        self.ban_reason = self.config.get("firewall.ban_reason", "Automated security ban")
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform firewall security scan.
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check firewall status
        findings.extend(self._check_firewall_status())
        
        # Check for unauthorized access
        findings.extend(self._check_unauthorized_access())
        
        # Check firewall rules
        findings.extend(self._check_firewall_rules())
        
        logger.info(f"Firewall scan completed with {len(findings)} findings")
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
                logger.debug("iptables not available")
            
            # Check if UFW is available and active
            ufw_active = False
            ufw_status = ""
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ufw_active = "Status: active" in result.stdout
                    ufw_status = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("ufw not available")
            
            # Check if firewalld is available and active
            firewalld_active = False
            try:
                result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=10)
                firewalld_active = result.returncode == 0 and result.stdout.strip() == 'running'
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("firewalld not available")
            
            # Determine if any firewall is active
            firewall_active = iptables_active or ufw_active or firewalld_active
            
            if not firewall_active:
                findings.append({
                    'title': 'No Active Firewall',
                    'severity': 'critical',
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
                            'severity': 'high',
                            'description': 'UFW default policy allows all incoming connections',
                            'recommendation': 'Set UFW default policy to deny incoming connections: sudo ufw default deny incoming',
                            'location': 'UFW configuration'
                        })
                    elif "Default: deny" in ufw_status:
                        # Check if SSH is allowed (common requirement)
                        if "22/tcp" not in ufw_status and "ssh" not in ufw_status.lower():
                            findings.append({
                                'title': 'SSH Access Not Configured',
                                'severity': 'medium',
                                'description': 'SSH access is not explicitly allowed in UFW',
                                'recommendation': 'Allow SSH access to prevent lockout: sudo ufw allow ssh or sudo ufw allow 22/tcp',
                                'location': 'UFW configuration'
                            })
        
        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            raise FirewallError(f"Error checking firewall status: {e}")
        
        return findings
    
    def _check_unauthorized_access(self) -> List[Dict[str, Any]]:
        """Check system logs for unauthorized access attempts."""
        findings = []
        
        try:
            # Common log files to check for failed login attempts
            log_files = [
                '/var/log/auth.log',  # Debian/Ubuntu
                '/var/log/secure',    # RHEL/CentOS
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        # Count failed login attempts in the last hour
                        one_hour_ago = time.time() - 3600
                        failed_attempts = 0
                        suspicious_ips = {}
                        
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                if any(pattern in line.lower() for pattern in 
                                      ['failed password', 'invalid user', 'authentication failure']):
                                    # Extract IP if present
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                                    if ip_match:
                                        ip = ip_match.group()
                                        if ip in suspicious_ips:
                                            suspicious_ips[ip] += 1
                                        else:
                                            suspicious_ips[ip] = 1
                                        failed_attempts += 1
                        
                        # Check for IPs with high number of failed attempts
                        for ip, count in suspicious_ips.items():
                            if count >= self.threshold:
                                findings.append({
                                    'title': f'Suspicious IP Activity: {ip}',
                                    'severity': 'high',
                                    'description': f'IP {ip} has {count} failed login attempts in the last hour',
                                    'recommendation': f'Consider banning IP {ip} if not legitimate',
                                    'location': f'Log file: {log_file}, IP: {ip}'
                                })
                    
                    except PermissionError:
                        logger.warning(f"Cannot access log file {log_file} - insufficient privileges")
                    except Exception as e:
                        logger.error(f"Error reading log file {log_file}: {e}")
        
        except Exception as e:
            logger.error(f"Error checking unauthorized access: {e}")
            raise FirewallError(f"Error checking unauthorized access: {e}")
        
        return findings
    
    def _check_firewall_rules(self) -> List[Dict[str, Any]]:
        """Check firewall rules for security issues."""
        findings = []
        
        try:
            # Check UFW rules
            try:
                result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ufw_rules = result.stdout
                    
                    # Check for overly permissive rules
                    if "Anywhere" in ufw_rules:
                        # Look for rules that allow access from anywhere
                        anywhere_lines = [line for line in ufw_rules.split('\n') if 'Anywhere' in line and 'ALLOW' in line]
                        for line in anywhere_lines:
                            if 'Anywhere' in line and 'ALLOW' in line:
                                # Don't flag SSH if it's specifically for SSH
                                if '22' not in line or 'ssh' not in line.lower():
                                    findings.append({
                                        'title': 'Overly Permissive Firewall Rule',
                                        'severity': 'high',
                                        'description': f'Firewall rule allows access from anywhere: {line.strip()}',
                                        'recommendation': 'Restrict access to specific IP ranges instead of allowing from anywhere',
                                        'location': 'UFW rules'
                                    })
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("UFW not available for rule checking")
            
            # Check iptables rules
            try:
                result = subprocess.run(['iptables', '-L', '-n', '-v'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    iptables_rules = result.stdout
                    
                    # Check for rules that might be too permissive
                    lines = iptables_rules.split('\n')
                    for line in lines:
                        if '0.0.0.0/0' in line and ('ACCEPT' in line or 'allow' in line.lower()):
                            findings.append({
                                'title': 'Overly Permissive iptables Rule',
                                'severity': 'high',
                                'description': f'iptables rule allows access from all IPs: {line.strip()}',
                                'recommendation': 'Restrict iptables rules to specific IP ranges',
                                'location': 'iptables rules'
                            })
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("iptables not available for rule checking")
        
        except Exception as e:
            logger.error(f"Error checking firewall rules: {e}")
            raise FirewallError(f"Error checking firewall rules: {e}")
        
        return findings
    
    def get_firewall_status(self) -> Dict[str, Any]:
        """Get current firewall status.
        
        Returns:
            Dictionary with firewall status information
        """
        status = {
            'ufw_active': False,
            'iptables_active': False,
            'firewalld_active': False,
            'rules_count': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check UFW
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                status['ufw_active'] = result.returncode == 0 and "Status: active" in result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Check iptables
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=10)
                status['iptables_active'] = result.returncode == 0
                # Count rules
                if status['iptables_active']:
                    rules_output = result.stdout
                    status['rules_count'] = rules_output.count('target') + rules_output.count('ACCEPT') + rules_output.count('DROP') - rules_output.count('Chain')
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Check firewalld
            try:
                result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=10)
                status['firewalld_active'] = result.returncode == 0 and result.stdout.strip() == 'running'
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        except Exception as e:
            logger.error(f"Error getting firewall status: {e}")
        
        return status
    
    def ban_ip(self, ip: str, reason: Optional[str] = None, duration: Optional[int] = None) -> bool:
        """Ban an IP address using the available firewall.
        
        Args:
            ip: IP address to ban
            reason: Reason for the ban
            duration: Duration of ban in seconds (None for permanent)
            
        Returns:
            True if successful, False otherwise
        """
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        reason = reason or self.ban_reason
        duration = duration or self.ban_duration
        
        try:
            # Try UFW first
            try:
                cmd = ['ufw', 'deny', 'from', ip, 'comment', f'CyberSec: {reason}']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Successfully banned {ip} using UFW: {reason}")
                    
                    # If temporary ban, schedule unban
                    if duration > 0:
                        self._schedule_unban(ip, duration)
                    
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("UFW not available for banning")
            
            # Try iptables
            try:
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP', '-m', 'comment', '--comment', f'CyberSec: {reason}']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Successfully banned {ip} using iptables: {reason}")
                    
                    # If temporary ban, schedule unban
                    if duration > 0:
                        self._schedule_unban(ip, duration)
                    
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("iptables not available for banning")
            
            logger.error(f"Could not ban IP {ip}: No available firewall tool")
            return False
        
        except PermissionError:
            logger.error("Insufficient permissions to ban IP - try running with sudo")
            raise PermissionError("Insufficient permissions to ban IP - try running with sudo")
        except Exception as e:
            logger.error(f"Error banning IP {ip}: {e}")
            return False
    
    def unban_ip(self, ip: str) -> bool:
        """Unban an IP address.
        
        Args:
            ip: IP address to unban
            
        Returns:
            True if successful, False otherwise
        """
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        try:
            # Try UFW first
            try:
                cmd = ['ufw', '--force', 'delete', 'deny', 'from', ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Successfully unbanned {ip} using UFW")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("UFW not available for unbanning")
            
            # Try iptables - this is more complex as we need to find the rule number
            try:
                # List current iptables rules
                result = subprocess.run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    rule_number = None
                    
                    # Find the rule for this IP
                    for line in lines:
                        if ip in line and 'DROP' in line:
                            # Extract rule number
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                rule_number = parts[0]
                                break
                    
                    if rule_number:
                        # Delete the rule
                        cmd = ['iptables', '-D', 'INPUT', rule_number]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            logger.info(f"Successfully unbanned {ip} using iptables")
                            return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("iptables not available for unbanning")
            
            logger.warning(f"Could not find ban rule for IP {ip}")
            return False
        
        except PermissionError:
            logger.error("Insufficient permissions to unban IP - try running with sudo")
            raise PermissionError("Insufficient permissions to unban IP - try running with sudo")
        except Exception as e:
            logger.error(f"Error unbanning IP {ip}: {e}")
            return False
    
    def list_banned_ips(self) -> List[Dict[str, Any]]:
        """List currently banned IP addresses.
        
        Returns:
            List of banned IP information
        """
        banned_ips = []
        
        try:
            # Try UFW
            try:
                result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'DENY' in line and 'Anywhere' in line:
                            # Extract IP pattern - this is a simplified approach
                            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                            if ip_match:
                                ip = ip_match.group()
                                banned_ips.append({
                                    'ip': ip,
                                    'method': 'ufw',
                                    'rule': line.strip(),
                                    'timestamp': datetime.now().isoformat()
                                })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("UFW not available for listing banned IPs")
            
            # Try iptables
            try:
                result = subprocess.run(['iptables', '-L', 'INPUT', '-n', '-v'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'DROP' in line and '0.0.0.0/0' not in line:  # Exclude default drop rules
                            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                            if ip_match:
                                ip = ip_match.group()
                                banned_ips.append({
                                    'ip': ip,
                                    'method': 'iptables',
                                    'rule': line.strip(),
                                    'timestamp': datetime.now().isoformat()
                                })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("iptables not available for listing banned IPs")
        
        except Exception as e:
            logger.error(f"Error listing banned IPs: {e}")
        
        return banned_ips
    
    def check_ip_status(self, ip: str) -> Dict[str, Any]:
        """Check if an IP is currently banned.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with IP status information
        """
        if not self._is_valid_ip(ip):
            return {'ip': ip, 'valid': False, 'banned': False, 'method': None}
        
        status = {
            'ip': ip,
            'valid': True,
            'banned': False,
            'method': None,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check UFW
        try:
            result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and ip in result.stdout:
                status['banned'] = True
                status['method'] = 'ufw'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check iptables
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n', '-v'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and ip in result.stdout:
                status['banned'] = True
                if not status['method']:  # Only set method if not already set
                    status['method'] = 'iptables'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return status
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _schedule_unban(self, ip: str, duration: int):
        """Schedule an IP to be unbanned after a certain duration.
        
        Args:
            ip: IP address to unban
            duration: Duration in seconds after which to unban
        """
        # This is a simplified implementation - in a real system you might use cron or a background service
        def delayed_unban():
            time.sleep(duration)
            self.unban_ip(ip)
            logger.info(f"Auto-unbanned IP {ip} after {duration} seconds")
        
        # Run in a separate thread
        import threading
        unban_thread = threading.Thread(target=delayed_unban, daemon=True)
        unban_thread.start()


import os  # Import os for file access in _check_unauthorized_access