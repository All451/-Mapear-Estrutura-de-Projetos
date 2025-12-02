"""Firewall scanner module for the cybersecurity toolkit."""
import subprocess
import logging
from typing import Dict, List, Any, Optional


class FirewallScanner:
    """Scanner for firewall security checks."""

    def __init__(self):
        """Initialize the firewall scanner."""
        self.rules = []
        self.status = None
        self.logger = logging.getLogger(__name__)

    def get_ufw_status(self) -> Optional[str]:
        """
        Get the UFW firewall status.
        
        Returns:
            Status of UFW firewall ('active', 'inactive', or None if error)
        """
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
            output = result.stdout.strip()
            
            if 'active' in output.lower():
                return 'active'
            elif 'inactive' in output.lower():
                return 'inactive'
            else:
                return None
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting UFW status: {e}")
            return None
        except FileNotFoundError:
            self.logger.error("UFW command not found. Is UFW installed?")
            return None

    def get_ufw_rules(self) -> List[Dict[str, str]]:
        """
        Get the UFW firewall rules.
        
        Returns:
            List of firewall rules
        """
        rules = []
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
            output_lines = result.stdout.strip().split('\n')
            
            # Find the line that starts the rules table
            rules_started = False
            for line in output_lines:
                if 'To' in line and 'Action' in line and 'From' in line:
                    # This is the header line, rules start after
                    rules_started = True
                    continue
                
                if rules_started and line.strip() and '--' not in line:
                    # Parse rule line
                    parts = line.split()
                    if len(parts) >= 3:
                        rule = {
                            'rule': parts[0],  # Port/service
                            'action': parts[1],  # ALLOW/DENY
                            'from': ' '.join(parts[2:])  # Source
                        }
                        rules.append(rule)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting UFW rules: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing UFW rules: {e}")
        
        return rules

    def ban_ip(self, ip: str, reason: str = None) -> bool:
        """
        Ban an IP address using UFW.
        
        Args:
            ip: IP address to ban
            reason: Optional reason for the ban
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = ['ufw', 'deny', 'from', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"Successfully banned IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error banning IP {ip}: {e}")
            return False
        except FileNotFoundError:
            self.logger.error("UFW command not found. Is UFW installed?")
            return False

    def unban_ip(self, ip: str) -> bool:
        """
        Unban an IP address using UFW.
        
        Args:
            ip: IP address to unban
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = ['ufw', 'delete', 'deny', 'from', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"Successfully unbanned IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error unbanning IP {ip}: {e}")
            return False
        except FileNotFoundError:
            self.logger.error("UFW command not found. Is UFW installed?")
            return False

    def list_banned_ips(self) -> List[str]:
        """
        List all banned IP addresses.
        
        Returns:
            List of banned IP addresses
        """
        banned_ips = []
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
            output_lines = result.stdout.strip().split('\n')
            
            for line in output_lines:
                if 'DENY' in line and 'Anywhere' in line:
                    # Extract IP from DENY rules
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == 'DENY':
                        # The IP is usually in the last part
                        ip_part = parts[-1] if parts[-1] != 'Anywhere' else parts[-2] if len(parts) > 2 else None
                        if ip_part and ip_part not in banned_ips:
                            banned_ips.append(ip_part)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error listing banned IPs: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing banned IPs: {e}")
        
        return banned_ips

    def check_ip_status(self, ip: str) -> str:
        """
        Check if an IP is banned.
        
        Args:
            ip: IP address to check
            
        Returns:
            Status of IP ('banned', 'not_banned', 'unknown')
        """
        banned_ips = self.list_banned_ips()
        if ip in banned_ips:
            return 'banned'
        else:
            # Try to determine if it's explicitly allowed or just not banned
            return 'not_banned'

    def scan(self) -> Dict[str, Any]:
        """
        Perform a complete firewall security scan.
        
        Returns:
            Dictionary containing firewall scan results
        """
        self.logger.info("Starting firewall scan...")
        
        results = {
            'ufw_status': self.get_ufw_status(),
            'rules': self.get_ufw_rules(),
            'banned_ips': self.list_banned_ips()
        }
        
        self.logger.info("Firewall scan completed.")
        return results